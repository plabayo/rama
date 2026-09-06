"""Parse TCP/UDP pressure telemetry and summarize retained os_log records."""

import argparse
from datetime import datetime
from decimal import Decimal
import json
from pathlib import Path
import re

SELECTION_RE = re.compile(
    r"flow pressure: occupancy (\d+) over soft cap (\d+); selected (\d+) idle"
)

NO_HEADROOM_RE = re.compile(
    r"flow pressure: occupancy (\d+), soft cap (\d+), but no flow idle"
)

PRESSURE_GAUGE_SCHEMA_LEGACY = 1

PRESSURE_GAUGE_SCHEMA_CURRENT = 2

GAUGE_CURRENT_RE = re.compile(
    r"live-flow counts tcp=(\d+) udp=(\d+) total=(\d+) peak=(\d+) softCap=(\d+)"
    r" hardCap=(\d+)(?=\s|$)"
    r" retiring=(\d+)(?=\s|$)"
    r" retirementOverlap=(\d+)(?=\s|$)"
)

GAUGE_LEGACY_RE = re.compile(
    r"live-flow counts tcp=(\d+) udp=(\d+) total=(\d+) peak=(\d+) softCap=(\d+)"
)

PRESSURE_COUNTER_RE = re.compile(
    r"pressure\[triggers=(\d+) scans=(\d+) skipped=(\d+) selected=(\d+) "
    r"evicted=(\d+) spared=(\d+) canceled=(\d+) expired=(\d+) pending=(\d+)\]"
)

PRESSURE_EPISODE_RE = re.compile(
    r"flow pressure episode (ended|interrupted): startEpochMs=(\d+) "
    r"durationMs=(\d+) "
    r"peakOccupancy=(\d+) softCap=(\d+) scans=(\d+) skipped=(\d+) "
    r"selected=(\d+) evicted=(\d+) spared=(\d+) canceled=(\d+) expired=(\d+)"
)

UDP_PRESSURE_DROP_MARKER = "UDP ingress pressure dropped datagram"

UDP_PRESSURE_RESUME_MARKER = "UDP ingress pressure resumed flow"

UDP_PRESSURE_REASONS = ("channel_count", "flow_bytes", "global_bytes")

SWIFT_UDP_STAGING_DROP_MARKER = "UDP Swift ingress staging dropped datagrams"

SWIFT_UDP_STAGING_DROP_REASONS = (
    "flow_items", "flow_bytes", "generation_items", "generation_bytes"
)

UDP_PRESSURE_DROP_RE = re.compile(
    rf"{UDP_PRESSURE_DROP_MARKER} "
    r"flow_id=(\d+) "
    rf'pressure="({"|".join(UDP_PRESSURE_REASONS)})" '
    r"cumulative_drops=(\d+) global_retained_bytes=(\d+) "
    r"global_max_retained_bytes=(\d+)(?=\s|$)"
)

UDP_PRESSURE_RESUME_RE = re.compile(
    rf"{UDP_PRESSURE_RESUME_MARKER} "
    r"flow_id=(\d+) "
    rf'pressure="({"|".join(UDP_PRESSURE_REASONS)})" '
    r"cumulative_resumptions=(\d+) global_retained_bytes=(\d+) "
    r"global_max_retained_bytes=(\d+)(?=\s|$)"
)

SWIFT_UDP_STAGING_DROP_RE = re.compile(
    rf"{SWIFT_UDP_STAGING_DROP_MARKER} "
    rf'reason="({"|".join(SWIFT_UDP_STAGING_DROP_REASONS)})" '
    r"cumulative_drop_events=(\d+) cumulative_dropped_items=(\d+) "
    r"cumulative_dropped_bytes_lower_bound=(\d+) "
    r"generation_retained_items=(\d+) generation_max_retained_items=(\d+) "
    r"generation_retained_bytes=(\d+) generation_max_retained_bytes=(\d+)(?=\s|$)"
)

WRITER_MEMORY_PRESSURE_MARKER = "writer memory pressure "

WRITER_MEMORY_PRESSURE_RE = re.compile(
    r'writer memory pressure (entered|recovered) '
    r'protocol="(tcp|udp|aggregate)" '
    r'reason="(aggregate_bytes|aggregate_items|tcp_waiter_gate|udp_service_bytes|'
    r'udp_service_items|reconfiguring|low_water)" '
    r"retainedBytes=(\d+) maxBytes=(\d+) retainedItems=(\d+) maxItems=(\d+)(?=\s|$)"
)

WRITER_MEMORY_PRESSURE_REASONS = (
    "aggregate_bytes", "aggregate_items", "tcp_waiter_gate",
    "udp_service_bytes", "udp_service_items", "reconfiguring",
)

UDP_WRITER_DROP_MARKER = "UDP client writer dropped datagrams"
UDP_WRITER_DROP_RE = re.compile(
    r"UDP client writer dropped datagrams reason=(aggregate_capacity|flow_capacity) "
    r"cumulative_dropped_items=(\d+) cumulative_dropped_bytes=(\d+) "
    r"aggregate_dropped_items=(\d+)$"
)

START_EPOCH_US_RE = re.compile(r"\bstartEpochUs=(\d+)\b")

ENGINE_LIFECYCLE_RE = re.compile(
    r"\b(?:startProxy|stopProxy|engine created|engine detached)\b",
    re.IGNORECASE,
)

SYSTEM_SLEEP_RE = re.compile(r"^system sleep\b", re.IGNORECASE)

SYSTEM_WAKE_RE = re.compile(r"^system wake\b", re.IGNORECASE)

PROVIDER_ALLOCATION_FAILURE_RE = re.compile(
    r"\bkernel flow allocation exhausted: resource=(?:nexus|necp)\b",
    re.IGNORECASE,
)

PRESSURE_COUNTER_KEYS = (
    "triggers",
    "scans",
    "skipped",
    "selected",
    "evicted",
    "spared",
    "canceled",
    "expired",
    "pending",
)

MAX_ARTIFACT_UINT = (1 << 64) - 1

def parse_artifact_uint(value, maximum=MAX_ARTIFACT_UINT):
    """Parse one bounded canonical unsigned integer from an artifact."""
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9]\d*", value) is None:
        return None
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
        return None
    maximum_text = str(maximum)
    if len(value) > len(maximum_text) or (
        len(value) == len(maximum_text) and value > maximum_text
    ):
        return None
    return int(value)

def selection_event(message):
    """Return event-local occupancy, cap, and selected-victim count."""
    match = SELECTION_RE.search(message)
    if not match:
        return None
    values = [parse_artifact_uint(value) for value in match.groups()]
    if any(value is None for value in values):
        return None
    occupancy, soft_cap, selected = values
    return {"occupancy": occupancy, "soft_cap": soft_cap, "selected": selected}

def no_headroom_event(message):
    """Return event-local occupancy and cap from a no-headroom line."""
    match = NO_HEADROOM_RE.search(message)
    if not match:
        return None
    values = [parse_artifact_uint(value) for value in match.groups()]
    if any(value is None for value in values):
        return None
    occupancy, soft_cap = values
    return {"occupancy": occupancy, "soft_cap": soft_cap}

def flow_gauge(message, schema_version=PRESSURE_GAUGE_SCHEMA_CURRENT):
    """Return one periodic live-flow gauge, or None."""
    if schema_version == PRESSURE_GAUGE_SCHEMA_CURRENT:
        match = GAUGE_CURRENT_RE.search(message)
    elif schema_version == PRESSURE_GAUGE_SCHEMA_LEGACY:
        match = GAUGE_LEGACY_RE.search(message)
    else:
        return None
    if not match:
        return None
    required = [parse_artifact_uint(value) for value in match.groups()[:5]]
    if any(value is None for value in required):
        return None
    tcp, udp, total, peak, soft_cap = required
    if schema_version == PRESSURE_GAUGE_SCHEMA_CURRENT:
        hard_cap, retiring, retirement_overlap = (
            parse_artifact_uint(match.group(index)) for index in (6, 7, 8)
        )
        if None in (hard_cap, retiring, retirement_overlap):
            return None
    else:
        hard_cap = retiring = retirement_overlap = None
    registered = tcp + udp
    if registered > MAX_ARTIFACT_UINT or (
        retiring is not None
        and total != registered - (retirement_overlap or 0) + retiring
    ) or (
        retirement_overlap is not None
        and (
            retiring is None
            or retirement_overlap > retiring
            or retirement_overlap > registered
        )
    ) or (
        hard_cap is not None and hard_cap > 0 and total > hard_cap
    ):
        return None
    return {
        "tcp": tcp,
        "udp": udp,
        "registered": registered,
        "retiring": retiring,
        "retirement_overlap": retirement_overlap,
        "allocated": total,
        "total": total,
        "peak": peak,
        "soft_cap": soft_cap,
        "hard_cap": hard_cap,
    }

def flow_gauge_issue(message, schema_version=PRESSURE_GAUGE_SCHEMA_CURRENT):
    """Return a capture issue for a present but incomplete/invalid gauge."""
    if "live-flow counts" not in message:
        return None
    gauge = flow_gauge(message, schema_version=schema_version)
    if gauge is None:
        return (
            "flow-gauge sample is malformed, missing a current-schema field, "
            "or has inconsistent allocation/hard-cap totals"
        )
    if gauge["peak"] < gauge["allocated"]:
        return "flow-gauge peak is below its current allocated total"
    return None

def provider_allocation_failure(message):
    """Whether a provider log explicitly identifies kernel-flow exhaustion.

    A curl transport error cannot identify the failing layer, and ENOBUFS is
    also emitted for ordinary transient write backpressure.  Accept only a
    dedicated provider statement naming the exhausted nexus/NECP allocation.
    Current runtimes that do not emit this signal correctly remain heuristic.
    """
    return PROVIDER_ALLOCATION_FAILURE_RE.search(message) is not None

def pressure_telemetry_issue(message):
    """Reject present-but-malformed or locally contradictory telemetry."""
    if not isinstance(message, str):
        return "pressure telemetry message is not text"

    signals = (
        ("live-flow counts", flow_gauge, "flow-gauge"),
        ("pressure[", pressure_counters, "pressure-counter"),
        ("flow pressure episode", pressure_episode, "pressure-episode"),
        ("; selected ", selection_event, "pressure-selection"),
        ("but no flow idle", no_headroom_event, "pressure-no-headroom"),
        (UDP_PRESSURE_DROP_MARKER, udp_pressure_event, "UDP-pressure-drop"),
        (UDP_PRESSURE_RESUME_MARKER, udp_pressure_event, "UDP-pressure-resume"),
        (UDP_WRITER_DROP_MARKER, udp_writer_drop_event, "UDP-writer-drop"),
        (
            SWIFT_UDP_STAGING_DROP_MARKER,
            udp_pressure_event,
            "Swift-UDP-staging-drop",
        ),
        (
            WRITER_MEMORY_PRESSURE_MARKER,
            writer_memory_pressure_event,
            "writer-memory-pressure",
        ),
    )
    for marker, parser, label in signals:
        count = message.count(marker)
        if count > 1:
            return f"{label} sample contains duplicate telemetry markers"
        if count == 1 and parser(message) is None:
            return f"{label} sample is malformed or internally inconsistent"

    allocation_marker = "kernel flow allocation exhausted:"
    allocation_count = message.lower().count(allocation_marker)
    if allocation_count > 1:
        return "provider allocation-exhaustion sample contains duplicate telemetry markers"
    if allocation_count == 1 and not provider_allocation_failure(message):
        return "provider allocation-exhaustion sample is malformed or unrecognized"

    if (
        "flow pressure: occupancy" in message
        and selection_event(message) is None
        and no_headroom_event(message) is None
    ):
        return "pressure lifecycle sample is malformed or unrecognized"

    selection = selection_event(message)
    if selection is not None and selection["occupancy"] < selection["soft_cap"]:
        return "pressure selection is below its soft cap"
    no_headroom = no_headroom_event(message)
    if no_headroom is not None and no_headroom["occupancy"] < no_headroom["soft_cap"]:
        return "pressure no-headroom event is below its soft cap"
    return flow_gauge_issue(message)

def udp_writer_drop_event(message):
    match = UDP_WRITER_DROP_RE.search(message)
    if match is None:
        return None
    items, size, aggregate = [parse_artifact_uint(value) for value in match.groups()[1:]]
    if items is None or size is None or aggregate is None or items == 0 or aggregate > items:
        return None
    return dict(reason=match.group(1), dropped_items=items, dropped_bytes=size,
                aggregate_dropped_items=aggregate)


def writer_memory_pressure_event(message):
    """Parse the exact version-1 aggregate writer-budget transition schema."""
    if not isinstance(message, str) or message.count(WRITER_MEMORY_PRESSURE_MARKER) != 1:
        return None
    match = WRITER_MEMORY_PRESSURE_RE.search(message)
    if match is None:
        return None
    suffix = message[match.end():]
    if suffix and re.fullmatch(r"\s+spans=\[.*\]", suffix) is None:
        return None
    transition, protocol, reason = match.groups()[:3]
    values = [parse_artifact_uint(value) for value in match.groups()[3:]]
    if any(value is None for value in values):
        return None
    retained_bytes, max_bytes, retained_items, max_items = values
    if (
        max_bytes == 0 or max_items == 0 or retained_bytes > max_bytes
        or retained_items > max_items
    ):
        return None
    if transition == "entered":
        if protocol not in {"tcp", "udp"} or reason not in WRITER_MEMORY_PRESSURE_REASONS:
            return None
    elif protocol != "aggregate" or reason != "low_water":
        return None
    if transition == "recovered" and (
        retained_bytes > (max_bytes * 3) // 4
        or retained_items > (max_items * 3) // 4
    ):
        return None
    return {
        "schema_version": 1,
        "transition": transition,
        "protocol": protocol,
        "reason": reason,
        "retained_bytes": retained_bytes,
        "max_bytes": max_bytes,
        "retained_items": retained_items,
        "max_items": max_items,
    }

def summarize_writer_memory_pressure_rows(rows):
    """Pair each aggregate pressure episode by state, never by sample counts."""
    result = {
        "status": "NOT EXERCISED",
        "entered_reasons": [],
        "recovered_reasons": [],
        "unrecovered": [],
        "issues": [],
        "failures": [],
    }
    active = None
    for _, message in rows:
        has_marker = isinstance(message, str) and WRITER_MEMORY_PRESSURE_MARKER in message
        event = writer_memory_pressure_event(message)
        if has_marker and event is None:
            result["issues"].append("writer-memory pressure telemetry is malformed")
            continue
        if event is None:
            continue
        if event["transition"] == "entered":
            if active is not None:
                result["issues"].append(
                    "writer-memory pressure entered before the prior episode recovered"
                )
            active = event["reason"]
            result["entered_reasons"].append(event["reason"])
        elif active is None:
            result["issues"].append(
                "writer-memory pressure recovery has no preceding entry"
            )
        else:
            result["recovered_reasons"].append(active)
            active = None
    if active is not None:
        result["unrecovered"].append(active)
    if result["issues"]:
        result["status"] = "INCOMPLETE"
    elif result["unrecovered"]:
        result["status"] = "FAILED"
        result["failures"].append(
            "writer-memory pressure did not recover after: "
            + ", ".join(result["unrecovered"])
        )
    elif result["entered_reasons"]:
        result["status"] = "GOOD"
    return result

def udp_pressure_event(message):
    """Parse one canonical UDP pressure transition with cumulative counters."""
    if not isinstance(message, str):
        return None
    drop_count = message.count(UDP_PRESSURE_DROP_MARKER)
    resume_count = message.count(UDP_PRESSURE_RESUME_MARKER)
    staging_count = message.count(SWIFT_UDP_STAGING_DROP_MARKER)
    if drop_count + resume_count + staging_count != 1:
        return None
    if staging_count:
        match = SWIFT_UDP_STAGING_DROP_RE.search(message)
        if match is None:
            return None
        fields = (
            "reason",
            "cumulative_drop_events",
            "cumulative_dropped_items",
            "cumulative_dropped_bytes_lower_bound",
            "generation_retained_items",
            "generation_max_retained_items",
            "generation_retained_bytes",
            "generation_max_retained_bytes",
        )
        if any(len(re.findall(rf"\b{field}=", message)) != 1 for field in fields):
            return None
        if re.search(r"\bcumulative_(?:drops|resumptions)=", message):
            return None
        suffix = message[match.end():]
        if suffix and re.fullmatch(r"\s+spans=\[.*\]", suffix) is None:
            return None
        values = [parse_artifact_uint(value) for value in match.groups()[1:]]
        if any(value is None for value in values):
            return None
        (
            events,
            items,
            bytes_lower_bound,
            retained_items,
            maximum_items,
            retained,
            maximum,
        ) = values
        if (
            events == 0
            or events & (events - 1) != 0
            or items < events
            or maximum_items == 0
            or retained_items > maximum_items
            or maximum == 0
            or retained > maximum
        ):
            return None
        return {
            "layer": "swift_staging",
            "transition": "drop",
            "pressure": match.group(1),
            "cumulative": events,
            "cumulative_dropped_items": items,
            "cumulative_dropped_bytes_lower_bound": bytes_lower_bound,
            "generation_retained_items": retained_items,
            "generation_max_retained_items": maximum_items,
            "generation_retained_bytes": retained,
            "generation_max_retained_bytes": maximum,
        }
    transition = "drop" if drop_count else "resume"
    match = (
        UDP_PRESSURE_DROP_RE.search(message)
        if transition == "drop"
        else UDP_PRESSURE_RESUME_RE.search(message)
    )
    if match is None:
        return None
    counter_field = (
        "cumulative_drops" if transition == "drop" else "cumulative_resumptions"
    )
    forbidden_counter = (
        "cumulative_resumptions" if transition == "drop" else "cumulative_drops"
    )
    for field in (
        "flow_id",
        "pressure",
        counter_field,
        "global_retained_bytes",
        "global_max_retained_bytes",
    ):
        if len(re.findall(rf"\b{field}=", message)) != 1:
            return None
    if re.search(rf"\b{forbidden_counter}=", message):
        return None
    suffix = message[match.end():]
    if suffix and re.fullmatch(r"\s+spans=\[.*\]", suffix) is None:
        return None
    flow_id = parse_artifact_uint(match.group(1))
    values = [parse_artifact_uint(value) for value in match.groups()[2:]]
    if any(value is None for value in values):
        return None
    cumulative, retained, maximum = values
    if flow_id in (None, 0) or cumulative == 0 or maximum == 0 or retained > maximum:
        return None
    return {
        "layer": "rust_ingress",
        "transition": transition,
        "flow_id": flow_id,
        "pressure": match.group(2),
        "cumulative": cumulative,
        "global_retained_bytes": retained,
        "global_max_retained_bytes": maximum,
    }

def summarize_udp_pressure_rows(
    rows, *, workload_exercised, mode, baseline_end_epoch=None,
    required_flow_id=None,
):
    """Return a fail-closed, transition-based UDP pressure verdict.

    Counters are sampled cumulative producer counters, so skipped values are
    valid but repeats and rollbacks are not. Normal modes reject every
    attributable Rust-ingress drop. Ceiling mode accepts those drops only when
    a later sampled recovery exists for every affected pressure reason. Swift
    pre-queue staging has no recovery transition, so every staging drop fails.
    """
    result = {
        "status": "NOT EXERCISED",
        "events": 0,
        "drop_transitions": 0,
        "resume_transitions": 0,
        "drop_reasons": [],
        "recovered_reasons": [],
        "latest_drops": {},
        "latest_resumptions": {},
        "swift_staging_drop_samples": 0,
        "latest_swift_staging_drop": None,
        "unrecovered": [],
        "issues": [],
        "failures": [],
    }
    if workload_exercised not in (True, False):
        result["status"] = "INCOMPLETE"
        result["issues"].append("UDP workload exercise state is missing or invalid")
        return result
    if not workload_exercised:
        return result
    if required_flow_id is not None and (
        isinstance(required_flow_id, bool)
        or not isinstance(required_flow_id, int)
        or required_flow_id <= 0
        or required_flow_id > MAX_ARTIFACT_UINT
    ):
        result["status"] = "INCOMPLETE"
        result["issues"].append("required UDP pressure flow identity is invalid")
        return result

    latest = {"drop": {}, "resume": {}}
    last_in_run_transition = {}
    seen_in_run_drop_reasons = set()
    for epoch, message in rows:
        has_marker = isinstance(message, str) and (
            UDP_PRESSURE_DROP_MARKER in message
            or UDP_PRESSURE_RESUME_MARKER in message
            or SWIFT_UDP_STAGING_DROP_MARKER in message
        )
        event = udp_pressure_event(message)
        if has_marker and event is None:
            result["issues"].append(
                "UDP pressure telemetry is malformed or internally inconsistent"
            )
            continue
        if event is None:
            continue
        if (
            required_flow_id is not None
            and event["layer"] == "rust_ingress"
            and event["flow_id"] != required_flow_id
        ):
            result["issues"].append(
                "UDP pressure transition belongs to a different flow"
            )
            continue
        in_run = baseline_end_epoch is None or (
            epoch is not None and epoch > baseline_end_epoch
        )
        if event["layer"] == "swift_staging":
            previous = result["latest_swift_staging_drop"]
            if previous is not None and (
                event["cumulative"] <= previous["cumulative"]
                or event["cumulative_dropped_items"]
                <= previous["cumulative_dropped_items"]
                or event["cumulative_dropped_bytes_lower_bound"]
                < previous["cumulative_dropped_bytes_lower_bound"]
                or event["generation_max_retained_items"]
                != previous["generation_max_retained_items"]
                or event["generation_max_retained_bytes"]
                != previous["generation_max_retained_bytes"]
            ):
                result["issues"].append(
                    "Swift UDP staging cumulative counters repeated, rolled back, "
                    "or changed generation limit"
                )
            result["latest_swift_staging_drop"] = event
            if in_run:
                result["events"] += 1
                result["swift_staging_drop_samples"] += 1
            continue
        transition = event["transition"]
        reason = event["pressure"]
        previous = latest[transition].get(reason)
        if previous is not None and event["cumulative"] <= previous:
            result["issues"].append(
                f"UDP pressure {transition} counter for {reason} repeated or rolled back"
            )
        latest[transition][reason] = event["cumulative"]
        if not in_run:
            continue
        result["events"] += 1
        result[f"{transition}_transitions"] += 1
        last_in_run_transition[reason] = transition
        if transition == "drop":
            seen_in_run_drop_reasons.add(reason)

    result["latest_drops"] = dict(sorted(latest["drop"].items()))
    result["latest_resumptions"] = dict(sorted(latest["resume"].items()))
    result["drop_reasons"] = sorted(seen_in_run_drop_reasons)
    result["recovered_reasons"] = sorted(
        reason
        for reason in seen_in_run_drop_reasons
        if last_in_run_transition.get(reason) == "resume"
    )
    result["unrecovered"] = sorted(
        reason
        for reason, transition in last_in_run_transition.items()
        if transition == "drop"
    )
    if result["issues"]:
        result["status"] = "INCOMPLETE"
        return result
    if mode not in {
        "stress-only",
        "cap-validate",
        "cap-hard-limited",
        "cap-too-high",
        "find-ceiling",
    }:
        result["status"] = "INCOMPLETE"
        result["issues"].append("UDP pressure run mode is missing or invalid")
        return result
    if mode == "find-ceiling":
        if result["unrecovered"]:
            result["failures"].append(
                "UDP pressure did not recover after ceiling-mode drops: "
                + ", ".join(result["unrecovered"])
            )
    elif result["drop_transitions"]:
        result["failures"].append(
            f"{result['drop_transitions']} UDP ingress pressure drop transition(s) were observed"
        )
    if result["swift_staging_drop_samples"]:
        latest_staging = result["latest_swift_staging_drop"]
        result["failures"].append(
            f"{result['swift_staging_drop_samples']} Swift UDP ingress staging drop "
            f"sample(s) were observed ({latest_staging['cumulative']} cumulative "
            f"event(s), {latest_staging['cumulative_dropped_items']} dropped item(s))"
        )
    result["status"] = "FAILED" if result["failures"] else "GOOD"
    return result

def phase_for_epoch(epoch, phases):
    """Return the half-open phase containing `epoch`.

    Phase and sample epochs should retain their producer precision. In
    particular, callers must not round a probe down to whole seconds before
    using this helper.
    """
    if epoch is None:
        return "?"
    for name, start, end in phases:
        if start <= epoch < end:
            return name
    return "-"

def parse_epoch(value):
    """Parse one decimal epoch without discarding sub-second precision."""
    try:
        epoch = Decimal(str(value))
    except (ValueError, ArithmeticError):
        return None
    return epoch if epoch.is_finite() and epoch >= 0 else None

def parse_oslog_timestamp(value):
    """Parse one complete timestamp emitted by ``log --style ndjson``.

    Do not accept a valid-looking prefix followed by an unknown timezone or
    arbitrary suffix: phase attribution is evidence, not best-effort display.
    """
    if not isinstance(value, str):
        return None
    formats = (
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
    )
    for timestamp_format in formats:
        try:
            parsed = datetime.strptime(value, timestamp_format).timestamp()
        except (TypeError, ValueError, OverflowError):
            continue
        return parse_epoch(f"{parsed:.6f}")
    return None

class DuplicateJsonKeyError(ValueError):
    """A JSON artifact cannot bind one value to each field."""

def unique_json_object(pairs):
    """Retain unknown fields while rejecting ambiguous repeated JSON keys."""
    value = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError(f"duplicate JSON key: {key}")
        value[key] = item
    return value

def parse_ndjson_lines(lines, *, provider_pid=None, subsystem=None):
    """Decode records and the native stream's optional preamble/count footer."""
    pid = _nonnegative_int(provider_pid)
    preamble = None
    if pid is not None and pid > 0 and isinstance(subsystem, str) and subsystem:
        preamble = (
            f'Filtering the log data using "processIdentifier == {pid} '
            f'AND subsystem == "{subsystem}""'
        )
    records = [(line_number, raw.strip()) for line_number, raw in enumerate(lines, 1)
               if raw.strip() and not (
                   line_number == 1 and raw.rstrip("\r\n") == preamble
               )]
    decoded = []
    issues = []
    for line_number, line in records:
        try:
            value = json.loads(line, object_pairs_hook=unique_json_object)
        except (ValueError, RecursionError):
            issues.append(f"malformed NDJSON record at line {line_number}")
            continue
        if not isinstance(value, dict):
            issues.append(f"non-object NDJSON record at line {line_number}")
            continue
        # `log stream --style ndjson` emits this metadata when stopped cleanly.
        if (
            line_number == records[-1][0]
            and set(value) == {"count", "finished"}
            and type(value["finished"]) is int and value["finished"] == 1
            and type(value["count"]) is int and value["count"] == len(decoded)
        ):
            continue
        decoded.append(value)
    return decoded, issues

def filter_provider_ndjson_records(records, provider_pid, subsystem):
    """Keep only records provably emitted by one provider process."""
    provider_pid = _nonnegative_int(provider_pid)
    if (
        provider_pid is None
        or provider_pid <= 0
        or not isinstance(subsystem, str)
        or not subsystem
    ):
        return [], ["provider identity is missing or invalid"]

    accepted = []
    missing_pid = mismatched_pid = mismatched_subsystem = 0
    for record in records:
        process_id = record.get("processID")
        if isinstance(process_id, bool) or not isinstance(process_id, int):
            missing_pid += 1
            continue
        if process_id != provider_pid:
            mismatched_pid += 1
            continue
        if record.get("subsystem") != subsystem:
            mismatched_subsystem += 1
            continue
        accepted.append(record)

    issues = []
    if missing_pid:
        issues.append(f"{missing_pid} NDJSON record(s) have no numeric processID")
    if mismatched_pid:
        issues.append(
            f"{mismatched_pid} NDJSON record(s) came from a different processID"
        )
    if mismatched_subsystem:
        issues.append(
            f"{mismatched_subsystem} NDJSON record(s) came from a different subsystem"
        )
    return accepted, issues

def engine_lifecycle_event(message):
    """Return the generation-changing lifecycle text in one log message."""
    match = ENGINE_LIFECYCLE_RE.search(message)
    return match.group(0) if match else None

def lifecycle_category_issue(message, category):
    """Return an issue when a lifecycle-only signal has untrusted provenance."""
    is_lifecycle = (
        engine_lifecycle_event(message) is not None
        or SYSTEM_SLEEP_RE.search(message) is not None
        or SYSTEM_WAKE_RE.search(message) is not None
        or pressure_episode(message) is not None
        or flow_gauge(message) is not None
        or pressure_counters(message) is not None
        or selection_event(message) is not None
        or no_headroom_event(message) is not None
        or udp_pressure_event(message) is not None
        or writer_memory_pressure_event(message) is not None
        or provider_allocation_failure(message)
        or any(
            marker in message
            for marker in (
                "live-flow counts",
                "pressure[",
                "flow pressure episode",
                "flow pressure: occupancy",
                UDP_PRESSURE_DROP_MARKER,
                UDP_PRESSURE_RESUME_MARKER,
                SWIFT_UDP_STAGING_DROP_MARKER,
                WRITER_MEMORY_PRESSURE_MARKER,
                "kernel flow allocation exhausted:",
            )
        )
    )
    if is_lifecycle and category != "lifecycle":
        return f"lifecycle evidence used non-lifecycle category {category!r}"
    return None

def _nonnegative_int(value):
    """Return one canonical non-negative integer, rejecting coercions."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= MAX_ARTIFACT_UINT else None
    if isinstance(value, str):
        return parse_artifact_uint(value)
    return None

def pressure_counters(message):
    """Return one periodic pressure-counter delta, or None."""
    match = PRESSURE_COUNTER_RE.search(message)
    if not match:
        return None
    values = [parse_artifact_uint(value) for value in match.groups()]
    if any(value is None for value in values):
        return None
    return dict(zip(PRESSURE_COUNTER_KEYS, values))

def pressure_episode(message):
    """Return one final or detach-interrupted pressure episode summary."""
    match = PRESSURE_EPISODE_RE.search(message)
    if not match:
        return None
    values = match.groups()
    keys = (
        "outcome",
        "start_epoch_ms",
        "duration_ms",
        "peak_occupancy",
        "soft_cap",
        "scans",
        "skipped",
        "selected",
        "evicted",
        "spared",
        "canceled",
        "expired",
    )
    numeric_values = [parse_artifact_uint(value) for value in values[1:]]
    if any(value is None for value in numeric_values):
        return None
    event = dict(zip(keys, (values[0], *numeric_values)))
    precise_start = START_EPOCH_US_RE.search(message)
    if "startEpochUs=" in message and precise_start is None:
        return None
    if precise_start:
        start_epoch_us = parse_artifact_uint(precise_start.group(1))
        if start_epoch_us is None:
            return None
    else:
        start_epoch_us = event["start_epoch_ms"] * 1_000
        if start_epoch_us > MAX_ARTIFACT_UINT:
            return None
    if start_epoch_us // 1_000 != event["start_epoch_ms"]:
        return None
    if event["outcome"] == "ended" and event["selected"] != sum(
        event[key] for key in ("evicted", "spared", "canceled", "expired")
    ):
        return None
    if event["outcome"] == "interrupted" and event["selected"] < sum(
        event[key] for key in ("evicted", "spared", "canceled", "expired")
    ):
        return None
    if event["peak_occupancy"] < event["soft_cap"]:
        return None
    event["start_epoch_us"] = start_epoch_us
    return event

def summarize_pressure_rows(
    rows, baseline_end_epoch=None, baseline_end_epoch_us=None
):
    """Build non-double-counting pressure evidence from `(epoch, message)` rows.

    A lifecycle peak first observed after the boundary is not attributable to
    the run: it may have risen in the gap after the previous gauge. That first
    post-boundary gauge establishes a conservative floor; only later increases
    count. Likewise, the first periodic delta after a boundary is discarded
    unless the preceding tick was at/after the boundary, because its interval
    may straddle baseline. Episode producers carry their wall-clock start, so
    episode attribution never guesses from monotonic duration. Periodic deltas
    and episode totals overlap and callers must never sum them.
    """
    if baseline_end_epoch_us is None and baseline_end_epoch is not None:
        baseline_end_epoch_us = int(
            Decimal(str(baseline_end_epoch)) * 1_000_000
        )

    result = {
        "issues": [],
        "observed_peak": 0,
        "soft_caps": set(),
        "selection_events": 0,
        "selected": 0,
        "no_headroom": 0,
        "periodic_intervals": 0,
        "periodic": {key: 0 for key in PRESSURE_COUNTER_KEYS[:-1]},
        "episodes": 0,
        "validated_eviction_episodes": 0,
        "validated_eviction_episode_caps": {},
        "episode": {
            key: 0
            for key in ("selected", "evicted", "spared", "canceled", "expired")
        },
    }
    lifecycle_peak_floor = 0
    exact_boundary_gauge = False
    post_boundary_gauge_seen = False
    last_periodic_epoch = None

    for epoch, message in rows:
        gauge = flow_gauge(message)
        if gauge:
            result["soft_caps"].add(gauge["soft_cap"])
            if baseline_end_epoch is not None and (
                epoch is None or epoch <= baseline_end_epoch
            ):
                lifecycle_peak_floor = max(
                    lifecycle_peak_floor, gauge["peak"]
                )
                exact_boundary_gauge = (
                    exact_boundary_gauge or epoch == baseline_end_epoch
                )
            elif baseline_end_epoch is None or epoch > baseline_end_epoch:
                result["observed_peak"] = max(
                    result["observed_peak"], gauge["total"])
                may_attribute_lifecycle_peak = (
                    baseline_end_epoch is None
                    or post_boundary_gauge_seen
                    or exact_boundary_gauge
                )
                if (
                    may_attribute_lifecycle_peak
                    and gauge["peak"] > lifecycle_peak_floor
                ):
                    result["observed_peak"] = max(
                        result["observed_peak"], gauge["peak"])
                lifecycle_peak_floor = max(
                    lifecycle_peak_floor, gauge["peak"]
                )
                post_boundary_gauge_seen = True

        in_run = baseline_end_epoch is None or (
            epoch is not None and epoch > baseline_end_epoch
        )
        counters = pressure_counters(message)
        if counters:
            interval_is_in_run = in_run and (
                baseline_end_epoch is None
                or (
                    last_periodic_epoch is not None
                    and last_periodic_epoch >= baseline_end_epoch
                )
            )
            if interval_is_in_run:
                result["periodic_intervals"] += 1
                for key in result["periodic"]:
                    result["periodic"][key] += counters[key]
            if epoch is not None:
                last_periodic_epoch = epoch
        if not in_run:
            continue

        selection = selection_event(message)
        if selection:
            result["selection_events"] += 1
            result["selected"] += selection["selected"]
            result["observed_peak"] = max(
                result["observed_peak"], selection["occupancy"])
            result["soft_caps"].add(selection["soft_cap"])

        no_headroom = no_headroom_event(message)
        if no_headroom:
            result["no_headroom"] += 1
            result["observed_peak"] = max(
                result["observed_peak"], no_headroom["occupancy"])
            result["soft_caps"].add(no_headroom["soft_cap"])

        episode = pressure_episode(message)
        row_epoch = parse_epoch(epoch)
        if episode and (
            row_epoch is None
            or Decimal(episode["start_epoch_us"]) / Decimal(1_000_000) > row_epoch
        ):
            result["issues"].append(
                "pressure episode start timestamp is later than its log record"
            )
            episode = None
        if episode:
            if (
                baseline_end_epoch_us is not None
                and episode["start_epoch_us"] <= baseline_end_epoch_us
            ):
                continue
            result["episodes"] += 1
            if (
                episode["outcome"] == "ended"
                and
                episode["soft_cap"] > 0
                and episode["peak_occupancy"] >= episode["soft_cap"]
                and episode["evicted"] > 0
            ):
                result["validated_eviction_episodes"] += 1
                cap = episode["soft_cap"]
                result["validated_eviction_episode_caps"][cap] = (
                    result["validated_eviction_episode_caps"].get(cap, 0) + 1
                )
            result["observed_peak"] = max(
                result["observed_peak"], episode["peak_occupancy"])
            result["soft_caps"].add(episode["soft_cap"])
            for key in result["episode"]:
                result["episode"][key] += episode[key]

    result["eviction_observed"] = (
        result["periodic"]["evicted"] > 0 or result["episode"]["evicted"] > 0
    )
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="os_log export in NDJSON format")
    parser.add_argument("--pid", type=int, required=True, help="provider process ID")
    parser.add_argument("--subsystem", required=True, help="exact provider log subsystem")
    args = parser.parse_args(argv)
    try:
        with args.log.open() as source:
            records, issues = parse_ndjson_lines(
                source, provider_pid=args.pid, subsystem=args.subsystem)
    except (OSError, UnicodeError) as error:
        parser.error(str(error))
    records, identity_issues = filter_provider_ndjson_records(records, args.pid, args.subsystem)
    issues.extend(identity_issues)
    rows, udp_events, writer_drops = [], [], []
    for record in records:
        epoch = parse_oslog_timestamp(record.get("timestamp"))
        message = record.get("eventMessage")
        if epoch is None or not isinstance(message, str):
            issues.append("record has no valid timestamp or eventMessage")
            continue
        issue = pressure_telemetry_issue(message)
        if issue:
            issues.append(issue)
            continue
        rows.append((epoch, message))
        event = udp_pressure_event(message)
        if event:
            udp_events.append(event)
        drop = udp_writer_drop_event(message)
        if drop:
            writer_drops.append(drop)
    if not rows:
        issues.append("no usable provider log records")
    tcp = summarize_pressure_rows(rows)
    tcp["soft_caps"] = sorted(tcp["soft_caps"])
    writer = summarize_writer_memory_pressure_rows(rows)
    issues.extend(tcp["issues"])
    issues.extend(writer["issues"])
    print(json.dumps({
        "records": len(rows), "issues": issues, "tcp_pressure": tcp,
        "writer_pressure": writer, "udp_pressure_events": udp_events,
        "udp_writer_drop_samples": writer_drops,
    }, indent=2, sort_keys=True))
    return int(bool(issues))


if __name__ == "__main__":
    raise SystemExit(main())
