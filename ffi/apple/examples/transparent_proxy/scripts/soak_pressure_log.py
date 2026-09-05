"""Stable parser for pressure telemetry emitted by TransparentProxyCore."""

from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import os
import re
import stat
import uuid


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
# The canonical phase asks for ~45 seconds of real system sleep. This bound
# applies only to one raw provider lifecycle pair, never to the whole phase.
MAX_PROVEN_SLEEP_SECONDS = 120


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


def parse_artifact_epoch(value):
    """Parse a canonical integer or microsecond artifact timestamp."""
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(0|[1-9]\d*)(?:\.\d{1,6})?", value)
    if match is None or parse_artifact_uint(match.group(1)) is None:
        return None
    return parse_epoch(value)


def parse_phase_iso_timestamp(value):
    """Parse the exact UTC, whole-second timestamp emitted in phase rows."""
    if not isinstance(value, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ) is None:
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        return parse_epoch(int(parsed.timestamp()))
    except (TypeError, ValueError, OverflowError):
        return None


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
    """Decode records, allowing only the bound log stream's optional preamble."""
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


def parse_phase_marker_lines(lines, expected_order):
    """Parse paired, ordered, non-overlapping phase markers."""
    order = {name: index for index, name in enumerate(expected_order)}
    starts = {}
    ends = {}
    phases = []
    issues = []
    active = None
    last_started_index = -1

    for line_number, raw in enumerate(lines, 1):
        fields = raw.rstrip("\n").split("\t")
        if len(fields) != 4:
            if raw.strip():
                issues.append(f"malformed phase marker at line {line_number}")
            continue
        name, kind, raw_epoch, raw_iso = fields
        epoch = parse_artifact_epoch(raw_epoch)
        iso_epoch = parse_phase_iso_timestamp(raw_iso)
        if name not in order:
            issues.append(f"unexpected phase {name!r} at line {line_number}")
            continue
        if epoch is None:
            issues.append(f"invalid phase timestamp at line {line_number}")
            continue
        if iso_epoch is None:
            issues.append(f"invalid phase ISO timestamp at line {line_number}")
            continue
        if not (iso_epoch <= epoch < iso_epoch + 1):
            issues.append(f"phase epoch/ISO mismatch at line {line_number}")
            continue
        if kind == "start":
            if name in starts:
                issues.append(f"duplicate start marker for phase {name!r}")
                continue
            if active is not None:
                issues.append(
                    f"phase {name!r} started before phase {active!r} ended"
                )
            if order[name] <= last_started_index:
                issues.append(f"phase {name!r} is out of order")
            starts[name] = epoch
            active = name
            last_started_index = max(last_started_index, order[name])
        elif kind == "end":
            if name not in starts:
                issues.append(f"phase {name!r} ended without a start marker")
                continue
            if name in ends:
                issues.append(f"duplicate end marker for phase {name!r}")
                continue
            if active != name:
                issues.append(f"phase {name!r} ended while phase {active!r} was active")
            if epoch <= starts[name]:
                issues.append(f"phase {name!r} has a non-positive duration")
                continue
            ends[name] = epoch
            phases.append((name, starts[name], epoch))
            if active == name:
                active = None
        else:
            issues.append(f"invalid phase marker kind at line {line_number}")

    incomplete = set(starts) - set(ends)
    ordered_phases = sorted(phases, key=lambda phase: order[phase[0]])
    for previous, current in zip(ordered_phases, ordered_phases[1:]):
        if current[1] < previous[2]:
            issues.append(
                f"phase {current[0]!r} overlaps phase {previous[0]!r}"
            )
    starts_us = {name: int(epoch * 1_000_000) for name, epoch in starts.items()}
    ends_us = {name: int(epoch * 1_000_000) for name, epoch in ends.items()}
    return ordered_phases, incomplete, starts_us, ends_us, issues


def parse_provider_identity_lines(lines, expected_identity):
    """Validate every periodic provider identity observation."""
    if re.fullmatch(r"[0-9a-f]{64}", expected_identity or "") is None:
        return [], ["provider start identity is missing or invalid"]
    epochs = []
    issues = []
    previous = None
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        fields = raw.rstrip("\n").split("\t")
        if len(fields) != 2:
            issues.append(f"malformed provider identity sample at line {line_number}")
            continue
        epoch = parse_artifact_epoch(fields[0])
        identity = fields[1]
        if epoch is None or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            issues.append(f"malformed provider identity sample at line {line_number}")
            continue
        if previous is not None and epoch < previous:
            issues.append(f"out-of-order provider identity sample at line {line_number}")
            continue
        if identity != expected_identity:
            issues.append(f"provider identity changed at line {line_number}")
        epochs.append(epoch)
        previous = epoch
    if len(epochs) < 2:
        issues.append("fewer than two provider identity samples were captured")
    return epochs, issues


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


def cap_validation_hard_limited(
    soft_cap, hard_cap, baseline_registered, baseline_allocated
):
    """Return whether allocated headroom cannot reach the registered trigger."""
    values = tuple(
        _nonnegative_int(value)
        for value in (soft_cap, hard_cap, baseline_registered, baseline_allocated)
    )
    if any(value is None for value in values):
        return None
    soft_cap, hard_cap, baseline_registered, baseline_allocated = values
    if baseline_registered > baseline_allocated or (
        hard_cap > 0 and baseline_allocated > hard_cap
    ):
        return None
    if hard_cap == 0:
        return False
    soft_headroom = max(0, soft_cap - baseline_registered)
    hard_headroom = max(0, hard_cap - baseline_allocated)
    return hard_cap < soft_cap or hard_headroom < soft_headroom


def flow_pool_status(
    established_sustained,
    target,
    occupancy_samples,
    gauge_samples,
    soft_cap,
    hard_cap,
    sustained_intervals,
    phase,
    pool_bracket=None,
    required_hold_seconds=None,
):
    """Prove established workers plus bracketed provider-PID correlation.

    The provider does not expose worker identities. Require the strongest
    available cold-path evidence instead: fresh provider gauges immediately
    before spawning, while the target is sustained, and after killing it. The
    rise and fall must both cover the cap-aware contribution documented by
    the bracket artifact; this proves aggregate correlation, not identities.
    """
    if established_sustained == "skipped":
        return "skipped"
    if isinstance(established_sustained, bool) or established_sustained not in (
        0, 1, "0", "1"
    ):
        return None
    required_hold_seconds = _nonnegative_int(required_hold_seconds)
    if required_hold_seconds is None or required_hold_seconds <= 0:
        return None
    try:
        _, phase_start, phase_end = phase
        (
            baseline_epoch,
            baseline_registered,
            baseline_allocated,
            peak_epoch,
            peak_registered,
            peak_allocated,
            post_epoch,
            post_registered,
            post_allocated,
            recorded_contribution,
        ) = pool_bracket
    except (TypeError, ValueError):
        return None

    phase_start = parse_epoch(phase_start)
    phase_end = parse_epoch(phase_end)
    target = _nonnegative_int(target)
    soft_cap = _nonnegative_int(soft_cap)
    hard_cap = _nonnegative_int(hard_cap)
    baseline_epoch = parse_epoch(baseline_epoch)
    peak_epoch = parse_epoch(peak_epoch)
    post_epoch = parse_epoch(post_epoch)
    baseline_registered = _nonnegative_int(baseline_registered)
    baseline_allocated = _nonnegative_int(baseline_allocated)
    peak_registered = _nonnegative_int(peak_registered)
    peak_allocated = _nonnegative_int(peak_allocated)
    post_registered = _nonnegative_int(post_registered)
    post_allocated = _nonnegative_int(post_allocated)
    recorded_contribution = _nonnegative_int(recorded_contribution)
    if (
        target is None
        or target <= 0
        or soft_cap is None
        or hard_cap is None
        or baseline_epoch is None
        or peak_epoch is None
        or post_epoch is None
        or baseline_registered is None
        or baseline_allocated is None
        or peak_registered is None
        or peak_allocated is None
        or post_registered is None
        or post_allocated is None
        or recorded_contribution is None
        or phase_start is None
        or phase_end is None
        or baseline_registered > baseline_allocated
        or peak_registered > peak_allocated
        or post_registered > post_allocated
        or not (phase_start <= baseline_epoch < peak_epoch < post_epoch < phase_end)
    ):
        return None
    try:
        occupancy = {
            (parse_epoch(epoch), _nonnegative_int(registered))
            for epoch, registered in occupancy_samples
        }
        gauges = {
            (
                parse_epoch(epoch),
                _nonnegative_int(registered),
                _nonnegative_int(allocated),
            )
            for epoch, registered, allocated in gauge_samples
        }
    except (TypeError, ValueError):
        return None
    if any(epoch is None or registered is None for epoch, registered in occupancy):
        return None
    if any(
        epoch is None
        or registered is None
        or allocated is None
        or registered > allocated
        or (hard_cap > 0 and allocated > hard_cap)
        for epoch, registered, allocated in gauges
    ):
        return None
    bracket_gauges = {
        (baseline_epoch, baseline_registered, baseline_allocated),
        (peak_epoch, peak_registered, peak_allocated),
        (post_epoch, post_registered, post_allocated),
    }
    if not bracket_gauges.issubset(gauges):
        return None
    if (peak_epoch, peak_registered) not in occupancy:
        return None

    # This is aggregate correlation, not flow identity. In cap-validation mode
    # softCap applies to registered flows, while hardCap applies to all allocated
    # resources including retiring flows. Never let retiring allocations satisfy
    # a soft-cap worker target.
    if soft_cap:
        if hard_cap and hard_cap < soft_cap:
            return None
        baseline_metric = baseline_registered
        peak_metric = peak_registered
        post_metric = post_registered
        expected_contribution = min(
            target, max(0, soft_cap - baseline_registered)
        )
        if hard_cap:
            expected_contribution = min(
                expected_contribution,
                max(0, hard_cap - baseline_allocated),
            )
    elif hard_cap:
        baseline_metric = baseline_allocated
        peak_metric = peak_allocated
        post_metric = post_allocated
        expected_contribution = min(
            target, max(0, hard_cap - baseline_allocated)
        )
    else:
        baseline_metric = baseline_registered
        peak_metric = peak_registered
        post_metric = post_registered
        expected_contribution = target
    if expected_contribution <= 0 or recorded_contribution != expected_contribution:
        return None

    # A producer-observed miss is a workload result in its own right. The
    # bracket must still be structurally valid and its configured contribution
    # must agree with this parser. A failed workload need not have produced the
    # rise/fall or sustained interval required to prove a success.
    if str(established_sustained) == "0":
        return "0"

    if (
        peak_metric - baseline_metric < expected_contribution
        or peak_metric - post_metric < expected_contribution
    ):
        return None
    for raw_start, raw_end in sustained_intervals:
        interval_start = parse_epoch(raw_start)
        interval_end = parse_epoch(raw_end)
        if (
            interval_start is None
            or interval_end is None
            or interval_end - interval_start < Decimal(required_hold_seconds)
            or interval_start < phase_start
            or interval_end > phase_end
            or interval_start < baseline_epoch
            or interval_end > post_epoch
        ):
            continue
        if interval_start <= peak_epoch <= interval_end:
            return "1"
    return None


def flow_pool_evidence_issues(label, raw_status, correlated_status, has_bracket):
    """Return missing correlation evidence without masking workload failure."""
    if raw_status in (0, 1, "0", "1") and not has_bracket:
        return [f"{label} has no provider flow-pool bracket"]
    if raw_status in (0, 1, "0", "1") and correlated_status is None:
        return [f"{label} has no correlated phase-local provider occupancy evidence"]
    return []


def probe_succeeded(record):
    """Return whether one parsed probe completed cleanly with HTTP 2xx."""
    _, _, curl_rc, code, *_ = record
    return curl_rc == 0 and code.startswith("2")


def ceiling_transport_failed(record):
    """Return whether a probe had a non-DNS, non-TLS transport interruption."""
    _, _, curl_rc, code, *_ = record
    # These curl outcomes can describe a stalled/reset data path.  Connection,
    # name-resolution, certificate, and TLS setup failures are deliberately
    # excluded; even this subset is only a heuristic until a dedicated provider
    # nexus/NECP allocation-exhaustion signal corroborates it in
    # ``ceiling_outage_window``.
    return curl_rc in (28, 52, 55, 56) and code == "000"


def parse_probe_lines(lines, label="liveness probe"):
    """Parse start/completion/ISO/curl-rc/http-code probe records."""
    records = []
    issues = []
    previous_completion = None
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        fields = raw.rstrip("\n").split("\t")
        if len(fields) != 5:
            issues.append(f"malformed {label} at line {line_number}")
            continue
        started = parse_artifact_epoch(fields[0])
        completed = parse_artifact_epoch(fields[1])
        iso_epoch = parse_phase_iso_timestamp(fields[2])
        curl_rc = _nonnegative_int(fields[3])
        if (
            started is None
            or completed is None
            or completed < started
            or iso_epoch is None
            or not (iso_epoch <= completed < iso_epoch + 1)
            or curl_rc is None
            or re.fullmatch(r"\d{3}", fields[4]) is None
        ):
            issues.append(f"malformed {label} at line {line_number}")
            continue
        if previous_completion is not None and started < previous_completion:
            issues.append(f"out-of-order {label} at line {line_number}")
            continue
        records.append((started, completed, curl_rc, fields[4]))
        previous_completion = completed
    return records, issues


SLEEP_WORKLOAD_ARTIFACT_LIMITS = {
    "wake-download-headers.txt": 1024 * 1024,
    "wake-download.body": 32 * 1024 * 1024,
    "wake-download.txt": 64 * 1024,
}


def read_sleep_workload_artifacts(directory):
    """Read only bounded regular files after the wake worker has been joined."""
    artifacts = {}
    for name, maximum in SLEEP_WORKLOAD_ARTIFACT_LIMITS.items():
        path = os.path.join(directory, name)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise ValueError(f"sleep-wake workload artifact is not bounded and regular: {name}")
            content = source.read(maximum + 1)
            after = os.fstat(source.fileno())
            identity = lambda value: (
                value.st_dev, value.st_ino, value.st_mode, value.st_size,
                value.st_mtime_ns, value.st_ctime_ns,
            )
            if len(content) != before.st_size or identity(before) != identity(after):
                raise ValueError(f"sleep-wake workload artifact changed while reading: {name}")
            artifacts[name] = content
    return artifacts


def sleep_workload_artifact_issues(meta, artifacts):
    """Replay retained HTTP evidence, including deliberate partial-transfer TERM.

    The live capture still establishes timing and liveness. Final raw bytes must
    corroborate its HTTP status and observed body length; a natural completion
    must additionally prove the complete canonical 32 MiB transfer.
    """
    issues = []
    for name, maximum in SLEEP_WORKLOAD_ARTIFACT_LIMITS.items():
        content = artifacts.get(name)
        if not isinstance(content, bytes) or len(content) > maximum:
            issues.append(f"sleep-wake workload artifact is missing or oversized: {name}")
    if issues:
        return issues
    body_size = len(artifacts["wake-download.body"])
    established = parse_artifact_uint(meta.get("wake_workload_established_bytes"))
    if established in (None, 0) or body_size < established:
        issues.append("sleep-wake retained body does not contain the established bytes")

    headers = artifacts["wake-download-headers.txt"].replace(b"\r\n", b"\n")
    codes = []
    if b"\r" not in headers and headers.endswith(b"\n\n"):
        for block in headers[:-2].split(b"\n\n"):
            lines = block.split(b"\n")
            status = re.fullmatch(rb"HTTP/(?:1\.[01]|2|3) ([1-5][0-9]{2})(?: [^\n]*)?", lines[0])
            if status is None or any(
                re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[^\x00\n]*", line) is None
                for line in lines[1:]
            ):
                codes = []
                break
            codes.append(status.group(1).decode("ascii"))
    code = codes[-1] if codes else None
    if code is None or not code.startswith("2") or code != meta.get("wake_workload_http_code"):
        issues.append("sleep-wake retained headers do not match the established HTTP 2xx status")

    outcome = parse_artifact_uint(meta.get("wake_workload_child_rc"), maximum=255)
    output = artifacts["wake-download.txt"]
    # TERM normally interrupts curl before its writeout runs. If a complete
    # writeout was emitted before TERM, it must still describe the retained body.
    if output or outcome == 0:
        metrics = re.fullmatch(
            rb"wake-download: code=([0-9]{3}) size=(0|[1-9][0-9]*) "
            rb"time=((?:0|[1-9][0-9]*)(?:\.[0-9]+)?)s\n", output,
        )
        if (
            metrics is None
            or metrics.group(1).decode("ascii") != code
            or parse_artifact_uint(metrics.group(2).decode("ascii")) != body_size
            or Decimal(metrics.group(3).decode("ascii")) <= 0
        ):
            issues.append("sleep-wake curl writeout does not match its retained status/body")
    if outcome == 0 and body_size != SLEEP_WORKLOAD_ARTIFACT_LIMITS["wake-download.body"]:
        issues.append("naturally completed sleep-wake download is not the canonical 32 MiB")
    if outcome not in (0, 143):
        issues.append("sleep-wake retained workload has no valid joined child outcome")
    return issues


def sleep_wake_evidence(
    command_outcome,
    recovery_outcome,
    command_started,
    command_completed,
    sleep_epochs,
    wake_epochs,
    recovery_probes,
    phase,
    workload_evidence=None,
):
    """Return sleep proof issues and its corroborated outage window.

    A lifecycle marker alone does not prove that networking was exercised when
    the machine slept. ``workload_evidence`` must prove that a 2xx HTTP transfer
    was established and still alive when the sleep command began, then record
    the joined child outcome (0 for completion or 143 for the intentional TERM).
    """
    if command_outcome == "skipped" and recovery_outcome == "skipped":
        return {"issues": [], "outage_window": None}

    issues = []
    if command_outcome not in (0, 1, "0", "1"):
        issues.append("sleep command outcome is missing")
    if recovery_outcome not in (0, 1, "0", "1"):
        issues.append("post-wake recovery outcome is missing")
    command_started = parse_artifact_epoch(command_started)
    command_completed = parse_artifact_epoch(command_completed)
    try:
        _, phase_start, phase_end = phase
    except (TypeError, ValueError):
        phase_start = phase_end = None
    phase_start = parse_epoch(phase_start)
    phase_end = parse_epoch(phase_end)

    if not isinstance(workload_evidence, dict):
        issues.append("sleep-wake phase has no in-flight workload evidence")
    else:
        workload_started = parse_artifact_epoch(workload_evidence.get("started"))
        workload_established = parse_artifact_epoch(
            workload_evidence.get("established")
        )
        workload_code = workload_evidence.get("http_code")
        workload_alive = workload_evidence.get("alive_at_command")
        workload_joined = workload_evidence.get("joined")
        workload_child_rc = _nonnegative_int(workload_evidence.get("child_rc"))
        workload_nonzero = workload_evidence.get("established_nonzero_bytes")
        workload_bytes = _nonnegative_int(
            workload_evidence.get("established_bytes")
        )
        if (
            workload_started is None
            or workload_established is None
            or command_started is None
            or phase_start is None
            or not (
                phase_start
                <= workload_started
                <= workload_established
                <= command_started
            )
        ):
            issues.append(
                "sleep-wake workload timing is missing, invalid, or not established before sleep"
            )
        if not isinstance(workload_code, str) or re.fullmatch(
            r"2\d{2}", workload_code
        ) is None:
            issues.append("sleep-wake workload lacks an established HTTP 2xx response")
        if workload_alive not in (1, "1"):
            issues.append("sleep-wake workload was not alive at the sleep command")
        if (
            workload_nonzero not in (1, "1")
            or workload_bytes is None
            or workload_bytes <= 0
        ):
            issues.append("sleep-wake workload lacks established nonzero body bytes")
        if workload_joined not in (1, "1"):
            issues.append("sleep-wake workload child was not joined")
        if workload_child_rc not in (0, 143):
            issues.append("sleep-wake workload child outcome is missing or invalid")

    if (
        command_started is None
        or command_completed is None
        or command_completed < command_started
        or phase_start is None
        or phase_end is None
        or not (phase_start <= command_started <= command_completed < phase_end)
    ):
        issues.append("sleep command timing is missing, invalid, or outside its phase")
        return {"issues": issues, "outage_window": None}

    # A failed pmset invocation is a complete observed workload failure. It is
    # not additionally missing lifecycle markers that should never have fired.
    if str(command_outcome) == "0":
        return {"issues": issues, "outage_window": None}

    sleeps = [parse_epoch(raw) for raw in sleep_epochs]
    wakes = [parse_epoch(raw) for raw in wake_epochs]
    if (
        len(sleeps) != 1 or len(wakes) != 1
        or sleeps[0] is None or wakes[0] is None
        or not (command_started <= sleeps[0] < wakes[0] < phase_end)
    ):
        issues.append("sleep-wake phase requires exactly one ordered command-local sleep/wake pair")
        return {"issues": issues, "outage_window": None}

    sleep_epoch, wake_epoch = sleeps[0], wakes[0]
    if wake_epoch - sleep_epoch > MAX_PROVEN_SLEEP_SECONDS:
        issues.append("sleep-wake lifecycle interval exceeds the 120-second bound")
        return {"issues": issues, "outage_window": None}
    # pmset may return before the system actually sleeps. Its completion is
    # command evidence; the provider's real wake callback supplies this edge.
    probes_after_wake = [
        probe for probe in recovery_probes
        if max(command_completed, wake_epoch) <= probe[0] <= probe[1] <= phase_end
    ]
    if not probes_after_wake:
        issues.append("sleep-wake phase has no probe attempted after the wake marker")
        return {"issues": issues, "outage_window": None}

    successful_probe = next(
        (probe for probe in probes_after_wake if probe_succeeded(probe)), None
    )
    if str(recovery_outcome) == "1":
        if successful_probe is None:
            issues.append("claimed post-wake recovery lacks a successful paired probe")
            return {"issues": issues, "outage_window": None}
        return {
            "issues": issues,
            "outage_window": (sleep_epoch, wake_epoch),
        }
    if successful_probe is not None:
        issues.append("failed post-wake outcome conflicts with a successful paired probe")
    return {"issues": issues, "outage_window": None}


def parse_ceiling_probe_lines(lines):
    """Parse paired timestamp/rc/code/occupancy ceiling probes."""
    records = []
    issues = []
    previous_completion = None
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        fields = raw.rstrip("\n").split("\t")
        if len(fields) != 6:
            issues.append(f"malformed ceiling probe at line {line_number}")
            continue
        started = parse_artifact_epoch(fields[0])
        completed = parse_artifact_epoch(fields[1])
        gauge_epoch = parse_artifact_epoch(fields[5])
        curl_rc = _nonnegative_int(fields[2])
        occupancy = _nonnegative_int(fields[4])
        if (
            started is None
            or completed is None
            or completed < started
            or gauge_epoch is None
            or curl_rc is None
            or re.fullmatch(r"\d{3}", fields[3]) is None
            or occupancy is None
        ):
            issues.append(f"malformed ceiling probe at line {line_number}")
            continue
        if previous_completion is not None and started < previous_completion:
            issues.append(f"out-of-order ceiling probe at line {line_number}")
            continue
        records.append(
            (started, completed, curl_rc, fields[3], occupancy, gauge_epoch)
        )
        previous_completion = completed
    return records, issues


def ceiling_outage_window(
    records,
    baseline_total,
    phase,
    gauge_samples=(),
    allocation_failure_epochs=(),
):
    """Return a provider-corroborated failure-to-recovery half-open window."""
    try:
        _, start, end = phase
    except (TypeError, ValueError):
        return None
    baseline_total = _nonnegative_int(baseline_total)
    start = parse_epoch(start)
    end = parse_epoch(end)
    if baseline_total is None or start is None or end is None or end <= start:
        return None
    try:
        gauges = {
            (parse_epoch(epoch), _nonnegative_int(occupancy))
            for epoch, occupancy in gauge_samples
        }
        allocation_epochs = {
            parse_epoch(epoch) for epoch in allocation_failure_epochs
        }
    except (TypeError, ValueError):
        return None
    if any(epoch is None or occupancy is None for epoch, occupancy in gauges):
        return None
    if any(epoch is None for epoch in allocation_epochs):
        return None
    run = 0
    first_failure = None
    first_gauge_epoch = None
    proved_start = None
    for started, completed, curl_rc, code, occupancy, gauge_epoch in records:
        if not (start <= started <= completed < end):
            continue
        record = (started, completed, curl_rc, code, occupancy, gauge_epoch)
        if probe_succeeded(record):
            if proved_start is not None:
                return proved_start, completed
            run = 0
            first_failure = None
            continue
        if not ceiling_transport_failed(record):
            run = 0
            first_failure = None
            continue
        gauge_is_fresh = (
            start <= gauge_epoch <= started
            and started - gauge_epoch <= Decimal("70")
            and (gauge_epoch, occupancy) in gauges
        )
        if occupancy > baseline_total and gauge_is_fresh:
            if run == 0:
                first_failure = completed
                first_gauge_epoch = gauge_epoch
            run += 1
            allocation_corroborated = any(
                first_gauge_epoch <= epoch <= completed
                for epoch in allocation_epochs
            )
            if run >= 2 and allocation_corroborated:
                proved_start = first_failure
        else:
            run = 0
            first_failure = None
            first_gauge_epoch = None
    if proved_start is not None:
        return proved_start, None
    return None


def ceiling_probe_evidence_issues(
    records,
    ceiling_found,
    baseline_total,
    phase,
    ceiling_recovered=None,
    gauge_samples=(),
    allocation_failure_epochs=(),
):
    """Require attributable consecutive failure and claimed direct recovery."""
    if isinstance(ceiling_found, bool) or ceiling_found not in (0, 1, "0", "1"):
        return ["ceiling-finder outcome is missing"]
    if str(ceiling_found) != "1":
        return []
    window = ceiling_outage_window(
        records,
        baseline_total,
        phase,
        gauge_samples,
        allocation_failure_epochs,
    )
    if window is None:
        if phase is None:
            return ["ceiling failure proof has invalid baseline or phase"]
        return [
            "ceiling failure lacks two consecutive provider-gauge-corroborated "
            "transport probes plus a phase-local explicit provider allocation-exhaustion signal; "
            "transport pattern is heuristic only"
        ]
    if str(ceiling_recovered) == "1" and window[1] is None:
        return ["ceiling recovery lacks a phase-local direct success probe"]
    return []


def unexpected_probe_failure_count(failure_records, outage_window):
    """Count failed probe intervals not overlapping the proved outage.

    Completion-only attribution can count a request as unexpected even though
    it spent most of its lifetime inside a sleep or ceiling outage. Preserve
    both endpoints and waive a failure exactly when its request interval
    overlaps the half-open outage window. Malformed records are unexpected.
    """
    records = list(failure_records)
    try:
        if len(outage_window) != 2:
            return len(records)
        raw_outage_start, raw_outage_end = outage_window
    except (TypeError, ValueError):
        return len(records)
    outage_start = parse_epoch(raw_outage_start)
    outage_end = parse_epoch(raw_outage_end)
    if (
        outage_start is None
        or outage_end is None
        or outage_end <= outage_start
    ):
        return len(records)

    unexpected = 0
    for record in records:
        try:
            probe_start = parse_epoch(record[0])
            probe_end = parse_epoch(record[1])
        except (TypeError, IndexError):
            unexpected += 1
            continue
        if probe_start is None or probe_end is None or probe_end < probe_start:
            unexpected += 1
            continue
        overlaps = probe_start < outage_end and probe_end >= outage_start
        if not overlaps:
            unexpected += 1
    return unexpected


def unexpected_probe_failure_count_across_outages(failure_records, outage_windows):
    """Count failed probe intervals that overlap none of the proved outages."""
    records = list(failure_records)
    windows = list(outage_windows)
    return sum(
        1
        for record in records
        if all(
            unexpected_probe_failure_count([record], outage_window) == 1
            for outage_window in windows
        )
    )


def parse_leaks_output(text):
    """Return parsed ``leaks`` totals, or ``None`` for unknown output."""
    if not isinstance(text, str):
        return None
    number = r"(?:0|[1-9]\d*|[1-9]\d{0,2}(?:,\d{3})+)"
    matches = re.findall(
        rf"\bProcess\s+(\d+):\s+({number})\s+leaks?\s+for\s+"
        rf"({number})\s+total leaked bytes\b",
        text,
        re.IGNORECASE,
    )
    if len(matches) != 1:
        return None
    process_text, leaks_text, leaked_bytes_text = matches[0]
    process_pid = parse_artifact_uint(process_text, maximum=2_147_483_647)
    leaks = parse_artifact_uint(leaks_text.replace(",", ""))
    leaked_bytes = parse_artifact_uint(leaked_bytes_text.replace(",", ""))
    if process_pid in (None, 0) or leaks is None or leaked_bytes is None:
        return None
    return {
        "process_pid": process_pid,
        "leaks": leaks,
        "bytes": leaked_bytes,
    }


def leak_evidence(command_rc, text, *, expected_pid=None):
    """Return fail-closed leaks-tool evidence and the parsed leak count."""
    issues = []
    command_rc = _nonnegative_int(command_rc)
    parsed = parse_leaks_output(text)
    if parsed is None:
        issues.append("leaks output is missing or unparseable")
        leaks = leaked_bytes = 0
    else:
        process_pid = parsed["process_pid"]
        leaks = parsed["leaks"]
        leaked_bytes = parsed["bytes"]
        if expected_pid is not None:
            parsed_expected_pid = parse_artifact_uint(
                str(expected_pid), maximum=2_147_483_647)
            if parsed_expected_pid in (None, 0) or process_pid != parsed_expected_pid:
                issues.append("leaks output is not attributed to the exact provider PID")
    if command_rc is None or command_rc < 0:
        issues.append("leaks command outcome is missing or invalid")
    elif command_rc > 1:
        issues.append(f"leaks command failed with exit {command_rc}")
    elif parsed is not None:
        summary_is_zero = leaks == 0 and leaked_bytes == 0
        summary_is_nonzero = leaks > 0 and leaked_bytes > 0
        if not (summary_is_zero or summary_is_nonzero):
            issues.append("leaks output has inconsistent allocation and byte totals")
        elif (command_rc == 0 and not summary_is_zero) or (
            command_rc == 1 and not summary_is_nonzero
        ):
            issues.append("leaks command outcome contradicts its parsed summary")
    return {
        "issues": issues,
        "process_pid": parsed["process_pid"] if parsed is not None else None,
        "leaks": leaks,
        "bytes": leaked_bytes,
    }


def idle_cpu_evidence(
    lines,
    *,
    expected_pid,
    expected_identity,
    required_samples=10,
    hot_threshold_percent=Decimal("90.0"),
    hot_streak_samples=5,
    allowed_start_epoch=None,
    allowed_end_epoch=None,
    run_start_epoch_ms=None,
    run_end_epoch_ms=None,
    label="idle CPU",
):
    """Validate the fixed-cadence, exact-provider no-spin observations.

    Rows are ``index<TAB>epoch<TAB>pid<TAB>identity<TAB>cpu-percent``.  A
    sustained full-core spin is a product failure.  Missing, malformed,
    mis-spaced, or differently attributed observations are incomplete
    evidence instead: none of those conditions may be interpreted as a cool
    provider.
    """
    issues = []
    failures = []
    samples = []
    expected_pid = parse_artifact_uint(str(expected_pid), maximum=2_147_483_647)
    required_samples = _nonnegative_int(required_samples)
    hot_streak_samples = _nonnegative_int(hot_streak_samples)
    try:
        hot_threshold_percent = Decimal(str(hot_threshold_percent))
    except (ValueError, ArithmeticError):
        hot_threshold_percent = None
    if expected_pid in (None, 0):
        issues.append("idle CPU expected provider PID is missing or invalid")
    if re.fullmatch(r"[0-9a-f]{64}", str(expected_identity)) is None:
        issues.append("idle CPU expected provider identity is missing or invalid")
    if required_samples in (None, 0):
        issues.append("idle CPU required sample count is invalid")
    if hot_streak_samples in (None, 0):
        issues.append("idle CPU hot-streak length is invalid")
    if (
        hot_threshold_percent is None
        or not hot_threshold_percent.is_finite()
        or hot_threshold_percent < 0
        or hot_threshold_percent > Decimal("10000.0")
    ):
        issues.append("idle CPU hot threshold is invalid")

    def optional_epoch(value, description):
        if value is None:
            return None
        parsed = parse_artifact_epoch(str(value))
        if parsed is None:
            issues.append(f"{label} {description} is missing or invalid")
        return parsed

    allowed_start = optional_epoch(allowed_start_epoch, "phase start")
    allowed_end = optional_epoch(allowed_end_epoch, "phase end")
    run_start_ms = (
        parse_artifact_uint(str(run_start_epoch_ms))
        if run_start_epoch_ms is not None
        else None
    )
    run_end_ms = (
        parse_artifact_uint(str(run_end_epoch_ms))
        if run_end_epoch_ms is not None
        else None
    )
    if run_start_epoch_ms is not None and run_start_ms is None:
        issues.append(f"{label} run start is missing or invalid")
    if run_end_epoch_ms is not None and run_end_ms is None:
        issues.append(f"{label} run end is missing or invalid")
    run_start = Decimal(run_start_ms) / 1000 if run_start_ms is not None else None
    run_end = Decimal(run_end_ms) / 1000 if run_end_ms is not None else None
    if allowed_start is not None and allowed_end is not None and allowed_start > allowed_end:
        issues.append(f"{label} phase window is reversed")
    if run_start is not None and run_end is not None and run_start > run_end:
        issues.append(f"{label} run window is reversed")

    previous_epoch = None
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        fields = raw.rstrip("\n").split("\t")
        if len(fields) != 5:
            issues.append(f"malformed {label} sample at line {line_number}")
            continue
        index = parse_artifact_uint(fields[0], maximum=10_000)
        epoch = parse_artifact_epoch(fields[1])
        pid = parse_artifact_uint(fields[2], maximum=2_147_483_647)
        identity = fields[3]
        cpu_text = fields[4]
        try:
            cpu = Decimal(cpu_text)
        except (ValueError, ArithmeticError):
            cpu = None
        if (
            index is None
            or epoch is None
            or pid in (None, 0)
            or re.fullmatch(r"[0-9a-f]{64}", identity) is None
            or re.fullmatch(r"(?:0|[1-9]\d*)(?:\.\d+)?", cpu_text) is None
            or cpu is None
            or not cpu.is_finite()
            or cpu > Decimal("10000.0")
        ):
            issues.append(f"malformed {label} sample at line {line_number}")
            continue
        expected_index = len(samples) + 1
        if index != expected_index:
            issues.append(
                f"{label} sample index {index} at line {line_number} "
                f"does not follow {expected_index}"
            )
        if expected_pid is not None and pid != expected_pid:
            issues.append(f"{label} provider PID changed at line {line_number}")
        if identity != expected_identity:
            issues.append(f"{label} provider identity changed at line {line_number}")
        if previous_epoch is not None:
            spacing = epoch - previous_epoch
            if spacing < Decimal("0.75") or spacing > Decimal("2.50"):
                issues.append(
                    f"{label} sample cadence is not one second at line {line_number}"
                )
        if allowed_start is not None and epoch < allowed_start:
            issues.append(f"{label} sample at line {line_number} is before its phase")
        if allowed_end is not None and epoch > allowed_end:
            issues.append(f"{label} sample at line {line_number} is after its phase")
        if run_start is not None and epoch < run_start:
            issues.append(f"{label} sample at line {line_number} is before the run")
        if run_end is not None and epoch > run_end:
            issues.append(f"{label} sample at line {line_number} is after the run")
        previous_epoch = epoch
        samples.append((index, epoch, pid, identity, cpu))

    if required_samples is not None and len(samples) != required_samples:
        issues.append(
            f"{label} evidence has {len(samples)} sample(s); "
            f"expected exactly {required_samples}"
        )

    maximum = max((sample[4] for sample in samples), default=None)
    mean = (
        sum((sample[4] for sample in samples), Decimal(0)) / len(samples)
        if samples
        else None
    )
    current_streak = maximum_streak = 0
    if hot_threshold_percent is not None:
        for *_, cpu in samples:
            if cpu >= hot_threshold_percent:
                current_streak += 1
                maximum_streak = max(maximum_streak, current_streak)
            else:
                current_streak = 0
    if (
        not issues
        and hot_streak_samples is not None
        and maximum_streak >= hot_streak_samples
    ):
        failures.append(
            f"{label} provider CPU stayed at or above "
            f"{hot_threshold_percent}% for {maximum_streak} consecutive sample(s)"
        )
    return {
        "issues": issues,
        "failures": failures,
        "sample_count": len(samples),
        "maximum_percent": maximum,
        "mean_percent": mean,
        "maximum_hot_streak": maximum_streak,
        "warm_sample_count": sum(
            1 for *_, cpu in samples if cpu >= Decimal("80.0")
        ),
        "first_epoch": samples[0][1] if samples else None,
        "last_epoch": samples[-1][1] if samples else None,
        "cpu_percents": [sample[4] for sample in samples],
    }


def top_cpu_sample_rows(lines, *, expected_pid, expected_identity):
    """Extract ten instantaneous samples after discarding ``top``'s first row.

    The shell prefixes exact-PID data rows with their observation epoch while
    retaining column headers as ``-`` timestamp rows. With ``-l 11 -s 1``, the
    first value is the lifetime/decayed sample documented by macOS ``top``;
    only the following ten interval samples are release evidence.
    """
    issues = []
    samples = []
    expected_pid_value = parse_artifact_uint(
        str(expected_pid), maximum=2_147_483_647)
    if expected_pid_value in (None, 0):
        issues.append("top CPU expected provider PID is missing or invalid")
    if re.fullmatch(r"[0-9a-f]{64}", str(expected_identity)) is None:
        issues.append("top CPU expected provider identity is missing or invalid")

    awaiting_row = False
    for line_number, raw in enumerate(lines, 1):
        fields = raw.rstrip("\n").split("\t", 1)
        if len(fields) != 2:
            issues.append(f"malformed timestamped top output at line {line_number}")
            continue
        epoch_text, payload = fields
        columns = payload.split()
        if columns == ["PID", "%CPU"]:
            awaiting_row = True
            continue
        if not awaiting_row or not payload.strip():
            continue
        match = re.fullmatch(r"\s*(\d+)\s+(\d+(?:\.\d+)?)%?\s*", payload)
        if match is None:
            issues.append(f"malformed top CPU row at line {line_number}")
            awaiting_row = False
            continue
        epoch = parse_artifact_epoch(epoch_text)
        pid = parse_artifact_uint(match.group(1), maximum=2_147_483_647)
        cpu_text = match.group(2)
        if epoch is None or pid in (None, 0) or pid != expected_pid_value:
            issues.append(f"top CPU row is not attributed to the exact PID at line {line_number}")
        samples.append((epoch_text, match.group(1), cpu_text))
        awaiting_row = False

    if len(samples) != 11:
        issues.append(
            f"top CPU output has {len(samples)} process sample(s); expected exactly 11"
        )
    if issues:
        return [], issues
    rows = [
        f"{index}\t{epoch}\t{pid}\t{expected_identity}\t{cpu}\n"
        for index, (epoch, pid, cpu) in enumerate(samples[1:], 1)
    ]
    return rows, []


def idle_cpu_comparison_evidence(
    baseline_lines,
    post_lines,
    *,
    expected_pid,
    expected_identity,
    baseline_start_epoch,
    baseline_end_epoch,
    post_start_epoch,
    post_end_epoch,
    run_start_epoch_ms,
    run_end_epoch_ms,
    regression_allowance_percent=Decimal("5.0"),
    absolute_mean_ceiling_percent=Decimal("10.0"),
    warm_threshold_percent=Decimal("80.0"),
    maximum_warm_samples=4,
    minimum_post_quiescence_seconds=0,
):
    """Compare exact pre-load and post-load no-spin samples.

    Both series are bound to declared phase and run windows. The post-load
    provider must remain close to its device-local idle baseline and must not
    spend half of the fixed sample window near a full core.
    """
    baseline = idle_cpu_evidence(
        baseline_lines,
        expected_pid=expected_pid,
        expected_identity=expected_identity,
        allowed_start_epoch=baseline_start_epoch,
        allowed_end_epoch=baseline_end_epoch,
        run_start_epoch_ms=run_start_epoch_ms,
        run_end_epoch_ms=run_end_epoch_ms,
        label="idle CPU baseline",
    )
    post = idle_cpu_evidence(
        post_lines,
        expected_pid=expected_pid,
        expected_identity=expected_identity,
        allowed_start_epoch=post_start_epoch,
        allowed_end_epoch=post_end_epoch,
        run_start_epoch_ms=run_start_epoch_ms,
        run_end_epoch_ms=run_end_epoch_ms,
        label="idle CPU post-load",
    )
    issues = list(baseline["issues"]) + list(post["issues"])
    failures = list(baseline["failures"]) + list(post["failures"])
    if baseline_start_epoch is None or baseline_end_epoch is None:
        issues.append("idle CPU baseline phase window is unavailable")
    if post_start_epoch is None or post_end_epoch is None:
        issues.append("idle CPU post-load phase window is unavailable")
    if run_start_epoch_ms is None or run_end_epoch_ms is None:
        issues.append("idle CPU run window is unavailable")
    try:
        regression_allowance = Decimal(str(regression_allowance_percent))
        absolute_ceiling = Decimal(str(absolute_mean_ceiling_percent))
        warm_threshold = Decimal(str(warm_threshold_percent))
    except (ValueError, ArithmeticError):
        regression_allowance = absolute_ceiling = warm_threshold = None
    maximum_warm_samples = _nonnegative_int(maximum_warm_samples)
    minimum_post_quiescence = _nonnegative_int(minimum_post_quiescence_seconds)
    if (
        regression_allowance is None
        or absolute_ceiling is None
        or warm_threshold is None
        or not all(
            value.is_finite() and value >= 0
            for value in (regression_allowance, absolute_ceiling, warm_threshold)
        )
        or maximum_warm_samples is None
        or minimum_post_quiescence is None
    ):
        issues.append("idle CPU comparison policy is invalid")

    post_limit = None
    baseline_warm_count = None
    post_warm_count = None
    if not issues:
        baseline_warm_count = sum(
            1 for cpu in baseline["cpu_percents"] if cpu >= warm_threshold
        )
        post_warm_count = sum(
            1 for cpu in post["cpu_percents"] if cpu >= warm_threshold
        )
        for series_label, series, warm_count in (
            ("baseline", baseline, baseline_warm_count),
            ("post-load", post, post_warm_count),
        ):
            if series["mean_percent"] > absolute_ceiling:
                failures.append(
                    f"idle CPU {series_label} mean {series['mean_percent']}% "
                    f"exceeds the absolute {absolute_ceiling}% ceiling"
                )
            if warm_count > maximum_warm_samples:
                failures.append(
                    f"idle CPU {series_label} evidence has "
                    f"{warm_count} sample(s) at or above {warm_threshold}%; "
                    f"at most {maximum_warm_samples} are allowed"
                )
        post_limit = max(
            baseline["mean_percent"] + regression_allowance,
            absolute_ceiling,
        )
        if post["mean_percent"] > post_limit:
            failures.append(
                "idle CPU post-load mean "
                f"{post['mean_percent']}% exceeds the baseline-derived "
                f"{post_limit}% limit"
            )
        post_start = parse_artifact_epoch(str(post_start_epoch))
        if (
            post_start is not None
            and post["first_epoch"]
            < post_start + Decimal(minimum_post_quiescence)
        ):
            issues.append(
                "idle CPU post-load sampling began before the declared "
                "quiescence completed"
            )
    return {
        "issues": issues,
        "failures": failures,
        "baseline": baseline,
        "post": post,
        "post_mean_limit_percent": post_limit,
        "baseline_warm_sample_count": baseline_warm_count,
        "post_warm_sample_count": post_warm_count,
        "regression_allowance_percent": regression_allowance,
        "absolute_mean_ceiling_percent": absolute_ceiling,
        "warm_threshold_percent": warm_threshold,
        "maximum_warm_samples": maximum_warm_samples,
        "minimum_post_quiescence_seconds": minimum_post_quiescence,
    }


def cpu_sample_diagnostic_issues(meta):
    """Validate completion of the bounded five-second ``sample`` diagnostic."""
    issues = []
    if not isinstance(meta, dict):
        return ["CPU sample diagnostic metadata is missing"]
    child_rc = _nonnegative_int(meta.get("cpu_sample_command_rc"))
    if meta.get("cpu_sample_joined") != "1":
        issues.append("CPU sample diagnostic child was not reaped")
    if meta.get("cpu_sample_forced") != "0":
        issues.append("CPU sample diagnostic exceeded its bounded deadline")
    if meta.get("cpu_sample_privilege") != "sudo":
        issues.append("CPU sample diagnostic did not use cached sudo privilege")
    if meta.get("cpu_sample_ownership_normalized") != "1":
        issues.append("CPU sample diagnostic ownership was not normalized")
    if child_rc != 0:
        issues.append("CPU sample diagnostic command failed or has no valid outcome")
    return issues


def memory_diagnostic_issues(meta, *, baseline_artifact, final_artifact):
    """Validate bounded baseline/final attach commands and their artifacts."""
    if not isinstance(meta, dict):
        return ["memory diagnostic metadata is missing"]
    issues = []
    specifications = (
        ("baseline", ("sudo", "ps", "vmmap"), baseline_artifact),
        ("final", ("sudo", "ps", "vmmap", "heap", "heap_filter"), final_artifact),
    )
    expected_pid = parse_artifact_uint(
        meta.get("provider_start_pid"), maximum=2_147_483_647)
    expected_identity = meta.get("provider_start_identity")
    run_start = parse_artifact_uint(meta.get("run_start_epoch_ms"))
    run_end = parse_artifact_uint(meta.get("run_end_epoch_ms"))
    for label, commands, artifact in specifications:
        prefix = f"{label}_mem_"
        if _nonnegative_int(meta.get(prefix + "child_rc")) != 0:
            issues.append(
                f"{label} memory diagnostic child failed or has no valid outcome"
            )
        if meta.get(prefix + "joined") != "1":
            issues.append(f"{label} memory diagnostic child was not reaped")
        if meta.get(prefix + "forced") != "0":
            issues.append(
                f"{label} memory diagnostic exceeded its bounded deadline"
            )
        if meta.get(prefix + "privilege") != "sudo":
            issues.append(
                f"{label} memory diagnostic did not prove cached sudo privilege"
            )
        for command in commands:
            if _nonnegative_int(meta.get(prefix + command + "_rc")) != 0:
                issues.append(
                    f"{label} memory diagnostic {command} command failed "
                    "or has no valid outcome"
                )
        try:
            artifact_ok = os.path.isfile(artifact) and os.path.getsize(artifact) > 0
        except (OSError, TypeError, ValueError):
            artifact_ok = False
        if not artifact_ok:
            issues.append(f"{label} memory diagnostic artifact is missing or empty")
            continue
        try:
            with open(artifact, errors="replace") as source:
                artifact_text = source.read()
        except OSError:
            issues.append(f"{label} memory diagnostic artifact cannot be read")
            continue
        if expected_pid in (None, 0):
            issues.append(f"{label} memory diagnostic expected PID is invalid")
            continue
        header_label = "baseline" if label == "baseline" else "final snapshot"
        header = re.match(
            rf"\A=== {re.escape(header_label)} provider pid=(\d+) @ [^\n]+ ===\n",
            artifact_text,
        )
        if header is None or parse_artifact_uint(header.group(1)) != expected_pid:
            issues.append(f"{label} memory diagnostic header has the wrong PID")
        vmmap_marker = "\n--- vmmap --summary ---\n"
        heap_marker = "\n--- heap totals ---\n"
        before_vmmap, marker, after_vmmap = artifact_text.partition(vmmap_marker)
        if not marker:
            issues.append(f"{label} memory diagnostic vmmap section is missing")
            continue
        ps_pids = re.findall(
            r"(?m)^\s*(\d+)\s+\d+\s+\d+\s+\d+(?:\.\d+)?\s+\S+\s*$",
            before_vmmap,
        )
        if ps_pids != [str(expected_pid)]:
            issues.append(f"{label} memory diagnostic ps row has the wrong PID")
        vmmap_text = after_vmmap
        heap_text = None
        if label == "final":
            vmmap_text, marker, heap_text = after_vmmap.partition(heap_marker)
            if not marker:
                issues.append("final memory diagnostic heap section is missing")
        vmmap_pids = re.findall(r"(?m)^Process:\s+.*\[(\d+)\]\s*$", vmmap_text)
        if vmmap_pids != [str(expected_pid)]:
            issues.append(f"{label} memory diagnostic vmmap output has the wrong PID")
        if heap_text is not None:
            heap_pids = re.findall(r"(?m)^Process\s+(\d+):", heap_text)
            if heap_pids != [str(expected_pid)]:
                issues.append("final memory diagnostic heap output has the wrong PID")

    baseline_start = parse_artifact_uint(meta.get("baseline_mem_start_epoch_ms"))
    baseline_end = parse_artifact_uint(meta.get("baseline_mem_end_epoch_ms"))
    baseline_pid = parse_artifact_uint(
        meta.get("baseline_mem_provider_pid"), maximum=2_147_483_647)
    if (
        baseline_start is None
        or baseline_end is None
        or baseline_end < baseline_start
        or run_start is None
        or baseline_start < run_start
        or run_end is None
        or baseline_end > run_end
    ):
        issues.append("baseline memory diagnostic interval is outside the run")
    if (
        expected_pid in (None, 0)
        or baseline_pid != expected_pid
        or meta.get("baseline_mem_identity_before") != expected_identity
        or meta.get("baseline_mem_identity_after") != expected_identity
    ):
        issues.append(
            "baseline memory diagnostic is not bound to the exact run generation"
        )
    return issues


def top_cpu_collection_issues(meta):
    """Validate both bounded privileged instantaneous CPU collectors."""
    if not isinstance(meta, dict):
        return ["top CPU collection metadata is missing"]
    issues = []
    expected_identity = meta.get("provider_start_identity")
    for label in ("baseline", "post"):
        prefix = f"idle_cpu_{label}_top_"
        if _nonnegative_int(meta.get(prefix + "command_rc")) != 0:
            issues.append(f"{label} top CPU command failed or has no valid outcome")
        if meta.get(prefix + "joined") != "1":
            issues.append(f"{label} top CPU collector was not reaped")
        if meta.get(prefix + "forced") != "0":
            issues.append(f"{label} top CPU collector exceeded its bounded deadline")
        if meta.get(prefix + "privilege") != "sudo":
            issues.append(f"{label} top CPU collector did not use cached sudo")
        if (
            meta.get(f"idle_cpu_{label}_identity_before") != expected_identity
            or meta.get(f"idle_cpu_{label}_identity_after") != expected_identity
        ):
            issues.append(f"{label} top CPU provider identity changed")
    return issues


def dial9_diagnostic_claim_issues(meta):
    """Ensure arbitrary Dial9 traces cannot be promoted to soak coverage."""
    if not isinstance(meta, dict):
        return ["Dial9 diagnostic claim metadata is missing"]
    issues = []
    if meta.get("dial9_diagnostic_only") != "1":
        issues.append("Dial9 evidence is not marked diagnostic-only")
    if meta.get("dial9_coverage_claimed") != "0":
        issues.append("soak evidence must not claim Dial9 workload coverage")
    return issues


def dial9_diagnostic_collection_issues(meta):
    """Reject a started Dial9 diagnostic that escaped its bounded join."""
    if not isinstance(meta, dict):
        return ["Dial9 diagnostic collection metadata is missing"]
    if meta.get("dial9_collection_attempted") != "1":
        return []
    issues = []
    if meta.get("dial9_collect_joined") != "1":
        issues.append("Dial9 diagnostic collection child was not reaped")
    if meta.get("dial9_collect_forced") != "0":
        issues.append("Dial9 diagnostic collection exceeded its bounded deadline")
    if _nonnegative_int(meta.get("dial9_collect_child_rc")) is None:
        issues.append("Dial9 diagnostic collection outcome is missing or invalid")
    return issues


def soak_workload_claim_issues(lines, *, expected_run_uuid=None):
    """Require the exact release-set claims emitted by the TCP-only soak."""
    actual = []
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        fields = raw.rstrip("\n").split("\t")
        if len(fields) != 2 or not fields[0] or not fields[1]:
            return [f"malformed soak workload claim at line {line_number}"]
        actual.append(tuple(fields))
    run_uuid = actual[1][1] if len(actual) > 1 and actual[1][0] == "run_uuid" else ""
    try:
        canonical_run_uuid = str(uuid.UUID(run_uuid)) == run_uuid
    except (ValueError, AttributeError):
        canonical_run_uuid = False
    expected = [
        ("evidence_kind", "soak"),
        ("run_uuid", run_uuid),
        ("dial9_claim", "unattributed-diagnostic"),
        ("dial9_diagnostic_only", "1"),
        ("dial9_workload_coverage", "0"),
        ("tcp_workload_exercised", "1"),
        ("udp_workload_exercised", "0"),
        ("schema_complete", "1"),
    ]
    if (
        actual != expected
        or not canonical_run_uuid
        or (expected_run_uuid is not None and run_uuid != expected_run_uuid)
    ):
        return ["soak workload claims do not match the exact TCP-only contract"]
    return []


def final_provider_observation_issues(meta):
    """Bind run end to one generation across the crash-snapshot scan."""
    if not isinstance(meta, dict):
        return ["final provider observation metadata is missing"]
    issues = []
    start_pid = parse_artifact_uint(
        meta.get("provider_start_pid"), maximum=2_147_483_647)
    final_pid = parse_artifact_uint(
        meta.get("final_provider_observation_pid"), maximum=2_147_483_647)
    post_pid = parse_artifact_uint(
        meta.get("post_snapshot_provider_observation_pid"),
        maximum=2_147_483_647,
    )
    run_end = parse_artifact_uint(meta.get("run_end_epoch_ms"))
    final_epoch = parse_artifact_uint(
        meta.get("final_provider_observation_epoch_ms"))
    snapshot_epoch = parse_artifact_uint(meta.get("crash_snapshot_epoch_ms"))
    post_epoch = parse_artifact_uint(
        meta.get("post_snapshot_provider_observation_epoch_ms"))
    start_identity = meta.get("provider_start_identity")
    final_identity = meta.get("final_provider_observation_identity")
    post_identity = meta.get("post_snapshot_provider_observation_identity")

    if meta.get("final_provider_observation_ok") != "1":
        issues.append("final exact-provider observation is unavailable")
    if (
        start_pid in (None, 0)
        or final_pid != start_pid
        or final_identity != start_identity
    ):
        issues.append("final provider observation does not match the run generation")
    if final_epoch is None or run_end is None or final_epoch != run_end:
        issues.append("final provider observation does not define the exact run end")
    if snapshot_epoch is None or run_end is None or snapshot_epoch < run_end:
        issues.append("crash snapshot does not cover the declared run end")
    if meta.get("post_snapshot_provider_observation_ok") != "1":
        issues.append("post-snapshot exact-provider observation is unavailable")
    if (
        start_pid in (None, 0)
        or post_pid != start_pid
        or post_identity != start_identity
        or post_identity != final_identity
    ):
        issues.append(
            "provider generation changed during the post-workload crash scan"
        )
    if (
        post_epoch is None
        or snapshot_epoch is None
        or post_epoch < snapshot_epoch
    ):
        issues.append("post-snapshot provider observation does not follow the scan")
    return issues


def post_boundary_forensic_issues(meta):
    """Bind final memory/leak snapshots to the declared provider run boundary."""
    if not isinstance(meta, dict):
        return ["post-boundary forensic metadata is missing"]
    issues = []
    run_end = parse_artifact_uint(meta.get("run_end_epoch_ms"))
    expected_pid = parse_artifact_uint(
        meta.get("provider_start_pid"), maximum=2_147_483_647)
    expected_identity = meta.get("provider_start_identity")
    previous_end = run_end
    for prefix, label in (("final_mem", "final memory"), ("leaks", "leaks")):
        start = parse_artifact_uint(meta.get(prefix + "_start_epoch_ms"))
        end = parse_artifact_uint(meta.get(prefix + "_end_epoch_ms"))
        pid = parse_artifact_uint(
            meta.get(prefix + "_provider_pid"), maximum=2_147_483_647)
        identity_before = meta.get(prefix + "_identity_before")
        identity_after = meta.get(prefix + "_identity_after")
        if start is None or end is None or end < start:
            issues.append(f"{label} snapshot timestamps are missing or reversed")
        if previous_end is None or start is None or start < previous_end:
            issues.append(
                f"{label} snapshot does not follow the declared run boundary"
            )
        if (
            expected_pid in (None, 0)
            or pid != expected_pid
            or identity_before != expected_identity
            or identity_after != expected_identity
        ):
            issues.append(
                f"{label} snapshot is not bound to the exact run generation"
            )
        previous_end = end
    return issues


def crash_snapshot_evidence(
    before_lines,
    after_lines,
    *,
    run_start_epoch_ms,
    run_end_epoch_ms=None,
    expected_process_names="RamaTransparentProxyExampleExtension",
    expected_run_uuid=None,
    expected_provider_generation_identity=None,
):
    """Validate common crash snapshots bracketing the soak workload."""

    def parse_snapshot(lines, label):
        values = {}
        issues = []
        observed_order = []
        for line_number, raw in enumerate(lines, 1):
            if not raw.strip():
                continue
            fields = raw.rstrip("\n").split("\t")
            if len(fields) != 2 or not fields[0] or not fields[1]:
                issues.append(
                    f"malformed {label} crash snapshot at line {line_number}"
                )
                continue
            if fields[0] in values:
                issues.append(
                    f"duplicate {label} crash snapshot key {fields[0]!r}"
                )
                continue
            values[fields[0]] = fields[1]
            observed_order.append(fields[0])
        expected_order = [
            "schema_version",
            "run_uuid",
            "provider_generation_identity",
            "since_epoch_ms",
            "snapshot_epoch_ms",
            "process_names",
            "crash_count",
            "crash_names_sha256",
            "schema_complete",
        ]
        schema_invalid = observed_order != expected_order
        if schema_invalid:
            issues.append(
                f"{label} crash snapshot is unavailable or schema-incomplete"
            )
        since = parse_artifact_uint(values.get("since_epoch_ms"))
        snapshot = parse_artifact_uint(values.get("snapshot_epoch_ms"))
        count = parse_artifact_uint(values.get("crash_count"))
        names_hash = values.get("crash_names_sha256", "")
        if (
            schema_invalid
            or values.get("schema_version") != "2"
            or values.get("schema_complete") != "1"
            or since is None
            or snapshot is None
            or count is None
            or not values.get("process_names")
            or re.fullmatch(r"[0-9a-f]{64}", names_hash) is None
        ):
            if not schema_invalid:
                issues.append(f"{label} crash snapshot contains invalid values")
            return None, issues
        return {
            "since": since,
            "snapshot": snapshot,
            "count": count,
            "names_hash": names_hash,
            "process_names": values["process_names"],
            "run_uuid": values["run_uuid"],
            "provider_generation_identity": values[
                "provider_generation_identity"
            ],
        }, issues

    issues = []
    failures = []
    before, before_issues = parse_snapshot(before_lines, "pre-workload")
    after, after_issues = parse_snapshot(after_lines, "post-workload")
    issues.extend(before_issues)
    issues.extend(after_issues)
    expected_start = parse_artifact_uint(str(run_start_epoch_ms))
    expected_end = (
        parse_artifact_uint(str(run_end_epoch_ms))
        if run_end_epoch_ms is not None
        else None
    )
    if expected_start is None:
        issues.append("crash snapshot run-start timestamp is missing or invalid")
    if run_end_epoch_ms is not None and expected_end is None:
        issues.append("crash snapshot run-end timestamp is missing or invalid")
    if before is not None and after is not None and expected_start is not None:
        if before["since"] != expected_start or after["since"] != expected_start:
            issues.append("crash snapshots do not use the exact soak start boundary")
        if before["snapshot"] > after["snapshot"]:
            issues.append("crash snapshots are not ordered before/after the workload")
        if expected_end is not None and after["snapshot"] < expected_end:
            issues.append(
                "post-workload crash snapshot does not cover the exact run end"
            )
        if before["process_names"] != after["process_names"]:
            issues.append("crash snapshot process filters changed during the run")
        if (
            before["process_names"] != expected_process_names
            or after["process_names"] != expected_process_names
        ):
            issues.append("crash snapshots do not target the exact provider process")
        if (
            expected_run_uuid is None
            or before["run_uuid"] != expected_run_uuid
            or after["run_uuid"] != expected_run_uuid
        ):
            issues.append("crash snapshots do not match the exact run UUID")
        if (
            expected_provider_generation_identity is None
            or before["provider_generation_identity"]
                != expected_provider_generation_identity
            or after["provider_generation_identity"]
                != expected_provider_generation_identity
        ):
            issues.append(
                "crash snapshots do not match the exact provider generation"
            )
        if after["count"] < before["count"]:
            issues.append("post-workload crash snapshot lost a pre-workload report")
        if after["count"] > 0:
            failures.append(
                f"{after['count']} provider crash report(s) were created during the soak"
            )
    return {
        "issues": issues,
        "failures": failures,
        "before_count": before["count"] if before is not None else None,
        "after_count": after["count"] if after is not None else None,
        "after_snapshot_epoch_ms": (
            after["snapshot"] if after is not None else None
        ),
    }


def parse_evidence_status_lines(lines):
    """Validate the atomic, schema-complete terminal verdict tuple."""
    pairs = []
    for raw in lines:
        raw = raw.rstrip("\n")
        if not raw:
            continue
        fields = raw.split("\t", 1)
        if len(fields) != 2:
            return None
        pairs.append(fields)
    values = {}
    for key, value in pairs:
        if key not in (
            "complete", "passed", "exit_code", "issue", "failure",
            "schema_complete",
        ):
            return None
        if value == "":
            return None
        if key in ("complete", "passed", "exit_code", "schema_complete"):
            if key in values:
                return None
            values[key] = value
    if not pairs or pairs[-1] != ["schema_complete", "1"]:
        return None
    if [key for key, _ in pairs[:3]] != ["complete", "passed", "exit_code"]:
        return None
    verdict = (values.get("complete"), values.get("passed"), values.get("exit_code"))
    issue_count = sum(key == "issue" for key, _ in pairs)
    failure_count = sum(key == "failure" for key, _ in pairs)
    if verdict == ("1", "1", "0") and issue_count == 0 and failure_count == 0:
        return 0
    if verdict == ("1", "0", "1") and issue_count == 0 and failure_count > 0:
        return 1
    if verdict == ("0", "0", "2") and issue_count > 0:
        return 2
    return None


def artifact_identity_issues(meta):
    """Validate locally attainable source, script, binary, and signing identity."""
    issues = []
    if not isinstance(meta, dict):
        return ["artifact identity metadata is missing"]
    if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", meta.get("repo_head", "")) is None:
        issues.append("repository commit identity is missing or invalid")
    if meta.get("repo_dirty") not in ("0", "1"):
        issues.append("repository dirty-state identity is missing or invalid")
    if (
        meta.get("common_provider_generation_identity")
        != meta.get("provider_start_identity")
    ):
        issues.append(
            "soak runtime identity does not match the common provider generation"
        )
    for key, label in (
        ("provider_start_identity", "soak runtime provider generation"),
        ("common_provider_generation_identity", "common provider generation"),
    ):
        if re.fullmatch(r"[0-9a-f]{64}", meta.get(key, "")) is None:
            issues.append(f"{label} identity is missing or invalid")
    for key, label in (
        ("soak_script_sha256", "soak script"),
        ("stress_script_sha256", "stress script"),
        ("pressure_parser_sha256", "pressure parser"),
        ("signed_evidence_helper_sha256", "signed evidence helper"),
        ("provider_binary_sha256", "provider binary"),
    ):
        if re.fullmatch(r"[0-9a-f]{64}", meta.get(key, "")) is None:
            issues.append(f"{label} SHA-256 identity is missing or invalid")
    executable = meta.get("provider_executable", "")
    if not isinstance(executable, str) or not executable.startswith("/") or "\t" in executable:
        issues.append("provider executable identity is missing or invalid")
    executable_name = meta.get("provider_executable_name", "")
    crash_process_name = meta.get("crash_process_name", "")
    if (
        not isinstance(executable_name, str)
        or re.fullmatch(r"[A-Za-z0-9._-]+", executable_name) is None
        or os.path.basename(executable) != executable_name
        or crash_process_name != executable_name
    ):
        issues.append(
            "crash process filter does not match the exact provider executable"
        )
    bundle = meta.get("provider_bundle")
    signing_identifier = meta.get("provider_codesign_identifier")
    if not isinstance(bundle, str) or not bundle:
        issues.append("provider bundle identity is missing or invalid")
    if signing_identifier != bundle:
        issues.append("provider code-signing identifier does not match its log subsystem")
    for key, label in (
        ("provider_codesign_cdhash", "provider code-signing CDHash"),
        ("provider_codesign_team", "provider code-signing team"),
    ):
        value = meta.get(key, "")
        if not isinstance(value, str) or not value or value == "unavailable" or "\t" in value:
            issues.append(f"{label} is missing or unavailable")
    return issues


RELEASE_SOAK_PROFILE_ROWS = (
    ("schema_version", "1"),
    ("profile_name", "release-soak-v1"),
    ("required_mode", "cap-validate"),
    ("required_skip_stress", "0"),
    ("required_skip_fanout", "0"),
    ("required_skip_idle", "0"),
    ("required_skip_sleep", "0"),
    ("minimum_stress_seconds", "180"),
    ("minimum_stress_concurrency", "24"),
    ("minimum_fanout_target", "40"),
    ("minimum_fanout_hold_seconds", "90"),
    ("minimum_idle_target", "40"),
    ("minimum_idle_hold_seconds", "150"),
    ("minimum_idle_tail_seconds", "135"),
    ("minimum_max_safe_flows", "300"),
    ("minimum_file_descriptor_limit", "16384"),
    ("required_live_hard_cap_enabled", "1"),
    ("minimum_no_spin_quiescence_seconds", "60"),
    ("schema_complete", "1"),
)


def canonical_release_soak_profile_lines():
    """Return the exact hash-bound release soak profile document."""
    return [f"{key}\t{value}\n" for key, value in RELEASE_SOAK_PROFILE_ROWS]


def release_soak_profile_issues(lines, meta):
    """Validate the canonical profile and truthful release eligibility bit."""
    actual_lines = list(lines)
    expected_lines = canonical_release_soak_profile_lines()
    issues = []
    if actual_lines != expected_lines:
        issues.append("release soak profile is missing, mutated, or non-canonical")
    actual_bytes = "".join(actual_lines).encode("utf-8")
    actual_hash = hashlib.sha256(actual_bytes).hexdigest()
    if meta.get("release_profile_sha256") != actual_hash:
        issues.append("release soak profile hash does not match run metadata")

    exact_requirements = {
        "mode": "cap-validate",
        "configured_skip_stress": "0",
        "configured_skip_fanout": "0",
        "configured_skip_idle": "0",
        "configured_skip_sleep": "0",
        "configured_allow_unsafe_load": "0",
        "configured_live_hard_cap_enabled": "1",
    }
    minimum_requirements = {
        "configured_stress_seconds": 180,
        "configured_stress_concurrency": 24,
        "configured_fanout_target": 40,
        "configured_fanout_hold_seconds": 90,
        "configured_idle_target": 40,
        "configured_idle_hold_seconds": 150,
        "configured_idle_tail_seconds": 135,
        "configured_max_safe_flows": 300,
        "configured_file_descriptor_limit": 16384,
        "configured_no_spin_quiescence_seconds": 60,
    }
    valid = True
    valid_modes = {
        "stress-only", "cap-validate", "cap-hard-limited",
        "cap-too-high", "find-ceiling",
    }
    if meta.get("mode") not in valid_modes:
        issues.append("release soak configured mode is missing or invalid")
    for key in (
        "configured_skip_stress", "configured_skip_fanout",
        "configured_skip_idle", "configured_skip_sleep",
        "configured_allow_unsafe_load", "configured_live_hard_cap_enabled",
    ):
        if meta.get(key) not in ("0", "1"):
            issues.append(f"release soak configuration {key!r} is invalid")
    for key, expected in exact_requirements.items():
        if meta.get(key) != expected:
            valid = False
    for key, minimum in minimum_requirements.items():
        value = parse_artifact_uint(meta.get(key))
        if value is None:
            issues.append(f"release soak configuration {key!r} is invalid")
            valid = False
        elif value < minimum:
            valid = False
    expected_eligibility = "1" if valid else "0"
    if meta.get("release_profile_eligible") != expected_eligibility:
        issues.append("release soak eligibility contradicts the captured configuration")
    return issues


def producer_source_issues(meta, source_paths):
    """Require exact sealed copies of every program that produced soak evidence."""
    if not isinstance(meta, dict) or not isinstance(source_paths, dict):
        return ["soak producer source metadata is missing"]
    issues = []
    specifications = (
        ("soak_script_sha256", "soak_test", "soak script"),
        ("stress_script_sha256", "stress_traffic", "stress script"),
        ("pressure_parser_sha256", "soak_pressure_log", "pressure parser"),
        ("signed_evidence_helper_sha256", "signed_run_evidence", "signed evidence helper"),
    )
    for hash_key, source_key, label in specifications:
        expected = meta.get(hash_key, "")
        path = source_paths.get(source_key)
        try:
            with open(path, "rb") as source:
                content = source.read()
        except (OSError, TypeError):
            content = b""
        if not content:
            issues.append(f"sealed {label} source is missing or empty")
        elif hashlib.sha256(content).hexdigest() != expected:
            issues.append(f"sealed {label} source hash does not match metadata")
    return issues


def dial9_evidence_issues(meta, summary, trace_directory):
    """Validate current-only copied dial9 segments and their decoded-pair summary."""
    issues = []
    if meta.get("dial9_baseline_ready") != "1":
        issues.append("pre-workload dial9 trace identity is unavailable")
    if meta.get("dial9_collection_ok") != "1":
        issues.append("sealed current-run dial9 flow evidence is unavailable")
    baseline = meta.get("dial9_baseline_max_index")
    if baseline == "none":
        baseline_index = None
    else:
        baseline_index = parse_artifact_uint(baseline, maximum=2**32 - 1)
        if baseline_index is None:
            issues.append("dial9 baseline maximum index is invalid")
    if not isinstance(summary, dict):
        issues.append("dial9 evidence summary is missing or malformed")
        return issues
    if (
        type(summary.get("schema_version")) is not int
        or summary.get("schema_version") != 1
        or summary.get("schema_complete") is not True
    ):
        issues.append("dial9 evidence summary schema is incomplete or unsupported")
    summary_baseline = summary.get("baseline_max_index")
    if (
        summary_baseline is not None
        and (type(summary_baseline) is not int or not 0 <= summary_baseline < 2**32)
    ) or summary_baseline != baseline_index:
        issues.append("dial9 evidence summary baseline does not match the run baseline")
    artifacts = summary.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        issues.append("dial9 evidence summary contains no current sealed segments")
        return issues
    expected_count = parse_artifact_uint(meta.get("dial9_current_segment_count"))
    pair_count = parse_artifact_uint(meta.get("dial9_required_pair_count"))
    summary_count = summary.get("current_segment_count")
    if (
        expected_count != len(artifacts)
        or type(summary_count) is not int
        or summary_count != len(artifacts)
    ):
        issues.append("dial9 current segment count does not match its manifest")
    summary_pair_count = summary.get("required_pair_count")
    if (
        pair_count is None
        or pair_count < 1
        or type(summary_pair_count) is not int
        or summary_pair_count != pair_count
    ):
        issues.append("dial9 evidence does not contain a decoded open/close pair")
    seen_indices = set()
    expected_names = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            issues.append("dial9 evidence manifest contains a malformed artifact")
            continue
        name = artifact.get("name")
        match = (
            re.fullmatch(r"trace\.(\d+)\.bin(?:\.gz)?", name)
            if isinstance(name, str)
            else None
        )
        if match is None:
            issues.append("dial9 evidence manifest contains a non-canonical artifact name")
            continue
        index = int(match.group(1))
        if str(index) != match.group(1):
            issues.append(f"dial9 artifact {name!r} has a non-canonical index")
        expected_encoding = "gzip" if name.endswith(".gz") else "raw"
        if artifact.get("state") != "sealed":
            issues.append(f"dial9 artifact {name!r} is not declared sealed")
        if artifact.get("encoding") != expected_encoding:
            issues.append(f"dial9 artifact {name!r} encoding does not match its name")
        if type(artifact.get("index")) is not int or artifact.get("index") != index:
            issues.append(f"dial9 artifact {name!r} index does not match its name")
        if index in seen_indices:
            issues.append(f"dial9 trace index {index} has multiple retained representations")
        seen_indices.add(index)
        if baseline_index is not None and index <= baseline_index:
            issues.append(f"dial9 artifact {name!r} is not newer than the baseline")
        size = artifact.get("size")
        digest = artifact.get("sha256")
        if (
            type(size) is not int
            or size < 1
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            issues.append(f"dial9 artifact {name!r} has invalid size/hash identity")
            continue
        path = os.path.join(trace_directory, name)
        try:
            with open(path, "rb") as trace_input:
                content = trace_input.read()
        except OSError:
            issues.append(f"dial9 artifact {name!r} is missing from the copied bundle")
            continue
        if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
            issues.append(f"dial9 artifact {name!r} does not match its copied hash identity")
        expected_names.append(name)
    current_indices = summary.get("current_indices")
    if not isinstance(current_indices, list) or any(
        type(index) is not int for index in current_indices
    ) or current_indices != sorted(seen_indices):
        issues.append("dial9 current index list does not match its manifest")
    try:
        copied_names = sorted(
            name for name in os.listdir(trace_directory)
            if os.path.isfile(os.path.join(trace_directory, name))
        )
    except OSError:
        copied_names = []
    if copied_names != sorted(expected_names):
        issues.append("copied dial9 trace directory does not match its manifest")
    return issues


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


def settled_final_flow_gauge(
    rows,
    settle_start_epoch,
    settle_end_epoch,
    minimum_samples=2,
    nominal_period=60,
    maximum_sample_age=70,
):
    """Return a trustworthy final gauge from a completed quiet tail.

    A baseline or stress-phase gauge cannot prove that flows later settled.
    Require a long-enough quiet phase, at least two samples from that phase,
    and a sample near its end. `None` means the soak evidence is incomplete.
    """
    if settle_start_epoch is None or settle_end_epoch is None:
        return None
    if settle_end_epoch - settle_start_epoch < minimum_samples * nominal_period:
        return None

    samples_by_epoch = {}
    for epoch, message in rows:
        gauge = flow_gauge(message)
        if (
            epoch is not None
            and settle_start_epoch <= epoch < settle_end_epoch
            and gauge
        ):
            samples_by_epoch[epoch] = gauge
    samples = sorted(samples_by_epoch.items())
    if len(samples) < minimum_samples:
        return None
    last_epoch, last_gauge = samples[-1]
    if last_epoch < settle_end_epoch - maximum_sample_age:
        return None
    return last_gauge


def ceiling_configuration_issues(soft_cap, hard_cap):
    """Return configuration errors that invalidate a raw ceiling search."""
    issues = []
    if soft_cap is None:
        issues.append("flow-pressure soft cap was not observed")
    elif soft_cap != 0:
        issues.append(f"flow-pressure soft cap is enabled ({soft_cap})")
    if hard_cap is None:
        issues.append("live-flow hard cap was not observed")
    elif hard_cap != 0:
        issues.append(f"live-flow hard cap is enabled ({hard_cap})")
    return issues


def _phase_sample_issue(name, kind, start, end, samples, maximum_gap):
    intervals = []
    for sample in samples:
        if isinstance(sample, (tuple, list)) and len(sample) == 2:
            sample_start = parse_epoch(sample[0])
            sample_end = parse_epoch(sample[1])
        else:
            sample_start = sample_end = parse_epoch(sample)
        if (
            sample_start is None
            or sample_end is None
            or sample_end < sample_start
            or sample_end < start
            or sample_start >= end
        ):
            continue
        intervals.append((max(start, sample_start), min(end, sample_end)))
    intervals.sort()
    if not intervals:
        return f"phase {name!r} has no {kind} coverage"

    largest_gap = Decimal(0)
    covered_through = start
    for interval_start, interval_end in intervals:
        largest_gap = max(largest_gap, interval_start - covered_through)
        covered_through = max(covered_through, interval_end)
    largest_gap = max(largest_gap, end - covered_through)
    if largest_gap > maximum_gap:
        return (
            f"phase {name!r} has a {kind} gap of "
            f"{float(largest_gap):.3f}s (maximum {maximum_gap}s)"
        )
    return None


def soak_evidence_issues(
    meta,
    *,
    rows_count,
    gauge_count,
    probe_count,
    incomplete_phases=(),
    phase_coverage=(),
    required_phases=(),
    capture_issues=(),
    final_gauge_required=True,
    final_gauge_present=False,
    maximum_probe_gap=20,
    maximum_gauge_gap=70,
):
    """Return reasons a soak report must not claim a GOOD verdict.

    `phase_coverage` contains `(name, start, end, probe_epochs, gauge_epochs)`
    tuples. Short phases are allowed to fall between periodic samples;
    sustained phases must have bounded gaps from both phase edges and between
    samples, proving that a monitor did not merely die and restart later.
    """

    def meta_true(key):
        return meta.get(key) == "1"

    phase_coverage = list(phase_coverage)
    incomplete_phases = set(incomplete_phases)
    issues = []
    if not meta_true("log_stream_started"):
        issues.append("log stream did not start")
    if not meta_true("log_stream_alive_end"):
        issues.append("log stream did not cover the complete run")
    if not meta_true("log_stream_joined"):
        issues.append("log stream capture was not quiesced and joined")
    if _nonnegative_int(meta.get("log_stream_child_rc")) not in (0, 143):
        issues.append("log stream child outcome is missing or invalid")
    if not meta_true("baseline_gauge_seen"):
        issues.append("baseline gauge was not observed")
    if not meta_true("baseline_gauge_phase_local"):
        issues.append("baseline gauge was not captured within the baseline phase")
    if not meta_true("probe_monitor_alive_end"):
        issues.append("probe monitor did not cover the complete run")
    if not meta_true("probe_monitor_joined"):
        issues.append("probe monitor capture was not quiesced and joined")
    if _nonnegative_int(meta.get("probe_monitor_child_rc")) not in (0, 143):
        issues.append("probe monitor child outcome is missing or invalid")
    if not meta_true("provider_continuous"):
        issues.append("provider process identity changed or disappeared")
    if not meta_true("holder_cleanup_ok"):
        issues.append("one or more flow-holder workers were not joined")
    if rows_count == 0:
        issues.append("system log contains no parseable rows")
    if gauge_count < 2:
        issues.append("fewer than two flow-gauge samples were captured")
    if probe_count < 2:
        issues.append("fewer than two non-sleep liveness probes were captured")
    issues.extend(capture_issues)
    for name in sorted(incomplete_phases):
        issues.append(f"phase {name!r} has no end marker")
    completed_phases = {name for name, *_ in phase_coverage}
    for name in sorted(set(required_phases) - completed_phases - incomplete_phases):
        issues.append(f"phase {name!r} has no complete marker pair")
    for name, start, end, probes, gauges in phase_coverage:
        if name == "sleep-wake":
            continue
        duration = end - start
        if duration >= maximum_probe_gap:
            issue = _phase_sample_issue(
                name, "liveness probe", start, end, probes, maximum_probe_gap)
            if issue:
                issues.append(issue)
        if duration >= 75:
            issue = _phase_sample_issue(
                name, "flow-gauge", start, end, gauges, maximum_gauge_gap)
            if issue:
                issues.append(issue)
    if final_gauge_required and not final_gauge_present:
        issues.append("idle tail has no trustworthy final flow gauge")
    return issues


def pressure_reaper_status(pressure, soft_cap, evidence_complete):
    """Classify whether this run itself proved a successful pressure reap."""
    if not evidence_complete:
        return "inconclusive"
    if soft_cap <= 0:
        return "disabled"
    if pressure.get("validated_eviction_episode_caps", {}).get(soft_cap, 0) > 0:
        return "good"
    if pressure["observed_peak"] >= soft_cap:
        return "crossed-without-attributable-eviction"
    return "not-observed"


def classify_soak_result(
    meta,
    evidence_issues,
    *,
    probe_failures,
    body_errors,
    reaper_status,
    fanout_failures=0,
    leak_count=0,
    baseline_total=None,
    final_total=None,
    settlement_tolerance=5,
    provider_faults=0,
    unknown_provider_errors=0,
    udp_pressure_failures=(),
    no_spin_failures=(),
    crash_failures=(),
):
    """Return orthogonal evidence completeness and product verdict state."""
    issues = list(evidence_issues)
    failures = []
    mode = meta.get("mode")
    valid_modes = {
        "stress-only",
        "cap-validate",
        "cap-hard-limited",
        "cap-too-high",
        "find-ceiling",
    }
    if mode not in valid_modes:
        issues.append("run mode is missing or invalid")

    if mode == "find-ceiling":
        for key, label in (
            ("ceiling_found", "ceiling-finder outcome"),
            ("ceiling_recovered", "post-ceiling recovery outcome"),
        ):
            if meta.get(key) not in ("0", "1"):
                issues.append(f"{label} is missing")
        if meta.get("ceiling_found") == "0":
            failures.append("ceiling finder exhausted its ramp without finding the ceiling")
        if meta.get("ceiling_recovered") == "0":
            failures.append("network did not recover after the ceiling probe failed")
    elif mode in valid_modes:
        workload_fields = (
            ("download_host_preflight_ok", "download-host preflight"),
            ("stress_ok", "stress workload"),
            ("fanout_ok", "fanout target"),
            ("idle_holders_ok", "idle-holder target"),
            ("real_download_ok", "real download"),
            ("post_wake_ok", "post-wake recovery"),
            ("sleep_command_ok", "sleep command"),
        )
        raw_pool_fields = {
            "fanout_ok": "fanout_established_target_sustained",
            "idle_holders_ok": "idle_holders_established_target_sustained",
        }
        for key, label in workload_fields:
            value = meta.get(key)
            if value not in ("0", "1", "skipped"):
                issues.append(f"{label} outcome is missing")
            raw_key = raw_pool_fields.get(key)
            raw_value = meta.get(raw_key) if raw_key else None
            if raw_key and raw_value not in ("0", "1", "skipped"):
                issues.append(f"{label} raw outcome is missing")
            if value == "0" or raw_value == "0":
                failures.append(f"{label} failed")
            if (
                raw_key
                and value in ("0", "1", "skipped")
                and raw_value in ("0", "1", "skipped")
                and value != raw_value
            ):
                issues.append(f"{label} raw and correlated outcomes conflict")
        if mode == "cap-validate" and reaper_status not in ("good", "inconclusive"):
            failures.append(
                "cap-validation mode did not prove an attributable successful reap"
            )
        if mode == "cap-hard-limited":
            failures.append("live-flow hard cap prevents pressure-cap validation")

    numeric_values = {}
    for name, value in (
        ("probe failure count", probe_failures),
        ("body error count", body_errors),
        ("fanout transfer failure count", fanout_failures),
        ("leak count", leak_count),
        ("provider Fault count", provider_faults),
        ("unknown provider Error count", unknown_provider_errors),
    ):
        parsed = _nonnegative_int(value)
        if parsed is None:
            issues.append(f"{name} is missing or invalid")
            parsed = 0
        numeric_values[name] = parsed

    probe_failures = numeric_values["probe failure count"]
    body_errors = numeric_values["body error count"]
    fanout_failures = numeric_values["fanout transfer failure count"]
    leak_count = numeric_values["leak count"]
    provider_faults = numeric_values["provider Fault count"]
    unknown_provider_errors = numeric_values["unknown provider Error count"]
    if probe_failures:
        failures.append(f"{probe_failures} liveness probe(s) failed")
    if body_errors:
        failures.append(f"{body_errors} body decode/relay error(s) were observed")
    if fanout_failures:
        failures.append(
            f"{fanout_failures} active fanout transfer failure(s) were observed"
        )
    if leak_count:
        failures.append(f"leaks reported {leak_count} leaked allocation(s)")
    if provider_faults:
        failures.append(f"{provider_faults} provider Fault log(s) were observed")
    if unknown_provider_errors:
        failures.append(
            f"{unknown_provider_errors} unclassified provider Error log(s) were observed"
        )
    failures.extend(udp_pressure_failures)
    failures.extend(no_spin_failures)
    failures.extend(crash_failures)

    if mode in valid_modes - {"find-ceiling"}:
        if baseline_total is None:
            baseline_total = meta.get("baseline_total")
        if final_total is None:
            final_total = meta.get("final_total")
        baseline_total = _nonnegative_int(baseline_total)
        final_total = _nonnegative_int(final_total)
        settlement_tolerance = _nonnegative_int(settlement_tolerance)
        if baseline_total is None:
            issues.append("baseline allocated-flow total is missing or invalid")
        if final_total is None:
            issues.append("final allocated-flow total is missing or invalid")
        if settlement_tolerance is None:
            issues.append("flow-settlement tolerance is missing or invalid")
        if (
            baseline_total is not None
            and final_total is not None
            and settlement_tolerance is not None
            and final_total > baseline_total + settlement_tolerance
        ):
            failures.append(
                "final allocated-flow total did not settle to the baseline tolerance "
                f"({final_total} > {baseline_total} + {settlement_tolerance})"
            )

    complete = not issues
    passed = complete and not failures
    exit_code = 0 if passed else (2 if not complete else 1)
    return {
        "complete": complete,
        "passed": passed,
        "exit_code": exit_code,
        "evidence_issues": issues,
        "failures": failures,
    }


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
