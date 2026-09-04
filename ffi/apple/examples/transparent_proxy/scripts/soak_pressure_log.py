"""Stable parser for pressure telemetry emitted by TransparentProxyCore."""

from datetime import datetime, timezone
from decimal import Decimal
import json
import re


SELECTION_RE = re.compile(
    r"flow pressure: occupancy (\d+) over soft cap (\d+); selected (\d+) idle"
)
NO_HEADROOM_RE = re.compile(
    r"flow pressure: occupancy (\d+), soft cap (\d+), but no flow idle"
)
GAUGE_RE = re.compile(
    r"live-flow counts tcp=(\d+) udp=(\d+) total=(\d+) peak=(\d+) softCap=(\d+)"
    r"(?: hardCap=(\d+)(?=\s|$))?"
    r"(?: retiring=(\d+)(?=\s|$))?"
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
START_EPOCH_US_RE = re.compile(r"\bstartEpochUs=(\d+)\b")
ENGINE_LIFECYCLE_RE = re.compile(
    r"\b(?:startProxy|stopProxy|engine created|engine detached)\b",
    re.IGNORECASE,
)
SYSTEM_SLEEP_RE = re.compile(r"^system sleep\b", re.IGNORECASE)
SYSTEM_WAKE_RE = re.compile(r"^system wake\b", re.IGNORECASE)

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


def selected_count(message):
    """Return the selected-victim count from one selection line."""
    event = selection_event(message)
    return event["selected"] if event else None


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


def is_no_headroom(message):
    """Whether this is the current once-per-episode no-headroom line."""
    return no_headroom_event(message) is not None


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


def flow_gauge(message):
    """Return one periodic live-flow gauge, or None."""
    match = GAUGE_RE.search(message)
    if not match:
        return None
    required = [parse_artifact_uint(value) for value in match.groups()[:5]]
    if any(value is None for value in required):
        return None
    tcp, udp, total, peak, soft_cap = required
    hard_cap = (
        parse_artifact_uint(match.group(6))
        if match.group(6) is not None
        else None
    )
    retiring = (
        parse_artifact_uint(match.group(7))
        if match.group(7) is not None
        else None
    )
    gauge_text = message[match.start():]
    if (
        (" hardCap=" in gauge_text and hard_cap is None)
        or (" retiring=" in gauge_text and retiring is None)
    ):
        return None
    registered = tcp + udp
    if registered > MAX_ARTIFACT_UINT or (
        retiring is not None and total != registered + retiring
    ) or (
        hard_cap is not None and hard_cap > 0 and total > hard_cap
    ):
        return None
    return {
        "tcp": tcp,
        "udp": udp,
        "registered": registered,
        "retiring": retiring,
        "allocated": total,
        "total": total,
        "peak": peak,
        "soft_cap": soft_cap,
        "hard_cap": hard_cap,
    }


def flow_gauge_issue(message):
    """Return a capture issue for a present but incomplete/invalid gauge."""
    if "live-flow counts" not in message:
        return None
    gauge = flow_gauge(message)
    if gauge is None:
        return "flow-gauge sample is malformed or has inconsistent allocation/hard-cap totals"
    if gauge["retiring"] is None:
        return "flow-gauge sample omitted retiring allocations"
    if gauge["peak"] < gauge["allocated"]:
        return "flow-gauge peak is below its current allocated total"
    return None


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


def parse_ndjson_lines(lines):
    """Decode an ndjson stream and report every malformed record."""
    records = [(line_number, raw.strip()) for line_number, raw in enumerate(lines, 1)
               if raw.strip()]
    decoded = []
    issues = []
    for line_number, line in records:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
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
            or interval_end - interval_start < Decimal("5")
            or interval_start < phase_start
            or interval_end > phase_end
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
    _, _, curl_rc, code = record
    return curl_rc == 0 and code.startswith("2")


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

    sleeps = sorted(
        epoch for raw in sleep_epochs
        if (
            (epoch := parse_epoch(raw)) is not None
            and command_started <= epoch < phase_end
        )
    )
    wakes = sorted(
        epoch for raw in wake_epochs
        if (
            (epoch := parse_epoch(raw)) is not None
            and phase_start <= epoch <= command_completed
        )
    )
    ordered_pair = next(
        ((sleep, wake) for sleep in sleeps for wake in wakes if wake > sleep),
        None,
    )
    if ordered_pair is None:
        issues.append("sleep-wake phase has no ordered command-local sleep/wake markers")
        return {"issues": issues, "outage_window": None}

    sleep_epoch, wake_epoch = ordered_pair
    probes_after_wake = [
        probe for probe in recovery_probes
        if command_completed <= probe[0] <= probe[1] <= phase_end
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


def ceiling_outage_window(records, baseline_total, phase):
    """Return the proved direct-failure to direct-recovery half-open window."""
    try:
        _, start, end = phase
    except (TypeError, ValueError):
        return None
    baseline_total = _nonnegative_int(baseline_total)
    start = parse_epoch(start)
    end = parse_epoch(end)
    if baseline_total is None or start is None or end is None or end <= start:
        return None
    run = 0
    first_failure = None
    proved_start = None
    for started, completed, curl_rc, code, occupancy, gauge_epoch in records:
        if not (start <= started <= completed < end):
            continue
        if curl_rc == 0 and code.startswith("2"):
            if proved_start is not None:
                return proved_start, completed
            run = 0
            first_failure = None
            continue
        gauge_is_fresh = (
            start <= gauge_epoch <= started
            and started - gauge_epoch <= Decimal("70")
        )
        if occupancy > baseline_total and gauge_is_fresh:
            if run == 0:
                first_failure = completed
            run += 1
            if run >= 2:
                proved_start = first_failure
        else:
            run = 0
            first_failure = None
    if proved_start is not None:
        return proved_start, None
    return None


def ceiling_probe_evidence_issues(
    records, ceiling_found, baseline_total, phase, ceiling_recovered=None
):
    """Require attributable consecutive failure and claimed direct recovery."""
    if isinstance(ceiling_found, bool) or ceiling_found not in (0, 1, "0", "1"):
        return ["ceiling-finder outcome is missing"]
    if str(ceiling_found) != "1":
        return []
    window = ceiling_outage_window(records, baseline_total, phase)
    if window is None:
        if phase is None:
            return ["ceiling failure proof has invalid baseline or phase"]
        return ["ceiling failure lacks two consecutive elevated, phase-local probes"]
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
        rf"\b({number})\s+leaks?\s+for\s+"
        rf"({number})\s+total leaked bytes\b",
        text,
        re.IGNORECASE,
    )
    if len(matches) != 1:
        return None
    leaks_text, leaked_bytes_text = matches[0]
    leaks = parse_artifact_uint(leaks_text.replace(",", ""))
    leaked_bytes = parse_artifact_uint(leaked_bytes_text.replace(",", ""))
    if leaks is None or leaked_bytes is None:
        return None
    return {
        "leaks": leaks,
        "bytes": leaked_bytes,
    }


def leak_evidence(command_rc, text):
    """Return fail-closed leaks-tool evidence and the parsed leak count."""
    issues = []
    command_rc = _nonnegative_int(command_rc)
    parsed = parse_leaks_output(text)
    if parsed is None:
        issues.append("leaks output is missing or unparseable")
        leaks = leaked_bytes = 0
    else:
        leaks = parsed["leaks"]
        leaked_bytes = parsed["bytes"]
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
        "leaks": leaks,
        "bytes": leaked_bytes,
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
        if key in ("complete", "passed", "exit_code", "schema_complete"):
            if key in values:
                return None
            values[key] = value
    if not pairs or pairs[-1] != ["schema_complete", "1"]:
        return None
    expected = {
        ("1", "1", "0"),
        ("1", "0", "1"),
        ("0", "0", "2"),
    }
    verdict = (values.get("complete"), values.get("passed"), values.get("exit_code"))
    return int(verdict[2]) if verdict in expected else None


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
    if precise_start:
        start_epoch_us = parse_artifact_uint(precise_start.group(1))
        if start_epoch_us is None:
            return None
    else:
        start_epoch_us = event["start_epoch_ms"] * 1_000
        if start_epoch_us > MAX_ARTIFACT_UINT:
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
    leak_count=0,
    baseline_total=None,
    final_total=None,
    settlement_tolerance=5,
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
        ("leak count", leak_count),
    ):
        parsed = _nonnegative_int(value)
        if parsed is None:
            issues.append(f"{name} is missing or invalid")
            parsed = 0
        numeric_values[name] = parsed

    probe_failures = numeric_values["probe failure count"]
    body_errors = numeric_values["body error count"]
    leak_count = numeric_values["leak count"]
    if probe_failures:
        failures.append(f"{probe_failures} liveness probe(s) failed")
    if body_errors:
        failures.append(f"{body_errors} body decode/relay error(s) were observed")
    if leak_count:
        failures.append(f"leaks reported {leak_count} leaked allocation(s)")

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
