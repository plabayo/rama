"""Stable parser for pressure telemetry emitted by TransparentProxyCore."""

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
    r"(?: hardCap=(\d+))?"
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


def selected_count(message):
    """Return the selected-victim count from one selection line."""
    event = selection_event(message)
    return event["selected"] if event else None


def selection_event(message):
    """Return event-local occupancy, cap, and selected-victim count."""
    match = SELECTION_RE.search(message)
    if not match:
        return None
    occupancy, soft_cap, selected = map(int, match.groups())
    return {"occupancy": occupancy, "soft_cap": soft_cap, "selected": selected}


def is_no_headroom(message):
    """Whether this is the current once-per-episode no-headroom line."""
    return no_headroom_event(message) is not None


def no_headroom_event(message):
    """Return event-local occupancy and cap from a no-headroom line."""
    match = NO_HEADROOM_RE.search(message)
    if not match:
        return None
    occupancy, soft_cap = map(int, match.groups())
    return {"occupancy": occupancy, "soft_cap": soft_cap}


def flow_gauge(message):
    """Return one periodic live-flow gauge, or None."""
    match = GAUGE_RE.search(message)
    if not match:
        return None
    tcp, udp, total, peak, soft_cap = map(int, match.groups()[:5])
    hard_cap = int(match.group(6)) if match.group(6) is not None else None
    return {
        "tcp": tcp,
        "udp": udp,
        "total": total,
        "peak": peak,
        "soft_cap": soft_cap,
        "hard_cap": hard_cap,
    }


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
    return epoch if epoch.is_finite() else None


def parse_ndjson_lines(lines):
    """Decode an ndjson stream and report malformed interior records.

    Killing `log stream` can leave one final partial JSON object, which is not
    evidence of a capture gap. Any malformed non-final record is different: it
    proves that an interior portion of the artifact cannot be trusted.
    """
    records = [(line_number, raw.strip()) for line_number, raw in enumerate(lines, 1)
               if raw.strip()]
    decoded = []
    issues = []
    for index, (line_number, line) in enumerate(records):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            if index != len(records) - 1:
                issues.append(f"malformed interior NDJSON record at line {line_number}")
            continue
        if not isinstance(value, dict):
            issues.append(f"non-object NDJSON record at line {line_number}")
            continue
        decoded.append(value)
    return decoded, issues


def pressure_counters(message):
    """Return one periodic pressure-counter delta, or None."""
    match = PRESSURE_COUNTER_RE.search(message)
    if not match:
        return None
    return dict(zip(PRESSURE_COUNTER_KEYS, map(int, match.groups())))


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
    event = dict(zip(keys, (values[0], *map(int, values[1:]))))
    precise_start = START_EPOCH_US_RE.search(message)
    event["start_epoch_us"] = (
        int(precise_start.group(1))
        if precise_start
        else event["start_epoch_ms"] * 1_000
    )
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
    samples = sorted({sample for sample in samples if start <= sample < end})
    if not samples:
        return f"phase {name!r} has no {kind} coverage"
    points = [start, *samples, end]
    largest_gap = max(right - left for left, right in zip(points, points[1:]))
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
    if not meta_true("baseline_gauge_seen"):
        issues.append("baseline gauge was not observed")
    if not meta_true("probe_monitor_alive_end"):
        issues.append("probe monitor did not cover the complete run")
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
    if pressure["validated_eviction_episodes"] > 0:
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
):
    """Return orthogonal evidence completeness and product verdict state."""
    issues = list(evidence_issues)
    failures = []
    mode = meta.get("mode")
    if not mode:
        issues.append("run mode is missing")

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
    elif mode:
        workload_fields = (
            ("download_host_preflight_ok", "download-host preflight"),
            ("stress_ok", "stress workload"),
            ("fanout_ok", "fanout target"),
            ("idle_holders_ok", "idle-holder target"),
            ("real_download_ok", "real download"),
            ("post_wake_ok", "post-wake recovery"),
        )
        for key, label in workload_fields:
            value = meta.get(key)
            if value not in ("0", "1", "skipped"):
                issues.append(f"{label} outcome is missing")
            elif value == "0":
                failures.append(f"{label} failed")
        if mode == "cap-validate" and reaper_status not in ("good", "inconclusive"):
            failures.append(
                "cap-validation mode did not prove an attributable successful reap"
            )
        if mode == "cap-hard-limited":
            failures.append("live-flow hard cap prevents pressure-cap validation")

    if probe_failures:
        failures.append(f"{probe_failures} liveness probe(s) failed")
    if body_errors:
        failures.append(f"{body_errors} body decode/relay error(s) were observed")

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
                episode["soft_cap"] > 0
                and episode["peak_occupancy"] >= episode["soft_cap"]
                and episode["evicted"] > 0
            ):
                result["validated_eviction_episodes"] += 1
            result["observed_peak"] = max(
                result["observed_peak"], episode["peak_occupancy"])
            result["soft_caps"].add(episode["soft_cap"])
            for key in result["episode"]:
                result["episode"][key] += episode[key]

    result["eviction_observed"] = (
        result["periodic"]["evicted"] > 0 or result["episode"]["evicted"] > 0
    )
    return result
