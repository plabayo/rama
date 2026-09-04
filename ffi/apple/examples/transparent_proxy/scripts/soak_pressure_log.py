"""Stable parser for pressure telemetry emitted by TransparentProxyCore."""

from decimal import Decimal
import re


SELECTION_RE = re.compile(
    r"flow pressure: occupancy (\d+) over soft cap (\d+); selected (\d+) idle"
)
NO_HEADROOM_RE = re.compile(
    r"flow pressure: occupancy (\d+), soft cap (\d+), but no flow idle"
)
GAUGE_RE = re.compile(
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
    tcp, udp, total, peak, soft_cap = map(int, match.groups())
    return {
        "tcp": tcp,
        "udp": udp,
        "total": total,
        "peak": peak,
        "soft_cap": soft_cap,
    }


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
            and settle_start_epoch <= epoch <= settle_end_epoch
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


def soak_evidence_issues(
    meta,
    *,
    rows_count,
    gauge_count,
    probe_count,
    incomplete_phases=(),
    phase_coverage=(),
    final_gauge_required=True,
    final_gauge_present=False,
):
    """Return reasons a soak report must not claim a GOOD verdict.

    `phase_coverage` contains `(name, duration, probes, gauges)` tuples. Short
    phases are allowed to fall between periodic samples; sustained phases are
    required to prove that both monitors covered them.
    """

    def meta_true(key):
        return meta.get(key) == "1"

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
    for name in sorted(incomplete_phases):
        issues.append(f"phase {name!r} has no end marker")
    for name, duration, probes, gauges in phase_coverage:
        if name == "sleep-wake":
            continue
        if duration >= 20 and probes == 0:
            issues.append(f"phase {name!r} has no liveness probe coverage")
        if duration >= 75 and gauges == 0:
            issues.append(f"phase {name!r} has no flow-gauge coverage")
    if final_gauge_required and not final_gauge_present:
        issues.append("idle tail has no trustworthy final flow gauge")
    return issues


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
            result["observed_peak"] = max(
                result["observed_peak"], episode["peak_occupancy"])
            result["soft_caps"].add(episode["soft_cap"])
            for key in result["episode"]:
                result["episode"][key] += episode[key]

    result["eviction_observed"] = (
        result["periodic"]["evicted"] > 0 or result["episode"]["evicted"] > 0
    )
    return result
