"""Stable parser for pressure telemetry emitted by TransparentProxyCore."""

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
    r"flow pressure episode (ended|interrupted): durationMs=(\d+) "
    r"peakOccupancy=(\d+) softCap=(\d+) scans=(\d+) skipped=(\d+) "
    r"selected=(\d+) evicted=(\d+) spared=(\d+) canceled=(\d+) expired=(\d+)"
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
    return dict(zip(keys, (values[0], *map(int, values[1:]))))


def summarize_pressure_rows(rows, baseline_end_epoch=None):
    """Build non-double-counting pressure evidence from `(epoch, message)` rows.

    The first gauge at/before the baseline boundary snapshots the provider's
    lifecycle-wide peak. Only a later increase is attributable to this run.
    Periodic deltas and episode totals are retained as separate, overlapping
    evidence channels; callers must never sum them.
    """
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
    baseline_peak = 0

    for epoch, message in rows:
        gauge = flow_gauge(message)
        if gauge:
            result["soft_caps"].add(gauge["soft_cap"])
            if baseline_end_epoch is not None and (
                epoch is None or epoch <= baseline_end_epoch
            ):
                baseline_peak = max(baseline_peak, gauge["peak"])
            elif baseline_end_epoch is None or epoch > baseline_end_epoch:
                result["observed_peak"] = max(
                    result["observed_peak"], gauge["total"])
                if gauge["peak"] > baseline_peak:
                    result["observed_peak"] = max(
                        result["observed_peak"], gauge["peak"])

        in_run = baseline_end_epoch is None or (
            epoch is not None and epoch > baseline_end_epoch
        )
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

        counters = pressure_counters(message)
        if counters:
            result["periodic_intervals"] += 1
            for key in result["periodic"]:
                result["periodic"][key] += counters[key]

        episode = pressure_episode(message)
        if episode:
            if baseline_end_epoch is not None:
                start_epoch = epoch - episode["duration_ms"] / 1000
                if start_epoch <= baseline_end_epoch:
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
