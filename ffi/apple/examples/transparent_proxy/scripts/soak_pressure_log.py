"""Stable parser for pressure telemetry emitted by TransparentProxyCore."""

import re


SELECTION_RE = re.compile(
    r"flow pressure: occupancy (\d+) over soft cap (\d+); selected (\d+) idle"
)
NO_HEADROOM_RE = re.compile(
    r"flow pressure: occupancy (\d+), soft cap (\d+), but no flow idle"
)
PRESSURE_COUNTER_RE = re.compile(
    r"pressure\[triggers=(\d+) scans=(\d+) skipped=(\d+) selected=(\d+) "
    r"evicted=(\d+) spared=(\d+) canceled=(\d+) expired=(\d+) pending=(\d+)\]"
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
    match = SELECTION_RE.search(message)
    return int(match.group(3)) if match else None


def is_no_headroom(message):
    """Whether this is the current once-per-episode no-headroom line."""
    return NO_HEADROOM_RE.search(message) is not None


def pressure_counters(message):
    """Return one periodic pressure-counter delta, or None."""
    match = PRESSURE_COUNTER_RE.search(message)
    if not match:
        return None
    return dict(zip(PRESSURE_COUNTER_KEYS, map(int, match.groups())))
