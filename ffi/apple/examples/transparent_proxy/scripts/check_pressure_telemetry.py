"""Validate telemetry emitted by native tests with the production pressure parser."""

import sys
from pathlib import Path
from pressure_log import pressure_telemetry_issue

MARKER = "RAMA_PRESSURE_TELEMETRY "
REQUIRED = (
    "tproxy live-flow counts",
    "flow pressure: occupancy",
    "flow pressure episode",
    "writer memory pressure",
    "UDP ingress pressure dropped datagram",
    "UDP ingress pressure resumed flow",
    "UDP Swift ingress staging dropped datagrams",
)


def main(paths):
    seen = set()
    for path in paths:
        for line in Path(path).read_text().splitlines():
            if MARKER not in line:
                continue
            message = line.split(MARKER, 1)[1]
            category = next(
                (prefix for prefix in REQUIRED if message.startswith(prefix)), None
            )
            if category is None:
                continue
            issue = pressure_telemetry_issue(message)
            if issue is not None:
                raise SystemExit(f"native telemetry rejected: {issue}: {message}")
            seen.add(category)
    missing = set(REQUIRED) - seen
    if missing:
        raise SystemExit("native telemetry missing: " + ", ".join(sorted(missing)))
    print("Swift/Rust pressure telemetry accepted by pressure_log")


if __name__ == "__main__":
    main(sys.argv[1:])
