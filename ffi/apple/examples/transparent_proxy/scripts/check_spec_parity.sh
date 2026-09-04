#!/usr/bin/env bash
# Cross-file parity checks for the transparent-proxy example. Fast, no Xcode
# toolchain needed, so they run early in `just qa` (and thus in CI).
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# dev and dist Xcode specs must declare the same SPM products, else a product
# added to Project.yml but forgotten in Project.dist.yml silently breaks the
# Developer-ID build (which no other recipe compiles).
dev=$(grep -E '^[[:space:]]*product:' tproxy_app/Project.yml | awk '{print $2}' | sort -u)
dist=$(grep -E '^[[:space:]]*product:' tproxy_app/Project.dist.yml | awk '{print $2}' | sort -u)
if [ "$dev" != "$dist" ]; then
    echo "Project.yml vs Project.dist.yml SPM product deps diverged:" >&2
    diff <(echo "$dev") <(echo "$dist") >&2 || true
    fail=1
fi

# CA keychain service names must match between the Rust sysext and the Swift
# container, else `Clear CA` wipes nothing and leaves orphaned key material.
rs=$(grep -oE 'rama-tproxy-demo-ca-[a-z-]+' tproxy_rs/src/tls/mod.rs | sort -u)
sw=$(grep -oE 'rama-tproxy-demo-ca-[a-z-]+' tproxy_app/Container/main.swift | sort -u)
if [ "$rs" != "$sw" ]; then
    echo "CA keychain service names diverged between Rust and Swift:" >&2
    diff <(echo "$rs") <(echo "$sw") >&2 || true
    fail=1
fi

# The soak parser is evidence-critical. Keep its accepted field order aligned
# with the actual Swift emitters so a runtime wording change cannot degrade a
# complete on-device run into silently ignored telemetry.
if ! python3 - "$(pwd)" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts"))
from soak_pressure_log import pressure_telemetry_issue

source = (
    root.parent.parent
    / "RamaAppleNetworkExtension/Sources/RamaAppleNetworkExtension/Provider/TransparentProxyCore.swift"
).read_text()
udp_source = (
    root.parents[3]
    / "rama-net-apple-networkextension/src/tproxy/engine/udp_ingress.rs"
).read_text()
swift_udp_source = (
    root.parent.parent
    / "RamaAppleNetworkExtension/Sources/RamaAppleNetworkExtension/Provider/Session/UdpFlowSession.swift"
).read_text()
swift_udp_staging_source = (
    root.parent.parent
    / "RamaAppleNetworkExtension/Sources/RamaAppleNetworkExtension/Provider/UdpIngressStaging.swift"
).read_text()

def require_order(anchor, tokens, span=5000):
    start = source.find(anchor)
    if start < 0:
        raise SystemExit(f"Swift telemetry emitter anchor missing: {anchor}")
    block = source[start:start + span]
    cursor = 0
    for token in tokens:
        found = block.find(token, cursor)
        if found < 0:
            raise SystemExit(
                f"Swift telemetry emitter field missing/out of order after {anchor}: {token}"
            )
        cursor = found + len(token)

def require_literals(anchor, literals, span=5000):
    start = source.find(anchor)
    if start < 0:
        raise SystemExit(f"Swift telemetry emitter anchor missing: {anchor}")
    block = source[start:start + span]
    for literal in literals:
        if literal not in block:
            raise SystemExit(
                f"Swift telemetry emitter literal diverged after {anchor}: {literal}"
            )

def require_udp_order(anchor, tokens, span=1200):
    start = udp_source.find(anchor)
    if start < 0:
        raise SystemExit(f"Rust UDP telemetry emitter anchor missing: {anchor}")
    block = udp_source[start:start + span]
    cursor = 0
    for token in tokens:
        found = block.find(token, cursor)
        if found < 0:
            raise SystemExit(
                f"Rust UDP telemetry field missing/out of order after {anchor}: {token}"
            )
        cursor = found + len(token)

def require_swift_udp_order(anchor, tokens, span=1200):
    start = swift_udp_source.find(anchor)
    if start < 0:
        raise SystemExit(f"Swift UDP staging emitter anchor missing: {anchor}")
    block = swift_udp_source[start:start + span]
    cursor = 0
    for token in tokens:
        found = block.find(token, cursor)
        if found < 0:
            raise SystemExit(
                f"Swift UDP staging field missing/out of order after {anchor}: {token}"
            )
        cursor = found + len(token)

require_order(
    "let countSummary =",
    (
        "tcp=", "udp=", "total=", "peak=", "softCap=", "hardCap=",
        "retiring=", "retirementOverlap=",
    ),
    1200,
)
require_literals(
    "let countSummary =",
    (
        '"tproxy live-flow counts tcp=\\(tcp) udp=\\(udp) total=\\(total) "',
        '"peak=\\(self.flowCountHighWater) softCap=\\(flowPressurePolicy.softCap) "',
        '"hardCap=\\(flowPressurePolicy.liveHardCap) retiring=\\(retiring) "',
        '"retirementOverlap=\\(retirementOverlap)"',
    ),
    1200,
)
require_order(
    "let pressureSummary =",
    (
        "pressure[triggers=", "scans=", "skipped=", "selected=", "evicted=",
        "spared=", "canceled=", "expired=", "pending=",
    ),
    1600,
)
require_literals(
    "let pressureSummary =",
    (
        '"pressure[triggers=\\(triggers - pressureStatsAtLastTick.triggers) "',
        '"scans=\\(scans - pressureStatsAtLastTick.scans) "',
        '"skipped=\\(pressureSkipsTotal - pressureStatsAtLastTick.skips) "',
        '"selected=\\(pressureSelectionsTotal - pressureStatsAtLastTick.selections) "',
        '"evicted=\\(pressureEvictedTotal - pressureStatsAtLastTick.evicted) "',
        '"spared=\\(pressureSparedTotal - pressureStatsAtLastTick.spared) "',
        '"canceled=\\(pressureCanceledTotal - pressureStatsAtLastTick.canceled) "',
        '"expired=\\(pressureExpiredTotal - pressureStatsAtLastTick.expired) "',
        '"pending=\\(pending)]"',
    ),
    1600,
)
require_order(
    '"flow pressure: occupancy \\(occupancy) over soft cap',
    ("occupancy", "soft cap", "selected", "idle flow(s)", "pending teardown"),
    500,
)
require_literals(
    '"flow pressure: occupancy \\(occupancy) over soft cap',
    (
        '"flow pressure: occupancy \\(occupancy) over soft cap \\(softCap); selected "',
        '"\\(victims.count) idle flow(s) toward low-water \\(lowWater) "',
        '"(\\(pendingCount) pending teardown)"',
    ),
    500,
)
require_order(
    '"flow pressure: occupancy \\(occupancy), soft cap',
    ("occupancy", "soft cap", "no ", "flow idle past"),
    500,
)
require_literals(
    '"flow pressure: occupancy \\(occupancy), soft cap',
    (
        '"flow pressure: occupancy \\(occupancy), soft cap \\(softCap), but no "',
        '"flow idle past \\(floorMs)ms floor; admitting without reap"',
    ),
    500,
)
require_order(
    '"flow pressure episode \\(outcome):',
    (
        "startEpochMs=", "durationMs=", "peakOccupancy=", "softCap=", "scans=",
        "skipped=", "selected=", "evicted=", "spared=", "canceled=", "expired=",
        "startEpochUs=",
    ),
    1000,
)
require_literals(
    '"flow pressure episode \\(outcome):',
    (
        '"flow pressure episode \\(outcome): startEpochMs=\\(startEpochMs) "',
        '"durationMs=\\(durationMs) "',
        '"peakOccupancy=\\(episode.peakOccupancy) "',
        '"softCap=\\(episode.softCap) "',
        '"scans=\\(episode.scans) skipped=\\(episode.skips) "',
        '"selected=\\(episode.selections) evicted=\\(episode.evicted) "',
        '"spared=\\(episode.spared) canceled=\\(episode.canceled) "',
        '"expired=\\(episode.expired) "',
        '"startEpochUs=\\(episode.startEpochUs)"',
    ),
    1000,
)

fixtures = (
    "tproxy live-flow counts tcp=1 udp=2 total=4 peak=4 softCap=10 "
    "hardCap=20 retiring=1 retirementOverlap=0 "
    "pressure[triggers=1 scans=1 skipped=0 selected=1 "
    "evicted=1 spared=0 canceled=0 expired=0 pending=0]",
    "flow pressure: occupancy 11 over soft cap 10; selected 1 idle flow(s) "
    "toward low-water 8 (1 pending teardown)",
    "flow pressure: occupancy 11, soft cap 10, but no flow idle past 100ms "
    "floor; admitting without reap",
    "flow pressure episode ended: startEpochMs=100 durationMs=10 "
    "peakOccupancy=11 softCap=10 scans=1 skipped=0 selected=1 evicted=1 "
    "spared=0 canceled=0 expired=0 startEpochUs=100000",
)
for fixture in fixtures:
    issue = pressure_telemetry_issue(fixture)
    if issue is not None:
        raise SystemExit(f"canonical Swift telemetry fixture rejected: {issue}")

require_udp_order(
    "fn record_drop",
    (
        "pressure", "cumulative_drops", "global_retained_bytes",
        "global_max_retained_bytes",
        '"UDP ingress pressure dropped datagram pressure=\\"{}\\" '
        'cumulative_drops={} global_retained_bytes={} '
        'global_max_retained_bytes={}"',
    ),
)
require_swift_udp_order(
    '"UDP Swift ingress staging dropped datagrams reason=\\"',
    (
        "sample.reason.rawValue", "cumulative_drop_events=",
        "cumulative_dropped_items=", "cumulative_dropped_bytes_lower_bound=",
        "generation_retained_items=", "generation_max_retained_items=",
        "generation_retained_bytes=", "generation_max_retained_bytes=",
    ),
)
if "guard reason.isRetryableCapacityPressure else { return nil }" not in swift_udp_staging_source:
    raise SystemExit("Swift UDP staging teardown drops are not suppressed")
for case_name, public_reason in (
    ("flowItems", "flow_items"),
    ("flowBytes", "flow_bytes"),
    ("generationItems", "generation_items"),
    ("generationBytes", "generation_bytes"),
):
    literal = f'case {case_name} = "{public_reason}"'
    if literal not in swift_udp_staging_source:
        raise SystemExit(f"Swift UDP staging pressure reason missing: {literal}")
require_udp_order(
    "fn record_recovery",
    (
        "pressure", "cumulative_resumptions", "global_retained_bytes",
        "global_max_retained_bytes",
        '"UDP ingress pressure resumed flow pressure=\\"{}\\" '
        'cumulative_resumptions={} global_retained_bytes={} '
        'global_max_retained_bytes={}"',
    ),
)
for reason in ("channel_count", "flow_bytes", "global_bytes"):
    if f'"{reason}"' not in udp_source:
        raise SystemExit(f"Rust UDP telemetry reason missing: {reason}")

udp_fixtures = (
    'UDP ingress pressure dropped datagram pressure="channel_count" '
    'cumulative_drops=1 global_retained_bytes=1 global_max_retained_bytes=2',
    'UDP ingress pressure resumed flow pressure="channel_count" '
    'cumulative_resumptions=1 global_retained_bytes=0 global_max_retained_bytes=2',
    'UDP Swift ingress staging dropped datagrams reason="flow_items" '
    'cumulative_drop_events=1 cumulative_dropped_items=1 '
    'cumulative_dropped_bytes_lower_bound=0 generation_retained_items=0 '
    'generation_max_retained_items=2 generation_retained_bytes=0 '
    'generation_max_retained_bytes=2',
    'UDP Swift ingress staging dropped datagrams reason="generation_items" '
    'cumulative_drop_events=2 cumulative_dropped_items=3 '
    'cumulative_dropped_bytes_lower_bound=0 generation_retained_items=2 '
    'generation_max_retained_items=2 generation_retained_bytes=0 '
    'generation_max_retained_bytes=2',
)
for fixture in udp_fixtures:
    issue = pressure_telemetry_issue(fixture)
    if issue is not None:
        raise SystemExit(f"canonical UDP telemetry fixture rejected: {issue}")
for redacted in (
    "UDP ingress pressure dropped datagram",
    'UDP ingress pressure resumed flow pressure="<private>"',
    'UDP Swift ingress staging dropped datagrams reason="<private>"',
):
    if pressure_telemetry_issue(redacted) is None:
        raise SystemExit("redacted UDP telemetry was not rejected")
PY
then
    echo "pressure telemetry emitters diverged from soak parser" >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "spec parity OK (dev/dist products, keychain names, TCP/UDP pressure telemetry schema)"
