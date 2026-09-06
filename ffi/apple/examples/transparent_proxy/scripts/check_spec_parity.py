"""Keep the pressure parser aligned with Swift/Rust telemetry emitters."""

from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts"))
from pressure_log import PRESSURE_GAUGE_SCHEMA_CURRENT, pressure_telemetry_issue

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
swift_provider_source = (
    root.parent.parent
    / "RamaAppleNetworkExtension/Sources/RamaAppleNetworkExtension/Provider/RamaTransparentProxyProvider.swift"
).read_text()
swift_udp_staging_source = (
    root.parent.parent
    / "RamaAppleNetworkExtension/Sources/RamaAppleNetworkExtension/Provider/UdpIngressStaging.swift"
).read_text()
writer_budget_source = (
    root.parent.parent
    / "RamaAppleNetworkExtension/Sources/RamaAppleNetworkExtension/Provider/Pump/WriterMemoryBudget.swift"
).read_text()
tproxy_demo_source = (root / "tproxy_rs/src/lib.rs").read_text()
tproxy_udp_source = (root / "tproxy_rs/src/udp.rs").read_text()
udp_probe_source = (root / "scripts/modern_udp_e2e_probe.py").read_text()

if PRESSURE_GAUGE_SCHEMA_CURRENT != 2:
    raise SystemExit("pressure parser current gauge schema version is not 2")

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

writer_fixture = (
    'writer memory pressure entered protocol="udp" reason="aggregate_bytes" '
    'retainedBytes=8192 maxBytes=8192 retainedItems=8 maxItems=8'
)
if pressure_telemetry_issue(writer_fixture) is not None:
    raise SystemExit("canonical writer-memory pressure fixture was rejected")
for token in (
    "writer memory pressure \\(transition.rawValue)", 'protocol=\\"\\(protocolName)\\"',
    'reason=\\"\\(reasonName)\\"', "retainedBytes=\\(retainedBytes)",
    "maxBytes=\\(maxBytes)", "retainedItems=\\(retainedItems)",
    "maxItems=\\(maxItems)",
):
    if token.replace("\\\\", "\\") not in writer_budget_source:
        raise SystemExit(f"writer-memory telemetry source diverged: {token}")

for missing in ("hardCap=", "retiring=", "retirementOverlap="):
    incomplete = fixtures[0].replace(
        next(token for token in fixtures[0].split() if token.startswith(missing)), ""
    )
    if pressure_telemetry_issue(incomplete) is None:
        raise SystemExit(f"current pressure gauge accepted without {missing}")

capacity_start = swift_udp_source.find("case .capacityRefused")
capacity_block = swift_udp_source[capacity_start:capacity_start + 1000]
public_end = capacity_block.find("let privateMetadata")
if capacity_start < 0 or public_end < 0:
    raise SystemExit("Swift UDP capacity-refusal logging block is missing")
if "appId" in capacity_block[:public_end] or "app=" in capacity_block[:public_end]:
    raise SystemExit("Swift UDP capacity-refusal public log contains app identity")
if 'let privateMetadata = "app=\\(appId)"' not in capacity_block:
    raise SystemExit("Swift UDP capacity-refusal app identity is not private metadata")
callback_start = swift_provider_source.find("internal static func finishUdpCallback")
callback_block = swift_provider_source[callback_start:callback_start + 1800]
if callback_start < 0:
    raise SystemExit("Swift UDP callback logging block is missing")
public_callback = (
    '"udp_callback=\\(callback.rawValue) rama_decision=\\(decision.rawValue) '
    'callback_return=\\(callbackReturn)",'
)
if public_callback not in callback_block:
    raise SystemExit("Swift UDP callback public decision fields diverged")
public_end = callback_block.find(public_callback) + len(public_callback)
if "source_app=" in callback_block[:public_end] or "sourceAppSigningIdentifier" in callback_block[
        callback_block.find("logDebug("):public_end
]:
    raise SystemExit("Swift UDP callback public log contains source-app identity")
if '"source_app=\\(sourceAppSigningIdentifier ?? "<missing>") "' not in callback_block:
    raise SystemExit("Swift UDP callback source-app identity is not private metadata")
# Rust's udp_policy_tests verify the exact diagnostic and missing-PID rejection.
# Source-token matching here would constrain equivalent error-handling syntax.
if "with_udp_channel_capacity(8)" in tproxy_demo_source:
    raise SystemExit("signed UDP pressure mode still changes the engine-wide channel ceiling")
for required in (
    "try_new_service(ctx.clone(), udp_policy_scope)",
    "should_hold_e2e_pressure_flow(",
    'b"rama-udp-e2e-pressure-v1 "',
    'Some("com.apple.python3")',
    "scope.is_e2e_active_at(now)",
    "Duration::from_secs(2)",
):
    if required not in tproxy_demo_source + tproxy_udp_source:
        raise SystemExit(f"signed UDP pressure hold scope diverged: {required}")
if 'PRESSURE_MARKER_PREFIX = b"rama-udp-e2e-pressure-v1 "' not in udp_probe_source:
    raise SystemExit("Python pressure probe marker diverged from Rust service marker")
if 'f"{address}:123".encode("ascii") + b"\\0"' not in udp_probe_source:
    raise SystemExit("Python pressure probe does not bind the marker to its exact endpoint")

require_udp_order(
    "fn record_drop",
    (
        "flow_id", "pressure", "cumulative_drops", "global_retained_bytes",
        "global_max_retained_bytes",
        '"UDP ingress pressure dropped datagram flow_id={} pressure=\\"{}\\" '
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
        "flow_id", "pressure", "cumulative_resumptions", "global_retained_bytes",
        "global_max_retained_bytes",
        '"UDP ingress pressure resumed flow flow_id={} pressure=\\"{}\\" '
        'cumulative_resumptions={} global_retained_bytes={} '
        'global_max_retained_bytes={}"',
    ),
)
for reason in ("channel_count", "flow_bytes", "global_bytes"):
    if f'"{reason}"' not in udp_source:
        raise SystemExit(f"Rust UDP telemetry reason missing: {reason}")

udp_fixtures = (
    'UDP ingress pressure dropped datagram flow_id=41 pressure="channel_count" '
    'cumulative_drops=1 global_retained_bytes=1 global_max_retained_bytes=2',
    'UDP ingress pressure resumed flow flow_id=41 pressure="channel_count" '
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
