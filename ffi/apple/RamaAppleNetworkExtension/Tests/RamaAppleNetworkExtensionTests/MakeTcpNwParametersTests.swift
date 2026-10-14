import Darwin
import Network
import RamaAppleNetwork
import XCTest

@testable import RamaAppleNEFFI
@testable import RamaAppleNetworkExtension

/// Pin `allow_proxy = true` as the default and `allow_proxy`
/// as the opt-out — a regression in either polarity re-introduces the
/// stacked-proxy loop or breaks the intentional opt-in.
final class MakeTcpNwParametersTests: XCTestCase {

    private func makeOpts(
        allowProxy: Bool = false,
        keepaliveEnabled: Bool = true,
        hasIdle: Bool = false, idle: UInt32 = 0,
        hasInterval: Bool = false, interval: UInt32 = 0,
        hasCount: Bool = false, count: UInt32 = 0,
        noDelay: Bool = true,
        hasNoPush: Bool = false, noPush: Bool = false,
        hasNoOptions: Bool = false, noOptions: Bool = false,
        hasRetransmitFinDrop: Bool = false, retransmitFinDrop: Bool = false,
        hasDisableAckStretching: Bool = false, disableAckStretching: Bool = false,
        hasEnableFastOpen: Bool = false, enableFastOpen: Bool = false,
        hasDisableEcn: Bool = false, disableEcn: Bool = false,
        hasMaximumSegmentSize: Bool = false, maximumSegmentSize: UInt32 = 0,
        hasConnectionDropTime: Bool = false, connectionDropTime: UInt32 = 0,
        hasPersistTimeout: Bool = false, persistTimeout: UInt32 = 0
    ) -> RamaTcpEgressConnectOptions {
        RamaTcpEgressConnectOptions(
            parameters: RamaNwEgressParameters(
                has_service_class: false, service_class: 0,
                has_multipath_service_type: false, multipath_service_type: 0,
                has_required_interface_type: false, required_interface_type: 0,
                has_attribution: false, attribution: 0,
                prohibited_interface_types_mask: 0,
                preserve_original_meta_data: true,
                allow_proxy: allowProxy
            ),
            has_connect_timeout_ms: false,
            connect_timeout_ms: 0,
            has_linger_close_ms: false,
            linger_close_ms: 0,
            has_egress_eof_grace_ms: false,
            egress_eof_grace_ms: 0,
            tcp_keepalive_enabled: keepaliveEnabled,
            has_tcp_keepalive_idle_secs: hasIdle,
            tcp_keepalive_idle_secs: idle,
            has_tcp_keepalive_interval_secs: hasInterval,
            tcp_keepalive_interval_secs: interval,
            has_tcp_keepalive_count: hasCount,
            tcp_keepalive_count: count,
            tcp_no_delay: noDelay,
            has_tcp_no_push: hasNoPush,
            tcp_no_push: noPush,
            has_tcp_no_options: hasNoOptions,
            tcp_no_options: noOptions,
            has_tcp_retransmit_fin_drop: hasRetransmitFinDrop,
            tcp_retransmit_fin_drop: retransmitFinDrop,
            has_tcp_disable_ack_stretching: hasDisableAckStretching,
            tcp_disable_ack_stretching: disableAckStretching,
            has_tcp_enable_fast_open: hasEnableFastOpen,
            tcp_enable_fast_open: enableFastOpen,
            has_tcp_disable_ecn: hasDisableEcn,
            tcp_disable_ecn: disableEcn,
            has_tcp_maximum_segment_size: hasMaximumSegmentSize,
            tcp_maximum_segment_size: maximumSegmentSize,
            has_tcp_connection_drop_time_secs: hasConnectionDropTime,
            tcp_connection_drop_time_secs: connectionDropTime,
            has_tcp_persist_timeout_secs: hasPersistTimeout,
            tcp_persist_timeout_secs: persistTimeout
        )
    }

    private func tcpOptions(_ params: TcpNwParameters) -> NativeTcpOptions? {
        let stack = nw_parameters_copy_default_protocol_stack(params.native)
        return nw_protocol_stack_copy_transport_protocol(stack).map(NativeTcpOptions.init)
    }

    func testPreferNoProxiesIsTrueWhenOptsAreNil() {
        XCTAssertTrue(
            nw_parameters_get_prefer_no_proxy(makeTcpNwParameters(nil).native),
            "nil opts → loop guard active")
    }

    func testPreferNoProxiesIsTrueWhenAllowProxyIsFalse() {
        XCTAssertTrue(
            nw_parameters_get_prefer_no_proxy(
                makeTcpNwParameters(makeOpts(allowProxy: false)).native),
            "allow_proxy=false → loop guard active")
    }

    func testPreferNoProxiesIsFalseWhenAllowProxyIsTrue() {
        XCTAssertFalse(
            nw_parameters_get_prefer_no_proxy(
                makeTcpNwParameters(makeOpts(allowProxy: true)).native),
            "allow_proxy=true → opt-in honoured")
    }

    // MARK: - Keepalive

    /// nil opts (handler supplied none) → keepalive ON with the Swift
    /// defaults. This is the load-bearing default for the sleep/wake
    /// self-heal: a silently-dead egress fails its probes → `.failed` →
    /// the existing reaper tears it down.
    func testKeepaliveDefaultsOnWhenOptsAreNil() {
        let tcp = tcpOptions(makeTcpNwParameters(nil))
        XCTAssertNotNil(tcp)
        XCTAssertTrue(tcp?.enableKeepalive ?? false, "nil opts → keepalive ON by default")
        XCTAssertEqual(tcp?.keepaliveIdle, defaultTcpKeepaliveIdleSec)
        XCTAssertEqual(tcp?.keepaliveInterval, defaultTcpKeepaliveIntervalSec)
        XCTAssertEqual(tcp?.keepaliveCount, defaultTcpKeepaliveCount)
    }

    /// opts present with `tcp_keepalive_enabled = true` and no timing
    /// overrides → ON with the Swift defaults.
    func testKeepaliveOnUsesDefaultsWhenTimingsUnset() {
        let tcp = tcpOptions(makeTcpNwParameters(makeOpts(keepaliveEnabled: true)))
        XCTAssertTrue(tcp?.enableKeepalive ?? false)
        XCTAssertEqual(tcp?.keepaliveIdle, defaultTcpKeepaliveIdleSec)
        XCTAssertEqual(tcp?.keepaliveInterval, defaultTcpKeepaliveIntervalSec)
        XCTAssertEqual(tcp?.keepaliveCount, defaultTcpKeepaliveCount)
    }

    /// Opt-out: `tcp_keepalive_enabled = false` disables keepalive.
    func testKeepaliveOptOutDisablesKeepalive() {
        let tcp = tcpOptions(makeTcpNwParameters(makeOpts(keepaliveEnabled: false)))
        XCTAssertNotNil(tcp)
        XCTAssertFalse(tcp?.enableKeepalive ?? true, "tcp_keepalive_enabled=false → keepalive OFF")
    }

    /// Tuning: each timing override propagates to its own
    /// `NWProtocolTCP.Options` field (distinct values catch crossed wires).
    func testKeepaliveTimingOverridesAreApplied() {
        let tcp = tcpOptions(
            makeTcpNwParameters(
                makeOpts(
                    keepaliveEnabled: true,
                    hasIdle: true, idle: 23,
                    hasInterval: true, interval: 8,
                    hasCount: true, count: 5
                )))
        XCTAssertTrue(tcp?.enableKeepalive ?? false)
        XCTAssertEqual(tcp?.keepaliveIdle, 23)
        XCTAssertEqual(tcp?.keepaliveInterval, 8)
        XCTAssertEqual(tcp?.keepaliveCount, 5)
    }

    /// A partial override (only idle set) keeps the others at the Swift
    /// defaults — each knob falls back independently.
    func testKeepalivePartialOverrideKeepsOtherDefaults() {
        let tcp = tcpOptions(
            makeTcpNwParameters(makeOpts(keepaliveEnabled: true, hasIdle: true, idle: 42)))
        XCTAssertEqual(tcp?.keepaliveIdle, 42)
        XCTAssertEqual(tcp?.keepaliveInterval, defaultTcpKeepaliveIntervalSec)
        XCTAssertEqual(tcp?.keepaliveCount, defaultTcpKeepaliveCount)
    }

    /// Keep writer stall tolerance independent from the existing silent-peer
    /// detection policy. A writer with no outstanding payload has no watchdog.
    func testKeepalivePreservesSilentPeerDetectionDefaults() throws {
        for opts in [nil, makeOpts(keepaliveEnabled: true)] {
            let tcp = try XCTUnwrap(tcpOptions(makeTcpNwParameters(opts)))
            XCTAssertEqual(tcp.keepaliveIdle, 15)
            XCTAssertEqual(tcp.keepaliveInterval, 5)
            XCTAssertEqual(tcp.keepaliveCount, 3)
        }
    }

    // MARK: - TCP tuning

    /// nil opts (handler supplied none) → noDelay ON. This is the
    /// load-bearing default for relay TTFB: on a claimed flow the egress
    /// connection is the only Nagle decision in the path.
    func testNoDelayDefaultsOnWhenOptsAreNil() {
        let tcp = tcpOptions(makeTcpNwParameters(nil))
        XCTAssertEqual(tcp?.noDelay, true, "nil opts → TCP_NODELAY ON by default")
    }

    /// Opt-out: `tcp_no_delay = false` re-enables Nagle.
    func testNoDelayOptOutIsApplied() {
        let tcp = tcpOptions(makeTcpNwParameters(makeOpts(noDelay: false)))
        XCTAssertEqual(tcp?.noDelay, false, "tcp_no_delay=false → Nagle restored")
    }

    /// Unset tuning fields (`has_*` false) must leave the
    /// Network.framework defaults untouched — the wire values are
    /// deliberately non-default so a `has_` check that reads the value
    /// anyway fails loudly. (noDelay is exempt: it has no `has_` flag and
    /// is always applied.)
    func testTuningUnsetLeavesFrameworkDefaults() {
        let stack = nw_parameters_copy_default_protocol_stack(rama_nw_tcp_parameters())
        let fresh = NativeTcpOptions(nw_protocol_stack_copy_transport_protocol(stack)!)
        let tcp = tcpOptions(
            makeTcpNwParameters(
                makeOpts(
                    noPush: true, noOptions: true,
                    retransmitFinDrop: true, disableAckStretching: true,
                    enableFastOpen: true, disableEcn: true,
                    maximumSegmentSize: 1200, connectionDropTime: 9, persistTimeout: 9
                )))
        XCTAssertEqual(tcp?.noPush, fresh.noPush)
        XCTAssertEqual(tcp?.noOptions, fresh.noOptions)
        XCTAssertEqual(tcp?.retransmitFinDrop, fresh.retransmitFinDrop)
        XCTAssertEqual(tcp?.disableAckStretching, fresh.disableAckStretching)
        XCTAssertEqual(tcp?.enableFastOpen, fresh.enableFastOpen)
        XCTAssertEqual(tcp?.disableECN, fresh.disableECN)
        XCTAssertEqual(tcp?.maximumSegmentSize, fresh.maximumSegmentSize)
        XCTAssertEqual(tcp?.connectionDropTime, fresh.connectionDropTime)
        XCTAssertEqual(tcp?.persistTimeout, fresh.persistTimeout)
    }

    /// Each set flag propagates to its own `NWProtocolTCP.Options`
    /// field (distinct values catch crossed wires).
    func testTuningOverridesAreApplied() {
        let tcp = tcpOptions(
            makeTcpNwParameters(
                makeOpts(
                    noDelay: true,
                    hasNoPush: true, noPush: true,
                    hasNoOptions: true, noOptions: true,
                    hasRetransmitFinDrop: true, retransmitFinDrop: true,
                    hasDisableAckStretching: true, disableAckStretching: true,
                    hasEnableFastOpen: true, enableFastOpen: true,
                    hasDisableEcn: true, disableEcn: true,
                    hasMaximumSegmentSize: true, maximumSegmentSize: 1360,
                    hasConnectionDropTime: true, connectionDropTime: 17,
                    hasPersistTimeout: true, persistTimeout: 29
                )))
        XCTAssertEqual(tcp?.noDelay, true)
        XCTAssertEqual(tcp?.noPush, true)
        XCTAssertEqual(tcp?.noOptions, true)
        XCTAssertEqual(tcp?.retransmitFinDrop, true)
        XCTAssertEqual(tcp?.disableAckStretching, true)
        XCTAssertEqual(tcp?.enableFastOpen, true)
        XCTAssertEqual(tcp?.disableECN, true)
        XCTAssertEqual(tcp?.maximumSegmentSize, 1360)
        XCTAssertEqual(tcp?.connectionDropTime, 17)
        XCTAssertEqual(tcp?.persistTimeout, 29)
    }

    /// Explicit `false` is distinct from unset: a handler must be able
    /// to force a knob OFF even if the framework default ever flips.
    func testTuningExplicitFalseIsApplied() {
        let tcp = tcpOptions(
            makeTcpNwParameters(
                makeOpts(hasEnableFastOpen: true, enableFastOpen: false)))
        XCTAssertEqual(tcp?.enableFastOpen, false)
    }
}

// Test-only readers for the C options. They exercise the actual native parameters,
// rather than maintaining a second Swift NWParameters implementation in production.
private struct NativeTcpOptions {
    let native: nw_protocol_options_t
    init(_ native: nw_protocol_options_t) { self.native = native }
    private func bool(_ suffix: String) -> Bool {
        guard
            let symbol = dlsym(
                UnsafeMutableRawPointer(bitPattern: -2), "nw_tcp_options_get_" + suffix)
        else {
            XCTFail("missing TCP getter: \(suffix)")
            return false
        }
        return unsafeBitCast(symbol, to: (@convention(c) (nw_protocol_options_t) -> Bool).self)(
            native)
    }
    private func integer(_ suffix: String) -> Int {
        guard
            let symbol = dlsym(
                UnsafeMutableRawPointer(bitPattern: -2), "nw_tcp_options_get_" + suffix)
        else {
            XCTFail("missing TCP getter: \(suffix)")
            return 0
        }
        return Int(
            unsafeBitCast(symbol, to: (@convention(c) (nw_protocol_options_t) -> UInt32).self)(
                native))
    }
    var enableKeepalive: Bool { bool("enable_keepalive") }
    var noDelay: Bool { bool("no_delay") }
    var noPush: Bool { bool("no_push") }
    var noOptions: Bool { bool("no_options") }
    var retransmitFinDrop: Bool { bool("retransmit_fin_drop") }
    var disableAckStretching: Bool { bool("disable_ack_stretching") }
    var enableFastOpen: Bool { bool("enable_fast_open") }
    var disableECN: Bool { bool("disable_ecn") }
    var keepaliveIdle: Int { integer("keepalive_idle_time") }
    var keepaliveInterval: Int { integer("keepalive_interval") }
    var keepaliveCount: Int { integer("keepalive_count") }
    var maximumSegmentSize: Int { integer("maximum_segment_size") }
    var connectionDropTime: Int { integer("retransmit_connection_drop_time") }
    var persistTimeout: Int { integer("persist_timeout") }
}
