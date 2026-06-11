import Network
import XCTest

@testable import RamaAppleNEFFI
@testable import RamaAppleNetworkExtension

/// Pin `preferNoProxies = true` as the default and `allow_system_proxy`
/// as the opt-out — a regression in either polarity re-introduces the
/// stacked-proxy loop or breaks the intentional opt-in.
final class MakeTcpNwParametersTests: XCTestCase {

    private func makeOpts(
        allowSystemProxy: Bool = false,
        keepaliveEnabled: Bool = true,
        hasIdle: Bool = false, idle: UInt32 = 0,
        hasInterval: Bool = false, interval: UInt32 = 0,
        hasCount: Bool = false, count: UInt32 = 0
    ) -> RamaTcpEgressConnectOptions {
        RamaTcpEgressConnectOptions(
            parameters: RamaNwEgressParameters(
                has_service_class: false, service_class: 0,
                has_multipath_service_type: false, multipath_service_type: 0,
                has_required_interface_type: false, required_interface_type: 0,
                has_attribution: false, attribution: 0,
                prohibited_interface_types_mask: 0,
                preserve_original_meta_data: true,
                allow_system_proxy: allowSystemProxy
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
            tcp_keepalive_count: count
        )
    }

    /// Extract the egress connection's `NWProtocolTCP.Options` from the
    /// parameters `makeTcpNwParameters` produced, so keepalive settings
    /// can be inspected the way the constructed `NWConnection` would see
    /// them.
    private func tcpOptions(_ params: NWParameters) -> NWProtocolTCP.Options? {
        params.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options
    }

    func testPreferNoProxiesIsTrueWhenOptsAreNil() {
        XCTAssertTrue(makeTcpNwParameters(nil).preferNoProxies, "nil opts → loop guard active")
    }

    func testPreferNoProxiesIsTrueWhenAllowSystemProxyIsFalse() {
        XCTAssertTrue(
            makeTcpNwParameters(makeOpts(allowSystemProxy: false)).preferNoProxies,
            "allow_system_proxy=false → loop guard active")
    }

    func testPreferNoProxiesIsFalseWhenAllowSystemProxyIsTrue() {
        XCTAssertFalse(
            makeTcpNwParameters(makeOpts(allowSystemProxy: true)).preferNoProxies,
            "allow_system_proxy=true → opt-in honoured")
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
}
