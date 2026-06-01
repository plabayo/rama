import Network
import XCTest

@testable import RamaAppleNEFFI
@testable import RamaAppleNetworkExtension

/// Pin the `preferNoProxies` default + opt-out wiring on
/// `makeTcpNwParameters`.
///
/// `preferNoProxies` is the framework-level guard against the
/// stacked-proxy loop where a system / PAC HTTP/SOCKS proxy
/// (Charles, Proxyman, BurpSuite, corporate PAC, antivirus MITM, …)
/// would otherwise re-route our egress `NWConnection` back through
/// itself, the proxy re-emits, and we intercept again. Three cases
/// must hold:
///
///   1. `opts == nil` → default to `preferNoProxies = true`
///      (`allow_system_proxy` defaults to `false` Rust-side, but
///      Swift may not see opts at all).
///   2. `opts != nil`, `allow_system_proxy == false` → still
///      `preferNoProxies = true`.
///   3. `opts != nil`, `allow_system_proxy == true` → opt-out:
///      `preferNoProxies = false`.
///
/// A regression that hard-codes either polarity would silently
/// either re-introduce the loop (case 1/2 → false) or break
/// nested-debugging deployments that intentionally opted in
/// (case 3 → true). This test catches both.
final class MakeTcpNwParametersTests: XCTestCase {

    private func makeOpts(allowSystemProxy: Bool) -> RamaTcpEgressConnectOptions {
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
            egress_eof_grace_ms: 0
        )
    }

    func testPreferNoProxiesIsTrueWhenOptsAreNil() {
        let params = makeTcpNwParameters(nil)
        XCTAssertTrue(
            params.preferNoProxies,
            "nil opts must default to preferNoProxies = true so the system-proxy loop guard is in effect")
    }

    func testPreferNoProxiesIsTrueWhenAllowSystemProxyIsFalse() {
        let params = makeTcpNwParameters(makeOpts(allowSystemProxy: false))
        XCTAssertTrue(
            params.preferNoProxies,
            "allow_system_proxy = false → preferNoProxies must be true (loop guard active)")
    }

    func testPreferNoProxiesIsFalseWhenAllowSystemProxyIsTrue() {
        let params = makeTcpNwParameters(makeOpts(allowSystemProxy: true))
        XCTAssertFalse(
            params.preferNoProxies,
            "allow_system_proxy = true → preferNoProxies must be false (engine intentionally opted in to the system proxy)")
    }
}
