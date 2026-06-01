import Network
import XCTest

@testable import RamaAppleNEFFI
@testable import RamaAppleNetworkExtension

/// Pin `preferNoProxies = true` as the default and `allow_system_proxy`
/// as the opt-out — a regression in either polarity re-introduces the
/// stacked-proxy loop or breaks the intentional opt-in.
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
}
