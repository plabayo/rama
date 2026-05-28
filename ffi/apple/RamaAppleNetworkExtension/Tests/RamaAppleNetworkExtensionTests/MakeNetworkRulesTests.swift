import Foundation
import Network
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// Cardinality tests for
/// `RamaTransparentProxyProvider.makeNetworkRules`.
///
/// `NENetworkRule`'s read accessors aren't exposed to Swift,
/// so the assertions are limited to the number of emitted
/// rules. That is enough to pin the load-bearing audit
/// finding: a port-only rule MUST expand to two entries
/// (one IPv4 wildcard, one IPv6 wildcard) so the port
/// constraint isn't silently dropped. The byte-level content
/// of each NENetworkRule is covered by the Rust-side FFI
/// round-trip test.
final class MakeNetworkRulesTests: XCTestCase {

    private func bridge(
        remoteNetwork: String? = nil,
        remotePrefix: UInt8? = nil,
        remotePort: UInt16? = nil,
        localNetwork: String? = nil,
        localPrefix: UInt8? = nil,
        protocolRaw: UInt32 = 0,
        exclude: Bool = false
    ) -> RamaTransparentProxyRuleBridge {
        RamaTransparentProxyRuleBridge(
            remoteNetwork: remoteNetwork,
            remotePrefix: remotePrefix,
            remotePort: remotePort,
            localNetwork: localNetwork,
            localPrefix: localPrefix,
            protocolRaw: protocolRaw,
            exclude: exclude
        )
    }

    func testWildcardRuleEmitsOne() {
        XCTAssertEqual(
            RamaTransparentProxyProvider.makeNetworkRules(bridge()).count,
            1
        )
    }

    func testHostOnlyRuleEmitsOne() {
        XCTAssertEqual(
            RamaTransparentProxyProvider.makeNetworkRules(
                bridge(remoteNetwork: "example.com")
            ).count,
            1
        )
    }

    func testHostWithPortEmitsOne() {
        XCTAssertEqual(
            RamaTransparentProxyProvider.makeNetworkRules(
                bridge(remoteNetwork: "example.com", remotePort: 443)
            ).count,
            1
        )
    }

    func testNetworkPrefixRuleEmitsOne() {
        XCTAssertEqual(
            RamaTransparentProxyProvider.makeNetworkRules(
                bridge(remoteNetwork: "10.0.0.0", remotePrefix: 8)
            ).count,
            1
        )
    }

    /// Audit finding #2 regression: a port-only rule must
    /// emit two `NENetworkRule`s (v4 + v6 wildcards). The
    /// pre-fix Swift code returned a single wildcard rule
    /// with the port silently dropped — turning
    /// `exclude port 443` into `exclude everything`.
    func testPortOnlyRuleEmitsTwoRules() {
        XCTAssertEqual(
            RamaTransparentProxyProvider.makeNetworkRules(
                bridge(remotePort: 443)
            ).count,
            2,
            "port-only must emit v4 + v6 wildcards so the port reaches Apple"
        )
    }

    func testPortOnlyRuleWithLocalNetworkEmitsTwo() {
        XCTAssertEqual(
            RamaTransparentProxyProvider.makeNetworkRules(
                bridge(
                    remotePort: 443,
                    localNetwork: "10.0.0.0",
                    localPrefix: 8
                )
            ).count,
            2
        )
    }
}
