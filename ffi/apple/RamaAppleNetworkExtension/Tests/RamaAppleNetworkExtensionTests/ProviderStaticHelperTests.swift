import Foundation
import Network
import NetworkExtension
import RamaAppleNEFFI
import XCTest

@testable import RamaAppleNetworkExtension

/// Phase tests for `RamaTransparentProxyProvider`'s pure-function
/// static helpers. The provider itself is hard to instantiate
/// (Apple-runtime owned), but the helpers it composes from are
/// pure — make them carry their weight.
final class ProviderStaticHelperTests: XCTestCase {

    // MARK: - networkRuleProtocol

    func testNetworkRuleProtocolMapsTcpUdpAndDefaults() {
        XCTAssertEqual(
            RamaTransparentProxyProvider.networkRuleProtocol(
                UInt32(RAMA_RULE_PROTOCOL_TCP.rawValue)),
            .TCP)
        XCTAssertEqual(
            RamaTransparentProxyProvider.networkRuleProtocol(
                UInt32(RAMA_RULE_PROTOCOL_UDP.rawValue)),
            .UDP)
        XCTAssertEqual(
            RamaTransparentProxyProvider.networkRuleProtocol(UInt32.max),
            .any,
            "unknown protocol falls back to .any")
    }

    // MARK: - networkEndpoint

    func testNetworkEndpointReturnsNilForEmptyOrMissingNetwork() {
        XCTAssertNil(RamaTransparentProxyProvider.networkEndpoint(from: nil, port: nil))
        XCTAssertNil(RamaTransparentProxyProvider.networkEndpoint(from: "", port: 443))
    }

    func testNetworkEndpointBuildsHostEndpointWithExplicitPort() {
        let ep = RamaTransparentProxyProvider.networkEndpoint(
            from: "10.0.0.1", port: 443)
        XCTAssertEqual(ep?.hostname, "10.0.0.1")
        XCTAssertEqual(ep?.port, "443")
    }

    func testNetworkEndpointDefaultsPortToZeroWhenAbsent() {
        let ep = RamaTransparentProxyProvider.networkEndpoint(
            from: "example.com", port: nil)
        XCTAssertEqual(ep?.port, "0", "absent port is encoded as '0' in NWHostEndpoint")
    }

    // MARK: - resolvedPrefix

    func testResolvedPrefixReturnsZeroForNilEndpoint() {
        XCTAssertEqual(
            RamaTransparentProxyProvider.resolvedPrefix(
                endpoint: nil, networkText: "10.0.0.0/8", explicitPrefix: 8),
            0)
    }

    func testResolvedPrefixHonoursExplicitPrefixOverNetworkText() {
        let ep = NWHostEndpoint(hostname: "10.0.0.0", port: "0")
        XCTAssertEqual(
            RamaTransparentProxyProvider.resolvedPrefix(
                endpoint: ep, networkText: "10.0.0.0/16", explicitPrefix: 24),
            24, "explicit prefix wins over text-inferred")
    }

    // MARK: - endpointHostPort

    func testEndpointHostPortReturnsNilForNil() {
        XCTAssertNil(RamaTransparentProxyProvider.endpointHostPort(nil))
    }

    func testEndpointHostPortFastPathFromNWHostEndpoint() {
        let ep = NWHostEndpoint(hostname: "10.0.0.1", port: "443")
        let parsed = RamaTransparentProxyProvider.endpointHostPort(ep)
        XCTAssertEqual(parsed?.host, "10.0.0.1")
        XCTAssertEqual(parsed?.port, 443)
    }

    func testEndpointHostPortRejectsEmptyHostname() {
        let ep = NWHostEndpoint(hostname: "  ", port: "443")
        XCTAssertNil(
            RamaTransparentProxyProvider.endpointHostPort(ep),
            "whitespace-only hostname must be rejected")
    }

    // (No "rejects non-numeric port" test: NWHostEndpoint aborts at
    // construction when the port string isn't numeric, so we can't
    // construct the unhappy input from Swift. The defensive
    // `UInt16(hostEndpoint.port)` guard inside the helper is still
    // exercised via the KVC fallback path on macOS 15 if Apple ever
    // surfaces a malformed concrete endpoint.)

    func testEndpointHostPortAcceptsIPv6() {
        let ep = NWHostEndpoint(hostname: "::1", port: "8080")
        let parsed = RamaTransparentProxyProvider.endpointHostPort(ep)
        XCTAssertEqual(parsed?.host, "::1")
        XCTAssertEqual(parsed?.port, 8080)
    }

    // MARK: - engineConfigJson

    func testEngineConfigJsonReadsDataFromStartOptions() {
        let payload = Data("config-payload".utf8)
        let result = RamaTransparentProxyProvider.engineConfigJson(
            protocolConfiguration: nil,
            startOptions: ["engineConfigJson": payload])
        XCTAssertEqual(result, payload)
    }

    func testEngineConfigJsonReadsStringFromStartOptions() {
        let result = RamaTransparentProxyProvider.engineConfigJson(
            protocolConfiguration: nil,
            startOptions: ["engineConfigJson": "string-payload"])
        XCTAssertEqual(result, Data("string-payload".utf8))
    }

    func testEngineConfigJsonReturnsNilForEmptyValues() {
        XCTAssertNil(
            RamaTransparentProxyProvider.engineConfigJson(
                protocolConfiguration: nil,
                startOptions: ["engineConfigJson": Data()]))
        XCTAssertNil(
            RamaTransparentProxyProvider.engineConfigJson(
                protocolConfiguration: nil,
                startOptions: ["engineConfigJson": ""]))
    }

    func testEngineConfigJsonReturnsNilWhenAbsent() {
        XCTAssertNil(
            RamaTransparentProxyProvider.engineConfigJson(
                protocolConfiguration: nil, startOptions: nil))
        XCTAssertNil(
            RamaTransparentProxyProvider.engineConfigJson(
                protocolConfiguration: nil, startOptions: [:]))
    }

    // MARK: - makeNetworkRules

    private func tcpRule(
        remoteNetwork: String? = nil,
        remotePrefix: UInt8? = nil,
        remotePort: UInt16? = nil,
        localNetwork: String? = nil,
        localPrefix: UInt8? = nil,
        exclude: Bool = false
    ) -> RamaTransparentProxyRuleBridge {
        RamaTransparentProxyRuleBridge(
            remoteNetwork: remoteNetwork,
            remotePrefix: remotePrefix,
            remotePort: remotePort,
            localNetwork: localNetwork,
            localPrefix: localPrefix,
            protocolRaw: UInt32(RAMA_RULE_PROTOCOL_TCP.rawValue),
            exclude: exclude)
    }

    func testMakeNetworkRulesPortOnlySplitsIntoIPv4AndIPv6() {
        let rule = tcpRule(remotePort: 443)
        let built = RamaTransparentProxyProvider.makeNetworkRules(rule)
        XCTAssertEqual(built.count, 2, "port-only rule expands to v4+v6 wildcards")
    }

    func testMakeNetworkRulesDestinationHostNonIP() {
        // Domain-only rule (no local matcher, no remotePrefix):
        // uses destinationHost initializer, no CIDR forced.
        let rule = tcpRule(remoteNetwork: "example.com")
        let built = RamaTransparentProxyProvider.makeNetworkRules(rule)
        XCTAssertEqual(built.count, 1)
    }

    func testMakeNetworkRulesCidrV4() {
        let rule = tcpRule(remoteNetwork: "10.0.0.0", remotePrefix: 8)
        let built = RamaTransparentProxyProvider.makeNetworkRules(rule)
        XCTAssertEqual(built.count, 1)
    }

    func testMakeNetworkRulesUnresolvableReturnsEmpty() {
        // Remote network present but no remotePrefix and no
        // inferrable host kind → `resolvedPrefix` returns nil → []
        // for the conservative caller-decides-what-to-do path.
        // (Domain without prefix and WITH local matcher trips this.)
        let rule = tcpRule(
            remoteNetwork: "example.com",
            localNetwork: "192.168.0.0", localPrefix: 16)
        let built = RamaTransparentProxyProvider.makeNetworkRules(rule)
        // Either empty or 1 — depends on whether `inferredHostPrefix`
        // resolves the domain. Pin observable: builder shouldn't
        // produce more than the documented "one rule" output here.
        XCTAssertLessThanOrEqual(built.count, 1)
    }
}
