import Network
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

final class ModernUdpFlowHandlingTests: XCTestCase {

    func testConvertsIPv4HostAndPort() throws {
        let address = try XCTUnwrap(IPv4Address("192.0.2.7"))
        let port = try XCTUnwrap(Network.NWEndpoint.Port(rawValue: 8443))
        let endpoint = Network.NWEndpoint.hostPort(host: .ipv4(address), port: port)

        let converted = RamaTransparentProxyProvider.networkEndpointHostPort(endpoint)

        XCTAssertEqual(converted, EndpointHostPort(host: "192.0.2.7", port: 8443))
    }

    func testConvertsIPv6HostAndPort() throws {
        let address = try XCTUnwrap(IPv6Address("2001:db8::7"))
        let port = try XCTUnwrap(Network.NWEndpoint.Port(rawValue: 443))
        let endpoint = Network.NWEndpoint.hostPort(host: .ipv6(address), port: port)

        let converted = RamaTransparentProxyProvider.networkEndpointHostPort(endpoint)

        XCTAssertEqual(converted, EndpointHostPort(host: "2001:db8::7", port: 443))
        XCTAssertEqual(converted?.description, "[2001:db8::7]:443")
    }

    func testConvertsHostnameAndPort() throws {
        let port = try XCTUnwrap(Network.NWEndpoint.Port(rawValue: 5353))
        let endpoint = Network.NWEndpoint.hostPort(host: .name("udp.example.test", nil), port: port)

        let converted = RamaTransparentProxyProvider.networkEndpointHostPort(endpoint)

        XCTAssertEqual(converted, EndpointHostPort(host: "udp.example.test", port: 5353))
    }

    func testUnsupportedEndpointIsSafeAndDiagnostic() {
        var messages: [String] = []

        let converted = RamaTransparentProxyProvider.networkEndpointHostPort(
            .unix(path: "/tmp/rama-udp-test.sock"),
            logDebug: { messages.append($0) }
        )

        XCTAssertNil(converted)
        XCTAssertEqual(messages, ["udp initial remote endpoint variant=unix is unsupported"])
    }

    func testConvertedDestinationPropagatesIntoUdpMetadata() {
        let remote = EndpointHostPort(host: "203.0.113.42", port: 443)
        let local = EndpointHostPort(host: "192.0.2.10", port: 61234)

        let meta = RamaTransparentProxyProvider.udpMeta(
            flow: nil,
            remoteEndpoint: remote,
            localEndpoint: local
        )

        XCTAssertEqual(meta.protocolRaw, 2, "UDP protocol discriminant must be preserved")
        XCTAssertEqual(meta.remoteHost, "203.0.113.42")
        XCTAssertEqual(meta.remotePort, 443)
        XCTAssertEqual(meta.localHost, "192.0.2.10")
        XCTAssertEqual(meta.localPort, 61234)
    }

    func testDecisionMappingIsExact() {
        XCTAssertFalse(UdpFlowHandlingDecision.passthrough.callbackReturnValue)
        XCTAssertTrue(UdpFlowHandlingDecision.intercept.callbackReturnValue)
        XCTAssertTrue(UdpFlowHandlingDecision.blocked.callbackReturnValue)
    }

    func testModernAndLegacyCallbacksUseSameDecisionAndLogMapping() {
        let endpoint = EndpointHostPort(host: "203.0.113.9", port: 443)

        for callback in [UdpFlowCallbackSource.modern, .legacy] {
            var publicMessages: [String] = []
            var privateMetadata: [String] = []
            let callbackReturn = RamaTransparentProxyProvider.finishUdpCallback(
                callback: callback,
                remoteEndpoint: endpoint,
                sourceAppSigningIdentifier: "com.example.client",
                decision: .passthrough,
                logDebug: { publicMessage, metadata in
                    publicMessages.append(publicMessage)
                    privateMetadata.append(metadata)
                }
            )

            XCTAssertFalse(callbackReturn)
            XCTAssertEqual(publicMessages.count, 1)
            XCTAssertEqual(privateMetadata.count, 1)
            XCTAssertTrue(publicMessages[0].contains("udp_callback=\(callback.rawValue)"))
            XCTAssertTrue(publicMessages[0].contains("rama_decision=passthrough"))
            XCTAssertTrue(publicMessages[0].contains("callback_return=false"))
            // Destination stays private; the source app is public, like the
            // TCP shed lines and the tick's `topApps=`.
            XCTAssertFalse(publicMessages[0].contains("203.0.113.9"))
            XCTAssertTrue(publicMessages[0].contains("source_app=com.example.client"))
            XCTAssertTrue(privateMetadata[0].contains("initial_remote=203.0.113.9:443"))
            XCTAssertFalse(privateMetadata[0].contains("com.example.client"))
        }
    }

    @available(macOS 15.0, *)
    func testProviderDeclaresModernUdpFlowHandlingConformance() {
        let providerType: any NEAppProxyUDPFlowHandling.Type =
            RamaTransparentProxyProvider.self
        XCTAssertTrue(providerType == RamaTransparentProxyProvider.self)
    }
}
