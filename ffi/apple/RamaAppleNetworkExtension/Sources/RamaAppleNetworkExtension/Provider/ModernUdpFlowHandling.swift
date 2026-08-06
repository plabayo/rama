import Foundation
import Network
import NetworkExtension

extension RamaTransparentProxyProvider {
    /// Convert the modern, public `Network.NWEndpoint` representation without
    /// KVC or assumptions about private concrete endpoint classes.
    internal static func networkEndpointHostPort(
        _ endpoint: Network.NWEndpoint,
        logDebug: (String) -> Void = { RamaLog.debug($0) }
    ) -> EndpointHostPort? {
        switch endpoint {
        case .hostPort(let host, let port):
            let rawHost: String
            switch host {
            case .name(let hostname, _):
                rawHost = hostname
            case .ipv4(let address):
                rawHost = address.debugDescription
            case .ipv6(let address):
                rawHost = address.debugDescription
            @unknown default:
                logDebug("udp initial remote endpoint has an unsupported host variant")
                return nil
            }

            let normalizedHost = rawHost.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !normalizedHost.isEmpty else {
                logDebug("udp initial remote endpoint has an empty host")
                return nil
            }
            return EndpointHostPort(host: normalizedHost, port: port.rawValue)

        case .service:
            logDebug("udp initial remote endpoint variant=service is unsupported")
            return nil
        case .unix:
            logDebug("udp initial remote endpoint variant=unix is unsupported")
            return nil
        case .url:
            logDebug("udp initial remote endpoint variant=url is unsupported")
            return nil
        case .opaque:
            logDebug("udp initial remote endpoint variant=opaque is unsupported")
            return nil
        @unknown default:
            logDebug("udp initial remote endpoint has an unknown unsupported variant")
            return nil
        }
    }

    /// Type-erased bridge used by helpers that also accept legacy endpoints.
    /// A modern endpoint always takes the typed conversion above and never KVC.
    internal static func networkEndpointHostPortFromAny(_ endpoint: Any) -> EndpointHostPort? {
        guard let endpoint = endpoint as? Network.NWEndpoint else { return nil }
        return networkEndpointHostPort(endpoint)
    }
}

// NETransparentProxyProvider inherits its UDP flow-handling surface from
// NEAppProxyProvider. Starting with macOS 15, Swift providers must adopt
// NEAppProxyUDPFlowHandling to receive the initial remote Network.NWEndpoint.
//
// Apple DTS explicitly confirms that this applies to transparent proxies:
// https://developer.apple.com/forums/thread/795236
//
// API documentation:
// https://developer.apple.com/documentation/networkextension/neappproxyudpflowhandling
// https://developer.apple.com/documentation/networkextension/neappproxyudpflowhandling/handlenewudpflow(_:initialremoteflowendpoint:)
//
// The endpoint must come from this callback argument: NEAppProxyUDPFlow does
// not expose its intended remote destination through a public modern property.
// Apple's declarations are inconsistent here: the modern protocol method says
// `false` terminates, while NETransparentProxyProvider documents pass-through
// exceptions only for `handleNewFlow` and the legacy UDP callback. A signed
// macOS 26 L4 E2E has verified that `false` from this modern callback does pass
// the flow through for a transparent provider. Keep that live test as the
// compatibility guard rather than treating the inherited method wording as a
// reliable statement of transparent-provider behavior.
@available(macOS 15.0, *)
extension RamaTransparentProxyProvider: NEAppProxyUDPFlowHandling {
    public func handleNewUDPFlow(
        _ flow: NEAppProxyUDPFlow,
        initialRemoteFlowEndpoint remoteEndpoint: Network.NWEndpoint
    ) -> Bool {
        handleNewUdpFlow(
            flow,
            callback: .modern,
            remoteEndpoint: Self.networkEndpointHostPort(remoteEndpoint),
            localEndpoint: Self.udpLocalEndpoint(flow: flow)
        )
    }
}
