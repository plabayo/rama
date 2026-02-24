import Foundation
import NetworkExtension

enum RamaTransparentProxyConfig {
    static func loadConfigJSON() -> String {
        if let s = loadFromAppGroup() {
            return s
        }
        return "{}"
    }

    private static func loadFromAppGroup() -> String? {
        let appGroupId = ProcessInfo.processInfo.environment["RAMA_APP_GROUP_ID"] ?? ""
        if appGroupId.isEmpty { return nil }

        guard
            let containerURL = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: appGroupId)
        else {
            return nil
        }

        let url = containerURL.appendingPathComponent("rama_tproxy_config.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func tcpMetaJSON(flow: NEAppProxyTCPFlow) -> String {
        metaJSON(
            protocolName: "tcp",
            remoteEndpoint: flow.remoteEndpoint,
            localEndpoint: nil
        )
    }

    static func udpMetaJSON(remoteEndpoint: NWEndpoint?) -> String {
        metaJSON(
            protocolName: "udp",
            remoteEndpoint: remoteEndpoint,
            localEndpoint: nil
        )
    }

    static func remoteEndpointString(flow: NEAppProxyTCPFlow) -> String? {
        let s = endpointString(flow.remoteEndpoint)
        return s.isEmpty ? nil : s
    }

    private static func metaJSON(
        protocolName: String,
        remoteEndpoint: NWEndpoint?,
        localEndpoint: NWEndpoint?
    ) -> String {
        let dict: [String: Any] = [
            "protocol": protocolName,
            "remote_endpoint": endpointString(remoteEndpoint),
            "local_endpoint": endpointString(localEndpoint),
            "source_app_signing_identifier": "",
            "source_app_path": "",
        ]
        if let data = try? JSONSerialization.data(withJSONObject: dict),
            let s = String(data: data, encoding: .utf8)
        {
            return s
        }
        return "{}"
    }

    private static func endpointString(_ endpoint: NWEndpoint?) -> String {
        guard let endpoint else { return "" }
        return "\(endpoint)"
    }
}
