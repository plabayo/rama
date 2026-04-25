import Foundation

struct DemoProxySettings: Equatable {
    var htmlBadgeEnabled = true
    var htmlBadgeLabel = "proxied by rama"
    var tcpConnectTimeoutMs: Int = 2000
    var excludeDomains = [
        "detectportal.firefox.com",
        "connectivitycheck.gstatic.com",
        "captive.apple.com",
    ]

    var isDefault: Bool {
        self == Self()
    }
}

struct ProxyEngineConfigPayload: Encodable {
    let htmlBadgeEnabled: Bool
    let htmlBadgeLabel: String
    let tcpConnectTimeoutMs: Int
    let excludeDomains: [String]
    let caCertPEM: String
    let caKeyPEM: String

    private enum CodingKeys: String, CodingKey {
        case htmlBadgeEnabled = "html_badge_enabled"
        case htmlBadgeLabel = "html_badge_label"
        case tcpConnectTimeoutMs = "tcp_connect_timeout_ms"
        case excludeDomains = "exclude_domains"
        case caCertPEM = "ca_cert_pem"
        case caKeyPEM = "ca_key_pem"
    }
}

struct MITMCASecrets: Equatable {
    let certPEM: String
    let keyPEM: String
}
