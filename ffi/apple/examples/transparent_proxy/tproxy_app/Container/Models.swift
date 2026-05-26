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
    /// When `true` the sysext MITM relay writes session keys to
    /// `<storage_dir>/sslkeylog.txt` so Wireshark can decrypt the
    /// egress (and mirrored-ingress) TLS traffic. Off by default;
    /// flipping it while the proxy is active requires a provider
    /// restart (the GUI handles the prompt + restart).
    var tlsKeylogEnabled: Bool = false

    var isDefault: Bool {
        self == Self()
    }
}

struct ProxyEngineConfigPayload: Encodable {
    let htmlBadgeEnabled: Bool
    let htmlBadgeLabel: String
    let tcpConnectTimeoutMs: Int
    let excludeDomains: [String]
    let xpcServiceName: String
    /// Bundle ID of the container app, forwarded to the sysext so it can pin
    /// the XPC listener via `PeerSecurityRequirement::TeamIdentity(Some(...))`
    /// — same Apple Developer team **and** this exact signing identifier.
    let containerSigningIdentifier: String
    let tlsKeylogEnabled: Bool

    private enum CodingKeys: String, CodingKey {
        case htmlBadgeEnabled = "html_badge_enabled"
        case htmlBadgeLabel = "html_badge_label"
        case tcpConnectTimeoutMs = "tcp_connect_timeout_ms"
        case excludeDomains = "exclude_domains"
        case xpcServiceName = "xpc_service_name"
        case containerSigningIdentifier = "container_signing_identifier"
        case tlsKeylogEnabled = "tls_keylog_enabled"
    }
}
