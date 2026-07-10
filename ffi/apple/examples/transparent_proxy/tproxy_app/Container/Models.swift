import Foundation

struct DemoProxySettings: Equatable {
    var htmlBadgeEnabled = true
    var htmlBadgeLabel = "proxied by rama"
    var tcpConnectTimeoutMs: Int = 2000
    var excludeDomains = [
        "detectportal.firefox.com",
        "connectivitycheck.gstatic.com",
        "captive.apple.com",
        "my.securityjourney.com",
        "*.my.securityjourney.com",
        "webgate.ec.europa.eu",
    ]
    /// UI-display cache for the sysext's runtime TLS keylog toggle.
    /// The authoritative state lives in the sysext's
    /// `ToggleableKeyLogSink` (an `AtomicBool`); the GUI flips it
    /// via `setTlsKeylog:withReply:` and mirrors the reply here.
    /// Not persisted — re-synced from the sysext via
    /// `getTlsKeylog:withReply:` after the proxy connects.
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

    private enum CodingKeys: String, CodingKey {
        case htmlBadgeEnabled = "html_badge_enabled"
        case htmlBadgeLabel = "html_badge_label"
        case tcpConnectTimeoutMs = "tcp_connect_timeout_ms"
        case excludeDomains = "exclude_domains"
        case xpcServiceName = "xpc_service_name"
        case containerSigningIdentifier = "container_signing_identifier"
    }
}
