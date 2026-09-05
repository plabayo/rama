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
    /// Additional UDP destination ports declined up front by the demo policy.
    /// The signed modern-callback E2E passes these on the container command
    /// line; normal launches leave the list empty (UDP/53 remains the demo's
    /// built-in resolver pass-through).
    var udpPassthroughPorts: [UInt16] = []
    /// Exact UDP destinations blocked before the demo's normal policy.
    /// Test-only; normal launches leave the list empty.
    var udpBlockedEndpoints: [String] = []
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
    let udpPassthroughPorts: [UInt16]
    let udpBlockedEndpoints: [String]
    /// Enables the Rust example's temporary UDP rules and allowlisted public
    /// diagnostics solely for the signed live E2E. It is sent in start options
    /// and never saved in the NE profile.
    let udpE2EMode: Bool?
    /// Canonical launch-only identity attached to signed-E2E diagnostics.
    let evidenceRunUuid: String?
    /// Exact launch-only endpoint allowlist for signed-E2E diagnostics.
    let udpE2EDiagnosticEndpoints: [String]?
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
        case udpPassthroughPorts = "udp_passthrough_ports"
        case udpBlockedEndpoints = "udp_blocked_endpoints"
        case udpE2EMode = "udp_e2e_mode"
        case evidenceRunUuid = "evidence_run_uuid"
        case udpE2EDiagnosticEndpoints = "udp_e2e_diagnostic_endpoints"
        case xpcServiceName = "xpc_service_name"
        case containerSigningIdentifier = "container_signing_identifier"
    }
}
