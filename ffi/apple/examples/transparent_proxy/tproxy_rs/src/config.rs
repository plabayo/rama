use rama::error::{BoxError, ErrorContext as _};
use rama::net::address::HostWithPort;
use serde::Deserialize;

/// # Security
///
/// This struct is deserialized from the opaque config payload. Opaque config is
/// intended for non-sensitive runtime settings only (timeouts, domain exclusions,
/// feature flags, and similar public info). Apple logs this payload automatically —
/// it will appear in system diagnostic output with no ability to suppress it.
/// Never add secrets, private keys, or credentials here; use the system keychain
/// for sensitive material instead or transport it over a secure XPC connection yourself.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DemoProxyConfig {
    pub html_badge_enabled: bool,
    pub html_badge_label: String,
    pub peek_duration_s: f64,
    // Egress connect timeout (ms); applied via `egress_tcp_connect_options`.
    // `None`/`0` keeps the platform default.
    pub tcp_connect_timeout_ms: Option<u64>,
    // Egress TCP_NODELAY. The engine already defaults this ON (the relay
    // is the only Nagle decision-maker in the path); this knob exists to
    // opt back into Nagle for experiments.
    pub tcp_no_delay: bool,
    pub exclude_domains: Vec<String>,
    /// Extra UDP destination ports declined before Rama claims the flow.
    /// Used by the signed macOS modern-callback E2E; production defaults empty.
    pub udp_passthrough_ports: Vec<u16>,
    /// Exact UDP destinations blocked before the normal example policy runs.
    /// Used by the signed macOS modern-callback E2E; production defaults empty.
    pub udp_blocked_endpoints: Vec<HostWithPort>,
    /// Makes the UDP overrides temporary and enables allowlisted public
    /// diagnostics for the signed live E2E. Never persisted by the example app.
    pub udp_e2e_mode: bool,
    // Optional inline PEM overrides — if both are set they bypass the System Keychain.
    // Intended for environments (e.g. e2e test runners) that lack keychain access.
    // The production app leaves these unset and always uses the System Keychain.
    pub ca_cert_pem: Option<String>,
    pub ca_key_pem: Option<String>,
    // The XPC mach service name to listen on for live settings updates from the container app.
    // Set to the extension's bundle ID by the Swift container. If absent, XPC server is skipped.
    pub xpc_service_name: Option<String>,
    // The signing identifier (bundle ID) of the **container app** allowed to talk to
    // the XPC server. The sysext pins the listener via
    // `PeerSecurityRequirement::TeamIdentity(Some(<this>))` — same Apple Developer team
    // *and* this exact signing identifier. Set by the Swift container from
    // `Bundle.main.bundleIdentifier`. If absent or empty, the sysext refuses to start
    // the XPC server (fail-closed) so unrestricted access to install/uninstall routes
    // is impossible.
    pub container_signing_identifier: Option<String>,
}

impl Default for DemoProxyConfig {
    fn default() -> Self {
        Self {
            html_badge_enabled: true,
            html_badge_label: "proxied by rama".to_owned(),
            peek_duration_s: 8.,
            tcp_connect_timeout_ms: None,
            tcp_no_delay: true,
            // Keep in sync with `policy::DomainExclusionList::default()`
            // — that's the engine-internal fallback; this is the
            // user-visible default that ships in the opaque config.
            exclude_domains: vec![
                // Captive-portal probes.
                "detectportal.firefox.com".to_owned(),
                "connectivitycheck.gstatic.com".to_owned(),
                "captive.apple.com".to_owned(),
                "my.securityjourney.com".to_owned(),
                "*.my.securityjourney.com".to_owned(),
                "webgate.ec.europa.eu".to_owned(),
                // High-traffic dev/CDN endpoints — see policy.rs
                // for the rationale. Wildcards opt into subtree
                // matching (handled by `DomainTrie::is_match`).
                "*.github.com".to_owned(),
                "*.githubusercontent.com".to_owned(),
                "*.googleapis.com".to_owned(),
                "*.gstatic.com".to_owned(),
                "*.cloudflare.com".to_owned(),
                "*.jsdelivr.net".to_owned(),
                // More common high-traffic domains so a soak run drives the
                // promote → Swift-splice → teardown path with heavy, realistic
                // volume (the path we want to prove leak-free).
                "*.apple.com".to_owned(),
                "*.icloud.com".to_owned(),
                "*.microsoft.com".to_owned(),
                "*.azureedge.net".to_owned(),
                "*.fastly.net".to_owned(),
                "*.akamaized.net".to_owned(),
                "*.amazonaws.com".to_owned(),
                "*.cloudfront.net".to_owned(),
                "*.google.com".to_owned(),
                "*.googlevideo.com".to_owned(),
                "*.slack-edge.com".to_owned(),
                "registry.npmjs.org".to_owned(),
                "*.pythonhosted.org".to_owned(),
                "*.docker.io".to_owned(),
            ],
            udp_passthrough_ports: Vec::new(),
            udp_blocked_endpoints: Vec::new(),
            udp_e2e_mode: false,
            ca_cert_pem: None,
            ca_key_pem: None,
            xpc_service_name: None,
            container_signing_identifier: None,
        }
    }
}

impl DemoProxyConfig {
    pub fn from_opaque_config(opaque_config: Option<&[u8]>) -> Result<Self, BoxError> {
        match opaque_config {
            Some(bytes) if !bytes.is_empty() => {
                serde_json::from_slice(bytes).context("decode transparent proxy engine config JSON")
            }
            _ => Ok(Self::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_udp_policy_overrides_for_signed_e2e() {
        let config = DemoProxyConfig::from_opaque_config(Some(
            br#"{
                "udp_passthrough_ports":[443,53001],
                "udp_blocked_endpoints":["8.8.8.8:53","[2001:4860:4860::8888]:53"],
                "udp_e2e_mode":true
            }"#,
        ))
        .expect("valid test config");

        assert_eq!(config.udp_passthrough_ports, [443, 53001]);
        assert_eq!(config.udp_blocked_endpoints[0].to_string(), "8.8.8.8:53");
        assert_eq!(
            config.udp_blocked_endpoints[1].to_string(),
            "[2001:4860:4860::8888]:53"
        );
        assert!(config.udp_e2e_mode);
    }
}
