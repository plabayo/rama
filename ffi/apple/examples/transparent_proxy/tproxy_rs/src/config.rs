use rama::error::{BoxError, ErrorContext as _};
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
    pub exclude_domains: Vec<String>,
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
            // Keep in sync with `policy::DomainExclusionList::default()`
            // — that's the engine-internal fallback; this is the
            // user-visible default that ships in the opaque config.
            exclude_domains: vec![
                // Captive-portal probes.
                "detectportal.firefox.com".to_owned(),
                "connectivitycheck.gstatic.com".to_owned(),
                "captive.apple.com".to_owned(),
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
