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
}

impl Default for DemoProxyConfig {
    fn default() -> Self {
        Self {
            html_badge_enabled: true,
            html_badge_label: "proxied by rama".to_owned(),
            peek_duration_s: 8.,
            exclude_domains: vec![
                "detectportal.firefox.com".to_owned(),
                "connectivitycheck.gstatic.com".to_owned(),
                "captive.apple.com".to_owned(),
            ],
            ca_cert_pem: None,
            ca_key_pem: None,
            xpc_service_name: None,
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
