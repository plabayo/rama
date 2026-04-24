use rama::error::{BoxError, ErrorContext as _};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DemoProxyConfig {
    pub html_badge_enabled: bool,
    pub html_badge_label: String,
    pub peek_duration_s: f64,
    pub tcp_connect_timeout_ms: u64,
    pub exclude_domains: Vec<String>,
    pub ca_cert_secret_name: Option<String>,
    pub ca_key_secret_name: Option<String>,
    pub ca_secret_account: Option<String>,
    pub ca_secret_access_group: Option<String>,
    pub se_extension_access_group: Option<String>,
}

impl Default for DemoProxyConfig {
    fn default() -> Self {
        Self {
            html_badge_enabled: true,
            html_badge_label: "proxied by rama".to_owned(),
            peek_duration_s: 8.,
            tcp_connect_timeout_ms: 2000,
            exclude_domains: vec![
                "detectportal.firefox.com".to_owned(),
                "connectivitycheck.gstatic.com".to_owned(),
                "captive.apple.com".to_owned(),
            ],
            ca_cert_secret_name: None,
            ca_key_secret_name: None,
            ca_secret_account: None,
            ca_secret_access_group: None,
            se_extension_access_group: None,
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
