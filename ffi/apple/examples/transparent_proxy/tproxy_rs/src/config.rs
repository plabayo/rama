use rama::error::{BoxError, BoxErrorExt as _, ErrorContext as _};
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
    /// Optional Rust->Swift writer-pump cap exported in the startup config.
    /// Absent keeps the engine's 256 KiB production default.
    pub tcp_write_pump_max_pending_bytes: Option<usize>,
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
    /// Canonical run UUID attached to every signed-E2E decision diagnostic.
    /// Launch-only and non-secret; absent for ordinary provider starts.
    pub evidence_run_uuid: Option<String>,
    /// Exact remote endpoints eligible for the signed-E2E decision diagnostic.
    /// This prevents unrelated traffic from an allowlisted system tool from
    /// entering the evidence window.
    pub udp_e2e_diagnostic_endpoints: Vec<HostWithPort>,
    /// Optional global-pressure probe lease override. The engine default is
    /// 10 ms; larger values are useful for observability and loaded-system
    /// integration tests without changing the coordinator's semantics.
    pub udp_ingress_probe_lease_ms: Option<u64>,
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
            tcp_write_pump_max_pending_bytes: None,
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
            evidence_run_uuid: None,
            udp_e2e_diagnostic_endpoints: Vec::new(),
            udp_ingress_probe_lease_ms: None,
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
            Some(bytes) if !bytes.is_empty() => serde_json::from_slice(bytes)
                .context("decode transparent proxy engine config JSON")
                .and_then(Self::validate),
            _ => Ok(Self::default()),
        }
    }

    fn validate(config: Self) -> Result<Self, BoxError> {
        if config.udp_e2e_mode && !cfg!(any(test, feature = "e2e")) {
            return Err(BoxError::from_static_str(
                "udp_e2e_mode requires the e2e build feature",
            ));
        }
        let has_evidence_identity =
            config.evidence_run_uuid.is_some() || !config.udp_e2e_diagnostic_endpoints.is_empty();
        if !config.udp_e2e_mode && has_evidence_identity {
            return Err(BoxError::from_static_str(
                "launch-only evidence fields require udp_e2e_mode",
            ));
        }
        let evidence_identity_valid = config
            .evidence_run_uuid
            .as_deref()
            .is_some_and(is_canonical_uuid)
            && !config.udp_e2e_diagnostic_endpoints.is_empty()
            && config.udp_e2e_diagnostic_endpoints.len() <= 512;
        if config.udp_e2e_mode && !evidence_identity_valid {
            return Err(BoxError::from_static_str(
                "udp_e2e_mode requires one canonical evidence_run_uuid and 1..=512 diagnostic endpoints; launch-only evidence fields require udp_e2e_mode",
            ));
        }
        if config
            .udp_e2e_diagnostic_endpoints
            .iter()
            .map(ToString::to_string)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != config.udp_e2e_diagnostic_endpoints.len()
        {
            return Err(BoxError::from_static_str(
                "udp_e2e_diagnostic_endpoints must be unique",
            ));
        }
        if config
            .udp_e2e_diagnostic_endpoints
            .iter()
            .any(|endpoint| endpoint.port == 0 || endpoint.host.try_as_ip().is_err())
        {
            return Err(BoxError::from_static_str(
                "udp_e2e_diagnostic_endpoints must be nonzero IP endpoints",
            ));
        }
        Ok(config)
    }
}

fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
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
                "udp_e2e_mode":true,
                "evidence_run_uuid":"12345678-1234-4234-8234-123456789abc",
                "udp_e2e_diagnostic_endpoints":["1.1.1.1:53","8.8.8.8:53"]
                ,"udp_ingress_probe_lease_ms":500
                ,"tcp_write_pump_max_pending_bytes":16384
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
        assert_eq!(
            config.evidence_run_uuid.as_deref(),
            Some("12345678-1234-4234-8234-123456789abc")
        );
        assert_eq!(config.udp_e2e_diagnostic_endpoints.len(), 2);
        assert_eq!(config.udp_ingress_probe_lease_ms, Some(500));
        assert_eq!(config.tcp_write_pump_max_pending_bytes, Some(16_384));
    }

    #[test]
    fn signed_udp_diagnostics_fail_closed_without_exact_identity() {
        for json in [
            br#"{"udp_e2e_mode":true}"#.as_slice(),
            br#"{"udp_e2e_mode":true,"evidence_run_uuid":"NOT-A-UUID","udp_e2e_diagnostic_endpoints":["1.1.1.1:53"]}"#.as_slice(),
            br#"{"evidence_run_uuid":"12345678-1234-4234-8234-123456789abc","udp_e2e_diagnostic_endpoints":["1.1.1.1:53"]}"#.as_slice(),
            br#"{"evidence_run_uuid":"NOT-A-UUID","udp_e2e_diagnostic_endpoints":["1.1.1.1:53"]}"#.as_slice(),
            br#"{"udp_e2e_mode":true,"evidence_run_uuid":"12345678-1234-4234-8234-123456789abc","udp_e2e_diagnostic_endpoints":["1.1.1.1:53","1.1.1.1:53"]}"#.as_slice(),
            br#"{"udp_e2e_mode":true,"evidence_run_uuid":"12345678-1234-4234-8234-123456789abc","udp_e2e_diagnostic_endpoints":["example.com:443"]}"#.as_slice(),
            br#"{"udp_e2e_mode":true,"evidence_run_uuid":"12345678-1234-4234-8234-123456789abc","udp_e2e_diagnostic_endpoints":["127.0.0.1:0"]}"#.as_slice(),
        ] {
            assert!(DemoProxyConfig::from_opaque_config(Some(json)).is_err());
        }
    }
}
