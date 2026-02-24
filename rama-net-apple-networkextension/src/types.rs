use rama_net::{Protocol, address::HostWithPort};
use rama_utils::{macros::generate_set_and_with, str::arcstr::ArcStr};
use serde_json::Value;

/// Engine-level transparent proxy configuration.
///
/// This configuration is long-lived and shared by all flows handled by one
/// [`crate::TransparentProxyEngine`].
#[derive(Clone, Debug, Default)]
pub struct TransparentProxyConfig {
    default_remote_endpoint: Option<HostWithPort>,
}

impl TransparentProxyConfig {
    /// Create an empty configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            default_remote_endpoint: None,
        }
    }

    /// Returns the configured fallback remote endpoint, if any.
    #[must_use]
    pub fn default_remote_endpoint(&self) -> Option<&HostWithPort> {
        self.default_remote_endpoint.as_ref()
    }

    generate_set_and_with! {
        /// Set a fallback remote endpoint used when flow metadata does not provide one.
        pub fn default_remote_endpoint(mut self, endpoint: HostWithPort) -> Self {
            self.default_remote_endpoint = Some(endpoint);
            self
        }
    }

    pub(crate) fn from_json(raw: impl Into<String>) -> Self {
        let raw_json = raw.into();
        let parsed: Value = serde_json::from_str(&raw_json).unwrap_or(Value::Null);
        let mut cfg = Self::new();
        if let Some(endpoint) = parse_endpoint_field(&parsed, "default_remote_endpoint") {
            cfg.default_remote_endpoint = Some(endpoint);
        }
        cfg
    }
}

/// Per-flow transparent proxy metadata.
///
/// This metadata is specific to one intercepted flow and is injected into the
/// flow input extensions for user services.
#[derive(Clone, Debug)]
pub struct TransparentProxyMeta {
    protocol: Protocol,
    remote_endpoint: Option<HostWithPort>,
    local_endpoint: Option<HostWithPort>,
    source_app_signing_identifier: Option<ArcStr>,
    source_app_path: Option<ArcStr>,
}

impl TransparentProxyMeta {
    /// Create flow metadata from strongly typed fields.
    #[must_use]
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            remote_endpoint: None,
            local_endpoint: None,
            source_app_signing_identifier: None,
            source_app_path: None,
        }
    }

    /// Transport protocol for this flow.
    #[must_use]
    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    /// Remote endpoint for this flow, if known.
    #[must_use]
    pub fn remote_endpoint(&self) -> Option<&HostWithPort> {
        self.remote_endpoint.as_ref()
    }

    /// Local endpoint for this flow, if known.
    #[must_use]
    pub fn local_endpoint(&self) -> Option<&HostWithPort> {
        self.local_endpoint.as_ref()
    }

    /// Signing identifier of the source app, if available.
    #[must_use]
    pub fn source_app_signing_identifier(&self) -> Option<&str> {
        self.source_app_signing_identifier.as_deref()
    }

    /// File system path of the source app, if available.
    #[must_use]
    pub fn source_app_path(&self) -> Option<&str> {
        self.source_app_path.as_deref()
    }

    generate_set_and_with! {
        /// Set remote endpoint.
        pub fn remote_endpoint(mut self, endpoint: HostWithPort) -> Self {
            self.remote_endpoint = Some(endpoint);
            self
        }
    }

    generate_set_and_with! {
        /// Set local endpoint.
        pub fn local_endpoint(mut self, endpoint: HostWithPort) -> Self {
            self.local_endpoint = Some(endpoint);
            self
        }
    }

    generate_set_and_with! {
        /// Set source app signing identifier.
        pub fn source_app_signing_identifier(mut self, value: ArcStr) -> Self {
            self.source_app_signing_identifier = Some(value);
            self
        }
    }

    generate_set_and_with! {
        /// Set source app path.
        pub fn source_app_path(mut self, value: ArcStr) -> Self {
            self.source_app_path = Some(value);
            self
        }
    }

    pub(crate) fn from_json(raw: impl Into<String>) -> Self {
        let raw_json = raw.into();
        let parsed: Value = serde_json::from_str(&raw_json).unwrap_or(Value::Null);

        let protocol = parse_protocol_field(&parsed, "protocol").unwrap_or_else(default_protocol);

        Self {
            protocol,
            remote_endpoint: parse_endpoint_field(&parsed, "remote_endpoint"),
            local_endpoint: parse_endpoint_field(&parsed, "local_endpoint"),
            source_app_signing_identifier: parse_string_field(&parsed, "source_app_signing_identifier").map(ArcStr::from),
            source_app_path: parse_string_field(&parsed, "source_app_path").map(ArcStr::from),
        }
    }
}

fn default_protocol() -> Protocol {
    Protocol::from_static("tcp")
}

fn parse_protocol_field(v: &Value, key: &str) -> Option<Protocol> {
    let raw = parse_string_field(v, key)?;
    Protocol::try_from(raw).ok()
}

fn parse_endpoint_field(v: &Value, key: &str) -> Option<HostWithPort> {
    parse_string_field(v, key)?.parse().ok()
}

fn parse_string_field(v: &Value, key: &str) -> Option<String> {
    let raw = v.get(key)?.as_str()?.trim();
    (!raw.is_empty()).then(|| raw.to_owned())
}
