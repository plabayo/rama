use rama_net::address::HostWithPort;
use rama_utils::{
    macros::generate_set_and_with,
    str::{NonEmptyStr, arcstr::ArcStr},
};

/// Protocol filter used by transparent-proxy network rules.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransparentProxyRuleProtocol {
    /// Match both TCP and UDP.
    Any = 0,
    /// Match TCP only.
    Tcp = 1,
    /// Match UDP only.
    Udp = 2,
}

impl TransparentProxyRuleProtocol {
    #[inline(always)]
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

impl From<u32> for TransparentProxyRuleProtocol {
    fn from(value: u32) -> Self {
        if value <= Self::Udp as u32 {
            // SAFETY: repr(u32) and valid range
            unsafe { ::std::mem::transmute::<u32, Self>(value) }
        } else {
            tracing::debug!(
                "invalid raw u32 value transmuted as TransparentProxyRuleProtocol: {value} (defaulting it to Any)"
            );
            Self::Any
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransparentProxyFlowProtocol {
    Tcp = 1,
    Udp = 2,
}

impl TransparentProxyFlowProtocol {
    #[inline(always)]
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

impl From<u32> for TransparentProxyFlowProtocol {
    fn from(value: u32) -> Self {
        if value <= Self::Udp as u32 {
            // SAFETY: repr(u32) and valid range
            unsafe { ::std::mem::transmute::<u32, Self>(value) }
        } else {
            tracing::debug!(
                "invalid raw u32 value transmuted as TransparentProxyFlowProtocol: {value} (defaulting it to TCP)"
            );
            Self::Tcp
        }
    }
}

/// One network interception rule for transparent proxy settings.
#[derive(Clone, Debug)]
pub struct TransparentProxyNetworkRule {
    remote_network: Option<ArcStr>,
    remote_prefix: Option<u8>,
    local_network: Option<ArcStr>,
    local_prefix: Option<u8>,
    protocol: TransparentProxyRuleProtocol,
}

impl TransparentProxyNetworkRule {
    /// Create an "all traffic" rule.
    #[must_use]
    pub fn any() -> Self {
        Self {
            remote_network: None,
            remote_prefix: None,
            local_network: None,
            local_prefix: None,
            protocol: TransparentProxyRuleProtocol::Any,
        }
    }

    /// Optional remote network as textual IP address.
    #[must_use]
    pub fn remote_network(&self) -> Option<&str> {
        self.remote_network.as_deref()
    }

    /// Prefix length for `remote_network`, if set.
    #[must_use]
    pub const fn remote_prefix(&self) -> Option<u8> {
        self.remote_prefix
    }

    /// Optional local network as textual IP address.
    #[must_use]
    pub fn local_network(&self) -> Option<&str> {
        self.local_network.as_deref()
    }

    /// Prefix length for `local_network`, if set.
    #[must_use]
    pub const fn local_prefix(&self) -> Option<u8> {
        self.local_prefix
    }

    /// Rule protocol filter.
    #[must_use]
    pub const fn protocol(&self) -> TransparentProxyRuleProtocol {
        self.protocol
    }

    generate_set_and_with! {
        /// Set remote network + prefix.
        pub fn remote_network(mut self, network: ArcStr, prefix: u8) -> Self {
            self.remote_network = Some(network);
            self.remote_prefix = Some(prefix);
            self
        }
    }

    generate_set_and_with! {
        /// Set local network + prefix.
        pub fn local_network(mut self, network: ArcStr, prefix: u8) -> Self {
            self.local_network = Some(network);
            self.local_prefix = Some(prefix);
            self
        }
    }

    generate_set_and_with! {
        /// Set protocol filter.
        pub fn protocol(mut self, protocol: TransparentProxyRuleProtocol) -> Self {
            self.protocol = protocol;
            self
        }
    }
}

/// Engine-level transparent proxy configuration.
///
/// This configuration is long-lived and shared by all flows handled by one
/// [`crate::TransparentProxyEngine`].
#[derive(Clone, Debug)]
pub struct TransparentProxyConfig {
    tunnel_remote_address: ArcStr,
    rules: Vec<TransparentProxyNetworkRule>,
}

impl TransparentProxyConfig {
    /// Create an empty configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tunnel_remote_address: ArcStr::from("127.0.0.1"),
            rules: vec![TransparentProxyNetworkRule::any()],
        }
    }

    /// Placeholder tunnel remote address for `NETransparentProxyNetworkSettings`.
    ///
    /// Apple requires this field when constructing tunnel settings, even for
    /// transparent proxy providers where this is not used as a real upstream.
    #[must_use]
    pub fn tunnel_remote_address(&self) -> &str {
        &self.tunnel_remote_address
    }

    /// Network interception rules for `NETransparentProxyNetworkSettings`.
    #[must_use]
    pub fn rules(&self) -> &[TransparentProxyNetworkRule] {
        &self.rules
    }

    generate_set_and_with! {
        /// Set tunnel remote address placeholder.
        pub fn tunnel_remote_address(mut self, tunnel_remote_address: ArcStr) -> Self {
            self.tunnel_remote_address = tunnel_remote_address;
            self
        }
    }

    generate_set_and_with! {
        /// Set interception rules.
        pub fn rules(mut self, rules: Vec<TransparentProxyNetworkRule>) -> Self {
            self.rules = rules;
            self
        }
    }
}

impl Default for TransparentProxyConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-flow transparent proxy metadata.
///
/// This metadata is specific to one intercepted flow and is injected into the
/// flow input extensions for user services.
#[derive(Clone, Debug)]
pub struct TransparentProxyFlowMeta {
    /// Transport protocol for this flow.
    pub protocol: TransparentProxyFlowProtocol,
    /// Remote endpoint for this flow, if known.
    pub remote_endpoint: Option<HostWithPort>,
    /// Local endpoint for this flow, if known.
    pub local_endpoint: Option<HostWithPort>,
    /// Signing identifier of the source app, if available.
    pub source_app_signing_identifier: Option<NonEmptyStr>,
    /// Bundle identifier of the source app, if available.
    pub source_app_bundle_identifier: Option<NonEmptyStr>,
}

impl TransparentProxyFlowMeta {
    /// Create flow metadata from strongly typed fields.
    #[must_use]
    pub fn new(protocol: TransparentProxyFlowProtocol) -> Self {
        Self {
            protocol,
            remote_endpoint: None,
            local_endpoint: None,
            source_app_signing_identifier: None,
            source_app_bundle_identifier: None,
        }
    }

    generate_set_and_with! {
        /// Set remote endpoint.
        pub fn remote_endpoint(mut self, endpoint: Option<HostWithPort>) -> Self {
            self.remote_endpoint = endpoint;
            self
        }
    }

    generate_set_and_with! {
        /// Set local endpoint.
        pub fn local_endpoint(mut self, endpoint: Option<HostWithPort>) -> Self {
            self.local_endpoint = endpoint;
            self
        }
    }

    generate_set_and_with! {
        /// Set source app signing identifier.
        pub fn source_app_signing_identifier(mut self, value: Option<NonEmptyStr>) -> Self {
            self.source_app_signing_identifier = value;
            self
        }
    }

    generate_set_and_with! {
        /// Set source app bundle identifier.
        pub fn source_app_bundle_identifier(mut self, value: Option<NonEmptyStr>) -> Self {
            self.source_app_bundle_identifier = value;
            self
        }
    }
}
