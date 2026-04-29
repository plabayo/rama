use std::time::Duration;

use rama_core::extensions::Extension;
use rama_net::address::{Host, HostWithPort};
use rama_utils::{
    macros::generate_set_and_with,
    str::{NonEmptyStr, arcstr::ArcStr},
};

use crate::process::AuditToken;

/// NWParameters service class — maps to `NWParameters.serviceClass`.
///
/// Variants mirror the cases in `NWParameters.ServiceClass` from Apple's Network framework
/// (available on macOS 10.14+, iOS 12+).
///
/// | Variant         | Swift case             | Notes                                  |
/// |-----------------|------------------------|----------------------------------------|
/// | Default         | *(not set)*            | Use the system default (best-effort)   |
/// | Background      | `.background`          | Best effort, low priority              |
/// | InteractiveVideo| `.interactiveVideo`    | Video calls                            |
/// | InteractiveVoice| `.interactiveVoice`    | VoIP calls                             |
/// | ResponsiveData  | `.responsiveData`      | Interactive network traffic            |
/// | Signaling       | `.signaling`           | Control / signalling traffic           |
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NwServiceClass {
    /// Do not override; use the system default (`bestEffort`).
    #[default]
    Default,
    Background,
    InteractiveVideo,
    InteractiveVoice,
    ResponsiveData,
    /// Maps to `NWParameters.ServiceClass.signaling` (formerly `responsiveAV`).
    Signaling,
}

/// NWParameters multipath service type — maps to `NWParameters.multipathServiceType`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NwMultipathServiceType {
    #[default]
    Disabled,
    Handover,
    Interactive,
    Aggregate,
}

/// NWParameters interface type — maps to `NWParameters.requiredInterfaceType`
/// and `NWParameters.prohibitedInterfaceTypes`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NwInterfaceType {
    Cellular,
    Loopback,
    Other,
    Wifi,
    Wired,
}

/// NWParameters attribution — maps to `NWParameters.attribution`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NwAttribution {
    #[default]
    Developer,
    User,
}

/// Non-protocol `NWParameters` settings that apply equally to TCP and UDP egress connections.
///
/// All fields map directly to top-level `NWParameters` properties (not protocol-specific options).
/// Only parameters meaningful for a `NETransparentProxyProvider` egress connection are included.
#[derive(Clone, Debug)]
pub struct NwEgressParameters {
    /// Maps to `NWParameters.serviceClass`.
    pub service_class: Option<NwServiceClass>,
    /// Maps to `NWParameters.multipathServiceType`.
    pub multipath_service_type: Option<NwMultipathServiceType>,
    /// Maps to `NWParameters.prohibitedInterfaceTypes`.
    pub prohibited_interface_types: Vec<NwInterfaceType>,
    /// Maps to `NWParameters.requiredInterfaceType`.
    pub required_interface_type: Option<NwInterfaceType>,
    /// Maps to `NWParameters.attribution` — attribute outbound traffic to the
    /// originating app rather than the extension process.
    pub attribution: Option<NwAttribution>,
    /// When `true`, Swift calls `NEAppProxyFlow.setMetadata(_:)` on the egress
    /// `NWParameters` before constructing the `NWConnection`, propagating the
    /// intercepted flow's `NEFlowMetaData` (source app identifier / audit
    /// token) onto the egress connection.
    ///
    /// This is good-citizen behavior for stacked-proxy deployments: a
    /// downstream `NEAppProxyProvider` that intercepts our egress sees the
    /// **original** app rather than this extension's process.
    ///
    /// Defaults to `true`. Note that this propagates *identity*, it does not
    /// mark the flow as already-proxied — it cannot prevent infinite loops
    /// between two providers that both claim the same destinations. Disable
    /// it if you need downstream observers to see this extension as the
    /// source.
    pub preserve_original_meta_data: bool,
}

impl Default for NwEgressParameters {
    fn default() -> Self {
        Self {
            service_class: None,
            multipath_service_type: None,
            prohibited_interface_types: Vec::new(),
            required_interface_type: None,
            attribution: None,
            preserve_original_meta_data: true,
        }
    }
}

/// Options for the egress `NWConnection` on TCP flows.
///
/// TCP-specific: wraps [`NwEgressParameters`] and adds a connection timeout
/// that maps to `NWProtocolTCP.Options.connectionTimeout`.
#[derive(Clone, Debug, Default)]
pub struct NwTcpConnectOptions {
    /// Shared `NWParameters`-level settings.
    pub parameters: NwEgressParameters,
    /// Maps to `NWProtocolTCP.Options.connectionTimeout`.
    pub connect_timeout: Option<Duration>,
}

/// Options for the egress `NWConnection` on UDP flows.
///
/// For UDP there is no handshake timeout, so only the shared
/// [`NwEgressParameters`] are exposed.
#[derive(Clone, Debug, Default)]
pub struct NwUdpConnectOptions {
    /// Shared `NWParameters`-level settings.
    pub parameters: NwEgressParameters,
}

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
        if (Self::Tcp as u32..=Self::Udp as u32).contains(&value) {
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

/// Flow policy action returned by transparent-proxy policy logic.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransparentProxyFlowAction {
    /// Intercept the flow and route it through the Rust transparent-proxy engine.
    Intercept = 1,
    /// Leave the flow alone and let the system handle it normally.
    Passthrough = 2,
    /// Explicitly reject the flow.
    Blocked = 3,
}

impl TransparentProxyFlowAction {
    #[inline(always)]
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

impl From<u32> for TransparentProxyFlowAction {
    fn from(value: u32) -> Self {
        if (Self::Intercept as u32..=Self::Blocked as u32).contains(&value) {
            // SAFETY: repr(u32) and valid range
            unsafe { ::std::mem::transmute::<u32, Self>(value) }
        } else {
            tracing::debug!(
                "invalid raw u32 value transmuted as TransparentProxyFlowAction: {value} (defaulting it to Passthrough)"
            );
            Self::Passthrough
        }
    }
}

impl From<bool> for TransparentProxyFlowAction {
    fn from(value: bool) -> Self {
        if value {
            Self::Intercept
        } else {
            Self::Passthrough
        }
    }
}

/// One network interception rule for transparent proxy settings.
#[derive(Clone, Debug)]
pub struct TransparentProxyNetworkRule {
    remote_network: Option<Host>,
    remote_prefix: Option<u8>,
    local_network: Option<Host>,
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

    /// Optional remote network as domain or IP address.
    #[must_use]
    pub fn remote_network(&self) -> Option<&Host> {
        self.remote_network.as_ref()
    }

    /// Prefix length for `remote_network`, if set.
    #[must_use]
    pub const fn remote_prefix(&self) -> Option<u8> {
        self.remote_prefix
    }

    /// Optional local network as domain or IP address.
    #[must_use]
    pub fn local_network(&self) -> Option<&Host> {
        self.local_network.as_ref()
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
        /// Set remote network.
        pub fn remote_network(mut self, network: impl Into<Host>) -> Self {
            self.remote_network = Some(network.into());
            self
        }
    }

    generate_set_and_with! {
        /// Set local network.
        pub fn local_network(mut self, network: impl Into<Host>) -> Self {
            self.local_network = Some(network.into());
            self
        }
    }

    generate_set_and_with! {
        /// Set remote network prefix.
        pub fn remote_network_prefix(mut self, prefix: u8) -> Self {
            self.remote_prefix = Some(prefix);
            self
        }
    }

    generate_set_and_with! {
        /// Set local network prefix.
        pub fn local_network_prefix(mut self, prefix: u8) -> Self {
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
/// [`crate::tproxy::TransparentProxyEngine`].
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
#[derive(Clone, Debug, Extension)]
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
    /// Raw audit token of the source app, if available.
    pub source_app_audit_token: Option<AuditToken>,
    /// Process identifier resolved from the source-app audit token, if available.
    pub source_app_pid: Option<i32>,
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
            source_app_audit_token: None,
            source_app_pid: None,
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

    generate_set_and_with! {
        /// Set source app audit token.
        pub fn source_app_audit_token(mut self, value: Option<AuditToken>) -> Self {
            self.source_app_audit_token = value;
            self
        }
    }

    generate_set_and_with! {
        /// Set source app pid.
        pub fn source_app_pid(mut self, value: Option<i32>) -> Self {
            self.source_app_pid = value;
            self
        }
    }
}
