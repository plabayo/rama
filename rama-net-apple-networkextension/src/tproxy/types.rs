use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rama_core::extensions::Extension;
use rama_net::address::{Host, HostWithPort};
use rama_utils::{
    macros::generate_set_and_with,
    str::{NonEmptyStr, arcstr::ArcStr},
};

use crate::process::AuditToken;

/// Monotonic per-process counter used to generate [`TransparentProxyFlowMeta`]
/// `flow_id` values. Starts at 1; 0 is reserved as "unset / unknown."
///
/// In the (theoretical) event of overflow we wrap and skip 0 so the "unset"
/// reservation still holds — at ~2^64 flows we'd have bigger problems, but
/// the wrap path is defined rather than relying on Rust's overflow semantics.
static FLOW_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_flow_id() -> u64 {
    loop {
        let id = FLOW_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
        // Wrapped through u64::MAX back to 0 — skip the reserved
        // value. At a billion flows/second this branch is reachable
        // after ~292 years of continuous churn; it exists so the
        // wrap is *defined* rather than relying on Rust's overflow
        // semantics, not because it's a realistic operational
        // concern.
    }
}

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
// All four `Nw*` enums below are `#[repr(u8)]` with **explicit
// discriminants**. The discriminants are the FFI wire format: they
// appear in `RamaNwEgressParameters` (C struct) as the `service_class`
// / `multipath_service_type` / `required_interface_type` /
// `attribution` fields, in the Rust → C mapping at
// `ffi/tproxy.rs::{service_class_to_u8, multipath_to_u8,
// interface_type_to_u8, attribution_to_u8}`, and in the Swift bridge
// at `RamaTransparentProxyProvider.swift::{nwServiceClass,
// nwMultipathServiceType, nwInterfaceType}`.
//
// **Editing checklist** when adding or reordering a variant:
//   1. Bump the new variant's discriminant past the last one — never
//      reuse or shuffle existing values.
//   2. Update `ffi/tproxy.rs::*_to_u8` to match (compile fails today
//      because the matches are exhaustive — a missing arm errors out).
//   3. Update the Swift `Nw*` switch in
//      `RamaTransparentProxyProvider.swift` so it round-trips the new
//      code.
//   4. Update the C header doc comment on `RamaNwEgressParameters`.
//
// The `repr(u8)` + explicit discriminants make (1) compile-checked
// (`enum NwX { A = 0, B = 0 }` errors), and the Rust-side `*_to_u8`
// matches keep (2) compile-checked. Swift / C still need manual care,
// hence the checklist.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum NwServiceClass {
    /// Do not override; use the system default (`bestEffort`).
    #[default]
    Default = 0,
    Background = 1,
    InteractiveVideo = 2,
    InteractiveVoice = 3,
    ResponsiveData = 4,
    /// Maps to `NWParameters.ServiceClass.signaling` (formerly `responsiveAV`).
    Signaling = 5,
}

/// NWParameters multipath service type — maps to `NWParameters.multipathServiceType`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum NwMultipathServiceType {
    #[default]
    Disabled = 0,
    Handover = 1,
    Interactive = 2,
    Aggregate = 3,
}

/// NWParameters interface type — maps to `NWParameters.requiredInterfaceType`
/// and `NWParameters.prohibitedInterfaceTypes`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NwInterfaceType {
    Cellular = 0,
    Loopback = 1,
    Other = 2,
    Wifi = 3,
    Wired = 4,
}

/// NWParameters attribution — maps to `NWParameters.attribution`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum NwAttribution {
    #[default]
    Developer = 0,
    User = 1,
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

impl std::fmt::Display for TransparentProxyFlowProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

impl TransparentProxyFlowProtocol {
    /// Strict conversion: returns the unrecognised value as `Err`,
    /// letting the caller decide how to handle it (e.g. passthrough,
    /// blocked, surface to telemetry).
    ///
    /// Implemented as an inherent method (rather than a `TryFrom`
    /// impl) because Rust's blanket `impl<T, U> TryFrom<U> for T
    /// where U: Into<T>` already covers `TryFrom<u32>` via our
    /// [`From<u32>`] impl below — that auto-impl is infallible
    /// (uses the lenient default-on-invalid behavior). New code that
    /// wants strict checking should call this method explicitly.
    pub fn from_raw_strict(value: u32) -> Result<Self, u32> {
        if (Self::Tcp as u32..=Self::Udp as u32).contains(&value) {
            // SAFETY: repr(u32) with explicit discriminants 1..=2 and we
            // just verified `value` falls in that range.
            Ok(unsafe { ::std::mem::transmute::<u32, Self>(value) })
        } else {
            Err(value)
        }
    }
}

impl From<u32> for TransparentProxyFlowProtocol {
    /// Defensive lenient conversion: unknown protocol codes log a
    /// `debug` and default to TCP. Used at the FFI boundary where a
    /// future Swift/C ABI mismatch would surface as an unknown code
    /// and we'd rather default-and-log than abort. New code paths
    /// should prefer [`Self::from_raw_strict`] so the unknown case is
    /// a real error the caller can route (e.g. passthrough).
    fn from(value: u32) -> Self {
        Self::from_raw_strict(value).unwrap_or_else(|invalid| {
            tracing::debug!(
                invalid_raw_protocol = invalid,
                "invalid raw u32 value transmuted as TransparentProxyFlowProtocol; defaulting to TCP"
            );
            Self::Tcp
        })
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

impl std::fmt::Display for TransparentProxyFlowAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Intercept => "intercept",
            Self::Passthrough => "passthrough",
            Self::Blocked => "blocked",
        })
    }
}

impl TransparentProxyFlowAction {
    /// Strict conversion mirroring [`TransparentProxyFlowProtocol::from_raw_strict`].
    pub fn from_raw_strict(value: u32) -> Result<Self, u32> {
        if (Self::Intercept as u32..=Self::Blocked as u32).contains(&value) {
            // SAFETY: repr(u32) with explicit discriminants 1..=3 and we
            // just verified `value` falls in that range.
            Ok(unsafe { ::std::mem::transmute::<u32, Self>(value) })
        } else {
            Err(value)
        }
    }
}

impl From<u32> for TransparentProxyFlowAction {
    /// Defensive lenient conversion: unknown action codes log a
    /// `debug` and default to `Passthrough` (fail-open). See
    /// [`TransparentProxyFlowProtocol::from`] for the same pattern's
    /// rationale; prefer [`Self::from_raw_strict`] in new code.
    fn from(value: u32) -> Self {
        Self::from_raw_strict(value).unwrap_or_else(|invalid| {
            tracing::debug!(
                invalid_raw_action = invalid,
                "invalid raw u32 value transmuted as TransparentProxyFlowAction; defaulting to Passthrough"
            );
            Self::Passthrough
        })
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
///
/// `flow_id` and `opened_at` are populated automatically by [`Self::new`] using
/// a monotonic per-process counter and the current instant. `intercept_decision`
/// is set by the engine after the flow handler returns its decision; user code
/// observing the meta as a service input may see `None` until the engine has
/// recorded the decision.
#[derive(Clone, Debug, Extension)]
pub struct TransparentProxyFlowMeta {
    /// Transport protocol for this flow.
    pub protocol: TransparentProxyFlowProtocol,
    /// Monotonic per-process flow id. Useful for correlating engine-emitted
    /// trace events (open / decision / close) for the same flow.
    pub flow_id: u64,
    /// When the meta was constructed; used as the opened-at timestamp for
    /// computing flow age in close events.
    pub opened_at: Instant,
    /// Decision recorded by the engine after the flow handler returned.
    /// `None` until the handler has been invoked.
    pub intercept_decision: Option<TransparentProxyFlowAction>,
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
    ///
    /// `flow_id` is generated from a monotonic per-process counter; `opened_at`
    /// is set to [`Instant::now`]. `intercept_decision` starts as `None` and is
    /// populated by the engine once a flow decision is reached.
    #[must_use]
    pub fn new(protocol: TransparentProxyFlowProtocol) -> Self {
        Self {
            protocol,
            flow_id: next_flow_id(),
            opened_at: Instant::now(),
            intercept_decision: None,
            remote_endpoint: None,
            local_endpoint: None,
            source_app_signing_identifier: None,
            source_app_bundle_identifier: None,
            source_app_audit_token: None,
            source_app_pid: None,
        }
    }

    /// Age since the meta was constructed (i.e. since the flow was first seen).
    #[must_use]
    pub fn age(&self) -> Duration {
        self.opened_at.elapsed()
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

    generate_set_and_with! {
        /// Set the decision recorded by the engine after the flow handler returned.
        pub fn intercept_decision(mut self, value: Option<TransparentProxyFlowAction>) -> Self {
            self.intercept_decision = value;
            self
        }
    }
}
