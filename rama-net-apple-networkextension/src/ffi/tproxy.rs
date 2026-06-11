use std::{
    ffi::{c_char, c_void},
    path::PathBuf,
    ptr,
};

use rama_net::address::{Host, HostWithPort};
use rama_utils::str::NonEmptyStr;

use crate::ffi::BytesView;
use crate::process::AuditToken;
use crate::tproxy::{
    self, NwAttribution, NwEgressParameters as RustNwEgressParameters, NwInterfaceType,
    NwMultipathServiceType, NwServiceClass,
    TransparentProxyFlowAction as RustTransparentProxyFlowAction, TransparentProxyFlowProtocol,
};

#[repr(C)]
pub struct TransparentFlowEndpoint {
    pub host_utf8: *const c_char,
    pub host_utf8_len: usize,
    pub port: u16,
}

impl TransparentFlowEndpoint {
    /// # Safety
    ///
    /// `self.host_utf8` must either be null, or point to at least
    /// `self.host_utf8_len` bytes of valid UTF-8 for the duration of this call.
    pub unsafe fn as_optional_host_with_port(&self) -> Option<HostWithPort> {
        if self.port == 0 {
            return None;
        }

        // SAFETY: pointer + length validity is guaranteed by caller contract.
        let host = unsafe { opt_utf8_to_host(self.host_utf8, self.host_utf8_len) }?;
        Some(HostWithPort::new(host, self.port))
    }
}

#[repr(C)]
pub struct TransparentProxyFlowMeta {
    pub protocol: u32,
    pub remote_endpoint: TransparentFlowEndpoint,
    pub local_endpoint: TransparentFlowEndpoint,
    pub source_app_signing_identifier_utf8: *const c_char,
    pub source_app_signing_identifier_utf8_len: usize,
    pub source_app_bundle_identifier_utf8: *const c_char,
    pub source_app_bundle_identifier_utf8_len: usize,
    pub source_app_audit_token_bytes: *const u8,
    pub source_app_audit_token_bytes_len: usize,
    pub source_app_pid: i32,
    pub source_app_pid_is_set: bool,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransparentProxyFlowAction {
    Intercept = 1,
    Passthrough = 2,
    Blocked = 3,
}

impl From<RustTransparentProxyFlowAction> for TransparentProxyFlowAction {
    fn from(value: RustTransparentProxyFlowAction) -> Self {
        match value {
            RustTransparentProxyFlowAction::Intercept => Self::Intercept,
            RustTransparentProxyFlowAction::Passthrough => Self::Passthrough,
            RustTransparentProxyFlowAction::Blocked => Self::Blocked,
        }
    }
}

impl TransparentProxyFlowMeta {
    /// # Safety
    ///
    /// All pointer + length fields in `self` must be valid for reads during
    /// this call.
    ///
    /// Returns `Err(invalid_protocol_code)` when `self.protocol` is not
    /// a known [`TransparentProxyFlowProtocol`] discriminant. The FFI
    /// thunks treat that as a fail-safe `Passthrough` rather than
    /// silently coercing the unknown code into a TCP flow.
    pub unsafe fn as_owned_rust_type(&self) -> Result<tproxy::TransparentProxyFlowMeta, u32> {
        let protocol = TransparentProxyFlowProtocol::from_raw_strict(self.protocol)?;

        // SAFETY: pointer + length validity is guaranteed by caller contract.
        let source_app_audit_token = unsafe {
            opt_audit_token(
                self.source_app_audit_token_bytes,
                self.source_app_audit_token_bytes_len,
            )
        };
        let source_app_pid = if self.source_app_pid_is_set {
            Some(self.source_app_pid)
        } else {
            source_app_audit_token.as_ref().map(AuditToken::pid)
        };

        Ok(tproxy::TransparentProxyFlowMeta::new(protocol)
            .maybe_with_remote_endpoint(
                // SAFETY: pointer + length validity is guaranteed by caller contract.
                unsafe { self.remote_endpoint.as_optional_host_with_port() },
            )
            .maybe_with_local_endpoint(
                // SAFETY: pointer + length validity is guaranteed by caller contract.
                unsafe { self.local_endpoint.as_optional_host_with_port() },
            )
            .maybe_with_source_app_signing_identifier(
                // SAFETY: pointer + length validity is guaranteed by caller contract.
                unsafe {
                    opt_utf8_to_non_empty_str(
                        self.source_app_signing_identifier_utf8,
                        self.source_app_signing_identifier_utf8_len,
                    )
                },
            )
            .maybe_with_source_app_bundle_identifier(
                // SAFETY: pointer + length validity is guaranteed by caller contract.
                unsafe {
                    opt_utf8_to_non_empty_str(
                        self.source_app_bundle_identifier_utf8,
                        self.source_app_bundle_identifier_utf8_len,
                    )
                },
            )
            .maybe_with_source_app_audit_token(source_app_audit_token)
            .maybe_with_source_app_pid(source_app_pid))
    }
}

/// FFI representation of a single network rule for the transparent
/// proxy configuration.
///
/// **Adding a field that owns FFI memory?** You must mirror the new
/// allocation in [`TransparentProxyConfig::from_rust_type`] (alloc
/// path) AND update the per-rule loop in
/// [`TransparentProxyConfig::free`] to release it. The struct is
/// `repr(C)` POD with no `Drop` impl — the slice's `Box::from_raw`
/// in `free` does NOT run a per-element Drop, so any heap memory
/// owned by a field of this struct must be freed explicitly. The two
/// existing `*_utf8` pairs are the template.
///
/// Enforcement: `tests::ffi_config_round_trip_freed_under_lsan` does
/// the alloc → free round-trip with every field populated. Run under
/// AddressSanitizer (`just test-e2e-asan`, scheduled in CI on macOS)
/// for LeakSanitizer to catch any heap field that `free` didn't
/// release.
#[repr(C)]
pub struct TransparentProxyNetworkRule {
    pub remote_network_utf8: *const c_char,
    pub remote_network_utf8_len: usize,
    pub remote_prefix: u8,
    pub remote_prefix_is_set: bool,
    pub remote_port: u16,
    pub remote_port_is_set: bool,
    pub local_network_utf8: *const c_char,
    pub local_network_utf8_len: usize,
    pub local_prefix: u8,
    pub local_prefix_is_set: bool,
    pub protocol: u32,
    /// See [`tproxy::TransparentProxyNetworkRule::exclude`].
    pub exclude: bool,
}

#[repr(C)]
pub struct TransparentProxyConfig {
    pub tunnel_remote_address_utf8: *const c_char,
    pub tunnel_remote_address_utf8_len: usize,
    pub rules: *const TransparentProxyNetworkRule,
    pub rules_len: usize,
    /// Per-flow TCP write-pump back-pressure cap in bytes. Authoritative
    /// on the Swift side — the value emitted here is the value the pump
    /// uses. See
    /// [`tproxy::TransparentProxyConfig::tcp_write_pump_max_pending_bytes`].
    pub tcp_write_pump_max_pending_bytes: usize,
}

#[repr(C)]
pub struct TransparentProxyInitConfig {
    pub storage_dir_utf8: *const c_char,
    pub storage_dir_utf8_len: usize,
    pub app_group_dir_utf8: *const c_char,
    pub app_group_dir_utf8_len: usize,
}

impl TransparentProxyInitConfig {
    /// # Safety
    ///
    /// Pointer + length pairs in `self` must be valid for reads during this call.
    pub unsafe fn storage_dir(&self) -> Option<PathBuf> {
        // SAFETY: pointer + length validity is guaranteed by caller contract.
        unsafe { opt_utf8(self.storage_dir_utf8, self.storage_dir_utf8_len) }.map(PathBuf::from)
    }

    /// # Safety
    ///
    /// Pointer + length pairs in `self` must be valid for reads during this call.
    pub unsafe fn app_group_dir(&self) -> Option<PathBuf> {
        // SAFETY: pointer + length validity is guaranteed by caller contract.
        unsafe { opt_utf8(self.app_group_dir_utf8, self.app_group_dir_utf8_len) }.map(PathBuf::from)
    }
}

impl TransparentProxyConfig {
    /// Build an owned FFI representation from typed Rust config.
    #[must_use]
    pub fn from_rust_type(config: &tproxy::TransparentProxyConfig) -> Self {
        let (tunnel_remote_address_utf8, tunnel_remote_address_utf8_len) =
            alloc_str_utf8(config.tunnel_remote_address());

        let mut rules = Vec::with_capacity(config.rules().len());
        for rule in config.rules() {
            let (remote_network_utf8, remote_network_utf8_len) =
                opt_string_as_utf8_array(rule.remote_network().map(ToString::to_string));
            let (local_network_utf8, local_network_utf8_len) =
                opt_string_as_utf8_array(rule.local_network().map(ToString::to_string));

            rules.push(TransparentProxyNetworkRule {
                remote_network_utf8,
                remote_network_utf8_len,
                remote_prefix: rule.remote_prefix().unwrap_or(0),
                remote_prefix_is_set: rule.remote_prefix().is_some(),
                remote_port: rule.remote_port().unwrap_or(0),
                remote_port_is_set: rule.remote_port().is_some(),
                local_network_utf8,
                local_network_utf8_len,
                local_prefix: rule.local_prefix().unwrap_or(0),
                local_prefix_is_set: rule.local_prefix().is_some(),
                protocol: rule.protocol().as_u32(),
                exclude: rule.exclude(),
            });
        }

        let boxed_rules = rules.into_boxed_slice();
        let rules_len = boxed_rules.len();
        let rules = if rules_len == 0 {
            ptr::null()
        } else {
            Box::into_raw(boxed_rules) as *const TransparentProxyNetworkRule
        };

        Self {
            tunnel_remote_address_utf8,
            tunnel_remote_address_utf8_len,
            rules,
            rules_len,
            tcp_write_pump_max_pending_bytes: config.tcp_write_pump_max_pending_bytes(),
        }
    }

    /// # Safety
    ///
    /// `self` must have been created by [`TransparentProxyConfig::from_rust_type`]
    /// exactly once. Calling this twice on the same allocations is undefined behavior.
    pub unsafe fn free(self) {
        // SAFETY: this pointer/len pair came from `alloc_utf8` in `from_rust_type`.
        unsafe {
            free_utf8(
                self.tunnel_remote_address_utf8,
                self.tunnel_remote_address_utf8_len,
            )
        };

        if self.rules.is_null() || self.rules_len == 0 {
            return;
        }

        let rules_ptr = self.rules as *mut TransparentProxyNetworkRule;
        let boxed_rules = {
            let raw_slice = ptr::slice_from_raw_parts_mut(rules_ptr, self.rules_len);
            // SAFETY: `raw_slice` was produced via `Box::into_raw` in `from_rust_type`.
            unsafe { Box::from_raw(raw_slice) }
        };

        for rule in boxed_rules.iter() {
            // SAFETY: these pointer/len pairs came from `alloc_opt_utf8` in `from_rust_type`.
            unsafe { free_utf8(rule.remote_network_utf8, rule.remote_network_utf8_len) };
            // SAFETY: these pointer/len pairs came from `alloc_opt_utf8` in `from_rust_type`.
            unsafe { free_utf8(rule.local_network_utf8, rule.local_network_utf8_len) };
        }
    }
}

/// Callbacks Swift provides for Rust TCP session events.
///
/// # Lifetime / threading contract for `context`
///
/// * `context` must remain valid (and the pointee must not move) until the
///   corresponding session is freed via
///   `rama_transparent_proxy_tcp_session_free`.
///   `rama_transparent_proxy_tcp_session_cancel` guarantees no further
///   callbacks fire after it returns, but `context` must still outlive the
///   `_free` call — concurrent callbacks already in flight may still observe
///   the pointer until they complete.
///
///   Only to be used for "public" information... its contents are logged
///   to the native log system of Apple, by Apple.
/// * Callbacks may be invoked from any Tokio worker thread. The Swift caller
///   is responsible for any synchronization the pointee requires.
/// * `BytesView` arguments are borrowed for the duration of the call and must
///   be copied before the callback returns if the receiver wants to retain
///   the data.
#[repr(C)]
pub struct TransparentProxyTcpSessionCallbacks {
    pub context: *mut c_void,
    /// Rust → Swift: deliver response bytes to the intercepted client flow.
    /// Returns the raw `u8` of a [`crate::tproxy::TcpDeliverStatus`]
    /// (0=Accepted, 1=Paused, 2=Closed) — Rust decodes it via
    /// `TcpDeliverStatus::from_ffi_u8`, so an out-of-range byte can't
    /// materialize an invalid enum discriminant (UB). The C header /
    /// Swift side use the typed `uint8_t`-backed enum.
    pub on_server_bytes: Option<unsafe extern "C" fn(*mut c_void, BytesView) -> u8>,
    pub on_server_closed: Option<unsafe extern "C" fn(*mut c_void)>,
    /// Rust → Swift: signal that the per-flow ingress channel has space again
    /// after [`crate::tproxy::TransparentProxyTcpSession::on_client_bytes`] returned `Paused`.
    /// Swift must keep `flow.readData` paused until this fires.
    pub on_client_read_demand: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// Callbacks Swift provides for Rust UDP session events.
///
/// `context` lifetime / threading contract: see
/// [`TransparentProxyTcpSessionCallbacks`] above. Same rules apply.
///
/// `on_server_datagram` receives each Rust→Swift datagram along
/// with its peer — the source the reply arrived from, used as the
/// `sentBy` endpoint when Swift writes back through
/// `flow.writeDatagrams`. Peer may be marked absent
/// (`UdpPeerView { present: false, .. }`) when the engine cannot
/// supply attribution.
#[repr(C)]
pub struct TransparentProxyUdpSessionCallbacks {
    pub context: *mut c_void,
    pub on_server_datagram:
        Option<unsafe extern "C" fn(*mut c_void, BytesView, crate::ffi::UdpPeerView)>,
    pub on_client_read_demand: Option<unsafe extern "C" fn(*mut c_void)>,
    pub on_server_closed: Option<unsafe extern "C" fn(*mut c_void)>,
}

// ── Egress (NWConnection) options ─────────────────────────────────────────────

/// C representation of `NwEgressParameters` — NWParameters-level settings
/// applied to TCP egress `NWConnection`s. (UDP egress is service-owned
/// in Rust and does not consume these.)
///
/// Discriminant values for service_class:
///   0=Default 1=Background 2=InteractiveVideo 3=InteractiveVoice
///   4=ResponsiveData 5=Signaling
///
/// Discriminant values for multipath_service_type:
///   0=Disabled 1=Handover 2=Interactive 3=Aggregate
///
/// Discriminant values for required_interface_type / prohibited mask bits:
///   0=Cellular 1=Loopback 2=Other 3=Wifi 4=Wired
///
/// Discriminant values for attribution:
///   0=Developer 1=User
#[repr(C)]
pub struct NwEgressParameters {
    pub has_service_class: bool,
    pub service_class: u8,
    pub has_multipath_service_type: bool,
    pub multipath_service_type: u8,
    pub has_required_interface_type: bool,
    pub required_interface_type: u8,
    pub has_attribution: bool,
    pub attribution: u8,
    /// Bitmask of prohibited interface types (bit0=Cellular bit1=Loopback
    /// bit2=Other bit3=Wifi bit4=Wired).
    pub prohibited_interface_types_mask: u8,
    /// When `true`, Swift calls `NEAppProxyFlow.setMetadata(_:)` to stamp the
    /// intercepted flow's `NEFlowMetaData` onto the egress `NWParameters`.
    ///
    /// See [`crate::tproxy::NwEgressParameters::preserve_original_meta_data`].
    pub preserve_original_meta_data: bool,
    /// See [`crate::tproxy::NwEgressParameters::allow_system_proxy`].
    pub allow_system_proxy: bool,
}

impl NwEgressParameters {
    pub fn from_rust_type(p: &RustNwEgressParameters) -> Self {
        Self {
            has_service_class: p.service_class.is_some(),
            service_class: p.service_class.map(service_class_to_u8).unwrap_or(0),
            has_multipath_service_type: p.multipath_service_type.is_some(),
            multipath_service_type: p.multipath_service_type.map(multipath_to_u8).unwrap_or(0),
            has_required_interface_type: p.required_interface_type.is_some(),
            required_interface_type: p
                .required_interface_type
                .map(interface_type_to_u8)
                .unwrap_or(0),
            has_attribution: p.attribution.is_some(),
            attribution: p.attribution.map(attribution_to_u8).unwrap_or(0),
            prohibited_interface_types_mask: interface_types_to_mask(&p.prohibited_interface_types),
            preserve_original_meta_data: p.preserve_original_meta_data,
            allow_system_proxy: p.allow_system_proxy,
        }
    }
}

fn service_class_to_u8(sc: NwServiceClass) -> u8 {
    match sc {
        NwServiceClass::Default => 0,
        NwServiceClass::Background => 1,
        NwServiceClass::InteractiveVideo => 2,
        NwServiceClass::InteractiveVoice => 3,
        NwServiceClass::ResponsiveData => 4,
        NwServiceClass::Signaling => 5,
    }
}

fn multipath_to_u8(m: NwMultipathServiceType) -> u8 {
    match m {
        NwMultipathServiceType::Disabled => 0,
        NwMultipathServiceType::Handover => 1,
        NwMultipathServiceType::Interactive => 2,
        NwMultipathServiceType::Aggregate => 3,
    }
}

fn interface_type_to_u8(t: NwInterfaceType) -> u8 {
    match t {
        NwInterfaceType::Cellular => 0,
        NwInterfaceType::Loopback => 1,
        NwInterfaceType::Other => 2,
        NwInterfaceType::Wifi => 3,
        NwInterfaceType::Wired => 4,
    }
}

fn attribution_to_u8(a: NwAttribution) -> u8 {
    match a {
        NwAttribution::Developer => 0,
        NwAttribution::User => 1,
    }
}

fn interface_types_to_mask(types: &[NwInterfaceType]) -> u8 {
    let mut mask: u8 = 0;
    for &t in types {
        mask |= 1 << interface_type_to_u8(t);
    }
    mask
}

/// C representation of egress options for TCP `NWConnection`s.
#[repr(C)]
pub struct TcpEgressConnectOptions {
    pub parameters: NwEgressParameters,
    pub has_connect_timeout_ms: bool,
    /// Connection timeout in milliseconds (maps to `NWProtocolTCP.Options.connectionTimeout`).
    pub connect_timeout_ms: u32,
    /// Whether `linger_close_ms` carries a meaningful value.
    /// `false` ⇒ Swift uses its built-in default.
    pub has_linger_close_ms: bool,
    /// Wall-clock cap (milliseconds) on how long the egress
    /// `NWConnection` is allowed to linger after the local side has
    /// sent its FIN before the Swift side force-cancels it.
    ///
    /// See [`crate::tproxy::NwTcpConnectOptions::linger_close_timeout`].
    pub linger_close_ms: u32,
    /// Whether `egress_eof_grace_ms` carries a meaningful value.
    /// `false` ⇒ Swift uses its built-in default.
    pub has_egress_eof_grace_ms: bool,
    /// Grace window (milliseconds) between the egress read pump
    /// observing peer EOF and the Swift side force-cancelling the
    /// connection. See
    /// [`crate::tproxy::NwTcpConnectOptions::egress_eof_grace`].
    pub egress_eof_grace_ms: u32,
    /// Whether the egress `NWConnection` should enable TCP keepalive
    /// (`NWProtocolTCP.Options.enableKeepalive`). Unlike the optional
    /// timing fields below, this carries no `has_` flag: it is always
    /// meaningful and **defaults to `true`** on the Rust side. See
    /// [`crate::tproxy::NwTcpConnectOptions::tcp_keepalive_enabled`].
    pub tcp_keepalive_enabled: bool,
    /// Whether `tcp_keepalive_idle_secs` carries a meaningful value;
    /// `false` ⇒ Swift uses its built-in default.
    pub has_tcp_keepalive_idle_secs: bool,
    /// Idle period (seconds) before the first keepalive probe
    /// (`NWProtocolTCP.Options.keepaliveIdle`).
    pub tcp_keepalive_idle_secs: u32,
    /// Whether `tcp_keepalive_interval_secs` carries a meaningful value;
    /// `false` ⇒ Swift uses its built-in default.
    pub has_tcp_keepalive_interval_secs: bool,
    /// Interval (seconds) between keepalive probes after the first
    /// (`NWProtocolTCP.Options.keepaliveInterval`).
    pub tcp_keepalive_interval_secs: u32,
    /// Whether `tcp_keepalive_count` carries a meaningful value;
    /// `false` ⇒ Swift uses its built-in default.
    pub has_tcp_keepalive_count: bool,
    /// Number of unanswered probes before the connection is declared
    /// dead (`NWProtocolTCP.Options.keepaliveCount`).
    pub tcp_keepalive_count: u32,
}

/// Callbacks passed to
/// `rama_transparent_proxy_tcp_session_register_promote_callbacks`.
///
/// This is a Rust→Swift channel: Rust calls `on_promote_request`
/// when the in-Rust service invokes [`crate::tproxy::PromoteHandle::into_passthrough`].
/// Swift completes the cutover then ACKs by calling
/// `rama_transparent_proxy_tcp_session_confirm_promoted`.
///
/// `context` lifetime / threading contract: see
/// [`TransparentProxyTcpSessionCallbacks`] above. The pointee must
/// outlive the `_session_free` call, callbacks may run on any
/// Tokio worker thread (the Swift side is responsible for any
/// synchronization the pointee needs — e.g. hopping to its
/// flow-private dispatch queue).
#[repr(C)]
pub struct TransparentProxyTcpPromoteCallbacks {
    pub context: *mut c_void,
    /// Rust → Swift: a service called `into_passthrough` on the
    /// per-flow `PromoteHandle`. Swift drains its outgoing writer
    /// pump, atomically rewires the data path to bypass Rust, and
    /// then calls `rama_transparent_proxy_tcp_session_confirm_promoted`.
    pub on_promote_request: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// Status code passed to
/// `rama_transparent_proxy_tcp_session_confirm_promoted`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PromoteConfirmStatus {
    /// Swift completed the cutover. Rust drops its ingress sender so
    /// the service sees EOF after in-flight bytes drain, then
    /// `into_passthrough` resolves with `Ok(())`.
    Ok = 0,
    /// Swift could not complete the cutover. The accompanying reason
    /// string (if any) is surfaced via
    /// [`crate::tproxy::PromoteError::SwiftCutoverFailed`]; the
    /// in-Rust data path keeps running unchanged.
    Failed = 1,
}

impl PromoteConfirmStatus {
    /// Decode a raw byte received across the FFI boundary. The exported
    /// confirm fn takes `u8` (not this enum) so an out-of-range value
    /// can never materialize an invalid discriminant (UB). Unknown
    /// values fail safe to `Failed` — never claim a cutover succeeded
    /// on a corrupt status.
    #[must_use]
    pub fn from_ffi_u8(raw: u8) -> Self {
        match raw {
            0 => Self::Ok,
            _ => Self::Failed,
        }
    }
}

/// Callbacks passed to `rama_transparent_proxy_tcp_session_activate`.
///
/// These are Rust→Swift channels: Rust calls these when it has data for the
/// egress `NWConnection`.
///
/// `context` lifetime / threading contract: see
/// [`TransparentProxyTcpSessionCallbacks`] above. The pointee must outlive the
/// corresponding `_session_free` call, callbacks may run on any thread, and
/// `BytesView` is borrowed for the call's duration.
#[repr(C)]
pub struct TransparentProxyTcpEgressCallbacks {
    pub context: *mut c_void,
    /// Rust calls this to send bytes from the service to the egress NWConnection.
    /// Returns the raw `u8` of a [`crate::tproxy::TcpDeliverStatus`]
    /// (0=Accepted, 1=Paused, 2=Closed) — Rust decodes it via
    /// `TcpDeliverStatus::from_ffi_u8` to avoid UB on an out-of-range
    /// discriminant. The C header / Swift side use the typed enum.
    pub on_write_to_egress: Option<unsafe extern "C" fn(*mut c_void, BytesView) -> u8>,
    /// Rust calls this when the service is done writing to the egress NWConnection.
    pub on_close_egress: Option<unsafe extern "C" fn(*mut c_void)>,
    /// Rust → Swift: signal that the per-flow egress channel has space again
    /// after [`crate::tproxy::TransparentProxyTcpSession::on_egress_bytes`] returned `Paused`.
    /// Swift must keep `connection.receive` paused until this fires.
    pub on_egress_read_demand: Option<unsafe extern "C" fn(*mut c_void)>,
}

fn opt_string_as_utf8_array(value: Option<String>) -> (*const c_char, usize) {
    if let Some(s) = value {
        alloc_vec_utf8(s.into_bytes())
    } else {
        (ptr::null(), 0)
    }
}

#[inline(always)]
fn alloc_str_utf8(value: &str) -> (*const c_char, usize) {
    alloc_vec_utf8(value.as_bytes().to_vec())
}

fn alloc_vec_utf8(value: Vec<u8>) -> (*const c_char, usize) {
    let boxed: Box<[u8]> = value.into_boxed_slice();
    let len = boxed.len();
    if len == 0 {
        return (ptr::null(), 0);
    }
    (Box::into_raw(boxed) as *const u8 as *const c_char, len)
}

/// # Safety
///
/// `ptr/len` must come from `alloc_utf8` and must not be freed more than once.
unsafe fn free_utf8(ptr: *const c_char, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }

    let raw_slice = ptr::slice_from_raw_parts_mut(ptr as *mut u8, len);
    // SAFETY: caller guarantees this points to memory allocated via `alloc_utf8`.
    _ = unsafe { Box::from_raw(raw_slice) };
}

/// # Safety
///
/// `ptr` must be null or readable for `len` bytes and contain UTF-8.
unsafe fn opt_utf8_to_non_empty_str(ptr: *const c_char, len: usize) -> Option<NonEmptyStr> {
    // SAFETY: pointer + length validity is guaranteed by caller contract.
    let raw = unsafe { opt_utf8(ptr, len) }?;
    raw.try_into().ok()
}

/// # Safety
///
/// `ptr` must be null or readable for `len` bytes and contain UTF-8.
unsafe fn opt_utf8_to_host(ptr: *const c_char, len: usize) -> Option<Host> {
    // SAFETY: pointer + length validity is guaranteed by caller contract.
    let raw = unsafe { opt_utf8(ptr, len) }?;
    Host::try_from(raw).ok()
}

/// # Safety
///
/// `ptr` must be null or readable for `len` bytes and contain UTF-8.
unsafe fn opt_utf8<'a>(ptr: *const c_char, len: usize) -> Option<&'a str> {
    if ptr.is_null() || len == 0 {
        return None;
    }

    // SAFETY: pointer + length validity is guaranteed by caller contract.
    let raw = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    let text = std::str::from_utf8(raw).ok()?.trim();
    (!text.is_empty()).then_some(text)
}

/// # Safety
///
/// `ptr` must be null or readable for `len` bytes.
unsafe fn opt_audit_token(ptr: *const u8, len: usize) -> Option<AuditToken> {
    if ptr.is_null() || len == 0 {
        return None;
    }

    // SAFETY: pointer + length validity is guaranteed by caller contract.
    let raw = unsafe { std::slice::from_raw_parts(ptr, len) };
    AuditToken::from_bytes(raw)
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use crate::tproxy::{
        self, TransparentProxyFlowProtocol, TransparentProxyNetworkRule,
        TransparentProxyRuleProtocol,
    };

    use super::{
        NwEgressParameters, PromoteConfirmStatus, TransparentFlowEndpoint, TransparentProxyConfig,
        TransparentProxyFlowMeta,
    };

    #[test]
    fn ffi_enum_decoders_fail_safe_on_bad_byte() {
        use crate::tproxy::TcpDeliverStatus;
        assert_eq!(TcpDeliverStatus::from_ffi_u8(0), TcpDeliverStatus::Accepted);
        assert_eq!(TcpDeliverStatus::from_ffi_u8(1), TcpDeliverStatus::Paused);
        assert_eq!(TcpDeliverStatus::from_ffi_u8(2), TcpDeliverStatus::Closed);
        // Out-of-range bytes must not be UB — they fail safe to Closed.
        assert_eq!(TcpDeliverStatus::from_ffi_u8(3), TcpDeliverStatus::Closed);
        assert_eq!(TcpDeliverStatus::from_ffi_u8(255), TcpDeliverStatus::Closed);

        assert_eq!(
            PromoteConfirmStatus::from_ffi_u8(0),
            PromoteConfirmStatus::Ok
        );
        assert_eq!(
            PromoteConfirmStatus::from_ffi_u8(1),
            PromoteConfirmStatus::Failed
        );
        // Out-of-range bytes fail safe to Failed (never claim success).
        assert_eq!(
            PromoteConfirmStatus::from_ffi_u8(2),
            PromoteConfirmStatus::Failed
        );
        assert_eq!(
            PromoteConfirmStatus::from_ffi_u8(255),
            PromoteConfirmStatus::Failed
        );
    }

    /// Alloc → free round-trip for the FFI config struct. Designed so
    /// that under LeakSanitizer (`just test-e2e-asan`) any heap field
    /// added to `TransparentProxyNetworkRule` that `free` doesn't
    /// release surfaces as a leak. Plain `cargo test` only verifies
    /// that the round-trip doesn't double-free or panic.
    ///
    /// Includes a mix of included AND excluded rules to exercise
    /// both branches of the `exclude` field's round-trip.
    #[test]
    fn ffi_config_round_trip_freed_under_lsan() {
        let config = tproxy::TransparentProxyConfig::default()
            .with_tunnel_remote_address(rama_utils::str::arcstr::ArcStr::from("198.51.100.1:443"))
            .with_rules(vec![
                TransparentProxyNetworkRule::any()
                    .with_remote_network(
                        "example.com"
                            .parse::<rama_net::address::Host>()
                            .expect("valid host"),
                    )
                    .with_remote_network_prefix(24)
                    .with_local_network(
                        "10.0.0.0"
                            .parse::<rama_net::address::Host>()
                            .expect("valid host"),
                    )
                    .with_local_network_prefix(8)
                    .with_protocol(TransparentProxyRuleProtocol::Tcp),
                TransparentProxyNetworkRule::any(),
                // Excluded carve-out with a port — exercises
                // both `exclude = true` AND `remote_port_is_set`
                // branches of the round-trip.
                TransparentProxyNetworkRule::any()
                    .with_remote_network(
                        "169.254.169.254"
                            .parse::<rama_net::address::Host>()
                            .expect("valid host"),
                    )
                    .with_remote_network_prefix(32)
                    .with_remote_port(80)
                    .with_protocol(TransparentProxyRuleProtocol::Any)
                    .excluded(),
            ]);

        let ffi = TransparentProxyConfig::from_rust_type(&config);
        // SAFETY: `ffi` was just created by `from_rust_type` and not
        // freed yet.
        unsafe { ffi.free() };
    }

    /// Verify the `exclude` field round-trips through the FFI
    /// alloc → slice-read shape. Includes a mix to ensure the
    /// per-rule field is preserved at the correct index.
    #[test]
    fn ffi_rule_exclude_field_round_trips_through_ffi() {
        let config = tproxy::TransparentProxyConfig::default().with_rules(vec![
            TransparentProxyNetworkRule::any(),
            TransparentProxyNetworkRule::any()
                .with_protocol(TransparentProxyRuleProtocol::Tcp)
                .excluded(),
            TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Udp),
            TransparentProxyNetworkRule::any().with_exclude(true),
        ]);

        let ffi = TransparentProxyConfig::from_rust_type(&config);
        assert_eq!(ffi.rules_len, 4);
        // SAFETY: alloc came from `from_rust_type` and lives
        // until our `free` call at the end.
        let slice = unsafe { std::slice::from_raw_parts(ffi.rules, ffi.rules_len) };
        assert!(!slice[0].exclude, "rule 0: default = included");
        assert!(slice[1].exclude, "rule 1: `.excluded()` → excluded");
        assert!(!slice[2].exclude, "rule 2: default = included");
        assert!(slice[3].exclude, "rule 3: `.with_exclude(true)` → excluded");
        // SAFETY: same alloc as above.
        unsafe { ffi.free() };
    }

    #[test]
    fn ffi_rule_remote_port_field_round_trips_through_ffi() {
        let config = tproxy::TransparentProxyConfig::default().with_rules(vec![
            TransparentProxyNetworkRule::any(),
            TransparentProxyNetworkRule::any().with_remote_port(443),
            TransparentProxyNetworkRule::any().with_remote_port(0),
            TransparentProxyNetworkRule::any().with_remote_port(65535),
        ]);

        let ffi = TransparentProxyConfig::from_rust_type(&config);
        assert_eq!(ffi.rules_len, 4);
        // SAFETY: alloc came from `from_rust_type`; freed below.
        let slice = unsafe { std::slice::from_raw_parts(ffi.rules, ffi.rules_len) };
        assert!(!slice[0].remote_port_is_set);
        assert_eq!(slice[0].remote_port, 0, "unset → zeroed");
        assert!(slice[1].remote_port_is_set);
        assert_eq!(slice[1].remote_port, 443);
        assert!(slice[2].remote_port_is_set);
        assert_eq!(slice[2].remote_port, 0, "explicit 0 survives");
        assert!(slice[3].remote_port_is_set);
        assert_eq!(slice[3].remote_port, 65535, "u16 max survives");
        // SAFETY: same alloc as above.
        unsafe { ffi.free() };
    }

    /// Locks in `preserve_original_meta_data: true` as the FFI default
    /// for [`NwEgressParameters`]. Stacked-NE-provider deployments
    /// rely on this so a downstream `NEAppProxyProvider` sees the
    /// original app's `NEFlowMetaData` rather than the rama-extension
    /// process; flipping the default would silently break attribution
    /// in those topologies.
    #[test]
    fn ffi_egress_params_preserve_meta_default_round_trip() {
        let rust = tproxy::NwEgressParameters::default();
        assert!(rust.preserve_original_meta_data);
        let ffi = NwEgressParameters::from_rust_type(&rust);
        assert!(ffi.preserve_original_meta_data);
    }

    /// Pin `allow_system_proxy: false` default — flipping re-enables
    /// the stacked-proxy loop.
    #[test]
    fn ffi_egress_params_allow_system_proxy_default_round_trip() {
        let rust = tproxy::NwEgressParameters::default();
        assert!(!rust.allow_system_proxy);
        let ffi = NwEgressParameters::from_rust_type(&rust);
        assert!(!ffi.allow_system_proxy);
    }

    /// Opt-in round-trip — catches a regression that hard-codes `false`.
    #[test]
    fn ffi_egress_params_allow_system_proxy_opt_in_round_trip() {
        let rust = tproxy::NwEgressParameters {
            allow_system_proxy: true,
            ..tproxy::NwEgressParameters::default()
        };
        let ffi = NwEgressParameters::from_rust_type(&rust);
        assert!(ffi.allow_system_proxy);
    }

    #[test]
    fn flow_meta_uses_explicit_pid_when_present() {
        let meta = TransparentProxyFlowMeta {
            protocol: TransparentProxyFlowProtocol::Tcp.as_u32(),
            remote_endpoint: TransparentFlowEndpoint {
                host_utf8: ptr::null(),
                host_utf8_len: 0,
                port: 0,
            },
            local_endpoint: TransparentFlowEndpoint {
                host_utf8: ptr::null(),
                host_utf8_len: 0,
                port: 0,
            },
            source_app_signing_identifier_utf8: ptr::null(),
            source_app_signing_identifier_utf8_len: 0,
            source_app_bundle_identifier_utf8: ptr::null(),
            source_app_bundle_identifier_utf8_len: 0,
            source_app_audit_token_bytes: ptr::null(),
            source_app_audit_token_bytes_len: 0,
            source_app_pid: 4242,
            source_app_pid_is_set: true,
        };

        // SAFETY: every pointer field is null with matching len 0 above, so
        // the read-validity contract is trivially satisfied.
        let owned = unsafe { meta.as_owned_rust_type() }.expect("known protocol decodes");
        assert_eq!(owned.source_app_pid, Some(4242));
        assert!(owned.source_app_audit_token.is_none());
    }

    /// Unknown protocol values must surface as `Err(raw)` so the FFI
    /// thunks can fail-safe to passthrough rather than silently
    /// fabricating a TCP flow. Pinning the contract: if a future ABI
    /// renumbers the protocol enum, this test catches the regression.
    #[test]
    fn flow_meta_rejects_unknown_protocol() {
        let meta = TransparentProxyFlowMeta {
            protocol: 0xDEAD_BEEF,
            remote_endpoint: TransparentFlowEndpoint {
                host_utf8: ptr::null(),
                host_utf8_len: 0,
                port: 0,
            },
            local_endpoint: TransparentFlowEndpoint {
                host_utf8: ptr::null(),
                host_utf8_len: 0,
                port: 0,
            },
            source_app_signing_identifier_utf8: ptr::null(),
            source_app_signing_identifier_utf8_len: 0,
            source_app_bundle_identifier_utf8: ptr::null(),
            source_app_bundle_identifier_utf8_len: 0,
            source_app_audit_token_bytes: ptr::null(),
            source_app_audit_token_bytes_len: 0,
            source_app_pid: 0,
            source_app_pid_is_set: false,
        };
        // SAFETY: same as above.
        let result = unsafe { meta.as_owned_rust_type() };
        assert_eq!(result.unwrap_err(), 0xDEAD_BEEF);
    }
}
