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

/// Borrowed Swift establishment diagnostics; see the C header for ownership.
///
/// Every `*_utf8` pointer + length pair follows the
/// [byte-range contract](crate::ffi::BytesView#byte-range-contract).
#[repr(C)]
pub struct TcpEgressReport {
    pub ready: bool,
    pub report_available: bool,
    pub used_proxy: bool,
    pub proxy_configured: bool,
    pub allow_proxy: bool,
    pub proxy_policy: u8,
    pub connect_duration_ms: u64,
    pub report_duration_ms: u64,
    pub proxy_endpoint_utf8: *const c_char,
    pub proxy_endpoint_utf8_len: usize,
    pub error_utf8: *const c_char,
    pub error_utf8_len: usize,
}

impl TcpEgressReport {
    /// # Safety
    ///
    /// The caller must ensure both `*_utf8` pairs meet the
    /// [byte-range contract](crate::ffi::BytesView#byte-range-contract) for as
    /// long as the returned report is used. Non-UTF-8 text decodes as `None`.
    pub unsafe fn to_rust_type(&self) -> crate::tproxy::TcpEgressReport<'_> {
        crate::tproxy::TcpEgressReport {
            ready: self.ready,
            allow_proxy: self.allow_proxy,
            proxy_policy: self.proxy_policy.into(),
            connect_duration_ms: self.connect_duration_ms,
            report_duration_ms: self.report_available.then_some(self.report_duration_ms),
            used_proxy: self.report_available.then_some(self.used_proxy),
            proxy_configured: self.report_available.then_some(self.proxy_configured),
            // SAFETY: `opt_utf8_borrowed` needs the pair to meet the byte-range
            // contract for the returned borrow, tied here to the report's
            // lifetime; this fn's precondition covers exactly that.
            proxy_endpoint: unsafe {
                opt_utf8_borrowed(self.proxy_endpoint_utf8, self.proxy_endpoint_utf8_len)
            },
            // SAFETY: as for `proxy_endpoint` above.
            error: unsafe { opt_utf8_borrowed(self.error_utf8, self.error_utf8_len) },
        }
    }
}

// Unlike retained flow metadata, these strings only live through a synchronous log.
/// # Safety
///
/// The caller must ensure `(ptr, len)` meets the
/// [byte-range contract](crate::ffi::BytesView#byte-range-contract) for all
/// of `'a`.
unsafe fn opt_utf8_borrowed<'a>(ptr: *const c_char, len: usize) -> Option<&'a str> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: `slice::from_raw_parts` needs a non-null pointer aligned for
    // `u8` (`c_char` has the same size), valid for reads of `len` initialized
    // bytes in one allocation, `len <= isize::MAX`, unmutated for `'a`.
    // Non-null and `len > 0` are checked above; the rest is the precondition.
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(ptr.cast(), len) }).ok()
}

#[repr(C)]
pub struct TransparentFlowEndpoint {
    pub host_utf8: *const c_char,
    pub host_utf8_len: usize,
    pub port: u16,
}

impl TransparentFlowEndpoint {
    /// # Safety
    ///
    /// The caller must ensure `(host_utf8, host_utf8_len)` meets the
    /// [byte-range contract](crate::ffi::BytesView#byte-range-contract) for
    /// the duration of this call. The result owns a copy; non-UTF-8 or
    /// unparsable hosts yield `None`.
    pub unsafe fn as_optional_host_with_port(&self) -> Option<HostWithPort> {
        if self.port == 0 {
            return None;
        }

        // SAFETY: `opt_utf8_to_host` needs the byte-range contract for this
        // call, which is this fn's precondition.
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
    /// Remote hostname the originating app connected to (the DNS name, not the
    /// resolved IP), when the OS exposes it. `null` / `0` when absent.
    pub remote_hostname_utf8: *const c_char,
    /// Length of `remote_hostname_utf8`.
    pub remote_hostname_utf8_len: usize,
    /// Name of the network interface the flow egresses on (e.g. `en0`,
    /// `utun4`), when known. `null` / `0` when absent.
    pub local_interface_name_utf8: *const c_char,
    /// Length of `local_interface_name_utf8`.
    pub local_interface_name_utf8_len: usize,
    /// Egress interface index. Only valid when `local_interface_index_is_set`.
    pub local_interface_index: u32,
    /// Whether `local_interface_index` is set.
    pub local_interface_index_is_set: bool,
    /// Egress interface type, as a [`NwInterfaceType`] discriminant. Only valid
    /// when `local_interface_type_is_set`.
    pub local_interface_type: u8,
    /// Whether `local_interface_type` is set.
    pub local_interface_type_is_set: bool,
    /// Whether the app bound this flow to a specific interface. Only valid when
    /// `is_bound_is_set`.
    pub is_bound: bool,
    /// Whether `is_bound` is set.
    pub is_bound_is_set: bool,
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
    /// The caller must ensure every pointer + length pair in `self`
    /// (including both endpoints) meets the
    /// [byte-range contract](crate::ffi::BytesView#byte-range-contract) for
    /// the duration of this call. The result owns copies of all data.
    ///
    /// Returns `Err(invalid_protocol_code)` when `self.protocol` is not
    /// a known [`TransparentProxyFlowProtocol`] discriminant. The FFI
    /// thunks treat that as a fail-safe `Passthrough` rather than
    /// silently coercing the unknown code into a TCP flow.
    pub unsafe fn as_owned_rust_type(&self) -> Result<tproxy::TransparentProxyFlowMeta, u32> {
        let protocol = TransparentProxyFlowProtocol::from_raw_strict(self.protocol)?;

        // SAFETY: each `opt_*` / `as_optional_host_with_port` call below
        // needs its pair to meet the byte-range contract for this call; the
        // precondition gives that for every pair of `self`.
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

        let local_interface_type = if self.local_interface_type_is_set {
            interface_type_from_u8(self.local_interface_type)
        } else {
            None
        };
        let local_interface_index = self
            .local_interface_index_is_set
            .then_some(self.local_interface_index);
        let is_bound = self.is_bound_is_set.then_some(self.is_bound);

        Ok(tproxy::TransparentProxyFlowMeta::new(protocol)
            .maybe_with_remote_endpoint(
                // SAFETY: see `source_app_audit_token` above.
                unsafe { self.remote_endpoint.as_optional_host_with_port() },
            )
            .maybe_with_local_endpoint(
                // SAFETY: see `source_app_audit_token` above.
                unsafe { self.local_endpoint.as_optional_host_with_port() },
            )
            .maybe_with_source_app_signing_identifier(
                // SAFETY: see `source_app_audit_token` above.
                unsafe {
                    opt_utf8_to_non_empty_str(
                        self.source_app_signing_identifier_utf8,
                        self.source_app_signing_identifier_utf8_len,
                    )
                },
            )
            .maybe_with_source_app_bundle_identifier(
                // SAFETY: see `source_app_audit_token` above.
                unsafe {
                    opt_utf8_to_non_empty_str(
                        self.source_app_bundle_identifier_utf8,
                        self.source_app_bundle_identifier_utf8_len,
                    )
                },
            )
            .maybe_with_source_app_audit_token(source_app_audit_token)
            .maybe_with_source_app_pid(source_app_pid)
            .maybe_with_remote_hostname(
                // SAFETY: see `source_app_audit_token` above.
                unsafe {
                    opt_utf8_to_boxed_str(self.remote_hostname_utf8, self.remote_hostname_utf8_len)
                },
            )
            .maybe_with_local_interface_name(
                // SAFETY: see `source_app_audit_token` above.
                unsafe {
                    opt_utf8_to_boxed_str(
                        self.local_interface_name_utf8,
                        self.local_interface_name_utf8_len,
                    )
                },
            )
            .maybe_with_local_interface_type(local_interface_type)
            .maybe_with_local_interface_index(local_interface_index)
            .maybe_with_is_bound(is_bound))
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
    /// See [`tproxy::TransparentProxyConfig::flow_pressure_soft_cap`].
    pub flow_pressure_soft_cap: u32,
    /// See [`tproxy::TransparentProxyConfig::flow_pressure_low_water`].
    pub flow_pressure_low_water: u32,
    /// See [`tproxy::TransparentProxyConfig::flow_pressure_idle_floor_ms`].
    pub flow_pressure_idle_floor_ms: u32,
    /// See [`tproxy::TransparentProxyConfig::tcp_start_in_flight_hard_cap`].
    pub tcp_start_in_flight_hard_cap: u32,
    /// See [`tproxy::TransparentProxyConfig::tcp_start_in_flight_soft_cap`].
    pub tcp_start_in_flight_soft_cap: u32,
    /// See [`tproxy::TransparentProxyConfig::tcp_start_latency_breaker_p95_ms`].
    pub tcp_start_latency_breaker_p95_ms: u32,
    /// See [`tproxy::TransparentProxyConfig::tcp_start_latency_breaker_close_p95_ms`].
    pub tcp_start_latency_breaker_close_p95_ms: u32,
    /// See [`tproxy::TransparentProxyConfig::tcp_pressure_connect_timeout_ms`].
    pub tcp_pressure_connect_timeout_ms: u32,
    /// See [`tproxy::TransparentProxyConfig::tcp_breaker_connect_timeout_ms`].
    pub tcp_breaker_connect_timeout_ms: u32,
    /// Action when the provider declines a flow for its own reasons (start cap /
    /// breaker, or missing session): `0` = Block, `1` = Passthrough (default).
    /// See [`tproxy::FlowRefusalAction`].
    pub flow_refusal_action: u32,
    /// See [`tproxy::TransparentProxyConfig::live_flow_hard_cap`].
    pub live_flow_hard_cap: u32,
}

#[repr(C)]
pub struct TransparentProxyInitConfig {
    pub storage_dir_utf8: *const c_char,
    pub storage_dir_utf8_len: usize,
    pub app_group_dir_utf8: *const c_char,
    pub app_group_dir_utf8_len: usize,
    pub bundle_identifier_utf8: *const c_char,
    pub bundle_identifier_utf8_len: usize,
}

impl TransparentProxyInitConfig {
    /// Decode into the owned [`tproxy::TransparentProxyInitConfig`].
    ///
    /// # Safety
    ///
    /// The caller must ensure every pointer + length pair in `self` meets the
    /// [byte-range contract](crate::ffi::BytesView#byte-range-contract) for
    /// the duration of this call. The result owns copies of all data;
    /// non-UTF-8 or blank fields decode as `None`.
    #[must_use]
    pub unsafe fn as_owned_rust_type(&self) -> tproxy::TransparentProxyInitConfig {
        // SAFETY: `opt_utf8` needs its pair to meet the byte-range contract
        // for the borrow, which ends at the copy below; the precondition gives
        // that for every pair of `self` (also for the two blocks below).
        let storage_dir = unsafe { opt_utf8(self.storage_dir_utf8, self.storage_dir_utf8_len) };
        // SAFETY: see above.
        let app_group_dir =
            unsafe { opt_utf8(self.app_group_dir_utf8, self.app_group_dir_utf8_len) };
        // SAFETY: see above.
        let bundle_identifier =
            unsafe { opt_utf8(self.bundle_identifier_utf8, self.bundle_identifier_utf8_len) };
        tproxy::TransparentProxyInitConfig {
            storage_dir: storage_dir.map(PathBuf::from),
            app_group_dir: app_group_dir.map(PathBuf::from),
            bundle_identifier: bundle_identifier.map(Box::from),
        }
    }
}

impl TransparentProxyConfig {
    /// Build an owned FFI representation from typed Rust config.
    ///
    /// # Safety-usable invariant
    ///
    /// Each `*_utf8` pair is `(null, 0)` or the `alloc_vec_utf8` output for a
    /// non-empty buffer, and `rules` is null with `rules_len == 0` or the
    /// `Box::into_raw` pointer of a `Box<[TransparentProxyNetworkRule]>` of
    /// length `rules_len > 0`. Release it once with [`Self::free`].
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
            flow_pressure_soft_cap: config.flow_pressure_soft_cap(),
            flow_pressure_low_water: config.flow_pressure_low_water(),
            flow_pressure_idle_floor_ms: config.flow_pressure_idle_floor_ms(),
            tcp_start_in_flight_hard_cap: config.tcp_start_in_flight_hard_cap(),
            tcp_start_in_flight_soft_cap: config.tcp_start_in_flight_soft_cap(),
            tcp_start_latency_breaker_p95_ms: config.tcp_start_latency_breaker_p95_ms(),
            tcp_start_latency_breaker_close_p95_ms: config.tcp_start_latency_breaker_close_p95_ms(),
            tcp_pressure_connect_timeout_ms: config.tcp_pressure_connect_timeout_ms(),
            tcp_breaker_connect_timeout_ms: config.tcp_breaker_connect_timeout_ms(),
            flow_refusal_action: match config.flow_refusal_action() {
                tproxy::FlowRefusalAction::Block => 0,
                tproxy::FlowRefusalAction::Passthrough => 1,
            },
            live_flow_hard_cap: config.live_flow_hard_cap(),
        }
    }

    /// # Safety
    ///
    /// The caller must ensure `self` holds, unmodified, the fields returned by
    /// [`TransparentProxyConfig::from_rust_type`], and that no other copy of
    /// them is freed or used afterwards. Every allocation is then freed once.
    pub unsafe fn free(self) {
        // SAFETY: `free_utf8` needs an `alloc_vec_utf8` pair (or null/0) freed
        // once; the precondition and `from_rust_type`'s invariant give that.
        unsafe {
            free_utf8(
                self.tunnel_remote_address_utf8,
                self.tunnel_remote_address_utf8_len,
            )
        };

        if self.rules.is_null() || self.rules_len == 0 {
            return;
        }

        let rules_ptr = self.rules.cast_mut();
        let boxed_rules = {
            let raw_slice = ptr::slice_from_raw_parts_mut(rules_ptr, self.rules_len);
            // SAFETY: `Box::from_raw` needs a pointer from `Box::into_raw` of the
            // same type, not yet freed. Non-null here, so by the precondition and
            // `from_rust_type`'s invariant it is the boxed rules slice of length
            // `rules_len`, with no other owner. The new `Box` frees it on drop.
            unsafe { Box::from_raw(raw_slice) }
        };

        for rule in boxed_rules.iter() {
            // SAFETY: as for the tunnel address above; each rule pair is an
            // unfreed `alloc_vec_utf8` output (or null/0) owned by this config.
            unsafe { free_utf8(rule.remote_network_utf8, rule.remote_network_utf8_len) };
            // SAFETY: as above.
            unsafe { free_utf8(rule.local_network_utf8, rule.local_network_utf8_len) };
        }
    }
}

/// Callbacks Swift provides for Rust TCP session events.
///
/// # Callback contract
///
/// The foreign caller handing these callbacks to Rust must ensure:
///
/// * each `Some` entry is an `extern "C"` function with exactly this
///   signature that does not unwind, and may be called with `context` from
///   any thread, concurrently with the other entries of the same session;
/// * `context` (and whatever the callbacks reach through it) stays valid
///   from the registering call until `rama_transparent_proxy_tcp_session_free`
///   returns for this session. If the registering call yields no session,
///   Rust keeps no reference once that call returns.
///   `rama_transparent_proxy_tcp_session_cancel` guarantees no further
///   callbacks fire after it returns, but `context` must still outlive the
///   `_free` call — concurrent callbacks already in flight may still observe
///   the pointer until they complete.
///
///   Only to be used for "public" information... its contents are logged
///   to the native log system of Apple, by Apple.
/// * Callbacks may be invoked from any Tokio worker thread. The Swift caller
///   is responsible for any synchronization the pointee requires.
/// * A callback must not synchronously call back into the same session. The
///   engine holds a non-reentrant lifetime gate across dispatch, while foreign
///   wrappers commonly serialize session entry through their own lock. Re-entry
///   can therefore deadlock through lock inversion. Queue the work elsewhere
///   and return from the callback first.
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
/// The [callback contract](TransparentProxyTcpSessionCallbacks#callback-contract)
/// applies, with `rama_transparent_proxy_udp_session_free` ending it.
///
/// `on_server_datagram` receives each Rust→Swift datagram along
/// with its peer — the source the reply arrived from, used as the
/// `sentBy` endpoint when Swift writes back through
/// `flow.writeDatagrams`. Peer may be marked absent
/// (`UdpPeerView { present: false, .. }`) when the engine cannot
/// supply attribution.
/// The read-demand callback must only schedule the foreign read and return;
/// it must never synchronously re-enter the session. For a non-zero probe ID,
/// ACK that exact ID once the read completes, then submit its datagrams.
/// Pre-ACK delivery is rejected and cannot consume the leased credit.
#[repr(C)]
pub struct TransparentProxyUdpSessionCallbacks {
    pub context: *mut c_void,
    pub on_server_datagram:
        Option<unsafe extern "C" fn(*mut c_void, BytesView, crate::ffi::UdpPeerView)>,
    /// `probe_id == 0` is an ordinary service demand. A non-zero ID carries
    /// one leased global-pressure scheduling credit which must be ACKed via
    /// `rama_transparent_proxy_udp_session_on_client_read_complete` after the
    /// foreign read completes and before its datagrams are submitted.
    pub on_client_read_demand: Option<unsafe extern "C" fn(*mut c_void, u64)>,
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
    /// See [`crate::tproxy::NwEgressParameters::allow_proxy`].
    pub allow_proxy: bool,
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
            allow_proxy: p.allow_proxy,
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

/// Inverse of [`interface_type_to_u8`]: decode an FFI discriminant back into a
/// [`NwInterfaceType`]. Returns `None` for unknown codes (fail-safe: the egress
/// interface is simply treated as unknown rather than coerced). The Swift side
/// is responsible for mapping `nw_interface_type_t` to these discriminants.
fn interface_type_from_u8(raw: u8) -> Option<NwInterfaceType> {
    match raw {
        0 => Some(NwInterfaceType::Cellular),
        1 => Some(NwInterfaceType::Loopback),
        2 => Some(NwInterfaceType::Other),
        3 => Some(NwInterfaceType::Wifi),
        4 => Some(NwInterfaceType::Wired),
        _ => None,
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
    /// Grace (milliseconds) after a promoted flow reaches terminal before
    /// Swift force-cancels its egress `NWConnection`.
    ///
    /// See [`crate::tproxy::NwTcpConnectOptions::linger_close_timeout`].
    pub linger_close_ms: u32,
    /// Whether `egress_eof_grace_ms` carries a meaningful value.
    /// `false` ⇒ Swift uses its built-in default.
    pub has_egress_eof_grace_ms: bool,
    /// Grace window (milliseconds) after an abnormal egress-read stop
    /// before the Swift side force-cancels the connection. Clean peer
    /// EOF does not arm this fallback. See
    /// [`crate::tproxy::NwTcpConnectOptions::egress_eof_grace`].
    pub egress_eof_grace_ms: u32,
    /// Enable TCP keepalive (`enableKeepalive`). No `has_` flag — always
    /// meaningful, defaults `true`. See
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
    /// `NWProtocolTCP.Options.noDelay` (TCP_NODELAY). No `has_` flag —
    /// always meaningful, defaults `true` (like keepalive): the relay is
    /// the only Nagle decision-maker in the path. See
    /// [`crate::tproxy::NwTcpConnectOptions::tcp_no_delay`].
    pub tcp_no_delay: bool,
    /// Whether `tcp_no_push` carries a meaningful value.
    pub has_tcp_no_push: bool,
    /// `NWProtocolTCP.Options.noPush` (TCP_NOPUSH).
    pub tcp_no_push: bool,
    /// Whether `tcp_no_options` carries a meaningful value.
    pub has_tcp_no_options: bool,
    /// `NWProtocolTCP.Options.noOptions` — disable TCP option negotiation.
    pub tcp_no_options: bool,
    /// Whether `tcp_retransmit_fin_drop` carries a meaningful value.
    pub has_tcp_retransmit_fin_drop: bool,
    /// `NWProtocolTCP.Options.retransmitFinDrop`.
    pub tcp_retransmit_fin_drop: bool,
    /// Whether `tcp_disable_ack_stretching` carries a meaningful value.
    pub has_tcp_disable_ack_stretching: bool,
    /// `NWProtocolTCP.Options.disableAckStretching`.
    pub tcp_disable_ack_stretching: bool,
    /// Whether `tcp_enable_fast_open` carries a meaningful value.
    pub has_tcp_enable_fast_open: bool,
    /// `NWProtocolTCP.Options.enableFastOpen` (TFO). See
    /// [`crate::tproxy::NwTcpConnectOptions::tcp_enable_fast_open`].
    pub tcp_enable_fast_open: bool,
    /// Whether `tcp_disable_ecn` carries a meaningful value.
    pub has_tcp_disable_ecn: bool,
    /// `NWProtocolTCP.Options.disableECN`.
    pub tcp_disable_ecn: bool,
    /// Whether `tcp_maximum_segment_size` carries a meaningful value.
    pub has_tcp_maximum_segment_size: bool,
    /// `NWProtocolTCP.Options.maximumSegmentSize` (bytes).
    pub tcp_maximum_segment_size: u32,
    /// Whether `tcp_connection_drop_time_secs` carries a meaningful value.
    pub has_tcp_connection_drop_time_secs: bool,
    /// `NWProtocolTCP.Options.connectionDropTime` (seconds) — cap on
    /// unacknowledged retransmissions before the connection is dropped.
    pub tcp_connection_drop_time_secs: u32,
    /// Whether `tcp_persist_timeout_secs` carries a meaningful value.
    pub has_tcp_persist_timeout_secs: bool,
    /// `NWProtocolTCP.Options.persistTimeout` (seconds) — cap on
    /// zero-window persist before the connection is dropped.
    pub tcp_persist_timeout_secs: u32,
}

/// Callbacks passed to
/// `rama_transparent_proxy_tcp_session_register_promote_callbacks`.
///
/// This is a Rust→Swift channel: Rust calls `on_promote_request`
/// when the in-Rust service invokes [`crate::tproxy::PromoteHandle::into_passthrough`].
/// Swift queue-hops, returns from the callback, completes the cutover, then ACKs by calling
/// `rama_transparent_proxy_tcp_session_confirm_promoted`.
///
/// The [callback contract](TransparentProxyTcpSessionCallbacks#callback-contract)
/// applies: the pointee must outlive the `_session_free` call, callbacks may
/// run on any Tokio worker thread (the Swift side is responsible for any
/// synchronization the pointee needs — e.g. hopping to its flow-private
/// dispatch queue).
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
/// The [callback contract](TransparentProxyTcpSessionCallbacks#callback-contract)
/// applies: the pointee must outlive the corresponding `_session_free` call,
/// callbacks may run on any thread, and `BytesView` is borrowed for the
/// call's duration.
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

/// # Safety-usable invariant
///
/// Returns `(null, 0)` for empty input, else the `Box::into_raw` pointer of a
/// `Box<[u8]>` holding the input and its length, owned by the caller.
fn alloc_vec_utf8(value: Vec<u8>) -> (*const c_char, usize) {
    let boxed: Box<[u8]> = value.into_boxed_slice();
    let len = boxed.len();
    if len == 0 {
        return (ptr::null(), 0);
    }
    (Box::into_raw(boxed).cast::<c_char>().cast_const(), len)
}

/// # Safety
///
/// The caller must ensure `(ptr, len)` is `(null, 0)` or an unmodified
/// [`alloc_vec_utf8`] output that is freed only here and not used afterwards.
unsafe fn free_utf8(ptr: *const c_char, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }

    let raw_slice = ptr::slice_from_raw_parts_mut(ptr as *mut u8, len);
    // SAFETY: `Box::from_raw` needs a `Box::into_raw` pointer of the same type,
    // not yet freed. By the precondition and `alloc_vec_utf8`'s invariant,
    // `(ptr, len)` is the raw `Box<[u8]>` of length `len`, with no other owner.
    _ = unsafe { Box::from_raw(raw_slice) };
}

/// # Safety
///
/// The caller must ensure `(ptr, len)` meets the
/// [byte-range contract](crate::ffi::BytesView#byte-range-contract) for the
/// duration of this call. The result owns a copy.
unsafe fn opt_utf8_to_non_empty_str(ptr: *const c_char, len: usize) -> Option<NonEmptyStr> {
    // SAFETY: `opt_utf8` needs the byte-range contract for the borrow, which
    // ends at the copy below; the precondition covers this call.
    let raw = unsafe { opt_utf8(ptr, len) }?;
    raw.try_into().ok()
}

/// Copy a borrowed FFI string into an owned `Box<str>` (trimmed, non-empty),
/// or `None` when the pointer is null / empty. Used for transient flow-meta
/// strings the Swift side only keeps alive for the duration of the FFI call,
/// so they must be copied out rather than borrowed.
///
/// # Safety
///
/// Same as [`opt_utf8_to_non_empty_str`].
unsafe fn opt_utf8_to_boxed_str(ptr: *const c_char, len: usize) -> Option<Box<str>> {
    // SAFETY: `opt_utf8` needs the byte-range contract for the borrow, which
    // ends at the copy below; the precondition covers this call.
    let raw = unsafe { opt_utf8(ptr, len) }?;
    Some(Box::from(raw))
}

/// # Safety
///
/// Same as [`opt_utf8_to_non_empty_str`].
unsafe fn opt_utf8_to_host(ptr: *const c_char, len: usize) -> Option<Host> {
    // SAFETY: `opt_utf8` needs the byte-range contract for the borrow, which
    // ends at the copy below; the precondition covers this call.
    let raw = unsafe { opt_utf8(ptr, len) }?;
    Host::try_from(raw).ok()
}

/// # Safety
///
/// The caller must ensure `(ptr, len)` meets the
/// [byte-range contract](crate::ffi::BytesView#byte-range-contract) for all
/// of `'a`. Non-UTF-8 or blank text yields `None`.
unsafe fn opt_utf8<'a>(ptr: *const c_char, len: usize) -> Option<&'a str> {
    if ptr.is_null() || len == 0 {
        return None;
    }

    // SAFETY: `slice::from_raw_parts` needs a non-null pointer aligned for
    // `u8` (`c_char` has the same size), valid for reads of `len` initialized
    // bytes in one allocation, `len <= isize::MAX`, unmutated for `'a`.
    // Non-null and `len > 0` are checked above; the rest is the precondition.
    let raw = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    let text = std::str::from_utf8(raw).ok()?.trim();
    (!text.is_empty()).then_some(text)
}

/// # Safety
///
/// The caller must ensure `(ptr, len)` meets the
/// [byte-range contract](crate::ffi::BytesView#byte-range-contract) for the
/// duration of this call. The result owns a copy.
unsafe fn opt_audit_token(ptr: *const u8, len: usize) -> Option<AuditToken> {
    if ptr.is_null() || len == 0 {
        return None;
    }

    // SAFETY: `slice::from_raw_parts` needs a non-null `u8` pointer valid for
    // reads of `len` initialized bytes in one allocation, `len <= isize::MAX`,
    // unmutated for the borrow. Non-null and `len > 0` are checked above; the
    // rest is the precondition, and the borrow ends at the copy below.
    let raw = unsafe { std::slice::from_raw_parts(ptr, len) };
    AuditToken::from_bytes(raw)
}

// ABI pins: every `repr(C)` type above must match its twin in
// `rama_apple_ne_ffi.h` field for field (sizes, alignment and offsets as the
// header compiles on 64-bit Apple targets).
#[cfg(target_pointer_width = "64")]
const _: () = {
    use crate::ffi::{BytesOwned, BytesOwnedView, BytesView, UdpPeerView};
    use std::mem::{align_of, offset_of, size_of};

    macro_rules! pin {
        ($ty:ty, $size:literal, $align:literal; $($field:ident = $off:literal),+ $(,)?) => {
            assert!(size_of::<$ty>() == $size);
            assert!(align_of::<$ty>() == $align);
            $(assert!(offset_of!($ty, $field) == $off);)+
        };
    }

    pin!(BytesView, 16, 8;
        ptr = 0,
        len = 8);
    pin!(BytesOwned, 24, 8;
        ptr = 0,
        len = 8,
        cap = 16);
    pin!(BytesOwnedView, 32, 8;
        ptr = 0,
        len = 8,
        owner = 16,
        release = 24);
    pin!(TransparentFlowEndpoint, 24, 8;
        host_utf8 = 0,
        host_utf8_len = 8,
        port = 16);
    pin!(TransparentProxyFlowMeta, 160, 8;
        protocol = 0,
        remote_endpoint = 8,
        local_endpoint = 32,
        source_app_signing_identifier_utf8 = 56,
        source_app_signing_identifier_utf8_len = 64,
        source_app_bundle_identifier_utf8 = 72,
        source_app_bundle_identifier_utf8_len = 80,
        source_app_audit_token_bytes = 88,
        source_app_audit_token_bytes_len = 96,
        source_app_pid = 104,
        source_app_pid_is_set = 108,
        remote_hostname_utf8 = 112,
        remote_hostname_utf8_len = 120,
        local_interface_name_utf8 = 128,
        local_interface_name_utf8_len = 136,
        local_interface_index = 144,
        local_interface_index_is_set = 148,
        local_interface_type = 149,
        local_interface_type_is_set = 150,
        is_bound = 151,
        is_bound_is_set = 152);
    pin!(TransparentProxyNetworkRule, 56, 8;
        remote_network_utf8 = 0,
        remote_network_utf8_len = 8,
        remote_prefix = 16,
        remote_prefix_is_set = 17,
        remote_port = 18,
        remote_port_is_set = 20,
        local_network_utf8 = 24,
        local_network_utf8_len = 32,
        local_prefix = 40,
        local_prefix_is_set = 41,
        protocol = 44,
        exclude = 48);
    pin!(TransparentProxyConfig, 88, 8;
        tunnel_remote_address_utf8 = 0,
        tunnel_remote_address_utf8_len = 8,
        rules = 16,
        rules_len = 24,
        tcp_write_pump_max_pending_bytes = 32,
        flow_pressure_soft_cap = 40,
        flow_pressure_low_water = 44,
        flow_pressure_idle_floor_ms = 48,
        tcp_start_in_flight_hard_cap = 52,
        tcp_start_in_flight_soft_cap = 56,
        tcp_start_latency_breaker_p95_ms = 60,
        tcp_start_latency_breaker_close_p95_ms = 64,
        tcp_pressure_connect_timeout_ms = 68,
        tcp_breaker_connect_timeout_ms = 72,
        flow_refusal_action = 76,
        live_flow_hard_cap = 80);
    pin!(TransparentProxyInitConfig, 48, 8;
        storage_dir_utf8 = 0,
        storage_dir_utf8_len = 8,
        app_group_dir_utf8 = 16,
        app_group_dir_utf8_len = 24,
        bundle_identifier_utf8 = 32,
        bundle_identifier_utf8_len = 40);
    pin!(TransparentProxyTcpSessionCallbacks, 32, 8;
        context = 0,
        on_server_bytes = 8,
        on_server_closed = 16,
        on_client_read_demand = 24);
    pin!(UdpPeerView, 32, 8;
        present = 0,
        host_utf8 = 8,
        host_utf8_len = 16,
        port = 24,
        scope_id = 28);
    pin!(TransparentProxyUdpSessionCallbacks, 32, 8;
        context = 0,
        on_server_datagram = 8,
        on_client_read_demand = 16,
        on_server_closed = 24);
    pin!(NwEgressParameters, 11, 1;
        has_service_class = 0,
        service_class = 1,
        has_multipath_service_type = 2,
        multipath_service_type = 3,
        has_required_interface_type = 4,
        required_interface_type = 5,
        has_attribution = 6,
        attribution = 7,
        prohibited_interface_types_mask = 8,
        preserve_original_meta_data = 9,
        allow_proxy = 10);
    pin!(TcpEgressConnectOptions, 92, 4;
        parameters = 0,
        has_connect_timeout_ms = 11,
        connect_timeout_ms = 12,
        has_linger_close_ms = 16,
        linger_close_ms = 20,
        has_egress_eof_grace_ms = 24,
        egress_eof_grace_ms = 28,
        tcp_keepalive_enabled = 32,
        has_tcp_keepalive_idle_secs = 33,
        tcp_keepalive_idle_secs = 36,
        has_tcp_keepalive_interval_secs = 40,
        tcp_keepalive_interval_secs = 44,
        has_tcp_keepalive_count = 48,
        tcp_keepalive_count = 52,
        tcp_no_delay = 56,
        has_tcp_no_push = 57,
        tcp_no_push = 58,
        has_tcp_no_options = 59,
        tcp_no_options = 60,
        has_tcp_retransmit_fin_drop = 61,
        tcp_retransmit_fin_drop = 62,
        has_tcp_disable_ack_stretching = 63,
        tcp_disable_ack_stretching = 64,
        has_tcp_enable_fast_open = 65,
        tcp_enable_fast_open = 66,
        has_tcp_disable_ecn = 67,
        tcp_disable_ecn = 68,
        has_tcp_maximum_segment_size = 69,
        tcp_maximum_segment_size = 72,
        has_tcp_connection_drop_time_secs = 76,
        tcp_connection_drop_time_secs = 80,
        has_tcp_persist_timeout_secs = 84,
        tcp_persist_timeout_secs = 88);
    pin!(TransparentProxyTcpEgressCallbacks, 32, 8;
        context = 0,
        on_write_to_egress = 8,
        on_close_egress = 16,
        on_egress_read_demand = 24);
    pin!(TransparentProxyTcpPromoteCallbacks, 16, 8;
        context = 0,
        on_promote_request = 8);
    pin!(TcpEgressReport, 56, 8;
        ready = 0,
        report_available = 1,
        used_proxy = 2,
        proxy_configured = 3,
        allow_proxy = 4,
        proxy_policy = 5,
        connect_duration_ms = 8,
        report_duration_ms = 16,
        proxy_endpoint_utf8 = 24,
        proxy_endpoint_utf8_len = 32,
        error_utf8 = 40,
        error_utf8_len = 48);
    assert!(size_of::<TransparentProxyFlowAction>() == 4);
    assert!(size_of::<PromoteConfirmStatus>() == 1);
};

#[cfg(test)]
mod tests {
    use std::ptr;

    use crate::tproxy::{
        self, NwInterfaceType, TransparentProxyFlowProtocol, TransparentProxyNetworkRule,
        TransparentProxyRuleProtocol,
    };

    use super::{
        NwEgressParameters, PromoteConfirmStatus, TcpEgressReport, TransparentFlowEndpoint,
        TransparentProxyConfig, TransparentProxyFlowMeta,
        TransparentProxyInitConfig as FfiTransparentProxyInitConfig, interface_type_from_u8,
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
            .with_flow_pressure_soft_cap(10)
            .with_flow_pressure_low_water(9)
            .with_flow_pressure_idle_floor_ms(8)
            .with_live_flow_hard_cap(20)
            .with_tcp_start_in_flight_hard_cap(7)
            .with_tcp_start_in_flight_soft_cap(6)
            .with_tcp_start_latency_breaker_p95_ms(5)
            .with_tcp_start_latency_breaker_close_p95_ms(4)
            .with_tcp_pressure_connect_timeout_ms(3)
            .with_tcp_breaker_connect_timeout_ms(2)
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

    #[test]
    fn flow_refusal_action_defaults_passthrough_and_maps_to_ffi() {
        use crate::tproxy::FlowRefusalAction;
        // Default is fail-open: capacity refusals decline to the direct route.
        assert_eq!(
            tproxy::TransparentProxyConfig::new().flow_refusal_action(),
            FlowRefusalAction::Passthrough
        );
        assert_eq!(FlowRefusalAction::default(), FlowRefusalAction::Passthrough);
        let pass = TransparentProxyConfig::from_rust_type(&tproxy::TransparentProxyConfig::new());
        assert_eq!(pass.flow_refusal_action, 1);
        // SAFETY: freshly built, not yet freed.
        unsafe { pass.free() };

        // The wire encoding is fixed (0 = Block, 1 = Passthrough) independent
        // of which one is the default, so the Swift side never has to know.
        let cfg = tproxy::TransparentProxyConfig::new()
            .with_flow_refusal_action(FlowRefusalAction::Block);
        assert_eq!(cfg.flow_refusal_action(), FlowRefusalAction::Block);
        let block = TransparentProxyConfig::from_rust_type(&cfg);
        assert_eq!(block.flow_refusal_action, 0);
        // SAFETY: freshly built, not yet freed.
        unsafe { block.free() };
    }

    #[test]
    fn tcp_egress_report_decodes_borrowed_ffi_fields() {
        // Exercise independent ABI fields; this is not a native connection scenario.
        let endpoint = String::from("127.0.0.1:8888");
        let error = String::from("POSIXErrorCode: ECONNREFUSED");
        let mut ffi = TcpEgressReport {
            ready: false,
            report_available: true,
            used_proxy: true,
            proxy_configured: true,
            allow_proxy: false,
            proxy_policy: 1,
            connect_duration_ms: 123,
            report_duration_ms: 120,
            proxy_endpoint_utf8: endpoint.as_ptr().cast(),
            proxy_endpoint_utf8_len: endpoint.len(),
            error_utf8: error.as_ptr().cast(),
            error_utf8_len: error.len(),
        };
        // SAFETY: both pairs point into `endpoint`/`error`, which outlive
        // every report below and are not written.
        let report = unsafe { ffi.to_rust_type() };
        assert!(!report.ready);
        assert_eq!(report.connect_duration_ms, 123);
        assert_eq!(report.report_duration_ms, Some(120));
        assert_eq!(report.used_proxy, Some(true));
        assert_eq!(report.proxy_configured, Some(true));
        assert_eq!(report.proxy_endpoint.unwrap().as_ptr(), endpoint.as_ptr());
        assert_eq!(report.error.unwrap().as_ptr(), error.as_ptr());
        assert!(!report.allow_proxy);
        assert_eq!(
            report.proxy_policy,
            crate::tproxy::TcpProxyPolicy::NoProxyApplied
        );
        assert_eq!(report.proxy_endpoint, Some("127.0.0.1:8888"));
        assert_eq!(report.error, Some("POSIXErrorCode: ECONNREFUSED"));
        ffi.proxy_endpoint_utf8 = std::ptr::null();
        ffi.error_utf8 = std::ptr::null();
        ffi.report_available = false;
        // SAFETY: both pointers are null.
        let report = unsafe { ffi.to_rust_type() };
        assert_eq!(report.used_proxy, None);
        assert_eq!(report.proxy_configured, None);
        assert_eq!(report.report_duration_ms, None);
        assert_eq!(report.proxy_endpoint, None);
        assert_eq!(report.error, None);
        ffi.ready = true;
        ffi.report_available = true;
        ffi.used_proxy = false;
        ffi.proxy_configured = false;
        // SAFETY: both pointers are null.
        let report = unsafe { ffi.to_rust_type() };
        assert!(report.ready);
        assert_eq!(report.used_proxy, Some(false));
        assert_eq!(report.proxy_configured, Some(false));
    }

    #[test]
    fn init_config_reads_bundle_identifier() {
        let bundle_identifier = b"com.example.proxy.provider";
        let config = FfiTransparentProxyInitConfig {
            storage_dir_utf8: ptr::null(),
            storage_dir_utf8_len: 0,
            app_group_dir_utf8: ptr::null(),
            app_group_dir_utf8_len: 0,
            bundle_identifier_utf8: bundle_identifier.as_ptr().cast(),
            bundle_identifier_utf8_len: bundle_identifier.len(),
        };

        // SAFETY: the pair points into the static `bundle_identifier`; the
        // other pairs are null.
        let owned = unsafe { config.as_owned_rust_type() };
        assert_eq!(
            owned.bundle_identifier.as_deref(),
            Some("com.example.proxy.provider")
        );
        assert_eq!(owned.storage_dir, None);
        assert_eq!(owned.app_group_dir, None);
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
    fn ffi_config_overload_fields_round_trip() {
        let config = tproxy::TransparentProxyConfig::default()
            .with_flow_pressure_soft_cap(11)
            .with_flow_pressure_low_water(12)
            .with_flow_pressure_idle_floor_ms(13)
            .with_live_flow_hard_cap(20)
            .with_tcp_start_in_flight_hard_cap(14)
            .with_tcp_start_in_flight_soft_cap(15)
            .with_tcp_start_latency_breaker_p95_ms(16)
            .with_tcp_start_latency_breaker_close_p95_ms(17)
            .with_tcp_pressure_connect_timeout_ms(18)
            .with_tcp_breaker_connect_timeout_ms(19);

        let ffi = TransparentProxyConfig::from_rust_type(&config);
        assert_eq!(ffi.flow_pressure_soft_cap, 11);
        assert_eq!(ffi.flow_pressure_low_water, 12);
        assert_eq!(ffi.flow_pressure_idle_floor_ms, 13);
        assert_eq!(ffi.live_flow_hard_cap, 20);
        assert_eq!(ffi.tcp_start_in_flight_hard_cap, 14);
        assert_eq!(ffi.tcp_start_in_flight_soft_cap, 15);
        assert_eq!(ffi.tcp_start_latency_breaker_p95_ms, 16);
        assert_eq!(ffi.tcp_start_latency_breaker_close_p95_ms, 17);
        assert_eq!(ffi.tcp_pressure_connect_timeout_ms, 18);
        assert_eq!(ffi.tcp_breaker_connect_timeout_ms, 19);
        // SAFETY: `ffi` was just created by `from_rust_type` and not freed yet.
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

    /// Pin `allow_proxy: false` default — flipping re-enables
    /// the stacked-proxy loop.
    #[test]
    fn ffi_egress_params_allow_proxy_default_round_trip() {
        let rust = tproxy::NwEgressParameters::default();
        assert!(!rust.allow_proxy);
        let ffi = NwEgressParameters::from_rust_type(&rust);
        assert!(!ffi.allow_proxy);
    }

    /// Opt-in round-trip — catches a regression that hard-codes `false`.
    #[test]
    fn ffi_egress_params_allow_proxy_opt_in_round_trip() {
        let rust = tproxy::NwEgressParameters {
            allow_proxy: true,
            ..tproxy::NwEgressParameters::default()
        };
        let ffi = NwEgressParameters::from_rust_type(&rust);
        assert!(ffi.allow_proxy);
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
            remote_hostname_utf8: ptr::null(),
            remote_hostname_utf8_len: 0,
            local_interface_name_utf8: ptr::null(),
            local_interface_name_utf8_len: 0,
            local_interface_index: 0,
            local_interface_index_is_set: false,
            local_interface_type: 0,
            local_interface_type_is_set: false,
            is_bound: false,
            is_bound_is_set: false,
        };

        // SAFETY: every pointer field is null with matching len 0 above, so
        // the read-validity contract is trivially satisfied.
        let owned = unsafe { meta.as_owned_rust_type() }.expect("known protocol decodes");
        assert_eq!(owned.source_app_pid, Some(4242));
        assert!(owned.source_app_audit_token.is_none());
        // Unset interface / hostname fields decode to None.
        assert!(owned.remote_hostname.is_none());
        assert!(owned.local_interface_name.is_none());
        assert!(owned.local_interface_type.is_none());
        assert!(owned.local_interface_index.is_none());
        assert!(owned.is_bound.is_none());
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
            remote_hostname_utf8: ptr::null(),
            remote_hostname_utf8_len: 0,
            local_interface_name_utf8: ptr::null(),
            local_interface_name_utf8_len: 0,
            local_interface_index: 0,
            local_interface_index_is_set: false,
            local_interface_type: 0,
            local_interface_type_is_set: false,
            is_bound: false,
            is_bound_is_set: false,
        };
        // SAFETY: same as above.
        let result = unsafe { meta.as_owned_rust_type() };
        assert_eq!(result.unwrap_err(), 0xDEAD_BEEF);
    }

    #[test]
    fn flow_meta_decodes_interface_and_hostname() {
        let hostname = "api.github.com";
        let iface = "utun4";
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
            source_app_pid: 0,
            source_app_pid_is_set: false,
            remote_hostname_utf8: hostname.as_ptr().cast(),
            remote_hostname_utf8_len: hostname.len(),
            local_interface_name_utf8: iface.as_ptr().cast(),
            local_interface_name_utf8_len: iface.len(),
            local_interface_index: 14,
            local_interface_index_is_set: true,
            // 2 == NwInterfaceType::Other (utun/VPN tunnels report as "other").
            local_interface_type: 2,
            local_interface_type_is_set: true,
            is_bound: true,
            is_bound_is_set: true,
        };

        // SAFETY: the two utf8 fields point at the `hostname`/`iface` str
        // literals (valid for this scope, matching lengths); all other
        // pointers are null with len 0.
        let owned = unsafe { meta.as_owned_rust_type() }.expect("known protocol decodes");
        assert_eq!(owned.remote_hostname.as_deref(), Some("api.github.com"));
        assert_eq!(owned.local_interface_name.as_deref(), Some("utun4"));
        assert_eq!(owned.local_interface_type, Some(NwInterfaceType::Other));
        assert_eq!(owned.local_interface_index, Some(14));
        assert_eq!(owned.is_bound, Some(true));
    }

    #[test]
    fn flow_meta_unknown_interface_type_decodes_to_none() {
        // An out-of-range interface-type discriminant must fail safe to None
        // rather than coerce into a valid variant.
        assert!(interface_type_from_u8(2).is_some());
        assert!(interface_type_from_u8(5).is_none());
        assert!(interface_type_from_u8(255).is_none());
    }
}
