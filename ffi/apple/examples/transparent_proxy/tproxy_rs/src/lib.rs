use std::{
    ffi::{CStr, c_char, c_void},
    sync::Once,
};

use rama::telemetry::tracing::subscriber;
use rama::{
    net::{
        Protocol,
        address::{Host, HostWithPort},
        apple::networkextension::{
            ffi::{BytesOwned, BytesView},
            tproxy::{
                TransparentProxyConfig, TransparentProxyEngine, TransparentProxyEngineBuilder,
                TransparentProxyMeta, TransparentProxyNetworkRule, TransparentProxyTcpSession,
                TransparentProxyUdpSession,
            },
        },
    },
    telemetry::tracing,
};

mod tcp;
mod udp;
mod utils;

pub type RamaTransparentProxyEngine = TransparentProxyEngine;
pub type RamaTransparentProxyTcpSession = TransparentProxyTcpSession;
pub type RamaTransparentProxyUdpSession = TransparentProxyUdpSession;

static INIT_TRACING: Once = Once::new();

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlowProtocol {
    Tcp = 1,
    Udp = 2,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleProtocol {
    Any = 0,
    Tcp = 1,
    Udp = 2,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrafficDirection {
    Outbound = 0,
    Inbound = 1,
    Any = 2,
}

#[repr(C)]
pub struct RamaFlowEndpoint {
    pub host_utf8: *const c_char,
    pub port: u16,
}

#[repr(C)]
pub struct RamaTransparentProxyFlowMeta {
    pub protocol: u32,
    pub remote_endpoint: RamaFlowEndpoint,
    pub local_endpoint: RamaFlowEndpoint,
    pub source_app_signing_identifier_utf8: *const c_char,
    pub source_app_bundle_identifier_utf8: *const c_char,
}

#[repr(C)]
pub struct RamaTransparentProxyNetworkRule {
    pub remote_network_utf8: *const c_char,
    pub remote_prefix: u8,
    pub local_network_utf8: *const c_char,
    pub local_prefix: u8,
    pub protocol: u32,
    pub direction: u32,
}

#[repr(C)]
pub struct RamaTransparentProxyStartupConfig {
    pub tunnel_remote_address_utf8: *const c_char,
    pub rules: *const RamaTransparentProxyNetworkRule,
    pub rules_len: usize,
}

#[repr(C)]
pub struct RamaTransparentProxyTcpSessionCallbacks {
    pub context: *mut c_void,
    pub on_server_bytes: Option<extern "C" fn(*mut c_void, BytesView)>,
    pub on_server_closed: Option<extern "C" fn(*mut c_void)>,
}

#[repr(C)]
pub struct RamaTransparentProxyUdpSessionCallbacks {
    pub context: *mut c_void,
    pub on_server_datagram: Option<extern "C" fn(*mut c_void, BytesView)>,
    pub on_server_closed: Option<extern "C" fn(*mut c_void)>,
}

pub use ::rama::net::apple::networkextension::ffi::{LogLevel, log_callback as rama_log};

/// For a transparent proxy implemented via Apple's NetworkExtension framework
/// (using NETransparentProxyProvider), the tunnelRemoteAddress is
/// typically set to localhost (127.0.0.1) as a placeholder/sentinel value.
const TUNNEL_REMOTE_ADDRESS: &CStr = c"127.0.0.1";

static mut STARTUP_RULES: [RamaTransparentProxyNetworkRule; 1] =
    [RamaTransparentProxyNetworkRule {
        remote_network_utf8: std::ptr::null(),
        remote_prefix: 0,
        local_network_utf8: std::ptr::null(),
        local_prefix: 0,
        protocol: RuleProtocol::Any as u32,
        direction: TrafficDirection::Outbound as u32,
    }];
const STARTUP_RULES_LEN: usize = 1;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_initialize() -> bool {
    INIT_TRACING.call_once(|| {
        // TODO: support richer subscriber setup as part of proc macro in future
        let _ = subscriber::fmt::init();
    });
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_get_startup_config(
    out_config: *mut RamaTransparentProxyStartupConfig,
) -> bool {
    if out_config.is_null() {
        return false;
    }
    // SAFETY: `out_config` is checked non-null above and valid per FFI contract.
    unsafe {
        *out_config = RamaTransparentProxyStartupConfig {
            tunnel_remote_address_utf8: TUNNEL_REMOTE_ADDRESS.as_ptr(),
            rules: core::ptr::addr_of!(STARTUP_RULES[0]),
            rules_len: STARTUP_RULES_LEN,
        };
    }
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_should_intercept_flow(
    meta: *const RamaTransparentProxyFlowMeta,
) -> bool {
    if meta.is_null() {
        return false;
    }
    // SAFETY: pointer validity is part of FFI contract.
    let meta = unsafe { meta_from_ffi(&*meta) };
    tracing::trace!(
        protocol = %meta.protocol(),
        remote = ?meta.remote_endpoint(),
        local = ?meta.local_endpoint(),
        "flow intercept decision: accepted"
    );
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_engine_new() -> *mut RamaTransparentProxyEngine {
    let config =
        TransparentProxyConfig::new().with_rules(vec![TransparentProxyNetworkRule::any_outbound()]);

    let engine = TransparentProxyEngineBuilder::new(config)
        .with_tcp_service(self::tcp::new_service())
        .with_udp_service(self::udp::new_service())
        .build();

    Box::into_raw(Box::new(engine))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_engine_free(
    engine: *mut RamaTransparentProxyEngine,
) {
    if engine.is_null() {
        return;
    }
    // SAFETY: `engine` came from `Box::into_raw` in `rama_transparent_proxy_engine_new`.
    unsafe { drop(Box::from_raw(engine)) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_engine_start(
    engine: *mut RamaTransparentProxyEngine,
) {
    if engine.is_null() {
        return;
    }
    // SAFETY: pointer validity is part of FFI contract.
    unsafe { (*engine).start() };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_engine_stop(
    engine: *mut RamaTransparentProxyEngine,
    reason: i32,
) {
    if engine.is_null() {
        return;
    }
    // SAFETY: pointer validity is part of FFI contract.
    unsafe { (*engine).stop(reason) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_engine_new_tcp_session(
    engine: *mut RamaTransparentProxyEngine,
    meta: *const RamaTransparentProxyFlowMeta,
    callbacks: RamaTransparentProxyTcpSessionCallbacks,
) -> *mut RamaTransparentProxyTcpSession {
    if engine.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: pointer validity is part of FFI contract.
    let typed_meta = if meta.is_null() {
        TransparentProxyMeta::new(Protocol::from_static("tcp"))
    } else {
        // SAFETY: pointer validity is part of FFI contract.
        unsafe { meta_from_ffi(&*meta) }
    };

    let context = callbacks.context as usize;
    let on_server_bytes = callbacks.on_server_bytes;
    let on_server_closed = callbacks.on_server_closed;

    // SAFETY: pointer validity is part of FFI contract.
    let session = unsafe {
        (*engine).new_tcp_session(
            typed_meta,
            move |bytes| {
                let Some(callback) = on_server_bytes else {
                    return;
                };
                if bytes.is_empty() {
                    return;
                }
                callback(
                    context as *mut c_void,
                    BytesView {
                        ptr: bytes.as_ptr(),
                        len: bytes.len(),
                    },
                );
            },
            move || {
                if let Some(callback) = on_server_closed {
                    callback(context as *mut c_void);
                }
            },
        )
    };

    match session {
        Some(session) => Box::into_raw(Box::new(session)),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_free(
    session: *mut RamaTransparentProxyTcpSession,
) {
    if session.is_null() {
        return;
    }
    // SAFETY: `session` came from `Box::into_raw` in session constructor.
    unsafe { drop(Box::from_raw(session)) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_bytes(
    session: *mut RamaTransparentProxyTcpSession,
    bytes: BytesView,
) {
    if session.is_null() {
        return;
    }
    // SAFETY: caller guarantees bytes view validity for this call.
    let slice = unsafe { bytes.into_slice() };
    // SAFETY: pointer validity is part of FFI contract.
    unsafe { (*session).on_client_bytes(slice) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_eof(
    session: *mut RamaTransparentProxyTcpSession,
) {
    if session.is_null() {
        return;
    }
    // SAFETY: pointer validity is part of FFI contract.
    unsafe { (*session).on_client_eof() };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_engine_new_udp_session(
    engine: *mut RamaTransparentProxyEngine,
    meta: *const RamaTransparentProxyFlowMeta,
    callbacks: RamaTransparentProxyUdpSessionCallbacks,
) -> *mut RamaTransparentProxyUdpSession {
    if engine.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: pointer validity is part of FFI contract.
    let typed_meta = if meta.is_null() {
        TransparentProxyMeta::new(Protocol::from_static("udp"))
    } else {
        // SAFETY: pointer validity is part of FFI contract.
        unsafe { meta_from_ffi(&*meta) }
    };

    let context = callbacks.context as usize;
    let on_server_datagram = callbacks.on_server_datagram;
    let on_server_closed = callbacks.on_server_closed;

    // SAFETY: pointer validity is part of FFI contract.
    let session = unsafe {
        (*engine).new_udp_session(
            typed_meta,
            move |bytes| {
                let Some(callback) = on_server_datagram else {
                    return;
                };
                if bytes.is_empty() {
                    return;
                }
                callback(
                    context as *mut c_void,
                    BytesView {
                        ptr: bytes.as_ptr(),
                        len: bytes.len(),
                    },
                );
            },
            move || {
                if let Some(callback) = on_server_closed {
                    callback(context as *mut c_void);
                }
            },
        )
    };

    match session {
        Some(session) => Box::into_raw(Box::new(session)),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_udp_session_free(
    session: *mut RamaTransparentProxyUdpSession,
) {
    if session.is_null() {
        return;
    }
    // SAFETY: `session` came from `Box::into_raw` in session constructor.
    unsafe { drop(Box::from_raw(session)) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_udp_session_on_client_datagram(
    session: *mut RamaTransparentProxyUdpSession,
    bytes: BytesView,
) {
    if session.is_null() {
        return;
    }
    // SAFETY: caller guarantees bytes view validity for this call.
    let slice = unsafe { bytes.into_slice() };
    // SAFETY: pointer validity is part of FFI contract.
    unsafe { (*session).on_client_datagram(slice) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_transparent_proxy_udp_session_on_client_close(
    session: *mut RamaTransparentProxyUdpSession,
) {
    if session.is_null() {
        return;
    }
    // SAFETY: pointer validity is part of FFI contract.
    unsafe { (*session).on_client_close() };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_owned_bytes_free(bytes: BytesOwned) {
    // SAFETY: caller guarantees `bytes` came from this FFI layer and is not freed yet.
    unsafe { bytes.free() }
}

unsafe fn cstr_opt(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    assert!(ptr.is_aligned());
    // SAFETY: pointer validity is part of FFI contract.
    let raw = unsafe { CStr::from_ptr(ptr).to_string_lossy().trim().to_owned() };
    (!raw.is_empty()).then_some(raw)
}

unsafe fn endpoint_opt(ep: &RamaFlowEndpoint) -> Option<HostWithPort> {
    if !ep.is_set || ep.port == 0 {
        return None;
    }
    // SAFETY: pointer validity is part of FFI contract.
    let host = unsafe { cstr_opt(ep.host_utf8)? };
    let host = Host::try_from(host.as_str()).ok()?;
    Some(HostWithPort::new(host, ep.port))
}

unsafe fn meta_from_ffi(meta: &RamaTransparentProxyFlowMeta) -> TransparentProxyMeta {
    let protocol = match meta.protocol {
        x if x == FlowProtocol::Tcp as u32 => Protocol::from_static("tcp"),
        x if x == FlowProtocol::Udp as u32 => Protocol::from_static("udp"),
        _ => Protocol::from_static("tcp"),
    };

    let mut out = TransparentProxyMeta::new(protocol);

    // SAFETY: pointer validity is part of FFI contract.
    if let Some(remote) = unsafe { endpoint_opt(&meta.remote_endpoint) } {
        out = out.with_remote_endpoint(remote);
    }
    // SAFETY: pointer validity is part of FFI contract.
    if let Some(local) = unsafe { endpoint_opt(&meta.local_endpoint) } {
        out = out.with_local_endpoint(local);
    }
    // SAFETY: pointer validity is part of FFI contract.
    if let Some(v) = unsafe { cstr_opt(meta.source_app_signing_identifier_utf8) } {
        out = out.with_source_app_signing_identifier(v.into());
    }
    // SAFETY: pointer validity is part of FFI contract.
    if let Some(v) = unsafe { cstr_opt(meta.source_app_bundle_identifier_utf8) } {
        out = out.with_source_app_bundle_identifier(v.into());
    }

    out
}
