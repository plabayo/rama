use std::sync::Once;

use rama::telemetry::tracing::subscriber;
use rama::{
    net::apple::networkextension::{
        ffi::{BytesOwned, BytesView, tproxy as ffi_tproxy},
        tproxy::{
            TransparentProxyConfig, TransparentProxyEngine, TransparentProxyEngineBuilder,
            TransparentProxyFlowMeta, TransparentProxyFlowProtocol, TransparentProxyNetworkRule,
        },
    },
    telemetry::tracing,
};

mod tcp;
mod udp;
mod utils;

pub type RamaTransparentProxyEngine = TransparentProxyEngine;
pub type RamaTransparentProxyTcpSession =
    rama::net::apple::networkextension::tproxy::TransparentProxyTcpSession;
pub type RamaTransparentProxyUdpSession =
    rama::net::apple::networkextension::tproxy::TransparentProxyUdpSession;

pub type RamaTransparentProxyFlowMeta = ffi_tproxy::TransparentProxyFlowMeta;
pub type RamaTransparentProxyConfig = ffi_tproxy::TransparentProxyConfig;
pub type RamaTransparentProxyTcpSessionCallbacks = ffi_tproxy::TransparentProxyTcpSessionCallbacks;
pub type RamaTransparentProxyUdpSessionCallbacks = ffi_tproxy::TransparentProxyUdpSessionCallbacks;

static INIT_TRACING: Once = Once::new();

fn proxy_config() -> TransparentProxyConfig {
    TransparentProxyConfig::new().with_rules(vec![TransparentProxyNetworkRule::any()])
}

#[unsafe(no_mangle)]
/// # Safety
///
/// This function is FFI entrypoint and may be called from Swift/C.
pub unsafe extern "C" fn rama_transparent_proxy_initialize() -> bool {
    INIT_TRACING.call_once(|| {
        // TODO: support richer subscriber setup as part of proc macro in future.
        subscriber::fmt::init();
    });
    true
}

#[unsafe(no_mangle)]
/// # Safety
///
pub unsafe extern "C" fn rama_transparent_proxy_get_config() -> *mut RamaTransparentProxyConfig {
    let config = proxy_config();
    let ffi_cfg = RamaTransparentProxyConfig::from_rust_type(&config);
    Box::into_raw(Box::new(ffi_cfg))
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `config` must be either null or a pointer returned by
/// `rama_transparent_proxy_get_config` that was not freed yet.
pub unsafe extern "C" fn rama_transparent_proxy_config_free(
    config: *mut RamaTransparentProxyConfig,
) {
    if config.is_null() {
        return;
    }
    // SAFETY: `config` came from `Box::into_raw` in `rama_transparent_proxy_get_config`.
    let config = unsafe { Box::from_raw(config) };
    // SAFETY: guaranteed by function contract above.
    unsafe { config.free() }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `meta` must be either null or a valid pointer to `RamaTransparentProxyFlowMeta`.
pub unsafe extern "C" fn rama_transparent_proxy_should_intercept_flow(
    meta: *const RamaTransparentProxyFlowMeta,
) -> bool {
    if meta.is_null() {
        return false;
    }

    // SAFETY: pointer validity is guaranteed by FFI contract.
    let meta = unsafe { (*meta).as_owned_rust_type() };

    tracing::trace!(
        protocol = ?meta.protocol,
        remote = ?meta.remote_endpoint,
        local = ?meta.local_endpoint,
        "flow intercept decision: accepted"
    );

    true
}

#[unsafe(no_mangle)]
/// # Safety
///
/// This function is FFI entrypoint and may be called from Swift/C.
pub unsafe extern "C" fn rama_transparent_proxy_engine_new() -> *mut RamaTransparentProxyEngine {
    let engine = TransparentProxyEngineBuilder::new(proxy_config())
        .with_tcp_service(self::tcp::new_service())
        .with_udp_service(self::udp::new_service())
        .build();

    Box::into_raw(Box::new(engine))
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `engine` must either be null or a pointer returned by
/// `rama_transparent_proxy_engine_new` that has not been freed.
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
/// # Safety
///
/// `engine` must be a valid pointer returned by
/// `rama_transparent_proxy_engine_new`.
pub unsafe extern "C" fn rama_transparent_proxy_engine_start(
    engine: *mut RamaTransparentProxyEngine,
) {
    if engine.is_null() {
        return;
    }

    // SAFETY: pointer validity is guaranteed by FFI contract.
    unsafe { (*engine).start() };
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `engine` must be a valid pointer returned by
/// `rama_transparent_proxy_engine_new`.
pub unsafe extern "C" fn rama_transparent_proxy_engine_stop(
    engine: *mut RamaTransparentProxyEngine,
    reason: i32,
) {
    if engine.is_null() {
        return;
    }

    // SAFETY: pointer validity is guaranteed by FFI contract.
    unsafe { (*engine).stop(reason) };
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `engine` must be valid and `meta` must be either null or point to a valid
/// `RamaTransparentProxyFlowMeta`.
pub unsafe extern "C" fn rama_transparent_proxy_engine_new_tcp_session(
    engine: *mut RamaTransparentProxyEngine,
    meta: *const RamaTransparentProxyFlowMeta,
    callbacks: RamaTransparentProxyTcpSessionCallbacks,
) -> *mut RamaTransparentProxyTcpSession {
    if engine.is_null() {
        return std::ptr::null_mut();
    }

    let typed_meta = if meta.is_null() {
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
    } else {
        // SAFETY: pointer validity is guaranteed by FFI contract.
        unsafe { (*meta).as_owned_rust_type() }
    };

    let context = callbacks.context as usize;
    let on_server_bytes = callbacks.on_server_bytes;
    let on_server_closed = callbacks.on_server_closed;

    // SAFETY: pointer validity is guaranteed by FFI contract.
    let engine = unsafe { &*engine };
    let session = engine.new_tcp_session(
        typed_meta,
        move |bytes| {
            let Some(callback) = on_server_bytes else {
                return;
            };
            if bytes.is_empty() {
                return;
            }
            // SAFETY: callback pointer is provided by Swift and expected callable.
            unsafe {
                callback(
                    context as *mut std::ffi::c_void,
                    BytesView {
                        ptr: bytes.as_ptr(),
                        len: bytes.len(),
                    },
                );
            }
        },
        move || {
            if let Some(callback) = on_server_closed {
                // SAFETY: callback pointer is provided by Swift and expected callable.
                unsafe { callback(context as *mut std::ffi::c_void) };
            }
        },
    );

    match session {
        Some(session) => Box::into_raw(Box::new(session)),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `session` must either be null or a pointer returned by
/// `rama_transparent_proxy_engine_new_tcp_session`.
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
/// # Safety
///
/// `session` must be valid. `bytes` must reference readable memory for this call.
pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_bytes(
    session: *mut RamaTransparentProxyTcpSession,
    bytes: BytesView,
) {
    if session.is_null() {
        return;
    }

    // SAFETY: caller guarantees bytes view validity for this call.
    let slice = unsafe { bytes.into_slice() };
    // SAFETY: pointer validity is guaranteed by FFI contract.
    unsafe { (*session).on_client_bytes(slice) };
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `session` must be valid.
pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_eof(
    session: *mut RamaTransparentProxyTcpSession,
) {
    if session.is_null() {
        return;
    }

    // SAFETY: pointer validity is guaranteed by FFI contract.
    unsafe { (*session).on_client_eof() };
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `engine` must be valid and `meta` must be either null or point to a valid
/// `RamaTransparentProxyFlowMeta`.
pub unsafe extern "C" fn rama_transparent_proxy_engine_new_udp_session(
    engine: *mut RamaTransparentProxyEngine,
    meta: *const RamaTransparentProxyFlowMeta,
    callbacks: RamaTransparentProxyUdpSessionCallbacks,
) -> *mut RamaTransparentProxyUdpSession {
    if engine.is_null() {
        return std::ptr::null_mut();
    }

    let typed_meta = if meta.is_null() {
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
    } else {
        // SAFETY: pointer validity is guaranteed by FFI contract.
        unsafe { (*meta).as_owned_rust_type() }
    };

    let context = callbacks.context as usize;
    let on_server_datagram = callbacks.on_server_datagram;
    let on_server_closed = callbacks.on_server_closed;

    // SAFETY: pointer validity is guaranteed by FFI contract.
    let engine = unsafe { &*engine };
    let session = engine.new_udp_session(
        typed_meta,
        move |bytes| {
            let Some(callback) = on_server_datagram else {
                return;
            };
            if bytes.is_empty() {
                return;
            }
            // SAFETY: callback pointer is provided by Swift and expected callable.
            unsafe {
                callback(
                    context as *mut std::ffi::c_void,
                    BytesView {
                        ptr: bytes.as_ptr(),
                        len: bytes.len(),
                    },
                );
            }
        },
        move || {
            if let Some(callback) = on_server_closed {
                // SAFETY: callback pointer is provided by Swift and expected callable.
                unsafe { callback(context as *mut std::ffi::c_void) };
            }
        },
    );

    match session {
        Some(session) => Box::into_raw(Box::new(session)),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `session` must either be null or a pointer returned by
/// `rama_transparent_proxy_engine_new_udp_session`.
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
/// # Safety
///
/// `session` must be valid. `bytes` must reference readable memory for this call.
pub unsafe extern "C" fn rama_transparent_proxy_udp_session_on_client_datagram(
    session: *mut RamaTransparentProxyUdpSession,
    bytes: BytesView,
) {
    if session.is_null() {
        return;
    }

    // SAFETY: caller guarantees bytes view validity for this call.
    let slice = unsafe { bytes.into_slice() };
    // SAFETY: pointer validity is guaranteed by FFI contract.
    unsafe { (*session).on_client_datagram(slice) };
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `session` must be valid.
pub unsafe extern "C" fn rama_transparent_proxy_udp_session_on_client_close(
    session: *mut RamaTransparentProxyUdpSession,
) {
    if session.is_null() {
        return;
    }

    // SAFETY: pointer validity is guaranteed by FFI contract.
    unsafe { (*session).on_client_close() };
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `message.ptr` must be readable for `message.len` bytes for this call.
pub unsafe extern "C" fn rama_log(level: u32, message: BytesView) {
    // SAFETY: guaranteed by function contract above.
    unsafe { rama::net::apple::networkextension::ffi::log_callback(level, message) };
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `bytes` must have been returned by this Rust FFI layer and not freed yet.
pub unsafe extern "C" fn rama_owned_bytes_free(bytes: BytesOwned) {
    // SAFETY: guaranteed by function contract above.
    unsafe { bytes.free() };
}
