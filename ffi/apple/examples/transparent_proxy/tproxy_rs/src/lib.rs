use rama::{
    extensions::ExtensionsRef,
    net::{
        address::HostWithPort,
        apple::networkextension::{
            TcpFlow, TransparentProxyConfig, TransparentProxyEngine, TransparentProxyEngineBuilder,
            TransparentProxyMeta, TransparentProxyTcpSession, TransparentProxyUdpSession, UdpFlow,
            ffi::{RamaBytesOwned, RamaBytesView},
        },
        proxy::{ProxyRequest, ProxyTarget, StreamForwardService},
    },
    rt::Executor,
    service::{Service, service_fn},
    tcp::client::default_tcp_connect,
    telemetry::tracing,
};

use std::{
    convert::Infallible,
    ffi::{CStr, c_int},
    os::raw::{c_char, c_void},
};

pub type RamaTransparentProxyEngine = TransparentProxyEngine;
pub type RamaTransparentProxyTcpSession = TransparentProxyTcpSession;
pub type RamaTransparentProxyUdpSession = TransparentProxyUdpSession;

#[repr(C)]
pub struct RamaTcpSessionCallbacks {
    pub context: *mut c_void,
    pub on_server_bytes: Option<extern "C" fn(*mut c_void, RamaBytesView)>,
    pub on_server_closed: Option<extern "C" fn(*mut c_void)>,
}

#[repr(C)]
pub struct RamaUdpSessionCallbacks {
    pub context: *mut c_void,
    pub on_server_datagram: Option<extern "C" fn(*mut c_void, RamaBytesView)>,
    pub on_server_closed: Option<extern "C" fn(*mut c_void)>,
}

#[unsafe(no_mangle)]
/// Create a new transparent proxy engine.
///
/// This constructs a `TransparentProxyEngine` driven by a Rust runtime, using Rama and Tokio.
///
/// # Safety
///
/// `config_utf8` must be either null or a valid pointer to a NUL terminated C string.
/// The string must be valid UTF 8, containing a JSON encoded config.
/// The pointer must be aligned for `c_char` and must be valid for reads until the NUL terminator.
pub unsafe extern "C" fn rama_transparent_proxy_engine_new(
    config_utf8: *const c_char,
) -> *mut RamaTransparentProxyEngine {
    // SAFETY: the function contract requires `config_utf8` to be null or a valid C string pointer.
    let config_json = unsafe { cstr_to_string(config_utf8) };

    let engine = TransparentProxyEngineBuilder::new(config_json)
        .with_tcp_service(service_fn(custom_tcp_service))
        .with_udp_service(service_fn(custom_udp_service))
        .build();

    Box::into_raw(Box::new(engine))
}

#[unsafe(no_mangle)]
/// Free a transparent proxy engine previously created by `rama_transparent_proxy_engine_new`.
///
/// It is valid to pass a null pointer, in which case this is a no op.
///
/// # Safety
///
/// If `engine` is non null, it must be a pointer returned by `rama_transparent_proxy_engine_new`
/// that has not already been freed by this function.
pub unsafe extern "C" fn rama_transparent_proxy_engine_free(
    engine: *mut RamaTransparentProxyEngine,
) {
    if engine.is_null() {
        return;
    }

    // SAFETY: the function contract requires the pointer to be a live allocation from
    // `rama_transparent_proxy_engine_new`, and the null check above ensures it is non null.
    unsafe {
        drop(Box::from_raw(engine));
    }
}

#[unsafe(no_mangle)]
/// Start a transparent proxy engine.
///
/// It is valid to pass a null pointer, in which case this is a no op.
///
/// # Safety
///
/// If `engine` is non null, it must be a valid pointer to an engine created by
/// `rama_transparent_proxy_engine_new` that is still alive.
pub unsafe extern "C" fn rama_transparent_proxy_engine_start(
    engine: *mut RamaTransparentProxyEngine,
) {
    if engine.is_null() {
        return;
    }

    // SAFETY: the engine pointer is checked for null above, and the contract requires it to be valid.
    unsafe {
        (*engine).start();
    }
}

#[unsafe(no_mangle)]
/// Stop a transparent proxy engine with a reason code.
///
/// It is valid to pass a null pointer, in which case this is a no op.
///
/// # Safety
///
/// If `engine` is non null, it must be a valid pointer to an engine created by
/// `rama_transparent_proxy_engine_new` that is still alive.
pub unsafe extern "C" fn rama_transparent_proxy_engine_stop(
    engine: *mut RamaTransparentProxyEngine,
    reason: i32,
) {
    if engine.is_null() {
        return;
    }

    // SAFETY: the engine pointer is checked for null above, and the contract requires it to be valid.
    unsafe {
        (*engine).stop(reason);
    }
}

#[unsafe(no_mangle)]
/// Create a new TCP session from the given engine and metadata.
///
/// `callbacks` are stored by the session and invoked when bytes arrive from the server side,
/// and when the server side closes.
///
/// Returns null if the session could not be created.
///
/// # Safety
///
/// `engine` must be either null or a valid pointer to a live engine created by
/// `rama_transparent_proxy_engine_new`.
///
/// `meta_json_utf8` must be either null or a valid pointer to a NUL terminated C string.
/// The string must be valid UTF 8, containing a JSON encoded metadata object.
/// The pointer must be aligned for `c_char` and must be valid for reads until the NUL terminator.
///
/// `callbacks.context` is passed back to the user callbacks as provided.
/// The callback function pointers, if present, must be safe to call from the engine runtime thread.
pub unsafe extern "C" fn rama_transparent_proxy_engine_new_tcp_session(
    engine: *mut RamaTransparentProxyEngine,
    meta_json_utf8: *const c_char,
    callbacks: RamaTcpSessionCallbacks,
) -> *mut RamaTransparentProxyTcpSession {
    if engine.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: the function contract requires `meta_json_utf8` to be null or a valid C string pointer.
    let meta_json = unsafe { cstr_to_string(meta_json_utf8) };

    let context = callbacks.context as usize;
    let on_server_bytes = callbacks.on_server_bytes;
    let on_server_closed = callbacks.on_server_closed;

    // SAFETY: the engine pointer is checked for null above and the contract requires it to be valid.
    let session = unsafe {
        (*engine).new_tcp_session(
            meta_json,
            move |bytes| {
                let Some(callback) = on_server_bytes else {
                    return;
                };
                if bytes.is_empty() {
                    return;
                }
                let len = match c_int::try_from(bytes.len()) {
                    Ok(len) => len,
                    Err(err) => {
                        tracing::debug!("TCP session: failed to convert bytes len to c_int: {err}");
                        return;
                    }
                };

                callback(
                    context as *mut c_void,
                    RamaBytesView {
                        ptr: bytes.as_ptr(),
                        len,
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
/// Free a TCP session previously created by `rama_transparent_proxy_engine_new_tcp_session`.
///
/// It is valid to pass a null pointer, in which case this is a no op.
///
/// # Safety
///
/// If `session` is non null, it must be a pointer returned by
/// `rama_transparent_proxy_engine_new_tcp_session` that has not already been freed.
pub unsafe extern "C" fn rama_tcp_session_free(session: *mut RamaTransparentProxyTcpSession) {
    if session.is_null() {
        return;
    }

    // SAFETY: the function contract requires the pointer to be a live allocation from
    // `rama_transparent_proxy_engine_new_tcp_session`, and the null check above ensures it is non null.
    unsafe {
        drop(Box::from_raw(session));
    }
}

#[unsafe(no_mangle)]
/// Provide client bytes to a TCP session.
///
/// It is valid to pass a null `session`, in which case this is a no op.
///
/// # Safety
///
/// If `session` is non null, it must be a valid pointer to a live session created by
/// `rama_transparent_proxy_engine_new_tcp_session`.
///
/// `bytes` must describe a valid memory region of length `bytes.len` starting at `bytes.ptr`,
/// and that region must remain valid for the duration of this call.
pub unsafe extern "C" fn rama_tcp_session_on_client_bytes(
    session: *mut RamaTransparentProxyTcpSession,
    bytes: RamaBytesView,
) {
    if session.is_null() {
        return;
    }

    // SAFETY: the function contract requires `bytes` to describe a valid region for this call.
    let slice = unsafe { bytes.into_slice() };

    // SAFETY: the session pointer is checked for null above, and the contract requires it to be valid.
    unsafe {
        (*session).on_client_bytes(slice);
    }
}

#[unsafe(no_mangle)]
/// Signal client EOF to a TCP session.
///
/// It is valid to pass a null `session`, in which case this is a no op.
///
/// # Safety
///
/// If `session` is non null, it must be a valid pointer to a live session created by
/// `rama_transparent_proxy_engine_new_tcp_session`.
pub unsafe extern "C" fn rama_tcp_session_on_client_eof(
    session: *mut RamaTransparentProxyTcpSession,
) {
    if session.is_null() {
        return;
    }

    // SAFETY: the session pointer is checked for null above, and the contract requires it to be valid.
    unsafe {
        (*session).on_client_eof();
    }
}

#[unsafe(no_mangle)]
/// Create a new UDP session from the given engine and metadata.
///
/// `callbacks` are stored by the session and invoked when datagrams arrive from the server side,
/// and when the server side closes.
///
/// Returns null if the session could not be created.
///
/// # Safety
///
/// `engine` must be either null or a valid pointer to a live engine created by
/// `rama_transparent_proxy_engine_new`.
///
/// `meta_json_utf8` must be either null or a valid pointer to a NUL terminated C string.
/// The string must be valid UTF 8, containing a JSON encoded metadata object.
/// The pointer must be aligned for `c_char` and must be valid for reads until the NUL terminator.
///
/// `callbacks.context` is passed back to the user callbacks as provided.
/// The callback function pointers, if present, must be safe to call from the engine runtime thread.
pub unsafe extern "C" fn rama_transparent_proxy_engine_new_udp_session(
    engine: *mut RamaTransparentProxyEngine,
    meta_json_utf8: *const c_char,
    callbacks: RamaUdpSessionCallbacks,
) -> *mut RamaTransparentProxyUdpSession {
    if engine.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: the function contract requires `meta_json_utf8` to be null or a valid C string pointer.
    let meta_json = unsafe { cstr_to_string(meta_json_utf8) };

    let context = callbacks.context as usize;
    let on_server_datagram = callbacks.on_server_datagram;
    let on_server_closed = callbacks.on_server_closed;

    // SAFETY: the engine pointer is checked for null above and the contract requires it to be valid.
    let session = unsafe {
        (*engine).new_udp_session(
            meta_json,
            move |bytes| {
                let Some(callback) = on_server_datagram else {
                    return;
                };
                if bytes.is_empty() {
                    return;
                }
                let len = match c_int::try_from(bytes.len()) {
                    Ok(len) => len,
                    Err(err) => {
                        tracing::debug!("udp session: failed to convert bytes len to c_int: {err}");
                        return;
                    }
                };

                callback(
                    context as *mut c_void,
                    RamaBytesView {
                        ptr: bytes.as_ptr(),
                        len,
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
/// Free a UDP session previously created by `rama_transparent_proxy_engine_new_udp_session`.
///
/// It is valid to pass a null pointer, in which case this is a no op.
///
/// # Safety
///
/// If `session` is non null, it must be a pointer returned by
/// `rama_transparent_proxy_engine_new_udp_session` that has not already been freed.
pub unsafe extern "C" fn rama_udp_session_free(session: *mut RamaTransparentProxyUdpSession) {
    if session.is_null() {
        return;
    }

    // SAFETY: the function contract requires the pointer to be a live allocation from
    // `rama_transparent_proxy_engine_new_udp_session`, and the null check above ensures it is non null.
    unsafe {
        drop(Box::from_raw(session));
    }
}

#[unsafe(no_mangle)]
/// Provide a client datagram to a UDP session.
///
/// It is valid to pass a null `session`, in which case this is a no op.
///
/// # Safety
///
/// If `session` is non null, it must be a valid pointer to a live session created by
/// `rama_transparent_proxy_engine_new_udp_session`.
///
/// `bytes` must describe a valid memory region of length `bytes.len` starting at `bytes.ptr`,
/// and that region must remain valid for the duration of this call.
pub unsafe extern "C" fn rama_udp_session_on_client_datagram(
    session: *mut RamaTransparentProxyUdpSession,
    bytes: RamaBytesView,
) {
    if session.is_null() {
        return;
    }

    // SAFETY: the function contract requires `bytes` to describe a valid region for this call.
    let slice = unsafe { bytes.into_slice() };

    // SAFETY: the session pointer is checked for null above, and the contract requires it to be valid.
    unsafe {
        (*session).on_client_datagram(slice);
    }
}

#[unsafe(no_mangle)]
/// Signal that the client side has closed for a UDP session.
///
/// It is valid to pass a null `session`, in which case this is a no op.
///
/// # Safety
///
/// If `session` is non null, it must be a valid pointer to a live session created by
/// `rama_transparent_proxy_engine_new_udp_session`.
///
/// This function must only be called once, at the end of the session lifecycle.
pub unsafe extern "C" fn rama_udp_session_on_client_close(
    session: *mut RamaTransparentProxyUdpSession,
) {
    if session.is_null() {
        return;
    }

    // SAFETY: the session pointer is checked for null above, and the contract requires it to be valid.
    // The caller also guarantees this is only called once at the end of the session lifecycle.
    unsafe {
        (*session).on_client_close();
    }
}

#[unsafe(no_mangle)]
/// Free owned bytes previously returned to the caller by this FFI.
///
/// # Safety
///
/// `bytes` must be a valid `RamaBytesOwned` value produced by the same FFI layer,
/// and it must not be freed more than once.
pub unsafe extern "C" fn rama_owned_bytes_free(bytes: RamaBytesOwned) {
    // SAFETY: the function contract requires `bytes` to be a valid owned allocation and not freed yet.
    unsafe { bytes.free() }
}

/// Convert an optional C string pointer into an owned Rust `String`.
///
/// This is a helper for FFI entry points where null means "empty string".
///
/// # Safety
///
/// `ptr` must be either null or a valid pointer to a NUL terminated C string.
/// The pointer must be aligned for `c_char` and must be valid for reads until the NUL terminator.
unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }

    assert!(ptr.is_aligned());

    // SAFETY: the function contract requires `ptr` to point to a valid NUL terminated C string.
    unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
}

/// Resolve a remote target endpoint from extensions.
///
/// Resolution order:
/// 1. `ProxyTarget` if present.
/// 2. `TransparentProxyMeta` remote endpoint if present.
/// 3. `TransparentProxyConfig` default remote endpoint if present.
fn resolve_target_from_extensions(ext: &rama::extensions::Extensions) -> Option<HostWithPort> {
    ext.get::<ProxyTarget>()
        .cloned()
        .map(|target| target.0)
        .or_else(|| {
            ext.get::<TransparentProxyMeta>()
                .and_then(|meta| meta.remote_endpoint().cloned())
        })
        .or_else(|| {
            ext.get::<TransparentProxyConfig>()
                .and_then(|cfg| cfg.default_remote_endpoint().cloned())
        })
}

/// TCP flow handler used by the transparent proxy engine.
///
/// This resolves the remote target, establishes a TCP connection, then forwards bytes between
/// the client flow and the upstream stream.
async fn custom_tcp_service(stream: TcpFlow) -> Result<(), Infallible> {
    let meta = stream
        .extensions()
        .get::<TransparentProxyMeta>()
        .cloned()
        .unwrap_or_else(|| TransparentProxyMeta::new(rama::net::Protocol::from_static("tcp")));
    let target = resolve_target_from_extensions(stream.extensions());

    tracing::info!(
        protocol = meta.protocol().as_str(),
        remote = ?meta.remote_endpoint(),
        local = ?meta.local_endpoint(),
        "tproxy tcp start"
    );

    let Some(target_addr) = target else {
        tracing::error!("tproxy tcp missing target endpoint, closing flow");
        return Ok(());
    };

    let extensions = stream.extensions().clone();
    let exec = Executor::default();

    let Ok((target, _sock_addr)) = default_tcp_connect(&extensions, target_addr, exec).await else {
        tracing::error!("tproxy tcp connect failed");
        return Ok(());
    };

    let req = ProxyRequest {
        source: stream,
        target,
    };

    match StreamForwardService::new().serve(req).await {
        Ok(()) => tracing::info!("tproxy tcp forward completed"),
        Err(err) => tracing::error!(error = %err, "tproxy tcp forward error"),
    }

    Ok(())
}

/// UDP flow handler used by the transparent proxy engine.
///
/// This resolves the remote target, binds a local UDP socket, connects it to the upstream,
/// then forwards datagrams in both directions until either side closes or an error occurs.
async fn custom_udp_service(mut flow: UdpFlow) -> Result<(), Infallible> {
    let target = resolve_target_from_extensions(flow.extensions());

    let Some(target_addr) = target else {
        tracing::error!("tproxy udp missing target endpoint, draining flow");
        while flow.recv().await.is_some() {}
        return Ok(());
    };

    let remote = format!("{}:{}", target_addr.host, target_addr.port);

    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => socket,
        Err(err) => {
            tracing::error!(error = %err, "tproxy udp bind failed");
            while flow.recv().await.is_some() {}
            return Ok(());
        }
    };

    if let Err(err) = socket.connect(&remote).await {
        tracing::error!(remote = %remote, error = %err, "tproxy udp connect failed");
        while flow.recv().await.is_some() {}
        return Ok(());
    }

    tracing::info!(remote = %remote, "tproxy udp forwarding started");

    let mut up_packets: u64 = 0;
    let mut down_packets: u64 = 0;
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            maybe_datagram = flow.recv() => {
                let Some(datagram) = maybe_datagram else {
                    break;
                };
                if datagram.is_empty() {
                    continue;
                }

                up_packets += 1;
                up_bytes += datagram.len() as u64;

                if let Err(err) = socket.send(&datagram).await {
                    tracing::error!(error = %err, "tproxy udp upstream send failed");
                    break;
                }
            }
            recv_result = socket.recv(&mut buf) => {
                match recv_result {
                    Ok(0) => break,
                    Ok(n) => {
                        down_packets += 1;
                        down_bytes += n as u64;
                        flow.send(rama::bytes::Bytes::copy_from_slice(&buf[..n]));
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "tproxy udp upstream recv failed");
                        break;
                    }
                }
            }
        }
    }

    tracing::info!(
        up_packets,
        up_bytes,
        down_packets,
        down_bytes,
        "tproxy udp forwarding done"
    );

    Ok(())
}
