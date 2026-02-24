use rama::{
    extensions::ExtensionsRef,
    net::{
        address::HostWithPort,
        apple::networkextension::{
            RamaBytesView, TcpFlow, TransparentProxyConfig, TransparentProxyEngine,
            TransparentProxyEngineBuilder, TransparentProxyMeta, TransparentProxyTcpSession,
            TransparentProxyUdpSession, UdpFlow, bytes_free, bytes_view_as_slice,
        },
        proxy::{ProxyRequest, ProxyTarget, StreamForwardService},
    },
    rt::Executor,
    service::{Service, service_fn},
    tcp::client::default_tcp_connect,
};
use std::{
    convert::Infallible,
    ffi::CStr,
    os::raw::{c_char, c_void},
};

pub type RamaTransparentProxyEngine = TransparentProxyEngine;
pub type RamaTcpSession = TransparentProxyTcpSession;
pub type RamaUdpSession = TransparentProxyUdpSession;

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
pub extern "C" fn rama_transparent_proxy_engine_new(
    config_utf8: *const c_char,
) -> *mut RamaTransparentProxyEngine {
    let config_json = cstr_to_string(config_utf8);
    let engine = TransparentProxyEngineBuilder::new(config_json)
        .with_tcp_service(service_fn(custom_tcp_service))
        .with_udp_service(service_fn(custom_udp_service))
        .build();
    Box::into_raw(Box::new(engine))
}

#[unsafe(no_mangle)]
pub extern "C" fn rama_transparent_proxy_engine_free(engine: *mut RamaTransparentProxyEngine) {
    if engine.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(engine));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rama_transparent_proxy_engine_start(engine: *mut RamaTransparentProxyEngine) {
    if engine.is_null() {
        return;
    }
    unsafe {
        (*engine).start();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rama_transparent_proxy_engine_stop(
    engine: *mut RamaTransparentProxyEngine,
    reason: i32,
) {
    if engine.is_null() {
        return;
    }
    unsafe {
        (*engine).stop(reason);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rama_transparent_proxy_engine_new_tcp_session(
    engine: *mut RamaTransparentProxyEngine,
    meta_json_utf8: *const c_char,
    callbacks: RamaTcpSessionCallbacks,
) -> *mut RamaTcpSession {
    if engine.is_null() {
        return std::ptr::null_mut();
    }

    let meta_json = cstr_to_string(meta_json_utf8);
    let context = callbacks.context as usize;
    let on_server_bytes = callbacks.on_server_bytes;
    let on_server_closed = callbacks.on_server_closed;

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
                let len = match i32::try_from(bytes.len()) {
                    Ok(len) => len,
                    Err(_) => return,
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
pub extern "C" fn rama_tcp_session_free(session: *mut RamaTcpSession) {
    if session.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(session));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rama_tcp_session_on_client_bytes(
    session: *mut RamaTcpSession,
    bytes: RamaBytesView,
) {
    if session.is_null() {
        return;
    }
    let slice = unsafe { bytes_view_as_slice(bytes) };
    unsafe {
        (*session).on_client_bytes(slice);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rama_tcp_session_on_client_eof(session: *mut RamaTcpSession) {
    if session.is_null() {
        return;
    }
    unsafe {
        (*session).on_client_eof();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rama_transparent_proxy_engine_new_udp_session(
    engine: *mut RamaTransparentProxyEngine,
    meta_json_utf8: *const c_char,
    callbacks: RamaUdpSessionCallbacks,
) -> *mut RamaUdpSession {
    if engine.is_null() {
        return std::ptr::null_mut();
    }

    let meta_json = cstr_to_string(meta_json_utf8);
    let context = callbacks.context as usize;
    let on_server_datagram = callbacks.on_server_datagram;
    let on_server_closed = callbacks.on_server_closed;

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
                let len = match i32::try_from(bytes.len()) {
                    Ok(len) => len,
                    Err(_) => return,
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
pub extern "C" fn rama_udp_session_free(session: *mut RamaUdpSession) {
    if session.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(session));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rama_udp_session_on_client_datagram(
    session: *mut RamaUdpSession,
    bytes: RamaBytesView,
) {
    if session.is_null() {
        return;
    }
    let slice = unsafe { bytes_view_as_slice(bytes) };
    unsafe {
        (*session).on_client_datagram(slice);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rama_udp_session_on_client_close(session: *mut RamaUdpSession) {
    if session.is_null() {
        return;
    }
    unsafe {
        (*session).on_client_close();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rama_bytes_free(ptr_: *mut u8, len: i32) {
    bytes_free(ptr_, len);
}

fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
}

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

async fn custom_tcp_service(stream: TcpFlow) -> Result<(), Infallible> {
    let meta = stream
        .extensions()
        .get::<TransparentProxyMeta>()
        .cloned()
        .unwrap_or_else(|| TransparentProxyMeta::new(rama::net::Protocol::from_static("tcp")));
    let target = resolve_target_from_extensions(stream.extensions());

    eprintln!(
        "[tproxy_rs][tcp] start proto={} remote={:?} local={:?}",
        meta.protocol().as_str(),
        meta.remote_endpoint(),
        meta.local_endpoint()
    );

    let Some(target_addr) = target else {
        eprintln!("[tproxy_rs][tcp] missing target endpoint; closing flow");
        return Ok(());
    };

    let extensions = stream.extensions().clone();
    let exec = Executor::default();
    let Ok((target, _sock_addr)) = default_tcp_connect(&extensions, target_addr, exec).await else {
        eprintln!("[tproxy_rs][tcp] connect failed");
        return Ok(());
    };

    let req = ProxyRequest {
        source: stream,
        target,
    };

    if let Err(err) = StreamForwardService::new().serve(req).await {
        eprintln!("[tproxy_rs][tcp] forward error: {err}");
    } else {
        eprintln!("[tproxy_rs][tcp] forward completed");
    }

    Ok(())
}

async fn custom_udp_service(mut flow: UdpFlow) -> Result<(), Infallible> {
    let target = resolve_target_from_extensions(flow.extensions());

    let Some(target_addr) = target else {
        eprintln!("[tproxy_rs][udp] missing target endpoint; draining flow");
        while flow.recv().await.is_some() {}
        return Ok(());
    };

    let remote = format!("{}:{}", target_addr.host, target_addr.port);
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => socket,
        Err(err) => {
            eprintln!("[tproxy_rs][udp] bind failed: {err}");
            while flow.recv().await.is_some() {}
            return Ok(());
        }
    };

    if let Err(err) = socket.connect(&remote).await {
        eprintln!("[tproxy_rs][udp] connect to {remote} failed: {err}");
        while flow.recv().await.is_some() {}
        return Ok(());
    }

    eprintln!("[tproxy_rs][udp] forwarding to {remote}");

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
                    eprintln!("[tproxy_rs][udp] upstream send failed: {err}");
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
                        eprintln!("[tproxy_rs][udp] upstream recv failed: {err}");
                        break;
                    }
                }
            }
        }
    }

    eprintln!(
        "[tproxy_rs][udp] done up={}pkts/{}bytes down={}pkts/{}bytes",
        up_packets, up_bytes, down_packets, down_bytes
    );

    Ok(())
}
