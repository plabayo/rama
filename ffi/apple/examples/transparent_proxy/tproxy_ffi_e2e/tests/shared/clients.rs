use std::{ffi::c_void, ptr, sync::Arc, time::Duration};

use rama::{
    Layer, Service,
    error::BoxError,
    http::{
        BodyExtractExt as _, Request, Response, Version,
        client::EasyHttpWebClient,
        conn::TargetHttpVersion,
        layer::{
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            required_header::AddRequiredRequestHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
        },
        service::client::{self, HttpClientExt as _},
        ws::{Message, handshake::client::HttpClientWebSocketExt},
    },
    net::{
        Protocol,
        address::{Domain, HostWithPort, ProxyAddress},
        tls::client::ServerVerifyMode,
    },
    rt::Executor,
    service::BoxService,
    tcp::client::default_tcp_connect,
    telemetry::tracing,
    tls::boring::client::{TlsConnectorDataBuilder, tls_connect},
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UdpSocket,
    sync::{Notify, mpsc},
};

use super::{
    bindings,
    ffi::EngineHandle,
    types::{ProxyKind, TcpMode},
};

pub(crate) type ClientService = BoxService<Request, Response, BoxError>;

struct UdpCallbackContext {
    sender: mpsc::UnboundedSender<Vec<u8>>,
}

unsafe extern "C" fn on_udp_server_datagram(ctx: *mut c_void, bytes: bindings::RamaBytesView) {
    let ctx = unsafe { &*(ctx as *const UdpCallbackContext) };
    let payload = if bytes.ptr.is_null() || bytes.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len).to_vec() }
    };
    _ = ctx.sender.send(payload);
}

unsafe extern "C" fn on_udp_server_closed(_ctx: *mut c_void) {}

unsafe extern "C" fn on_udp_client_read_demand(_ctx: *mut c_void) {}

struct UdpEgressCallbackContext {
    sender: mpsc::UnboundedSender<Vec<u8>>,
}

unsafe extern "C" fn on_udp_send_to_egress(ctx: *mut c_void, bytes: bindings::RamaBytesView) {
    let ctx = unsafe { &*(ctx as *const UdpEgressCallbackContext) };
    let payload = if bytes.ptr.is_null() || bytes.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len).to_vec() }
    };
    _ = ctx.sender.send(payload);
}

pub(crate) fn build_http_client(
    cert_store: Option<Arc<rama::tls::boring::core::x509::store::X509Store>>,
) -> ClientService {
    let builder = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .with_proxy_support();

    let inner = match cert_store {
        Some(store) => {
            let config = TlsConnectorDataBuilder::new_http_auto()
                .with_server_verify_mode(ServerVerifyMode::Auto)
                .with_server_verify_cert_store(store)
                .into_shared_builder();
            builder
                .with_tls_support_using_boringssl_and_default_http_version(
                    Some(config),
                    Version::HTTP_11,
                )
                .with_default_http_connector(Executor::default())
                .build_client()
        }
        None => builder
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .build_client(),
    };

    (
        MapResponseBodyLayer::new_boxed_streaming_body(),
        DecompressionLayer::new(),
        AddRequiredRequestHeadersLayer::default(),
        RetryLayer::new(
            ManagedPolicy::default().with_backoff(
                ExponentialBackoff::new(
                    Duration::from_millis(25),
                    Duration::from_secs(5),
                    0.01,
                    HasherRng::default,
                )
                .expect("build backoff"),
            ),
        ),
    )
        .into_layer(inner)
        .boxed()
}

pub(crate) fn apply_proxy_extensions(
    mut builder: client::RequestBuilder<'_, ClientService, Response>,
    proxy_kind: ProxyKind,
    proxy_addr: std::net::SocketAddr,
) -> client::RequestBuilder<'_, ClientService, Response> {
    if let Some(proxy_address) = proxy_address(proxy_kind, proxy_addr) {
        builder = builder.extension(proxy_address);
    }
    builder
}

pub(crate) fn apply_http_version(
    mut builder: client::RequestBuilder<'_, ClientService, Response>,
    version: Version,
) -> client::RequestBuilder<'_, ClientService, Response> {
    builder = builder
        .version(version)
        .extension(TargetHttpVersion(version));
    builder
}

pub(crate) async fn fetch_text(
    client: &ClientService,
    url: &str,
    version: Version,
    proxy_kind: ProxyKind,
    proxy_addr: std::net::SocketAddr,
) -> String {
    let builder = client.get(url);
    let builder = apply_http_version(builder, version);
    let builder = apply_proxy_extensions(builder, proxy_kind, proxy_addr);
    builder
        .send()
        .await
        .expect("send request")
        .try_into_string()
        .await
        .expect("response body as string")
}

pub(crate) async fn fetch_response(
    client: &ClientService,
    url: &str,
    version: Version,
    proxy_kind: ProxyKind,
    proxy_addr: std::net::SocketAddr,
) -> Response {
    let builder = client.get(url);
    let builder = apply_http_version(builder, version);
    let builder = apply_proxy_extensions(builder, proxy_kind, proxy_addr);
    builder.send().await.expect("send request")
}

pub(crate) async fn post_with_body(
    client: &ClientService,
    url: &str,
    version: Version,
    proxy_kind: ProxyKind,
    proxy_addr: std::net::SocketAddr,
    body: Vec<u8>,
) -> Response {
    let builder = client.post(url).body(body);
    let builder = apply_http_version(builder, version);
    let builder = apply_proxy_extensions(builder, proxy_kind, proxy_addr);
    builder.send().await.expect("send post request")
}

pub(crate) async fn websocket_echo(
    client: &ClientService,
    url: String,
    version: Version,
    proxy_kind: ProxyKind,
    proxy_addr: std::net::SocketAddr,
) {
    let extensions = rama::extensions::Extensions::new();
    if let Some(proxy_address) = proxy_address(proxy_kind, proxy_addr) {
        extensions.insert(proxy_address);
    }

    tracing::info!(?version, ?proxy_kind, %proxy_addr, "start ws handshake");

    let mut ws = match version {
        Version::HTTP_2 => client.websocket_h2(url),
        _ => client.websocket(url),
    }
    .handshake(extensions)
    .await
    .expect("websocket handshake");

    tracing::info!(?version, ?proxy_kind, %proxy_addr, "ws handshake complete");

    ws.send_message(Message::text("hello ffi"))
        .await
        .expect("send websocket message");

    tracing::info!(?version, ?proxy_kind, %proxy_addr, "ws hello msg sent");

    let echoed = ws
        .recv_message()
        .await
        .expect("recv websocket message")
        .into_text()
        .expect("websocket text response");
    assert_eq!(echoed.as_str(), "hello ffi");

    tracing::info!(?version, ?proxy_kind, %proxy_addr, "ws reply received");

    _ = tokio::time::timeout(Duration::from_millis(250), ws.close(None)).await;
}

pub(crate) async fn roundtrip_custom_protocol(
    mode: TcpMode,
    proxy_kind: ProxyKind,
    target_port: u16,
    direct_addr: std::net::SocketAddr,
    proxy_addr: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut stream = match proxy_kind {
        ProxyKind::None => {
            let (stream, _) = default_tcp_connect(
                &rama::extensions::Extensions::new(),
                HostWithPort::from(direct_addr),
                Executor::default(),
            )
            .await
            .expect("connect direct ingress");
            stream
        }
        ProxyKind::Http | ProxyKind::Socks5 => {
            let (mut stream, _) = default_tcp_connect(
                &rama::extensions::Extensions::new(),
                HostWithPort::from(proxy_addr),
                Executor::default(),
            )
            .await
            .expect("connect proxy ingress");
            match proxy_kind {
                ProxyKind::Http => {
                    let request = format!(
                        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
                    );
                    stream
                        .write_all(request.as_bytes())
                        .await
                        .expect("write http connect");
                    let mut response = Vec::new();
                    let mut buf = [0_u8; 1024];
                    loop {
                        let n = stream.read(&mut buf).await.expect("read http connect");
                        response.extend_from_slice(&buf[..n]);
                        if response.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    assert!(
                        String::from_utf8_lossy(&response).contains("200"),
                        "http connect response = {:?}",
                        String::from_utf8_lossy(&response)
                    );
                }
                ProxyKind::Socks5 => {
                    stream
                        .write_all(&[0x05, 0x01, 0x00])
                        .await
                        .expect("socks greet");
                    let mut two = [0_u8; 2];
                    stream.read_exact(&mut two).await.expect("socks greet resp");
                    assert_eq!(&two, &[0x05, 0x00]);
                    let connect = [
                        0x05,
                        0x01,
                        0x00,
                        0x01,
                        127,
                        0,
                        0,
                        1,
                        (target_port >> 8) as u8,
                        target_port as u8,
                    ];
                    stream.write_all(&connect).await.expect("socks connect");
                    let mut resp = [0_u8; 10];
                    stream
                        .read_exact(&mut resp)
                        .await
                        .expect("socks connect resp");
                    assert_eq!(resp[1], 0x00);
                }
                ProxyKind::None => unreachable!(),
            }
            stream
        }
    };

    match mode {
        TcpMode::Plain => {
            stream.write_all(payload).await.expect("write raw payload");
            let mut buf = vec![0_u8; payload.len()];
            stream.read_exact(&mut buf).await.expect("read raw payload");
            buf
        }
        TcpMode::Tls => {
            let connector = TlsConnectorDataBuilder::new()
                .with_server_verify_mode(ServerVerifyMode::Disable)
                .with_server_name(Domain::from_static("127.0.0.1"))
                .build()
                .expect("build tls connector data");
            let tls_stream = tls_connect(stream, Some(connector))
                .await
                .expect("tls connect over established tunnel");
            roundtrip_over_stream(tls_stream, payload).await
        }
    }
}

async fn roundtrip_over_stream<S>(mut stream: S, payload: &[u8]) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream.write_all(payload).await.expect("write payload");
    let mut buf = vec![0_u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read payload");
    buf
}

/// One-shot UDP echo round-trip through the FFI proxy engine.
///
/// Same Swift-driven activate contract as TCP: bytes pushed via
/// `on_client_datagram` only reach the service after the session is
/// activated with the egress callbacks. The harness opens a real UDP
/// socket connected to `remote_addr` and pretends to be the
/// `NWConnection` Swift would have wired.
pub(crate) async fn udp_roundtrip(
    engine: Arc<EngineHandle>,
    remote_addr: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ctx_ptr = Box::into_raw(Box::new(UdpCallbackContext { sender: tx })) as usize;

    let (egress_tx, mut egress_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let egress_ctx_ptr =
        Box::into_raw(Box::new(UdpEgressCallbackContext { sender: egress_tx })) as usize;

    let session = {
        let remote_host = remote_addr.ip().to_string().into_bytes();
        let meta = bindings::RamaTransparentProxyFlowMeta {
            protocol: bindings::RamaTransparentProxyFlowProtocol_RAMA_FLOW_PROTOCOL_UDP,
            remote_endpoint: bindings::RamaTransparentProxyFlowEndpoint {
                host_utf8: remote_host.as_ptr().cast(),
                host_utf8_len: remote_host.len(),
                port: remote_addr.port(),
            },
            local_endpoint: bindings::RamaTransparentProxyFlowEndpoint {
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
        let result = unsafe {
            bindings::rama_transparent_proxy_engine_new_udp_session(
                engine.raw,
                &meta,
                bindings::RamaTransparentProxyUdpSessionCallbacks {
                    context: ctx_ptr as *mut c_void,
                    on_server_datagram: Some(on_udp_server_datagram),
                    on_client_read_demand: Some(on_udp_client_read_demand),
                    on_server_closed: Some(on_udp_server_closed),
                },
            )
        };
        assert_eq!(
            result.action,
            bindings::RamaTransparentProxyFlowAction_RAMA_FLOW_ACTION_INTERCEPT,
            "ffi udp session decision should intercept"
        );
        let raw = result.session;
        assert!(!raw.is_null(), "ffi udp session must allocate");
        raw as usize
    };

    // Connect a UDP socket as our pretend-NWConnection to the upstream
    // echo server. Bind 0 → ephemeral port; `connect` filters peer.
    let egress_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind ffi udp egress socket");
    egress_socket
        .connect(remote_addr)
        .await
        .expect("connect ffi udp egress socket");
    let egress_socket = Arc::new(egress_socket);

    // Activate the session — until this is called bytes pushed via
    // `on_client_datagram` queue up and never reach the service.
    unsafe {
        bindings::rama_transparent_proxy_udp_session_activate(
            session as *mut bindings::RamaTransparentProxyUdpSession,
            bindings::RamaTransparentProxyUdpEgressCallbacks {
                context: egress_ctx_ptr as *mut c_void,
                on_send_to_egress: Some(on_udp_send_to_egress),
            },
        );
    }

    // Egress writer: service-bound datagrams → upstream socket.
    let stop_egress = Arc::new(Notify::new());
    let stop_egress_for_writer = stop_egress.clone();
    let writer_socket = egress_socket.clone();
    let egress_writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                next = egress_rx.recv() => {
                    match next {
                        Some(chunk) => {
                            _ = writer_socket.send(&chunk).await;
                        }
                        None => break,
                    }
                }
                _ = stop_egress_for_writer.notified() => break,
            }
        }
    });

    // Egress reader: upstream datagrams → on_egress_datagram.
    let stop_egress_for_reader = stop_egress.clone();
    let reader_socket = egress_socket.clone();
    let egress_session = session;
    let egress_reader = tokio::spawn(async move {
        let mut buf = [0_u8; 64 * 1024];
        loop {
            tokio::select! {
                result = reader_socket.recv(&mut buf) => {
                    match result {
                        Ok(n) if n > 0 => unsafe {
                            bindings::rama_transparent_proxy_udp_session_on_egress_datagram(
                                egress_session as *mut bindings::RamaTransparentProxyUdpSession,
                                bindings::RamaBytesView {
                                    ptr: buf.as_ptr(),
                                    len: n,
                                },
                            );
                        },
                        Ok(_) | Err(_) => break,
                    }
                }
                _ = stop_egress_for_reader.notified() => break,
            }
        }
    });

    // Now push the client datagram through the session.
    unsafe {
        bindings::rama_transparent_proxy_udp_session_on_client_datagram(
            session as *mut bindings::RamaTransparentProxyUdpSession,
            bindings::RamaBytesView {
                ptr: payload.as_ptr(),
                len: payload.len(),
            },
        );
    }

    let response = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("udp callback timeout")
        .expect("udp callback payload");

    unsafe {
        bindings::rama_transparent_proxy_udp_session_on_client_close(
            session as *mut bindings::RamaTransparentProxyUdpSession,
        );
    }

    stop_egress.notify_waiters();
    egress_writer.abort();
    egress_reader.abort();
    _ = egress_writer.await;
    _ = egress_reader.await;

    response
}

fn proxy_address(proxy_kind: ProxyKind, proxy_addr: std::net::SocketAddr) -> Option<ProxyAddress> {
    let proxy_address = match proxy_kind {
        ProxyKind::None => return None,
        ProxyKind::Http => ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: HostWithPort::from(proxy_addr),
            credential: None,
        },
        ProxyKind::Socks5 => ProxyAddress {
            protocol: Some(Protocol::SOCKS5),
            address: HostWithPort::from(proxy_addr),
            credential: None,
        },
    };
    Some(proxy_address)
}
