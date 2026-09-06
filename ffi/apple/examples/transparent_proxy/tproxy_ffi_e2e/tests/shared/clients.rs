use std::{
    collections::VecDeque,
    ffi::c_void,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    ptr,
    sync::Arc,
    time::{Duration, Instant},
};

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
        client::ProxyRoute,
    },
    rt::Executor,
    service::BoxService,
    tcp::client::default_tcp_connect,
    telemetry::tracing,
    tls::{
        boring::client::{BoringClientConfigExt as _, TlsConnectorData, tls_connect},
        client::{ServerVerifyMode, TlsClientConfig},
    },
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::mpsc,
};

use super::{
    bindings,
    ffi::EngineHandle,
    types::{ProxyKind, TcpMode},
};

pub(crate) type ClientService = BoxService<Request, Response, BoxError>;

struct UdpCallbackContext {
    sender: mpsc::UnboundedSender<UdpCallbackEvent>,
}

#[derive(Debug, Eq, PartialEq)]
enum UdpCallbackEvent {
    ClientReadDemand { probe_id: u64, observed_at: Instant },
    ServerDatagram(UdpDatagram),
    ServerClosed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnedUdpPeer {
    pub(crate) host_utf8: Vec<u8>,
    pub(crate) port: u16,
    pub(crate) scope_id: u32,
}

impl OwnedUdpPeer {
    pub(crate) fn from_socket_addr(addr: SocketAddr) -> Self {
        let scope_id = match addr {
            SocketAddr::V4(_) => 0,
            SocketAddr::V6(addr) => addr.scope_id(),
        };
        Self {
            host_utf8: addr.ip().to_string().into_bytes(),
            port: addr.port(),
            scope_id,
        }
    }

    pub(crate) fn socket_addr(&self) -> SocketAddr {
        let host = std::str::from_utf8(&self.host_utf8)
            .expect("FFI UDP callback peer host must be UTF-8")
            .parse::<IpAddr>()
            .expect("FFI UDP callback peer host must be an IP literal");
        match host {
            IpAddr::V4(addr) => SocketAddr::new(IpAddr::V4(addr), self.port),
            IpAddr::V6(addr) => {
                SocketAddr::V6(SocketAddrV6::new(addr, self.port, 0, self.scope_id))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UdpDatagram {
    pub(crate) payload: Vec<u8>,
    pub(crate) peer: Option<OwnedUdpPeer>,
}

fn copy_udp_peer(peer: bindings::RamaUdpPeerView) -> Option<OwnedUdpPeer> {
    if !peer.present {
        return None;
    }
    let host_utf8 = if peer.host_utf8_len == 0 {
        Vec::new()
    } else if peer.host_utf8.is_null() {
        // This is an invalid producer view. Do not dereference it in the C
        // callback; retaining an empty host makes the later assertion fail
        // safely on the Rust test thread instead of unwinding across FFI.
        Vec::new()
    } else {
        unsafe {
            std::slice::from_raw_parts(peer.host_utf8.cast::<u8>(), peer.host_utf8_len).to_vec()
        }
    };
    Some(OwnedUdpPeer {
        host_utf8,
        port: peer.port,
        scope_id: peer.scope_id,
    })
}

unsafe extern "C" fn on_udp_server_datagram(
    ctx: *mut c_void,
    bytes: bindings::RamaBytesView,
    peer: bindings::RamaUdpPeerView,
) {
    let ctx = unsafe { &*(ctx as *const UdpCallbackContext) };
    let payload = if bytes.ptr.is_null() || bytes.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len).to_vec() }
    };
    _ = ctx
        .sender
        .send(UdpCallbackEvent::ServerDatagram(UdpDatagram {
            payload,
            peer: copy_udp_peer(peer),
        }));
}

unsafe extern "C" fn on_udp_server_closed(ctx: *mut c_void) {
    let ctx = unsafe { &*(ctx as *const UdpCallbackContext) };
    _ = ctx.sender.send(UdpCallbackEvent::ServerClosed);
}

unsafe extern "C" fn on_udp_client_read_demand(ctx: *mut c_void, probe_id: u64) {
    let ctx = unsafe { &*(ctx as *const UdpCallbackContext) };
    _ = ctx.sender.send(UdpCallbackEvent::ClientReadDemand {
        probe_id,
        observed_at: Instant::now(),
    });
}

pub(crate) fn build_http_client(
    cert_store: Option<Arc<rama::tls::boring::core::x509::store::X509Store>>,
) -> ClientService {
    let builder = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_proxy_support();

    let inner = match cert_store {
        Some(store) => {
            let config = TlsClientConfig::default_http()
                .with_server_verify(ServerVerifyMode::Auto)
                .with_server_verify_cert_store(store);
            builder
                .with_tls_support_using_boringssl_and_default_http_version(config, Version::HTTP_11)
                .with_default_http_connector(Executor::default())
                .without_connection_pool()
                .build_client()
        }
        None => builder
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .without_connection_pool()
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
        builder = builder.extension(ProxyRoute::Proxy(proxy_address));
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
        extensions.insert(ProxyRoute::Proxy(proxy_address));
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

/// Like [`websocket_echo`] but offers `permessage-deflate`, exactly as the
/// `rama` CLI WS client does (`.with_per_message_deflate_overwrite_extensions()`).
/// This is what `rama -k wss://echo.ramaproxy.org` negotiates in the wild, and
/// the plain [`websocket_echo`] path does NOT cover it — so a relay that can't
/// transcode compressed frames would slip through every other WS test.
pub(crate) async fn websocket_echo_deflate(
    client: &ClientService,
    url: String,
    version: Version,
    proxy_kind: ProxyKind,
    proxy_addr: std::net::SocketAddr,
) {
    let extensions = rama::extensions::Extensions::new();
    if let Some(proxy_address) = proxy_address(proxy_kind, proxy_addr) {
        extensions.insert(ProxyRoute::Proxy(proxy_address));
    }

    tracing::info!(?version, ?proxy_kind, %proxy_addr, "start deflate ws handshake");

    let mut ws = match version {
        Version::HTTP_2 => client.websocket_h2(url),
        _ => client.websocket(url),
    }
    .with_per_message_deflate_overwrite_extensions()
    .handshake(extensions)
    .await
    .expect("deflate websocket handshake");

    tracing::info!(?version, ?proxy_kind, "deflate ws handshake complete");

    // A payload long + repetitive enough that deflate actually compresses it,
    // so a broken inflate path on either relay leg corrupts the round-trip.
    let payload = "hello ffi ".repeat(64);
    ws.send_message(Message::text(payload.clone()))
        .await
        .expect("send deflate websocket message");
    let echoed = ws
        .recv_message()
        .await
        .expect("recv deflate websocket message")
        .into_text()
        .expect("deflate websocket text response");
    assert_eq!(echoed.as_str(), payload.as_str());

    _ = tokio::time::timeout(Duration::from_millis(250), ws.close(None)).await;
}

/// Like [`websocket_echo`] but keeps the tunnel open for several
/// round-trips with a sleep between each, so the test fails if the
/// upgraded tunnel is torn down after the initial 101 instead of
/// living for the duration of the conversation.
pub(crate) async fn websocket_echo_sustained(
    client: &ClientService,
    url: String,
    version: Version,
    proxy_kind: ProxyKind,
    proxy_addr: std::net::SocketAddr,
    rounds: usize,
    gap: Duration,
) {
    let extensions = rama::extensions::Extensions::new();
    if let Some(proxy_address) = proxy_address(proxy_kind, proxy_addr) {
        extensions.insert(ProxyRoute::Proxy(proxy_address));
    }

    tracing::info!(?version, ?proxy_kind, %proxy_addr, rounds, ?gap, "start sustained ws handshake");

    let mut ws = match version {
        Version::HTTP_2 => client.websocket_h2(url),
        _ => client.websocket(url),
    }
    .handshake(extensions)
    .await
    .expect("websocket handshake");

    tracing::info!(?version, ?proxy_kind, "sustained ws handshake complete");

    for round in 0..rounds {
        if round > 0 {
            tokio::time::sleep(gap).await;
        }
        let payload = format!("hello ffi #{round}");
        ws.send_message(Message::text(payload.clone()))
            .await
            .unwrap_or_else(|err| panic!("send ws message (round {round}): {err}"));
        let echoed = ws
            .recv_message()
            .await
            .unwrap_or_else(|err| panic!("recv ws message (round {round}): {err}"))
            .into_text()
            .unwrap_or_else(|err| panic!("ws text response (round {round}): {err}"));
        assert_eq!(
            echoed.as_str(),
            payload.as_str(),
            "echo mismatch on round {round}"
        );
        tracing::info!(?version, ?proxy_kind, round, "sustained ws round ok");
    }

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
            )
            .await
            .expect("connect direct ingress");
            stream
        }
        ProxyKind::Http | ProxyKind::Socks5 => {
            let (mut stream, _) = default_tcp_connect(
                &rama::extensions::Extensions::new(),
                HostWithPort::from(proxy_addr),
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
            let config = TlsClientConfig::new()
                .with_server_verify(ServerVerifyMode::Disable)
                .with_server_name(Domain::from_static("127.0.0.1").into());
            let connector = TlsConnectorData::try_from(&config).expect("build tls connector data");
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

/// Live UDP session driven through the exported C ABI.
///
/// The callback context deliberately records demand, attributed datagrams,
/// and terminal close as distinct events. This mirrors Swift's production
/// contract: client reads begin only after Rust requests one, callback views
/// are copied before returning across FFI, and callback storage remains alive
/// until service close or client-close quiescence has been observed and the
/// session is freed.
pub(crate) struct UdpFfiSession {
    _engine: Arc<EngineHandle>,
    session: usize,
    context: usize,
    events: mpsc::UnboundedReceiver<UdpCallbackEvent>,
    pending_demands: VecDeque<(u64, Instant)>,
    demand_permits: VecDeque<u64>,
    pending_datagrams: VecDeque<UdpDatagram>,
}

impl UdpFfiSession {
    /// Create a session matching the Swift bridge's probe/ACK contract.
    pub(crate) fn new(engine: Arc<EngineHandle>, remote_addr: SocketAddr) -> Self {
        let (tx, events) = mpsc::unbounded_channel();
        let context = Box::into_raw(Box::new(UdpCallbackContext { sender: tx })) as usize;
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
        let result = unsafe {
            bindings::rama_transparent_proxy_engine_new_udp_session(
                engine.raw,
                &meta,
                bindings::RamaTransparentProxyUdpSessionCallbacks {
                    context: context as *mut c_void,
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
        Self {
            _engine: engine,
            session: raw as usize,
            context,
            events,
            pending_demands: VecDeque::new(),
            demand_permits: VecDeque::new(),
            pending_datagrams: VecDeque::new(),
        }
    }

    pub(crate) fn activate(&self) {
        unsafe {
            bindings::rama_transparent_proxy_udp_session_activate(
                self.session as *mut bindings::RamaTransparentProxyUdpSession,
            );
        }
    }

    async fn next_event(&mut self) -> UdpCallbackEvent {
        tokio::time::timeout(Duration::from_secs(10), self.events.recv())
            .await
            .expect("UDP FFI callback event timed out")
            .expect("UDP FFI callback channel closed before session teardown")
    }

    pub(crate) async fn wait_for_read_demand(&mut self) -> u64 {
        if let Some((probe_id, _)) = self.pending_demands.pop_front() {
            self.demand_permits.push_back(probe_id);
            return probe_id;
        }
        loop {
            match self.next_event().await {
                UdpCallbackEvent::ClientReadDemand { probe_id, .. } => {
                    self.demand_permits.push_back(probe_id);
                    return probe_id;
                }
                UdpCallbackEvent::ServerDatagram(datagram) => {
                    self.pending_datagrams.push_back(datagram);
                }
                UdpCallbackEvent::ServerClosed => {
                    panic!("UDP server closed before requesting the next client read")
                }
            }
        }
    }

    /// Wait specifically for a leased global-pressure retry. Ordinary
    /// zero-ID demands are retained for their own later reads. Seeing any
    /// server datagram first proves the supposedly rejected datagram reached
    /// the service and fails the boundary test immediately.
    pub(crate) async fn wait_for_probe_read_demand(&mut self) -> u64 {
        if let Some(position) = self.pending_demands.iter().position(|(id, _)| *id != 0) {
            let (probe_id, _) = self
                .pending_demands
                .remove(position)
                .expect("located UDP probe demand");
            self.demand_permits.push_back(probe_id);
            return probe_id;
        }
        loop {
            match self.next_event().await {
                UdpCallbackEvent::ClientReadDemand {
                    probe_id: 0,
                    observed_at,
                } => {
                    self.pending_demands.push_back((0, observed_at));
                }
                UdpCallbackEvent::ClientReadDemand { probe_id, .. } => {
                    self.demand_permits.push_back(probe_id);
                    return probe_id;
                }
                UdpCallbackEvent::ServerDatagram(datagram) => {
                    panic!(
                        "globally stalled UDP flow delivered a datagram before probe demand: {datagram:?}"
                    )
                }
                UdpCallbackEvent::ServerClosed => {
                    panic!("globally stalled UDP flow closed before probe demand")
                }
            }
        }
    }

    /// Submit one datagram after the caller has consumed a read-demand event.
    /// A non-zero probe ID must be acknowledged separately before this call.
    /// Returns the exact probe ID associated with that read (zero for ordinary demand).
    pub(crate) fn send_client_datagram(&mut self, payload: &[u8], peer: Option<SocketAddr>) -> u64 {
        let probe_id = self
            .demand_permits
            .pop_front()
            .expect("UDP client datagram submitted without a preceding read-demand callback");
        self.deliver_client_datagram(payload, peer);
        probe_id
    }

    /// Stage ingress on an inactive session through the public C ABI. This is
    /// used only by the global-budget boundary test: keeping the service
    /// unactivated makes retained-byte ownership deterministic while avoiding
    /// any engine-internal test hooks.
    pub(crate) fn stage_client_datagram_before_activation(
        &self,
        payload: &[u8],
        peer: Option<SocketAddr>,
    ) {
        self.deliver_client_datagram(payload, peer);
    }

    /// Stage caller-owned payload and peer-host views through the public ABI.
    /// The caller may overwrite both buffers as soon as this method returns;
    /// Rust must already have copied/parsed everything it retains.
    pub(crate) fn stage_borrowed_client_datagram_before_activation(
        &self,
        payload: &[u8],
        peer_host_utf8: &[u8],
        port: u16,
        scope_id: u32,
    ) {
        self.deliver_client_datagram_view(
            payload,
            bindings::RamaUdpPeerView {
                present: true,
                host_utf8: peer_host_utf8.as_ptr().cast(),
                host_utf8_len: peer_host_utf8.len(),
                port,
                scope_id,
            },
        );
    }

    fn deliver_client_datagram(&self, payload: &[u8], peer: Option<SocketAddr>) {
        let peer_host = peer.map(|addr| addr.ip().to_string().into_bytes());
        let peer_view = match (peer, peer_host.as_ref()) {
            (Some(addr), Some(host)) => bindings::RamaUdpPeerView {
                present: true,
                host_utf8: host.as_ptr().cast(),
                host_utf8_len: host.len(),
                port: addr.port(),
                scope_id: match addr {
                    SocketAddr::V4(_) => 0,
                    SocketAddr::V6(addr) => addr.scope_id(),
                },
            },
            (None, None) => bindings::RamaUdpPeerView {
                present: false,
                host_utf8: ptr::null(),
                host_utf8_len: 0,
                port: 0,
                scope_id: 0,
            },
            _ => unreachable!("peer and its encoded host are created together"),
        };
        self.deliver_client_datagram_view(payload, peer_view);
    }

    fn deliver_client_datagram_view(&self, payload: &[u8], peer_view: bindings::RamaUdpPeerView) {
        unsafe {
            bindings::rama_transparent_proxy_udp_session_on_client_datagram(
                self.session as *mut bindings::RamaTransparentProxyUdpSession,
                bindings::RamaBytesView {
                    ptr: payload.as_ptr(),
                    len: payload.len(),
                },
                peer_view,
            );
        }
    }

    pub(crate) fn acknowledge_client_read(&self, probe_id: u64) {
        unsafe {
            bindings::rama_transparent_proxy_udp_session_on_client_read_complete(
                self.session as *mut bindings::RamaTransparentProxyUdpSession,
                probe_id,
            );
        }
    }

    /// Wait for a probe callback for at most `timeout`, returning `None` when
    /// no callback arrived. Pressure/ACK tests configure a deliberately long
    /// production lease and use a comfortably shorter negative window here;
    /// callback-entry timestamps separately prove positive progress preceded
    /// expiry even if the waiting task was descheduled.
    pub(crate) async fn wait_for_probe_read_demand_before(
        &mut self,
        timeout: Duration,
    ) -> Option<u64> {
        tokio::time::timeout(timeout, self.wait_for_probe_read_demand())
            .await
            .ok()
    }

    /// Like `wait_for_probe_read_demand`, but also returns the timestamp taken
    /// at C callback entry. Tests can prove progress preceded the lease-expiry
    /// backstop without depending on when their own task was scheduled.
    pub(crate) async fn wait_for_probe_read_demand_observed(&mut self) -> (u64, Instant) {
        if let Some(position) = self.pending_demands.iter().position(|(id, _)| *id != 0) {
            let observed = self
                .pending_demands
                .remove(position)
                .expect("located UDP probe demand");
            self.demand_permits.push_back(observed.0);
            return observed;
        }
        loop {
            match self.next_event().await {
                UdpCallbackEvent::ClientReadDemand {
                    probe_id: 0,
                    observed_at,
                } => self.pending_demands.push_back((0, observed_at)),
                UdpCallbackEvent::ClientReadDemand {
                    probe_id,
                    observed_at,
                } => {
                    self.demand_permits.push_back(probe_id);
                    return (probe_id, observed_at);
                }
                UdpCallbackEvent::ServerDatagram(datagram) => {
                    panic!(
                        "globally stalled UDP flow delivered a datagram before probe demand: {datagram:?}"
                    )
                }
                UdpCallbackEvent::ServerClosed => {
                    panic!("globally stalled UDP flow closed before probe demand")
                }
            }
        }
    }

    /// After another callback has provided a synchronization edge, prove this
    /// inactive flow was not selected as a global waiter. No deadline or sleep
    /// is involved: coordinator callbacks preceding that edge are already in
    /// this session's queue.
    pub(crate) fn assert_no_callbacks_queued(&mut self) {
        assert!(
            self.pending_demands.is_empty()
                && self.demand_permits.is_empty()
                && self.pending_datagrams.is_empty(),
            "UDP session retained an unexpected buffered callback"
        );
        if let Ok(event) = self.events.try_recv() {
            panic!("unexpected queued UDP callback: {event:?}");
        }
    }

    pub(crate) async fn recv_server_datagram(&mut self) -> UdpDatagram {
        if let Some(datagram) = self.pending_datagrams.pop_front() {
            return datagram;
        }
        loop {
            match self.next_event().await {
                UdpCallbackEvent::ClientReadDemand {
                    probe_id,
                    observed_at,
                } => {
                    self.pending_demands.push_back((probe_id, observed_at));
                }
                UdpCallbackEvent::ServerDatagram(datagram) => return datagram,
                UdpCallbackEvent::ServerClosed => {
                    panic!("UDP server closed before delivering its expected datagram")
                }
            }
        }
    }

    /// Close from the client through the C ABI, optionally issuing the
    /// idempotency probe twice, then prove that teardown suppresses all later
    /// server callbacks before releasing the callback context.
    pub(crate) fn close_from_client_and_assert(mut self, close_calls: usize) {
        assert!(
            close_calls > 0,
            "a UDP FFI session must be closed at least once"
        );
        for _ in 0..close_calls {
            unsafe {
                bindings::rama_transparent_proxy_udp_session_on_client_close(
                    self.session as *mut bindings::RamaTransparentProxyUdpSession,
                );
            }
        }

        unsafe {
            bindings::rama_transparent_proxy_udp_session_free(
                self.session as *mut bindings::RamaTransparentProxyUdpSession,
            );
        }
        self.session = 0;

        // `on_client_close` returns only after taking the same callback gate
        // used by every Rust-to-Swift dispatch and switching it off. Therefore
        // this absence check needs no sleep: callbacks in the queue happened
        // before close, while future callbacks are contractually suppressed.
        let mut close_count = 0;
        while let Ok(event) = self.events.try_recv() {
            match event {
                UdpCallbackEvent::ClientReadDemand { .. } => {}
                UdpCallbackEvent::ServerDatagram(datagram) => {
                    panic!("unexpected unconsumed UDP server datagram at close: {datagram:?}")
                }
                UdpCallbackEvent::ServerClosed => close_count += 1,
            }
        }
        assert_eq!(
            close_count, 0,
            "client-close teardown must suppress the server-close callback"
        );
        assert!(
            self.pending_datagrams.is_empty(),
            "all UDP server datagrams must be consumed before close"
        );

        unsafe {
            drop(Box::from_raw(self.context as *mut UdpCallbackContext));
        }
        self.context = 0;
    }

    /// Wait for the service to close the server side, prove its terminal
    /// callback fires exactly once, and only then release the callback context.
    pub(crate) async fn assert_server_close_and_free(mut self) {
        let mut close_count = 0;
        loop {
            match self.next_event().await {
                UdpCallbackEvent::ClientReadDemand {
                    probe_id,
                    observed_at,
                } => {
                    self.pending_demands.push_back((probe_id, observed_at));
                }
                UdpCallbackEvent::ServerDatagram(datagram) => {
                    self.pending_datagrams.push_back(datagram);
                }
                UdpCallbackEvent::ServerClosed => {
                    close_count += 1;
                    break;
                }
            }
        }

        // The service task has completed after dispatching the close callback.
        // Closing now disables any stray dispatch before the callback box is
        // released; freeing the session also makes duplicate events impossible.
        unsafe {
            bindings::rama_transparent_proxy_udp_session_on_client_close(
                self.session as *mut bindings::RamaTransparentProxyUdpSession,
            );
            bindings::rama_transparent_proxy_udp_session_free(
                self.session as *mut bindings::RamaTransparentProxyUdpSession,
            );
        }
        self.session = 0;

        while let Ok(event) = self.events.try_recv() {
            match event {
                UdpCallbackEvent::ClientReadDemand { .. } => {}
                UdpCallbackEvent::ServerDatagram(datagram) => {
                    panic!("unexpected UDP server datagram after service close: {datagram:?}")
                }
                UdpCallbackEvent::ServerClosed => close_count += 1,
            }
        }
        assert_eq!(
            close_count, 1,
            "service-side UDP close callback must fire exactly once"
        );
        assert!(
            self.pending_datagrams.is_empty(),
            "unexpected UDP server datagram remained at service close"
        );

        unsafe {
            drop(Box::from_raw(self.context as *mut UdpCallbackContext));
        }
        self.context = 0;
    }
}

/// One-shot UDP echo round-trip through the real example static library.
///
/// Unlike the old payload-only helper, this follows Rust's read-demand before
/// submitting and asserts the reply's per-datagram peer before proving clean
/// terminal callback delivery.
pub(crate) async fn udp_roundtrip(
    engine: Arc<EngineHandle>,
    remote_addr: SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut session = UdpFfiSession::new(engine, remote_addr);
    session.activate();
    let probe_id = session.wait_for_read_demand().await;
    assert_eq!(probe_id, 0, "ordinary UDP demand must use ID zero");
    session.acknowledge_client_read(probe_id);
    let delivered_probe_id = session.send_client_datagram(payload, Some(remote_addr));
    assert_eq!(delivered_probe_id, probe_id);
    let response = session.recv_server_datagram().await;
    assert_eq!(
        response.peer,
        Some(OwnedUdpPeer::from_socket_addr(remote_addr)),
        "UDP FFI reply must retain the real recv_from peer"
    );
    session.close_from_client_and_assert(1);
    response.payload
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

#[cfg(test)]
mod udp_callback_tests {
    use super::*;

    #[test]
    fn demand_callback_preserves_probe_id() {
        let (sender, mut events) = mpsc::unbounded_channel();
        let context = UdpCallbackContext { sender };

        unsafe {
            on_udp_client_read_demand(ptr::from_ref(&context).cast_mut().cast(), 0xfeed_beef);
        }

        assert!(matches!(
            events.try_recv().expect("demand callback event"),
            UdpCallbackEvent::ClientReadDemand {
                probe_id: 0xfeed_beef,
                ..
            }
        ));
    }

    #[test]
    fn datagram_callback_copies_payload_and_scoped_ipv6_peer() {
        let (sender, mut events) = mpsc::unbounded_channel();
        let context = UdpCallbackContext { sender };
        let mut payload = b"borrowed payload".to_vec();
        let mut host = b"fe80::1234".to_vec();

        unsafe {
            on_udp_server_datagram(
                ptr::from_ref(&context).cast_mut().cast(),
                bindings::RamaBytesView {
                    ptr: payload.as_ptr(),
                    len: payload.len(),
                },
                bindings::RamaUdpPeerView {
                    present: true,
                    host_utf8: host.as_ptr().cast(),
                    host_utf8_len: host.len(),
                    port: 5353,
                    scope_id: 17,
                },
            );
        }

        // Both views are borrowed only for the callback. Destroy their source
        // bytes before inspecting the channel event to catch retained pointers.
        payload.fill(0);
        host.fill(0);

        let event = events.try_recv().expect("datagram callback event");
        let expected_peer = OwnedUdpPeer {
            host_utf8: b"fe80::1234".to_vec(),
            port: 5353,
            scope_id: 17,
        };
        assert_eq!(
            event,
            UdpCallbackEvent::ServerDatagram(UdpDatagram {
                payload: b"borrowed payload".to_vec(),
                peer: Some(expected_peer.clone()),
            })
        );
        assert_eq!(
            expected_peer.socket_addr(),
            SocketAddr::V6(SocketAddrV6::new(
                "fe80::1234".parse().expect("IPv6 address"),
                5353,
                0,
                17,
            ))
        );
    }

    #[test]
    fn datagram_callback_preserves_absent_peer_and_zero_length_payload() {
        let (sender, mut events) = mpsc::unbounded_channel();
        let context = UdpCallbackContext { sender };

        unsafe {
            on_udp_server_datagram(
                ptr::from_ref(&context).cast_mut().cast(),
                bindings::RamaBytesView {
                    ptr: ptr::null(),
                    len: 0,
                },
                bindings::RamaUdpPeerView {
                    present: false,
                    host_utf8: ptr::null(),
                    host_utf8_len: 0,
                    port: 0,
                    scope_id: 0,
                },
            );
        }

        assert_eq!(
            events.try_recv().expect("datagram callback event"),
            UdpCallbackEvent::ServerDatagram(UdpDatagram {
                payload: Vec::new(),
                peer: None,
            })
        );
    }
}
