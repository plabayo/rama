//! CONNECT-UDP (RFC 9298) between a Rama client and a Rama MASQUE proxy on every carrier:
//! HTTP/1.1, HTTP/2, HTTP/3 with DATAGRAM capsules and HTTP/3 with native QUIC datagrams.
//! Targets are a loopback UDP echo server and, for HTTP/3 through the proxy, a loopback
//! HTTP/3 origin.

use rama::futures::future::join_all;
use rama::{
    Layer as _, Service,
    crypto::cert::boring::generate_certificate_authority_x509,
    dns::client::DnsConnector,
    error::{BoxError, error_chain, extra::OpaqueError},
    extensions::{Extensions, ExtensionsRef},
    http::{
        Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version,
        body::util::BodyExt as _,
        client::{DefaultHttpWebClient, EasyHttpWebClient, Http3Connector, masque_quic_transport},
        conn::TargetHttpVersion,
        headers::{HeaderMapExt as _, ProxyErrorType, ProxyStatus},
        layer::{
            error_handling::ErrorHandlerLayer,
            proxy_auth::ProxyAuthLayer,
            set_header::SetResponseHeaderLayer,
            upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        },
        proto::ext::HttpDatagrams,
        proxy::HttpProxyConnectMatcher,
        proxy::{h3::Http3MitmRelay, mitm::DefaultErrorResponse},
        server::HttpServer,
    },
    io::BridgeIo,
    layer::{AddInputExtensionLayer, ArcLayer, ConsumeErrLayer, MapInputLayer},
    net::{
        address::{HostWithPort, ProxyAddress, ProxyPathTemplate, SocketAddress},
        client::{
            ConnectRequest, ConnectionError, ConnectorTarget, EstablishedClientConnection,
            EstablishedProxyRoute, ProxyRoute,
        },
        mode::DnsResolveIpMode,
        proxy::IoForwardService,
        stream::Socket,
        tls::ApplicationProtocol,
        user::{UserId, credentials::basic},
    },
    proxy::masque::connect_udp::{
        ConnectUdpConnector, ConnectUdpDestination, ConnectUdpLimits, ConnectUdpPolicy,
        ConnectUdpRelay, ConnectUdpService, ConnectUdpSocket, ConnectUdpTarget,
        DestinationScopePolicy, MAX_UDP_PAYLOAD, MaybeTunneledSocket, TunnelBudget,
        connect_udp_request,
    },
    quic::{
        Endpoint, MIN_UDP_PAYLOAD, ServerConfig, SocketCapacityError, TransportConfig,
        client::QuicEndpointConnector,
        proto::VarInt,
        proxy::{InputWithQuicClientHello, PeekQuicClientHelloService, QuicMitmRelay, QuicRelay},
        tls::{
            BoringTlsProvider, QuicClientConfigProvider, TlsOptions, default_server_tls_provider,
            default_tls_provider,
        },
    },
    rt::Executor,
    service::{BoxService, service_fn},
    tcp::{TcpStream, client::service::TcpConnector, server::TcpListener},
    tls::{
        alpn::AlpnRouter,
        boring::{
            proxy::cert_issuer::{CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer},
            server::TlsAcceptorLayer,
        },
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, SelfSignedCaConfig, ServerAuthData, TlsServerConfig},
    },
    udp::{
        DatagramCapabilities, DatagramDemux, DatagramError, DatagramMetadata,
        DatagramSenderExt as _, DatagramSocket, DatagramSocketExt as _, DemuxConfig, DemuxedSocket,
        PrefixedDatagramSocket, SendDatagram, UdpPacketSender, UdpPacketSocket,
        proxy::{
            DatagramForwardService, DatagramToProxyBridge, EcnPolicy, PacketErrorPolicy,
            UdpConnector,
        },
    },
    username::UsernameOpaqueLabelParser,
    utils::octets::{kib, mib},
};
use std::{
    convert::Infallible,
    io::{ErrorKind, IoSliceMut},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};

mod matrix;
mod transparent;

const DEADLINE: Duration = Duration::from_secs(30);

/// The carriers a tunnel can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carrier {
    Http1,
    Http2,
    Http3Capsule,
    Http3Datagram,
}

impl Carrier {
    const ALL: [Self; 4] = [
        Self::Http1,
        Self::Http2,
        Self::Http3Capsule,
        Self::Http3Datagram,
    ];

    fn version(self) -> Version {
        match self {
            Self::Http1 => Version::HTTP_11,
            Self::Http2 => Version::HTTP_2,
            Self::Http3Capsule | Self::Http3Datagram => Version::HTTP_3,
        }
    }
}

/// The QUIC TLS backend of a fixture's clients and servers. A QUIC MITM keeps its BoringSSL
/// certificate issuer either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicTls {
    Boring,
    /// The feature default: Rustls with every feature enabled.
    Rustls,
}

impl QuicTls {
    fn client(self) -> Arc<dyn QuicClientConfigProvider> {
        match self {
            Self::Boring => Arc::new(BoringTlsProvider),
            Self::Rustls => default_tls_provider().unwrap(),
        }
    }

    fn server_config(self, tls: &TlsServerConfig) -> ServerConfig {
        match self {
            Self::Boring => ServerConfig::try_from_rama_tls_with_provider(
                tls,
                TlsOptions::default(),
                &BoringTlsProvider,
            ),
            Self::Rustls => ServerConfig::try_from_rama_tls_with_provider(
                tls,
                TlsOptions::default(),
                default_server_tls_provider().unwrap().as_ref(),
            ),
        }
        .unwrap()
    }
}

/// A fixture's tasks, stopped when dropped, and the requests it served.
struct Tasks {
    tasks: Vec<JoinHandle<()>>,
    endpoint: Option<Endpoint>,
    requests: Arc<AtomicUsize>,
    /// The TCP connections a fixture proxy accepted.
    tcp_connections: Arc<AtomicUsize>,
    /// The egress sockets of a fixture proxy's tunnels.
    proxy: Option<Arc<EgressSockets>>,
}

impl Tasks {
    fn new(tasks: Vec<JoinHandle<()>>, endpoint: Option<Endpoint>) -> Self {
        Self {
            tasks,
            endpoint,
            requests: Arc::default(),
            tcp_connections: Arc::default(),
            proxy: None,
        }
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32, b"test fixture dropped");
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Counts a proxy's tunnel egress sockets: each lives exactly as long as its tunnel's relay.
#[derive(Debug, Default)]
struct EgressSockets {
    opened: AtomicUsize,
    active: AtomicUsize,
}

impl EgressSockets {
    fn opened(&self) -> usize {
        self.opened.load(Ordering::SeqCst)
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

/// The proxy's egress connector, counting the sockets it hands out.
#[derive(Debug, Clone)]
struct CountingUdpConnector(Arc<EgressSockets>);

impl Service<ConnectRequest> for CountingUdpConnector {
    type Output = EstablishedClientConnection<CountedSocket, ConnectRequest>;
    type Error = BoxError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = UdpConnector::new().serve(input).await?;
        self.0.opened.fetch_add(1, Ordering::SeqCst);
        self.0.active.fetch_add(1, Ordering::SeqCst);
        Ok(EstablishedClientConnection {
            input,
            conn: CountedSocket {
                socket: conn,
                count: self.0.clone(),
            },
        })
    }
}

#[derive(Debug)]
struct CountedSocket {
    socket: UdpPacketSocket,
    count: Arc<EgressSockets>,
}

impl Drop for CountedSocket {
    fn drop(&mut self) {
        self.count.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ExtensionsRef for CountedSocket {
    fn extensions(&self) -> &Extensions {
        self.socket.extensions()
    }
}

impl Socket for CountedSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddress> {
        self.socket.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddress> {
        self.socket.peer_addr()
    }
}

impl DatagramSocket for CountedSocket {
    type Sender = UdpPacketSender;

    fn create_sender(&self) -> Self::Sender {
        self.socket.create_sender()
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        self.socket.poll_recv(cx, buffers, metadata)
    }

    fn capabilities(&self) -> DatagramCapabilities {
        self.socket.capabilities()
    }
}

/// A loopback UDP server answering every datagram with the same payload.
async fn udp_echo() -> (SocketAddress, Tasks) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = SocketAddress::from(socket.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; 65536];
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            _ = socket.send_to(&buffer[..len], from).await;
        }
    });
    (address, Tasks::new(vec![task], None))
}

/// Who a fixture proxy lets in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyAuth {
    Anonymous,
    /// `john` / `secret`.
    Basic,
    /// `john` / `secret`, with provider-style labels in the username (`john-country-be`).
    BasicWithLabels,
}

/// A MASQUE proxy on one TCP (HTTP/1.1, HTTP/2) and one UDP (HTTP/3) port.
async fn masque_proxy<P>(
    template: Option<&ProxyPathTemplate>,
    policy: P,
    h3_datagrams: bool,
) -> (SocketAddress, Tasks)
where
    P: ConnectUdpPolicy,
{
    masque_proxy_with(
        template,
        policy,
        h3_datagrams,
        ProxyAuth::Anonymous,
        QuicTls::Boring,
    )
    .await
}

async fn masque_proxy_with<P>(
    template: Option<&ProxyPathTemplate>,
    policy: P,
    h3_datagrams: bool,
    auth: ProxyAuth,
    quic: QuicTls,
) -> (SocketAddress, Tasks)
where
    P: ConnectUdpPolicy,
{
    masque_proxy_limited(
        template,
        policy,
        h3_datagrams,
        auth,
        quic,
        ConnectUdpLimits::new(),
        Some(TunnelBudget::new()),
    )
    .await
}

async fn masque_proxy_limited<P>(
    template: Option<&ProxyPathTemplate>,
    policy: P,
    h3_datagrams: bool,
    auth: ProxyAuth,
    quic: QuicTls,
    limits: ConnectUdpLimits,
    budget: Option<TunnelBudget>,
) -> (SocketAddress, Tasks)
where
    P: ConnectUdpPolicy,
{
    let exec = Executor::new();
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let stats = Arc::new(EgressSockets::default());
    let connect_udp = ConnectUdpService::try_new(exec.clone(), template)
        .unwrap()
        .with_policy(policy)
        .with_connector(CountingUdpConnector(stats.clone()))
        .with_limits(limits)
        .maybe_with_tunnel_budget(budget);
    // The fixtures resolve names to IPv4 loopback.
    let service = (
        MapInputLayer::new(move |request: Request| {
            counted.fetch_add(1, Ordering::SeqCst);
            request
        }),
        AddInputExtensionLayer::new(DnsResolveIpMode::SingleIpV4),
        // Ordinary CONNECT carries TCP through the same proxy; the rest is CONNECT-UDP.
        UpgradeLayer::new(
            exec.clone(),
            HttpProxyConnectMatcher::new(),
            EagerHttpProxyConnector::new(
                DnsConnector::new(TcpConnector::new()),
                IoForwardService::new(exec.clone()),
            ),
        ),
    )
        .into_layer(connect_udp);
    // One service type for every variant: anonymous access goes through the same layer.
    let service = match auth {
        ProxyAuth::Anonymous => ProxyAuthLayer::new(basic!("john", "secret"))
            .with_allow_anonymous(true)
            .into_layer(service)
            .boxed(),
        ProxyAuth::Basic => ProxyAuthLayer::new(basic!("john", "secret"))
            .into_layer(service)
            .boxed(),
        ProxyAuth::BasicWithLabels => ProxyAuthLayer::new(basic!("john", "secret"))
            .with_labels::<UsernameOpaqueLabelParser>()
            .into_layer(service)
            .boxed(),
    };
    let service = Arc::new(ErrorHandlerLayer::new().into_layer(service));
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();

    let tls = TlsServerConfig::new()
        .with_server_auth(auth.clone())
        .with_alpn(
            [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
                .into_iter()
                .collect(),
        );
    let mut http = HttpServer::auto(exec.clone());
    http.h2_mut().set_enable_connect_protocol();
    let tcp_connections = Arc::new(AtomicUsize::new(0));
    let accepted = tcp_connections.clone();
    let tcp = (
        MapInputLayer::new(move |stream: TcpStream| {
            accepted.fetch_add(1, Ordering::SeqCst);
            stream
        }),
        TlsAcceptorLayer::new(tls),
    )
        .into_layer(http.service(service.clone()));

    let mut h3 = HttpServer::new_http3(exec.clone());
    h3.http3_mut().extended_connect = true;
    if !h3_datagrams {
        h3.http3_mut().datagrams = None;
    }
    // Room for an inner QUIC packet in each native datagram, and quiet tunnels kept.
    let mut transport = masque_quic_transport();
    h3.http3().configure_transport(&mut transport).unwrap();
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut config = quic.server_config(&tls);
    config.set_transport_config(Arc::new(transport));

    // The same port number for TCP and UDP, as clients expect of an HTTP/3 proxy.
    let (listener, endpoint) = loop {
        let listener = TcpListener::bind_address("127.0.0.1:0", exec.clone())
            .await
            .unwrap();
        let address = SocketAddress::from(listener.local_addr().unwrap());
        match Endpoint::build(exec.clone())
            .with_server_config(config.clone())
            .bind_address(address)
            .await
        {
            Ok(endpoint) => break (listener, endpoint),
            Err(DatagramError::Io(error))
                if matches!(
                    error.kind(),
                    ErrorKind::AddrInUse | ErrorKind::PermissionDenied
                ) => {}
            Err(error) => panic!("{error}"),
        }
    };
    let address = SocketAddress::from(listener.local_addr().unwrap());
    let tcp_task = tokio::spawn(async move { listener.serve(tcp).await });
    let quic_task = tokio::spawn(endpoint.clone().serve(Executor::new(), h3.service(service)));
    let mut tasks = Tasks::new(vec![tcp_task, quic_task], Some(endpoint));
    tasks.requests = requests;
    tasks.tcp_connections = tcp_connections;
    tasks.proxy = Some(stats);
    (address, tasks)
}

type Client = BoxService<Request, Response, OpaqueError>;

fn http_client(exec: Executor) -> Client {
    http_client_on(exec, QuicTls::Boring)
}

/// A client to MASQUE proxies, its HTTP/3 on `quic`.
fn http_client_on(exec: Executor, quic: QuicTls) -> Client {
    http_client_with_transport(exec, masque_quic_transport(), quic)
}

fn http_client_with_transport(exec: Executor, transport: TransportConfig, quic: QuicTls) -> Client {
    let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
    let h3 = Http3Connector::builder(exec.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(quic.client())
        .with_transport(transport)
        .build_lazy()
        .unwrap();
    EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector(exec)
        .with_http3_support(h3)
        .with_default_connection_pool()
        .without_alt_svc()
        .build_client()
        .boxed()
}

fn proxy_address(scheme_and_template: &str, proxy: SocketAddress) -> ProxyAddress {
    let (scheme, template) = scheme_and_template
        .split_once("://")
        .unwrap_or((scheme_and_template, ""));
    ProxyAddress::try_from(format!("{scheme}://{proxy}{template}").as_str()).unwrap()
}

/// A CONNECT-UDP tunnel to `target` through `proxy` over `version`, as the connector layer
/// opens it for a request on a MASQUE proxy route.
async fn open_tunnel(
    exec: Executor,
    proxy: &ProxyAddress,
    target: impl Into<HostWithPort>,
    version: Version,
) -> Result<ConnectUdpSocket, ConnectionError> {
    let connector = ConnectUdpConnector::new(UdpConnector::new(), http_client(exec.clone()), exec)
        .with_version(version);
    let request = ConnectRequest::new(target.into());
    request.extensions.insert(ProxyRoute::Proxy(proxy.clone()));
    let EstablishedClientConnection { conn, .. } = connector.serve(request).await?;
    let MaybeTunneledSocket::Tunneled(socket) = conn else {
        panic!("a MASQUE route must tunnel");
    };
    let route = socket.extensions().get_ref::<EstablishedProxyRoute>();
    assert!(
        matches!(route, Some(EstablishedProxyRoute::Tunnel(established)) if established == proxy),
        "{route:?}"
    );
    Ok(socket)
}

async fn echo(socket: &mut ConnectUdpSocket, payload: &[u8]) {
    let peer = socket.peer_addr().unwrap();
    socket
        .create_sender()
        .send(SendDatagram::new(peer, payload))
        .await
        .unwrap();
    let mut buffer = vec![0; 65536];
    let metadata = timeout(Duration::from_secs(5), socket.recv(&mut buffer))
        .await
        .expect("echo within 5s")
        .unwrap();
    assert_eq!(&buffer[..metadata.len], payload);
    assert!(!metadata.truncated);
}

/// The tunnel runs on the named carrier: only native HTTP/3 datagrams limit payloads below
/// what UDP carries.
fn assert_carrier(socket: &ConnectUdpSocket, carrier: Carrier) {
    if carrier == Carrier::Http3Datagram {
        assert!(socket.max_payload() < 1500, "{carrier:?}: native datagrams");
    } else {
        assert_eq!(
            socket.max_payload(),
            MAX_UDP_PAYLOAD,
            "{carrier:?}: capsules"
        );
    }
}

#[tokio::test]
async fn tunnels_relay_udp_on_every_carrier_and_template() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        // Client-side proxy address (scheme, template) and the proxy's own template.
        let templates: [(&str, Option<&str>); 3] = [
            ("masque://", None),
            (
                "https:///masque/{target_host}/{target_port}/",
                Some("/masque/{target_host}/{target_port}/"),
            ),
            (
                "https:///masque{?h,p}",
                Some("/masque?h={target_host}&p={target_port}"),
            ),
        ];
        for (client_template, server_template) in templates {
            for carrier in Carrier::ALL {
                let label = format!("{carrier:?} via {client_template}");
                let server_template =
                    server_template.map(|template| ProxyPathTemplate::try_new(template).unwrap());
                let (proxy, _proxy) = masque_proxy(
                    server_template.as_ref(),
                    DestinationScopePolicy::allow_private(),
                    carrier != Carrier::Http3Capsule,
                )
                .await;
                let client_template = match client_template {
                    "https:///masque{?h,p}" => "https:///masque?h={target_host}&p={target_port}",
                    template => template,
                };
                let proxy = proxy_address(client_template, proxy);
                let mut socket = open_tunnel(Executor::new(), &proxy, target, carrier.version())
                    .await
                    .unwrap_or_else(|error| panic!("{label}: {error}"));
                for payload in [&b"hello"[..], b"", &[7; 1000]] {
                    echo(&mut socket, payload).await;
                }
                if carrier == Carrier::Http3Datagram {
                    assert!(socket.max_payload() < 1500, "{label}: native datagrams");
                } else {
                    assert_eq!(socket.max_payload(), MAX_UDP_PAYLOAD, "{label}: capsules");
                    // Capsules carry what native QUIC datagrams cannot.
                    echo(&mut socket, &[9; 4000]).await;
                }
            }
        }
    })
    .await
    .unwrap();
}

/// HTTP/2 and HTTP/3 carry several tunnels on one connection, each receiving only its own
/// payloads; an HTTP/1.1 tunnel takes its connection whole.
#[tokio::test]
async fn tunnels_share_one_connection_except_on_http1() {
    const TUNNELS: usize = 4;
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        for carrier in Carrier::ALL {
            let (proxy, fixture) = masque_proxy(
                None,
                DestinationScopePolicy::allow_private(),
                carrier != Carrier::Http3Capsule,
            )
            .await;
            let proxy = proxy_address("masque://", proxy);
            let exec = Executor::new();
            let connector =
                ConnectUdpConnector::new(UdpConnector::new(), http_client(exec.clone()), exec)
                    .with_version(carrier.version());
            let mut sockets = Vec::new();
            for _ in 0..TUNNELS {
                let request = ConnectRequest::new(HostWithPort::from(target));
                request.extensions.insert(ProxyRoute::Proxy(proxy.clone()));
                let EstablishedClientConnection { conn, .. } = connector
                    .serve(request)
                    .await
                    .unwrap_or_else(|error| panic!("{carrier:?}: {error}"));
                let MaybeTunneledSocket::Tunneled(socket) = conn else {
                    panic!("{carrier:?}: a MASQUE route must tunnel");
                };
                assert_carrier(&socket, carrier);
                sockets.push(socket);
            }
            // All tunnels send before any receives, so a misrouted payload would show.
            for (index, socket) in sockets.iter().enumerate() {
                let peer = socket.peer_addr().unwrap();
                socket
                    .create_sender()
                    .send(SendDatagram::new(peer, &[index as u8; 32]))
                    .await
                    .unwrap();
            }
            for (index, socket) in sockets.iter_mut().enumerate() {
                let mut buffer = vec![0; 64];
                let metadata = timeout(Duration::from_secs(5), socket.recv(&mut buffer))
                    .await
                    .unwrap_or_else(|_| panic!("{carrier:?}: tunnel {index} echo within 5s"))
                    .unwrap();
                assert_eq!(&buffer[..metadata.len], &[index as u8; 32], "{carrier:?}");
            }
            assert_eq!(
                fixture.proxy.as_ref().unwrap().active(),
                TUNNELS,
                "{carrier:?}"
            );
            let tcp = fixture.tcp_connections.load(Ordering::SeqCst);
            let quic = fixture.endpoint.as_ref().unwrap().open_connections();
            match carrier {
                Carrier::Http1 => assert_eq!((tcp, quic), (TUNNELS, 0), "{carrier:?}"),
                Carrier::Http2 => assert_eq!((tcp, quic), (1, 0), "{carrier:?}"),
                Carrier::Http3Capsule | Carrier::Http3Datagram => {
                    assert_eq!((tcp, quic), (0, 1), "{carrier:?}");
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn names_resolve_at_the_proxy() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        for carrier in Carrier::ALL {
            let (proxy, _proxy) = masque_proxy(
                None,
                DestinationScopePolicy::allow_private(),
                carrier != Carrier::Http3Capsule,
            )
            .await;
            let target =
                HostWithPort::try_from(format!("localhost:{}", target.port).as_str()).unwrap();
            let mut socket = open_tunnel(
                Executor::new(),
                &proxy_address("masque://", proxy),
                target,
                carrier.version(),
            )
            .await
            .unwrap();
            echo(&mut socket, b"by name").await;
            assert_carrier(&socket, carrier);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn the_default_policy_refuses_loopback_with_proxy_status() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        let (proxy, _proxy) = masque_proxy(None, DestinationScopePolicy::default(), true).await;
        let client = http_client(Executor::new());
        let proxy = proxy_address("masque://", proxy);
        for carrier in Carrier::ALL {
            let request = connect_udp_request(
                &proxy,
                &ConnectUdpTarget::new(target.ip_addr.into(), target.port.try_into().unwrap()),
                carrier.version(),
            )
            .unwrap();
            request.extensions().insert(HttpDatagrams);
            request
                .extensions()
                .insert(TargetHttpVersion(carrier.version()));
            let response = client.serve(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{carrier:?}");
            let status: ProxyStatus = response.headers().typed_get().unwrap();
            assert_eq!(
                status.entries()[0].error,
                Some(ProxyErrorType::DestinationIpProhibited),
                "{carrier:?}"
            );
            assert_eq!(&*status.entries()[0].proxy, "127.0.0.1", "{carrier:?}");
        }
    })
    .await
    .unwrap();
}

/// The policy sees the user the proxy's authentication layer identified, on every carrier.
#[tokio::test]
async fn the_policy_sees_the_authenticated_user_on_every_carrier() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        let only_john = |destination: &ConnectUdpDestination<'_>| {
            destination
                .extensions
                .get_ref::<UserId>()
                .is_some_and(|user| user == "john")
        };
        for carrier in Carrier::ALL {
            let (proxy, _proxy) = masque_proxy_with(
                None,
                (DestinationScopePolicy::allow_private(), only_john),
                carrier != Carrier::Http3Capsule,
                ProxyAuth::Anonymous,
                QuicTls::Boring,
            )
            .await;
            let john =
                ProxyAddress::try_from(format!("masque://john:secret@{proxy}").as_str()).unwrap();
            let mut socket = open_tunnel(Executor::new(), &john, target, carrier.version())
                .await
                .unwrap_or_else(|error| panic!("{carrier:?}: {error}"));
            echo(&mut socket, b"john").await;
            assert_carrier(&socket, carrier);

            let anonymous = proxy_address("masque://", proxy);
            let error = open_tunnel(Executor::new(), &anonymous, target, carrier.version())
                .await
                .expect_err("anonymous users are refused");
            let error = format!("{error:?}");
            assert!(error.contains("502"), "{carrier:?}: {error}");
        }
    })
    .await
    .unwrap();
}

/// A tunnel holds its place from admission until it ends, on every carrier.
#[tokio::test]
async fn a_tunnel_holds_its_place_until_it_ends_on_every_carrier() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        for carrier in Carrier::ALL {
            let limits = ConnectUdpLimits::new().with_max_tunnels(1);
            let (proxy, _proxy) = masque_proxy_limited(
                None,
                DestinationScopePolicy::allow_private(),
                carrier != Carrier::Http3Capsule,
                ProxyAuth::Anonymous,
                QuicTls::Boring,
                limits.clone(),
                Some(TunnelBudget::new()),
            )
            .await;
            let proxy = proxy_address("masque://", proxy);
            let mut first = open_tunnel(Executor::new(), &proxy, target, carrier.version())
                .await
                .unwrap_or_else(|error| panic!("{carrier:?}: {error}"));
            assert_carrier(&first, carrier);
            echo(&mut first, b"first").await;
            assert_eq!(limits.live_tunnels(), 1, "{carrier:?}");

            let error = open_tunnel(Executor::new(), &proxy, target, carrier.version())
                .await
                .expect_err("the proxy is full");
            let error = format!("{error:?}");
            assert!(error.contains("503"), "{carrier:?}: {error}");

            drop(first);
            while limits.live_tunnels() > 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let mut again = open_tunnel(Executor::new(), &proxy, target, carrier.version())
                .await
                .unwrap_or_else(|error| panic!("{carrier:?}: {error}"));
            echo(&mut again, b"again").await;
        }
    })
    .await
    .unwrap();
}

/// A target that never answers receives only the first-reply allowance, on every carrier.
#[tokio::test]
async fn a_silent_target_receives_only_the_first_reply_allowance_on_every_carrier() {
    timeout(DEADLINE, async {
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = SocketAddress::from(sink.local_addr().unwrap());
        let received = Arc::new(AtomicUsize::new(0));
        let counted = received.clone();
        let _sink = tokio::spawn(async move {
            let mut buffer = [0; 2048];
            while sink.recv_from(&mut buffer).await.is_ok() {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });
        for carrier in Carrier::ALL {
            let (proxy, _proxy) = masque_proxy_limited(
                None,
                DestinationScopePolicy::allow_private(),
                carrier != Carrier::Http3Capsule,
                ProxyAuth::Anonymous,
                QuicTls::Boring,
                ConnectUdpLimits::new(),
                Some(TunnelBudget::new().with_unanswered(3, kib(64) as u64)),
            )
            .await;
            let proxy = proxy_address("masque://", proxy);
            let socket = open_tunnel(Executor::new(), &proxy, target, carrier.version())
                .await
                .unwrap_or_else(|error| panic!("{carrier:?}: {error}"));
            assert_carrier(&socket, carrier);
            let before = received.load(Ordering::SeqCst);
            let mut sender = socket.create_sender();
            for _ in 0..8 {
                sender
                    .send(SendDatagram::new(target, b"anyone?"))
                    .await
                    .unwrap();
            }
            // Room for all eight to arrive, had they been forwarded.
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(received.load(Ordering::SeqCst) - before, 3, "{carrier:?}");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unknown_paths_get_not_found() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        let template = ProxyPathTemplate::try_new("/only/{target_host}/{target_port}").unwrap();
        let (proxy, _proxy) = masque_proxy(
            Some(&template),
            DestinationScopePolicy::allow_private(),
            true,
        )
        .await;
        for carrier in Carrier::ALL {
            let error = open_tunnel(
                Executor::new(),
                &proxy_address("masque://", proxy),
                target,
                carrier.version(),
            )
            .await
            .unwrap_err();
            assert!(
                format!("{error:?}").contains("404"),
                "{carrier:?}: {error:?}"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_unreachable_target_closes_the_tunnel() {
    timeout(DEADLINE, async {
        // A port nothing listens on: the proxy's connected socket learns it is refused.
        let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = SocketAddress::from(closed.local_addr().unwrap());
        drop(closed);
        for carrier in Carrier::ALL {
            let (proxy, _proxy) = masque_proxy(
                None,
                DestinationScopePolicy::allow_private(),
                carrier != Carrier::Http3Capsule,
            )
            .await;
            let mut socket = open_tunnel(
                Executor::new(),
                &proxy_address("masque://", proxy),
                target,
                carrier.version(),
            )
            .await
            .unwrap();
            assert_carrier(&socket, carrier);
            let peer = socket.peer_addr().unwrap();
            let mut buffer = [0; 64];
            let mut sender = socket.create_sender();
            let ended = timeout(Duration::from_secs(10), async {
                loop {
                    // Keep sending until the refusal ends the relay and the tunnel with it.
                    if sender
                        .send(SendDatagram::new(peer, b"anyone?"))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    tokio::select! {
                        result = socket.recv(&mut buffer) => {
                            assert!(result.is_err(), "{carrier:?}: unexpected answer");
                            break;
                        }
                        () = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                }
            })
            .await;
            assert!(ended.is_ok(), "{carrier:?}: tunnel stayed open");
        }
    })
    .await
    .unwrap();
}

/// A loopback HTTP/3 origin answering every request with its version.
async fn h3_origin() -> (SocketAddress, Tasks) {
    h3_origin_at(SocketAddress::local_ipv4(0), QuicTls::Boring)
        .await
        .unwrap()
}

/// Whether this host has an IPv6 loopback to bind; rows needing one are skipped without it.
fn ipv6_loopback_available() -> bool {
    std::net::UdpSocket::bind("[::1]:0").is_ok()
}

/// An HTTP/3 origin on `address`: `POST` echoes its body, anything else gets the version.
async fn h3_origin_at(
    address: SocketAddress,
    quic: QuicTls,
) -> Result<(SocketAddress, Tasks), BoxError> {
    let exec = Executor::new();
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let h3 = HttpServer::new_http3(exec.clone());
    let mut transport = TransportConfig::default();
    h3.http3().configure_transport(&mut transport).unwrap();
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut config = quic.server_config(&tls);
    config.set_transport_config(Arc::new(transport));
    let endpoint = Endpoint::build(exec.clone())
        .with_server_config(config)
        .bind_address(address)
        .await?;
    let address = SocketAddress::from(endpoint.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let service = h3.service(service_fn(move |request: Request| {
        counted.fetch_add(1, Ordering::SeqCst);
        handle_origin(request)
    }));
    let task = tokio::spawn(endpoint.clone().serve(exec, service));
    let mut tasks = Tasks::new(vec![task], Some(endpoint));
    tasks.requests = requests;
    Ok((address, tasks))
}

/// `POST` echoes its body, anything else gets the version.
async fn handle_origin(request: Request) -> Result<Response, Infallible> {
    if request.method() == Method::POST {
        return Ok(Response::new(request.into_body()));
    }
    let body = format!("{:?} origin", request.version());
    Ok(Response::new(Body::from(body)))
}

/// An HTTP/3 client whose QUIC connections tunnel through MASQUE proxies over `outer`.
fn tunneling_client(exec: Executor, outer: Version) -> Client {
    tunneling_client_with(exec.clone(), outer, http_client(exec), QuicTls::Boring)
}

fn tunneling_client_with(
    exec: Executor,
    outer: Version,
    outer_client: Client,
    quic: QuicTls,
) -> Client {
    let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
    let tunnels = ConnectUdpConnector::new(UdpConnector::new(), outer_client, exec.clone())
        .with_version(outer);
    let h3 = Http3Connector::builder(exec.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(quic.client())
        .with_endpoints(QuicEndpointConnector::new(tunnels, exec.clone()))
        .build_lazy()
        .unwrap();
    EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector(exec)
        .with_http3_support(h3)
        .with_default_connection_pool()
        .without_alt_svc()
        .build_client()
        .boxed()
}

async fn get_through(client: &Client, origin: &str, proxy: &ProxyAddress) -> String {
    let request = Request::builder()
        .version(Version::HTTP_3)
        .uri(format!("https://{origin}/"))
        .body(Body::empty())
        .unwrap();
    request
        .extensions()
        .insert(ProxyRoute::Proxy(proxy.clone()));
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_3));
    let response = client.serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn http3_runs_through_a_masque_proxy_on_every_carrier() {
    timeout(DEADLINE, async {
        let (origin, _origin) = h3_origin().await;
        for carrier in Carrier::ALL {
            let (proxy, proxy_tasks) = masque_proxy(
                None,
                DestinationScopePolicy::allow_private(),
                carrier != Carrier::Http3Capsule,
            )
            .await;
            let proxy = proxy_address("masque://", proxy);
            let client = tunneling_client(Executor::new(), carrier.version());
            for host in [origin.to_string(), format!("localhost:{}", origin.port)] {
                assert_eq!(
                    get_through(&client, &host, &proxy).await,
                    "HTTP/3.0 origin",
                    "{carrier:?} {host}"
                );
            }
            assert!(
                proxy_tasks.requests.load(Ordering::SeqCst) >= 1,
                "{carrier:?}: the proxy carried the connection"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_native_tunnel_too_small_for_quic_fails_typed() {
    timeout(DEADLINE, async {
        let (origin, _origin) = h3_origin().await;
        let (proxy, _proxy) =
            masque_proxy(None, DestinationScopePolicy::allow_private(), true).await;
        let proxy = proxy_address("masque://", proxy);
        // An outer path held at QUIC's 1200 bytes leaves less per native datagram.
        let exec = Executor::new();
        let mut outer = TransportConfig::default();
        outer.unset_mtu_discovery_config();
        let client = tunneling_client_with(
            exec.clone(),
            Version::HTTP_3,
            http_client_with_transport(exec, outer, QuicTls::Boring),
            QuicTls::Boring,
        );
        let request = Request::builder()
            .version(Version::HTTP_3)
            .uri(format!("https://{origin}/"))
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ProxyRoute::Proxy(proxy));
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        let error = client.serve(request).await.unwrap_err();
        let capacity =
            capacity_error(&error).unwrap_or_else(|| panic!("no capacity error in {error:?}"));
        assert!(capacity.max_payload < MIN_UDP_PAYLOAD, "{capacity:?}");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn the_masque_builder_step_tunnels_masque_routes_only() {
    timeout(DEADLINE, async {
        let (origin, _origin) = h3_origin().await;
        let (proxy, proxy_tasks) =
            masque_proxy(None, DestinationScopePolicy::allow_private(), true).await;
        let stats = proxy_tasks.proxy.clone().unwrap();
        let exec = Executor::new();
        let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
        let client =
            DefaultHttpWebClient::try_default_masque_using_boringssl(exec, tls.clone(), tls)
                .unwrap()
                .boxed();

        let masque = proxy_address("masque://", proxy);
        let body = get_through(&client, &origin.to_string(), &masque).await;
        assert_eq!(body, "HTTP/3.0 origin");
        assert_eq!(stats.opened(), 1);

        // Without a route the connection dials the origin over a UDP socket of its own.
        let request = Request::builder()
            .version(Version::HTTP_3)
            .uri(format!("https://localhost:{}/", origin.port))
            .body(Body::empty())
            .unwrap();
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        let response = client.serve(request).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"HTTP/3.0 origin");
        assert_eq!(stats.opened(), 1);

        // Any other kind of proxy is refused for HTTP/3, never bypassed.
        let request = Request::builder()
            .version(Version::HTTP_3)
            .uri(format!("https://{origin}/refused"))
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ProxyRoute::Proxy(
            ProxyAddress::try_from(format!("http://{proxy}").as_str()).unwrap(),
        ));
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        let error = client.serve(request).await.unwrap_err();
        assert!(
            format!("{error:?}").contains("masque proxies only"),
            "{error:?}"
        );
        assert_eq!(stats.opened(), 1);
        assert_eq!(proxy_tasks.requests.load(Ordering::SeqCst), 1);

        // The tunnel lives as long as its connection: dropping the client releases it.
        assert_eq!(stats.active(), 1);
        drop(client);
        timeout(Duration::from_secs(10), async {
            while stats.active() != 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the tunnel closes with its connection");
    })
    .await
    .unwrap();
}

fn demux_config() -> DemuxConfig {
    DemuxConfig {
        associations: NonZeroUsize::new(16).unwrap(),
        queue: NonZeroUsize::new(64).unwrap(),
        idle_timeout: Duration::from_secs(30),
        receive_bytes: NonZeroUsize::new(kib(64)).unwrap(),
        queued_bytes: NonZeroUsize::new(kib(256)).unwrap(),
    }
}

/// An untouched QUIC relay: every client association is forwarded as is through its own
/// CONNECT-UDP tunnel to `target`, via `proxy` over `outer`.
async fn quic_relay(
    proxy: ProxyAddress,
    target: impl Into<HostWithPort>,
    outer: Version,
    quic: QuicTls,
) -> (SocketAddress, Tasks) {
    let exec = Executor::new();
    let socket = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let connector = ConnectUdpConnector::new(
        UdpConnector::new(),
        http_client_on(exec.clone(), quic),
        exec.clone(),
    )
    .with_version(outer);
    let forward =
        DatagramForwardService::new(NonZeroUsize::new(kib(64)).unwrap(), EcnPolicy::Discard)
            .with_packet_errors(PacketErrorPolicy::DropPacketLocal);
    let bridge = DatagramToProxyBridge::new(forward, target).with_connector(connector);
    let service = AddInputExtensionLayer::new(ProxyRoute::Proxy(proxy)).into_layer(bridge);
    let demux = DatagramDemux::new(socket, demux_config());
    let task = tokio::spawn(async move {
        _ = demux.serve(exec, service).await;
    });
    (address, Tasks::new(vec![task], None))
}

#[tokio::test]
async fn an_untouched_quic_relay_egresses_through_masque_on_every_carrier() {
    timeout(DEADLINE, async {
        let (origin, _origin) = h3_origin().await;
        for carrier in Carrier::ALL {
            let (proxy, proxy_tasks) = masque_proxy(
                None,
                DestinationScopePolicy::allow_private(),
                carrier != Carrier::Http3Capsule,
            )
            .await;
            let (relay, _relay) = quic_relay(
                proxy_address("masque://", proxy),
                origin,
                carrier.version(),
                QuicTls::Boring,
            )
            .await;
            // The client speaks QUIC to the relay as if it were the origin.
            let client = http_client(Executor::new());
            let request = Request::builder()
                .version(Version::HTTP_3)
                .uri(format!("https://{relay}/"))
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            let response = client
                .serve(request)
                .await
                .unwrap_or_else(|error| panic!("{carrier:?}: {error}"));
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"HTTP/3.0 origin", "{carrier:?}");
            // At least one tunnel: under load a slow first handshake can be retried.
            assert!(
                proxy_tasks.requests.load(Ordering::SeqCst) >= 1,
                "{carrier:?}"
            );
        }
    })
    .await
    .unwrap();
}

type MitmAssociation = BridgeIo<
    PrefixedDatagramSocket<DemuxedSocket<UdpPacketSender>>,
    MaybeTunneledSocket<UdpPacketSocket>,
>;

/// A conditional QUIC MITM proxy, as the QUIC MITM example builds it, whose every egress is
/// a CONNECT-UDP tunnel to `upstream` via `proxy` over `outer`: `localhost` is terminated and
/// relayed request by request, every other name forwarded untouched.
async fn quic_mitm(
    proxy: ProxyAddress,
    upstream: impl Into<HostWithPort>,
    outer: Version,
) -> (SocketAddress, Tasks) {
    quic_mitm_with(proxy, upstream, outer, http_client(Executor::new())).await
}

async fn quic_mitm_with(
    proxy: ProxyAddress,
    upstream: impl Into<HostWithPort>,
    outer: Version,
    outer_client: Client,
) -> (SocketAddress, Tasks) {
    const FAILURE: u32 = 0x0101;
    let exec = Executor::new();
    let (ca_crt, ca_key) =
        generate_certificate_authority_x509(&SelfSignedCaConfig::default()).unwrap();
    let issuer = CachedBoringMitmCertIssuer::new(InMemoryBoringMitmCertIssuer::new(ca_crt, ca_key));
    let egress_tls = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let h3 = Http3MitmRelay::new(exec.clone()).with_http_middleware((
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-rama-mitm"),
            HeaderValue::from_static("h3"),
        ),
        ArcLayer::new(),
    ));
    let terminate = QuicMitmRelay::new(issuer, exec.clone(), egress_tls, VarInt::from_u32(FAILURE))
        .into_layer(
            AlpnRouter::new(ApplicationProtocol::HTTP_3, h3)
                .with_fallback(QuicRelay::new(VarInt::from_u32(FAILURE))),
        );
    let forward =
        DatagramForwardService::new(NonZeroUsize::new(kib(64)).unwrap(), EcnPolicy::Discard)
            .with_packet_errors(PacketErrorPolicy::DropPacketLocal);
    let route = service_fn(move |input: InputWithQuicClientHello<MitmAssociation>| {
        let terminate = terminate.clone();
        async move {
            let name = input.peeked.client_hello.ext_server_name().cloned();
            if name.is_some_and(|name| name.as_str() == "localhost") {
                terminate.serve(input).await
            } else {
                forward.serve(input.input).await.map_err(BoxError::from)
            }
        }
    });
    let inspect = PeekQuicClientHelloService::new(BoringTlsProvider, route).with_fallback(
        service_fn(move |input: MitmAssociation| async move {
            forward.serve(input).await.map_err(BoxError::from)
        }),
    );
    let connector = ConnectUdpConnector::new(UdpConnector::new(), outer_client, exec.clone())
        .with_version(outer);
    let association = AddInputExtensionLayer::new(ProxyRoute::Proxy(proxy))
        .into_layer(DatagramToProxyBridge::new(inspect, upstream).with_connector(connector));
    let socket = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let demux = DatagramDemux::new(socket, demux_config());
    let task = tokio::spawn(async move {
        _ = demux.serve(exec, association).await;
    });
    (address, Tasks::new(vec![task], None))
}

#[tokio::test]
async fn a_quic_mitm_egresses_through_masque_on_every_carrier() {
    timeout(DEADLINE, async {
        let (origin, _origin) = h3_origin().await;
        for carrier in Carrier::ALL {
            let (proxy, proxy_tasks) = masque_proxy(
                None,
                DestinationScopePolicy::allow_private(),
                carrier != Carrier::Http3Capsule,
            )
            .await;
            let (mitm, _mitm) =
                quic_mitm(proxy_address("masque://", proxy), origin, carrier.version()).await;
            // A name the MITM terminates, and an IP literal (no server name) it forwards. Each
            // from its own client socket: the MITM's association is the address pair.
            for (host, intercepted) in [
                (format!("localhost:{}", mitm.port), true),
                (mitm.to_string(), false),
            ] {
                let client = http_client(Executor::new());
                let request = Request::builder()
                    .version(Version::HTTP_3)
                    .uri(format!("https://{host}/"))
                    .body(Body::empty())
                    .unwrap();
                request
                    .extensions()
                    .insert(TargetHttpVersion(Version::HTTP_3));
                // The MITM listens on IPv4 loopback only.
                request.extensions().insert(DnsResolveIpMode::SingleIpV4);
                let response = client
                    .serve(request)
                    .await
                    .unwrap_or_else(|error| panic!("{carrier:?} {host}: {error}"));
                assert_eq!(
                    response.headers().contains_key("x-rama-mitm"),
                    intercepted,
                    "{carrier:?} {host}"
                );
                let body = response.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&body[..], b"HTTP/3.0 origin", "{carrier:?} {host}");
            }
            assert_eq!(
                proxy_tasks.requests.load(Ordering::SeqCst),
                2,
                "{carrier:?}"
            );
        }
    })
    .await
    .unwrap();
}

/// A TLS origin speaking HTTP/1.1 and HTTP/2, answering every request with its version.
async fn tls_origin() -> (SocketAddress, Tasks) {
    let exec = Executor::new();
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let tls = TlsServerConfig::new().with_server_auth(auth).with_alpn(
        [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
            .into_iter()
            .collect(),
    );
    let http = HttpServer::auto(exec.clone()).service(service_fn(|request: Request| async move {
        let body = format!("{:?} origin", request.version());
        Ok::<_, Infallible>(Response::new(Body::from(body)))
    }));
    let listener = TcpListener::bind_address("127.0.0.1:0", exec)
        .await
        .unwrap();
    let address = SocketAddress::from(listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        listener
            .serve(TlsAcceptorLayer::new(tls).into_layer(http))
            .await;
    });
    (address, Tasks::new(vec![task], None))
}

#[tokio::test]
async fn tcp_requests_on_a_masque_route_tunnel_with_connect() {
    timeout(DEADLINE, async {
        let (origin, _origin) = tls_origin().await;
        let (proxy, proxy_tasks) = masque_proxy_with(
            None,
            DestinationScopePolicy::allow_private(),
            true,
            ProxyAuth::Basic,
            QuicTls::Boring,
        )
        .await;
        let proxy =
            ProxyAddress::try_from(format!("masque://john:secret@{proxy}").as_str()).unwrap();
        let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
        let client = EasyHttpWebClient::connector_builder()
            .with_default_transport_connector()
            .with_default_dns_connector()
            .with_tls_proxy_support_using_boringssl_config(tls.clone())
            .with_proxy_support()
            .with_tls_support_using_boringssl(tls)
            .with_default_http_connector(Executor::new())
            .with_default_connection_pool()
            .without_alt_svc()
            .build_client();
        for version in [Version::HTTP_11, Version::HTTP_2] {
            let request = Request::builder()
                .version(version)
                .uri(format!("https://{origin}/"))
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(ProxyRoute::Proxy(proxy.clone()));
            request.extensions().insert(TargetHttpVersion(version));
            let response = client
                .serve(request)
                .await
                .unwrap_or_else(|error| panic!("{version:?}: {error}"));
            assert_eq!(response.status(), StatusCode::OK, "{version:?}");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], format!("{version:?} origin").as_bytes());
        }
        assert!(proxy_tasks.requests.load(Ordering::SeqCst) >= 1);
        // The tunnels are TCP: no CONNECT-UDP tunnel was opened.
        assert_eq!(proxy_tasks.proxy.as_ref().unwrap().opened(), 0);
    })
    .await
    .unwrap();
}

/// The capacity error behind `error`, wherever an I/O error in the chain carries it.
fn capacity_error(error: &(dyn std::error::Error + 'static)) -> Option<SocketCapacityError> {
    error_chain(error).find_map(|error| {
        error
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
            .and_then(|inner| inner.downcast_ref::<SocketCapacityError>())
            .copied()
    })
}

#[tokio::test]
async fn a_mitm_egress_tunnel_too_small_for_quic_refuses_before_any_handshake() {
    timeout(DEADLINE, async {
        let (origin, origin_tasks) = h3_origin().await;
        let (proxy, proxy_tasks) =
            masque_proxy(None, DestinationScopePolicy::allow_private(), true).await;
        // The MITM's own tunnels run over an outer path held at QUIC's 1200 bytes.
        let mut outer = TransportConfig::default();
        outer.unset_mtu_discovery_config();
        let (mitm, _mitm) = quic_mitm_with(
            proxy_address("masque://", proxy),
            origin,
            Version::HTTP_3,
            http_client_with_transport(Executor::new(), outer, QuicTls::Boring),
        )
        .await;
        let client = http_client(Executor::new());
        let request = Request::builder()
            .version(Version::HTTP_3)
            .uri(format!("https://localhost:{}/", mitm.port))
            .body(Body::empty())
            .unwrap();
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        request.extensions().insert(DnsResolveIpMode::SingleIpV4);
        client.serve(request).await.unwrap_err();
        let stats = proxy_tasks.proxy.as_ref().unwrap();
        assert_eq!(stats.opened(), 1, "the tunnel was opened");
        timeout(Duration::from_secs(10), async {
            while stats.active() > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the refused tunnel is released");
        assert_eq!(origin_tasks.requests.load(Ordering::SeqCst), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_custom_relay_gets_the_tunnel_with_its_target() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        let exec = Executor::new();
        let seen = Arc::new(parking_lot::Mutex::new(None));
        let recorded = seen.clone();
        let relay = service_fn(move |bridge: BridgeIo<ConnectUdpSocket, UdpPacketSocket>| {
            let recorded = recorded.clone();
            async move {
                *recorded.lock() = bridge
                    .0
                    .extensions()
                    .get_ref::<ConnectorTarget>()
                    .map(|target| target.0.clone());
                ConnectUdpRelay::new().serve(bridge).await
            }
        });
        let service = ConnectUdpService::try_new(exec.clone(), None)
            .unwrap()
            .with_policy(DestinationScopePolicy::allow_private())
            .with_relay(relay);
        let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        let tls = TlsServerConfig::new()
            .with_server_auth(auth)
            .with_alpn([ApplicationProtocol::HTTP_11].into_iter().collect());
        let listener = TcpListener::bind_address("127.0.0.1:0", exec.clone())
            .await
            .unwrap();
        let address = SocketAddress::from(listener.local_addr().unwrap());
        let server = HttpServer::auto(exec.clone()).service(Arc::new(service));
        let task = tokio::spawn(async move {
            listener
                .serve(TlsAcceptorLayer::new(tls).into_layer(server))
                .await;
        });
        let _tasks = Tasks::new(vec![task], None);

        let mut socket = open_tunnel(
            exec,
            &proxy_address("masque://", address),
            target,
            Version::HTTP_11,
        )
        .await
        .unwrap();
        echo(&mut socket, b"through a custom relay").await;
        assert_eq!(*seen.lock(), Some(HostWithPort::from(target)));
    })
    .await
    .unwrap();
}
