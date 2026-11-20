//! The easy client through a proxy, for every kind of proxied traffic and every HTTP
//! version toward the proxy.

use ahash::HashSet;
use parking_lot::Mutex;
use rama::{
    Layer as _, Service,
    dns::client::DnsConnector,
    error::extra::OpaqueError,
    extensions::ExtensionsRef as _,
    graceful::WeakScope,
    http::{
        Body, Method, Request, Response, StatusCode, Version,
        body::util::BodyExt as _,
        client::{EasyHttpWebClient, ProxyConnector, masque_quic_transport},
        conn::TargetHttpVersion,
        header,
        layer::upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        proxy::{HttpProxyConnectMatcher, PlaintextHttpProxyMode},
        server::HttpServer,
    },
    layer::MapInputLayer,
    matcher::Matcher as _,
    net::{
        address::{ProxyAddress, SocketAddress},
        client::ProxyRoute,
        proxy::IoForwardService,
        stream::SocketInfo,
        tls::ApplicationProtocol,
    },
    proxy::masque::connect_udp::{ConnectUdpService, DestinationScopePolicy},
    quic::{
        Endpoint, ServerConfig, TransportConfig,
        tls::{BoringTlsProvider, TlsOptions},
    },
    service::{BoxService, service_fn},
    tcp::{client::service::TcpConnector, server::TcpListener},
    tls::{
        boring::server::TlsAcceptorLayer,
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    udp::DatagramError,
};
use std::{convert::Infallible, io::ErrorKind, sync::Arc, time::Duration};
use tokio::{task::JoinHandle, time::timeout};

const DEADLINE: Duration = Duration::from_secs(30);

#[tokio::test]
async fn connect_to_h1_origin_over_proxy_h1() {
    connect_to_tls_origin(Version::HTTP_11, Version::HTTP_11).await;
}

#[tokio::test]
async fn connect_to_h1_origin_over_proxy_h2() {
    connect_to_tls_origin(Version::HTTP_11, Version::HTTP_2).await;
}

#[tokio::test]
async fn connect_to_h1_origin_over_proxy_h3() {
    connect_to_tls_origin(Version::HTTP_11, Version::HTTP_3).await;
}

#[tokio::test]
async fn connect_to_h2_origin_over_proxy_h1() {
    connect_to_tls_origin(Version::HTTP_2, Version::HTTP_11).await;
}

#[tokio::test]
async fn connect_to_h2_origin_over_proxy_h2() {
    connect_to_tls_origin(Version::HTTP_2, Version::HTTP_2).await;
}

#[tokio::test]
async fn connect_to_h2_origin_over_proxy_h3() {
    connect_to_tls_origin(Version::HTTP_2, Version::HTTP_3).await;
}

#[tokio::test]
async fn connect_to_plaintext_origin_over_proxy_h1() {
    connect_to_plaintext_origin(Version::HTTP_11).await;
}

#[tokio::test]
async fn connect_to_plaintext_origin_over_proxy_h2() {
    connect_to_plaintext_origin(Version::HTTP_2).await;
}

#[tokio::test]
async fn connect_to_plaintext_origin_over_proxy_h3() {
    connect_to_plaintext_origin(Version::HTTP_3).await;
}

#[tokio::test]
async fn forward_over_proxy_h1() {
    forward(Version::HTTP_11).await;
}

#[tokio::test]
async fn forward_over_proxy_h2() {
    forward(Version::HTTP_2).await;
}

#[tokio::test]
async fn forward_over_proxy_h3() {
    forward(Version::HTTP_3).await;
}

#[tokio::test]
async fn connect_udp_to_h3_origin_over_proxy_h1() {
    connect_udp_to_h3_origin(Version::HTTP_11).await;
}

#[tokio::test]
async fn connect_udp_to_h3_origin_over_proxy_h2() {
    connect_udp_to_h3_origin(Version::HTTP_2).await;
}

#[tokio::test]
async fn connect_udp_to_h3_origin_over_proxy_h3() {
    connect_udp_to_h3_origin(Version::HTTP_3).await;
}

async fn connect_to_tls_origin(origin_version: Version, proxy_version: Version) {
    timeout(DEADLINE, async {
        let (origin, _origin) = tls_origin(origin_version).await;
        let proxy = Proxy::start().await;
        let request = get(&format!("https://{origin}/"), proxy.https(proxy_version));
        let response = client().serve(request).await.unwrap();
        assert_eq!(body(response).await, format!("{origin_version:?} origin"));
        assert_eq!(proxy.seen(), [(Method::CONNECT, proxy_version)]);
    })
    .await
    .unwrap();
}

async fn connect_to_plaintext_origin(proxy_version: Version) {
    timeout(DEADLINE, async {
        let (origin, _origin) = plaintext_origin().await;
        let proxy = Proxy::start().await;
        let request = get(&format!("http://{origin}/"), proxy.https(proxy_version));
        request.extensions().insert(PlaintextHttpProxyMode::Tunnel);
        let response = client().serve(request).await.unwrap();
        assert_eq!(body(response).await, "HTTP/1.1 origin");
        assert_eq!(proxy.seen(), [(Method::CONNECT, proxy_version)]);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn plaintext_requests_are_forwarded_only_in_the_version_spoken_to_the_proxy() {
    timeout(DEADLINE, async {
        let (origin, _origin) = plaintext_origin().await;
        let mut wrong = Vec::new();
        for proxy_version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            for requested in [Version::HTTP_11, Version::HTTP_2] {
                let proxy = Proxy::start().await;
                let request = get(&format!("http://{origin}/"), proxy.https(proxy_version));
                request.extensions().insert(TargetHttpVersion(requested));
                let body = body(client().serve(request).await.unwrap()).await;

                let (expected_seen, expected_body) = if requested == proxy_version {
                    (Method::GET, format!("forwarded http://{origin}/"))
                } else {
                    (Method::CONNECT, format!("{requested:?} origin"))
                };
                let seen = proxy.seen();
                if seen != [(expected_seen.clone(), proxy_version)] || body != expected_body {
                    wrong.push(format!(
                        "proxy {proxy_version:?}, requested {requested:?}: \
                         expected {expected_seen} {expected_body:?}, got {seen:?} {body:?}"
                    ));
                }
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    })
    .await
    .unwrap();
}

async fn forward(proxy_version: Version) {
    timeout(DEADLINE, async {
        let proxy = Proxy::start().await;
        let request = get("http://origin.example/path", proxy.https(proxy_version));
        let response = client().serve(request).await.unwrap();
        assert_eq!(body(response).await, "forwarded http://origin.example/path");
        assert_eq!(proxy.seen(), [(Method::GET, proxy_version)]);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn two_tunnels_over_h1_use_a_proxy_connection_each() {
    tunnels_share_a_connection(Version::HTTP_11, 2).await;
}

#[tokio::test]
async fn two_tunnels_share_one_proxy_connection_over_h2() {
    tunnels_share_a_connection(Version::HTTP_2, 1).await;
}

#[tokio::test]
async fn two_tunnels_share_one_proxy_connection_over_h3() {
    tunnels_share_a_connection(Version::HTTP_3, 1).await;
}

async fn tunnels_share_a_connection(proxy_version: Version, connections: usize) {
    timeout(DEADLINE, async {
        let (origin, _origin) = tls_origin(Version::HTTP_11).await;
        let proxy = Proxy::start().await;
        let client = client();
        for user in ["alice", "bob"] {
            let address =
                ProxyAddress::try_from(format!("https://{user}:secret@{}", proxy.address).as_str())
                    .unwrap()
                    .with_http_version(proxy_version);
            let request = get(&format!("https://{origin}/"), address);
            let response = client.serve(request).await.unwrap();
            assert_eq!(body(response).await, "HTTP/1.1 origin");
        }
        assert_eq!(
            proxy.seen(),
            [
                (Method::CONNECT, proxy_version),
                (Method::CONNECT, proxy_version)
            ],
        );
        assert_eq!(proxy.connections(), connections);
        assert_eq!(
            proxy.credentials(),
            [
                "Basic YWxpY2U6c2VjcmV0".to_owned(),
                "Basic Ym9iOnNlY3JldA==".to_owned()
            ],
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn two_forwards_share_one_proxy_connection_over_h1() {
    forwards_share_a_connection(Version::HTTP_11).await;
}

#[tokio::test]
async fn two_forwards_share_one_proxy_connection_over_h2() {
    forwards_share_a_connection(Version::HTTP_2).await;
}

#[tokio::test]
async fn two_forwards_share_one_proxy_connection_over_h3() {
    forwards_share_a_connection(Version::HTTP_3).await;
}

async fn forwards_share_a_connection(proxy_version: Version) {
    timeout(DEADLINE, async {
        let proxy = Proxy::start().await;
        let client = client();
        for origin in ["http://one.example/a", "http://two.example/b"] {
            let request = get(origin, proxy.https(proxy_version));
            let response = client.serve(request).await.unwrap();
            assert_eq!(body(response).await, format!("forwarded {origin}"));
        }
        assert_eq!(
            proxy.seen(),
            [(Method::GET, proxy_version), (Method::GET, proxy_version)],
        );
        assert_eq!(proxy.connections(), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_forward_and_a_tunnel_share_one_proxy_connection_over_h2() {
    forward_and_tunnel_share_a_connection(Version::HTTP_2).await;
}

#[tokio::test]
async fn a_forward_and_a_tunnel_share_one_proxy_connection_over_h3() {
    forward_and_tunnel_share_a_connection(Version::HTTP_3).await;
}

async fn forward_and_tunnel_share_a_connection(proxy_version: Version) {
    timeout(DEADLINE, async {
        let (origin, _origin) = tls_origin(Version::HTTP_11).await;
        let proxy = Proxy::start().await;
        let client = client();

        let request = get("http://origin.example/path", proxy.https(proxy_version));
        let response = client.serve(request).await.unwrap();
        assert_eq!(body(response).await, "forwarded http://origin.example/path");

        let request = get(&format!("https://{origin}/"), proxy.https(proxy_version));
        let response = client.serve(request).await.unwrap();
        assert_eq!(body(response).await, "HTTP/1.1 origin");

        assert_eq!(
            proxy.seen(),
            [
                (Method::GET, proxy_version),
                (Method::CONNECT, proxy_version)
            ],
        );
        assert_eq!(proxy.connections(), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn forwards_of_two_users_share_one_proxy_connection_over_h1() {
    forwards_of_two_users_share_a_connection(Version::HTTP_11).await;
}

#[tokio::test]
async fn forwards_of_two_users_share_one_proxy_connection_over_h2() {
    forwards_of_two_users_share_a_connection(Version::HTTP_2).await;
}

#[tokio::test]
async fn forwards_of_two_users_share_one_proxy_connection_over_h3() {
    forwards_of_two_users_share_a_connection(Version::HTTP_3).await;
}

async fn forwards_of_two_users_share_a_connection(proxy_version: Version) {
    timeout(DEADLINE, async {
        let proxy = Proxy::start().await;
        let client = client();
        for user in ["alice", "bob"] {
            let address =
                ProxyAddress::try_from(format!("https://{user}:secret@{}", proxy.address).as_str())
                    .unwrap()
                    .with_http_version(proxy_version);
            let request = get("http://origin.example/path", address);
            let response = client.serve(request).await.unwrap();
            assert_eq!(body(response).await, "forwarded http://origin.example/path");
        }
        assert_eq!(proxy.connections(), 1);
        assert_eq!(
            proxy.credentials(),
            [
                "Basic YWxpY2U6c2VjcmV0".to_owned(),
                "Basic Ym9iOnNlY3JldA==".to_owned()
            ],
        );
    })
    .await
    .unwrap();
}

async fn connect_udp_to_h3_origin(proxy_version: Version) {
    timeout(DEADLINE, async {
        let (origin, _origin) = h3_origin().await;
        let proxy = Proxy::start().await;
        let request = get(&format!("https://{origin}/"), proxy.masque(proxy_version));
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        let response = client().serve(request).await.unwrap();
        assert_eq!(body(response).await, "HTTP/3.0 origin");
        let method = if proxy_version == Version::HTTP_11 {
            Method::GET
        } else {
            Method::CONNECT
        };
        assert_eq!(proxy.seen(), [(method, proxy_version)]);
    })
    .await
    .unwrap();
}

fn get(uri: &str, proxy: ProxyAddress) -> Request {
    let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
    request.extensions().insert(ProxyRoute::Proxy(proxy));
    request
}

async fn body(response: Response) -> String {
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

type Client = BoxService<Request, Response, OpaqueError>;

fn tls_client_config() -> TlsClientConfig {
    TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable)
}

fn client() -> Client {
    let scope = WeakScope::detached();
    let tls = tls_client_config();
    EasyHttpWebClient::connector_builder(scope.clone())
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_proxy_support(ProxyConnector::default_using_tls(scope, tls.clone()))
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector()
        .with_default_connection_pool()
        .without_alt_svc()
        .build_client()
        .boxed()
}

struct Proxy {
    address: SocketAddress,
    seen: Arc<Mutex<Vec<Seen>>>,
    _tasks: Tasks,
}

impl Proxy {
    async fn start() -> Self {
        let scope = WeakScope::detached();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let connect_udp = Arc::new(
            ConnectUdpService::try_new(scope.clone(), None)
                .unwrap()
                .with_policy(DestinationScopePolicy::allow_private()),
        );
        let route = service_fn(move |request: Request| {
            let connect_udp = connect_udp.clone();
            async move {
                if connect_udp.matcher().matches(None, &request) {
                    return connect_udp.serve(request).await;
                }
                let body = format!("forwarded {}", request.uri());
                Ok::<_, Infallible>(Response::new(Body::from(body)))
            }
        });
        let service = Arc::new(
            (
                MapInputLayer::new(move |request: Request| {
                    recorded.lock().push(Seen {
                        method: request.method().clone(),
                        version: request.version(),
                        peer: request
                            .extensions()
                            .get_ref::<SocketInfo>()
                            .map(|info| info.peer_addr()),
                        credential: request
                            .headers()
                            .get(header::PROXY_AUTHORIZATION)
                            .map(|value| value.to_str().unwrap().to_owned()),
                    });
                    request
                }),
                UpgradeLayer::new(
                    scope.clone(),
                    HttpProxyConnectMatcher::new(),
                    EagerHttpProxyConnector::new(
                        DnsConnector::new(TcpConnector::new()),
                        IoForwardService::new(scope.clone()),
                    ),
                ),
            )
                .into_layer(route),
        );
        let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();

        let tls = TlsServerConfig::new()
            .with_server_auth(auth.clone())
            .with_alpn(
                [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
                    .into_iter()
                    .collect(),
            );
        let mut http = HttpServer::auto(scope.clone());
        http.h2_mut().set_enable_connect_protocol();
        let tcp = TlsAcceptorLayer::new(tls).into_layer(http.service(service.clone()));

        let mut h3 = HttpServer::new_http3(scope.clone());
        h3.http3_mut().extended_connect = true;
        let mut transport = masque_quic_transport();
        h3.http3().configure_transport(&mut transport).unwrap();
        let tls = TlsServerConfig::new()
            .with_server_auth(auth)
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let mut quic_config = quic_server_config(&tls);
        quic_config.set_transport_config(Arc::new(transport));

        let (listener, endpoint) = loop {
            let listener = TcpListener::bind_address("127.0.0.1:0", scope.clone())
                .await
                .unwrap();
            let address = SocketAddress::from(listener.local_addr().unwrap());
            match Endpoint::build(scope.clone())
                .with_server_config(quic_config.clone())
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
        let quic_task = tokio::spawn(endpoint.clone().serve(scope, h3.service(service)));
        Self {
            address,
            seen,
            _tasks: Tasks::new(vec![tcp_task, quic_task], Some(endpoint)),
        }
    }

    fn https(&self, version: Version) -> ProxyAddress {
        ProxyAddress::try_from(format!("https://{}", self.address).as_str())
            .unwrap()
            .with_http_version(version)
    }

    fn masque(&self, version: Version) -> ProxyAddress {
        ProxyAddress::try_from(format!("h3+udp://{}", self.address).as_str())
            .unwrap()
            .with_http_version(version)
    }

    fn seen(&self) -> Vec<(Method, Version)> {
        self.seen
            .lock()
            .iter()
            .map(|seen| (seen.method.clone(), seen.version))
            .collect()
    }

    fn connections(&self) -> usize {
        self.seen
            .lock()
            .iter()
            .filter_map(|seen| seen.peer)
            .collect::<HashSet<_>>()
            .len()
    }

    fn credentials(&self) -> Vec<String> {
        self.seen
            .lock()
            .iter()
            .filter_map(|seen| seen.credential.clone())
            .collect()
    }
}

struct Seen {
    method: Method,
    version: Version,
    peer: Option<SocketAddress>,
    credential: Option<String>,
}

fn quic_server_config(tls: &TlsServerConfig) -> ServerConfig {
    ServerConfig::try_from_rama_tls_with_provider(
        tls,
        TlsOptions::default(),
        &BoringTlsProvider::new(),
    )
    .unwrap()
}

async fn origin_response(request: Request) -> Result<Response, Infallible> {
    let body = format!("{:?} origin", request.version());
    Ok(Response::new(Body::from(body)))
}

async fn tls_origin(version: Version) -> (SocketAddress, Tasks) {
    let scope = WeakScope::detached();
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let alpn = if version == Version::HTTP_2 {
        ApplicationProtocol::HTTP_2
    } else {
        ApplicationProtocol::HTTP_11
    };
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([alpn].into_iter().collect());
    let http = HttpServer::auto(scope.clone()).service(service_fn(origin_response));
    let listener = TcpListener::bind_address("127.0.0.1:0", scope)
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

async fn plaintext_origin() -> (SocketAddress, Tasks) {
    let scope = WeakScope::detached();
    let http = HttpServer::auto(scope.clone()).service(service_fn(origin_response));
    let listener = TcpListener::bind_address("127.0.0.1:0", scope)
        .await
        .unwrap();
    let address = SocketAddress::from(listener.local_addr().unwrap());
    let task = tokio::spawn(async move { listener.serve(http).await });
    (address, Tasks::new(vec![task], None))
}

async fn h3_origin() -> (SocketAddress, Tasks) {
    let scope = WeakScope::detached();
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let h3 = HttpServer::new_http3(scope.clone());
    let mut transport = TransportConfig::default();
    h3.http3().configure_transport(&mut transport).unwrap();
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut config = quic_server_config(&tls);
    config.set_transport_config(Arc::new(transport));
    let endpoint = Endpoint::build(scope.clone())
        .with_server_config(config)
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let address = SocketAddress::from(endpoint.local_addr().unwrap());
    let task = tokio::spawn(
        endpoint
            .clone()
            .serve(scope, h3.service(service_fn(origin_response))),
    );
    (address, Tasks::new(vec![task], Some(endpoint)))
}

struct Tasks {
    tasks: Vec<JoinHandle<()>>,
    endpoint: Option<Endpoint>,
}

impl Tasks {
    fn new(tasks: Vec<JoinHandle<()>>, endpoint: Option<Endpoint>) -> Self {
        Self { tasks, endpoint }
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
