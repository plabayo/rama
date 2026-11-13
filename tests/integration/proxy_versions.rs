//! The easy client through a proxy, for every kind of proxied traffic and every HTTP
//! version toward the proxy.

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
        client::{
            DefaultHttpWebClient, EasyHttpWebClient, Http3Connector, masque_quic_transport,
            proxy::layer::HttpProxyConnectorLayer,
        },
        conn::TargetHttpVersion,
        layer::upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        proxy::HttpProxyConnectMatcher,
        server::HttpServer,
    },
    layer::MapInputLayer,
    matcher::Matcher as _,
    net::{
        address::{ProxyAddress, SocketAddress},
        client::ProxyRoute,
        proxy::IoForwardService,
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
        let request = get(&format!("https://{origin}/"), proxy.https());
        let response = client(proxy_version, false).serve(request).await.unwrap();
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
        let request = get(&format!("http://{origin}/"), proxy.https());
        let response = client(proxy_version, true).serve(request).await.unwrap();
        assert_eq!(body(response).await, "HTTP/1.1 origin");
        assert_eq!(proxy.seen(), [(Method::CONNECT, proxy_version)]);
    })
    .await
    .unwrap();
}

async fn forward(proxy_version: Version) {
    timeout(DEADLINE, async {
        let proxy = Proxy::start().await;
        let request = get("http://origin.example/path", proxy.https());
        let response = client(proxy_version, false).serve(request).await.unwrap();
        assert_eq!(body(response).await, "forwarded http://origin.example/path");
        assert_eq!(proxy.seen(), [(Method::GET, proxy_version)]);
    })
    .await
    .unwrap();
}

async fn connect_udp_to_h3_origin(proxy_version: Version) {
    assert_eq!(
        proxy_version,
        Version::HTTP_3,
        "the easy client has no way to send CONNECT-UDP over another version"
    );
    timeout(DEADLINE, async {
        let (origin, _origin) = h3_origin().await;
        let proxy = Proxy::start().await;
        let request = get(&format!("https://{origin}/"), proxy.masque());
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        let response = masque_client().serve(request).await.unwrap();
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

fn client(proxy_version: Version, tunnel_plaintext: bool) -> Client {
    let tls = tls_client_config();
    EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl_config(tls.clone())
        .with_custom_proxy_connector(
            HttpProxyConnectorLayer::required().with_version(proxy_version),
        )
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector(WeakScope::detached())
        .with_default_connection_pool()
        .without_alt_svc()
        .build_client()
        .with_tunnel_plaintext_http(tunnel_plaintext)
        .boxed()
}

fn masque_client() -> Client {
    let scope = WeakScope::detached();
    let tls = tls_client_config();
    let proxy_client = DefaultHttpWebClient::try_default_masque_proxy_client_using_boringssl(
        scope.clone(),
        tls.clone(),
    )
    .unwrap();
    let h3 = Http3Connector::builder(scope.clone())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .with_tls_config(tls.clone());
    EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl_config(tls.clone())
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector(scope)
        .with_http3_masque_support(h3, proxy_client)
        .unwrap()
        .with_default_connection_pool()
        .without_alt_svc()
        .build_client()
        .boxed()
}

struct Proxy {
    address: SocketAddress,
    seen: Arc<Mutex<Vec<(Method, Version)>>>,
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
                    recorded
                        .lock()
                        .push((request.method().clone(), request.version()));
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

    fn https(&self) -> ProxyAddress {
        ProxyAddress::try_from(format!("https://{}", self.address).as_str()).unwrap()
    }

    fn masque(&self) -> ProxyAddress {
        ProxyAddress::try_from(format!("masque://{}", self.address).as_str()).unwrap()
    }

    fn seen(&self) -> Vec<(Method, Version)> {
        self.seen.lock().clone()
    }
}

fn quic_server_config(tls: &TlsServerConfig) -> ServerConfig {
    ServerConfig::try_from_rama_tls_with_provider(tls, TlsOptions::default(), &BoringTlsProvider)
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
    let http = HttpServer::new_http1(scope.clone()).service(service_fn(origin_response));
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
