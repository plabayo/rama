//! TLS on the connection to a proxy: from its address (`socks5+tls`), connector-wide with
//! a secure TLS connector, or per request and per route with `TlsRequired`.
//!
//! Every server here runs in memory over a `MockConnectorService`, and each one speaks
//! TLS exactly when its client is expected to: a client which disagrees fails the
//! handshake rather than quietly passing.

use rama::{
    Layer as _, Service,
    error::{BoxError, extra::OpaqueError},
    extensions::{Extensions, ExtensionsRef as _},
    graceful::WeakScope,
    http::{
        Body, Request, Response, StatusCode, Version,
        body::util::BodyExt as _,
        client::{EasyHttpWebClient, ProxyConnector},
        layer::upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        proxy::HttpProxyConnectMatcher,
        server::HttpServer,
    },
    layer::MapErrLayer,
    net::{
        Protocol, ProtocolInputExt as _,
        address::{ProxyAddress, ProxyProtocol},
        client::{
            ConnectRequest, ProxyConnectionExtensions, ProxyRoute, ProxyRoutes, ProxyRoutesLayer,
        },
        proxy::IoForwardService,
        test_utils::client::{MockConnectorService, MockSocket},
        tls::{ApplicationProtocol, TlsRequired},
    },
    proxy::socks5::{Socks5Acceptor, server::Connector as Socks5Connector},
    quic::{
        Connection, ServerConfig, TransportConfig,
        test_utils::MockQuicConnectorService,
        tls::{BoringTlsProvider, TlsOptions},
    },
    service::{BoxService, service_fn},
    tls::{
        boring::server::TlsAcceptorLayer,
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
};
use std::{
    convert::Infallible,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(30);

const SOCKS_PROXY: &str = "socks5h://socks-proxy.test:1080";
const SECURE_SOCKS_PROXY: &str = "socks5h+tls://socks-proxy.test:1080";
const OTHER_SOCKS_PROXY: &str = "socks5h://other-socks-proxy.test:1080";
const HTTP_PROXY: &str = "http://http-proxy.test:8080";
const H3_PROXY: &str = "https://127.0.0.1:443";

const PLAIN_ORIGIN: &str = "http://origin.test/";
const SECURE_ORIGIN: &str = "https://origin.test/";

#[tokio::test]
async fn a_secure_connector_secures_a_socks5_leg_end_to_end() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start(LegTls::Required);
        fixture.get(Case::new(PLAIN_ORIGIN, SOCKS_PROXY)).await;

        assert_eq!(
            fixture.counts(),
            Counts {
                legs: 1,
                secure_legs: 1,
                origins: 1
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_socks5_tls_address_secures_its_leg_end_to_end() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start(LegTls::PerRoute);
        fixture
            .get(Case::new(PLAIN_ORIGIN, SECURE_SOCKS_PROXY))
            .await;

        assert_eq!(
            fixture.counts(),
            Counts {
                legs: 1,
                secure_legs: 1,
                origins: 1
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_secure_connector_secures_a_leg_to_a_plaintext_http_proxy() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start(LegTls::Required);
        fixture.get(Case::new(SECURE_ORIGIN, HTTP_PROXY)).await;

        assert_eq!(
            fixture.counts(),
            Counts {
                legs: 1,
                secure_legs: 1,
                origins: 1
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_secure_connector_keeps_the_quic_leg_of_an_h3_proxy() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start(LegTls::Required);
        fixture
            .get(Case::new(SECURE_ORIGIN, H3_PROXY).with_http_version(Version::HTTP_3))
            .await;

        assert_eq!(
            fixture.counts(),
            Counts {
                legs: 1,
                secure_legs: 0,
                origins: 1
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn one_connector_secures_only_the_route_which_asks_for_tls() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start(LegTls::PerRoute);
        fixture
            .get(Case::new(PLAIN_ORIGIN, SOCKS_PROXY).asking(Asked::Route))
            .await;
        fixture
            .get(Case::new(PLAIN_ORIGIN, OTHER_SOCKS_PROXY).asking(Asked::Nothing))
            .await;

        assert_eq!(
            fixture.counts(),
            Counts {
                legs: 2,
                secure_legs: 1,
                origins: 2
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_build_without_tls_refuses_a_leg_which_asks_for_tls() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start(LegTls::None);
        let error = fixture
            .try_get(Case::new(PLAIN_ORIGIN, SOCKS_PROXY).asking(Asked::Route))
            .await
            .expect_err("a connection to a proxy which asks for TLS is never dialed in plaintext");

        assert!(
            format!("{error:?}").contains("a secure proxy needs a TLS connector"),
            "{error:?}",
        );
        assert_eq!(
            fixture.counts(),
            Counts {
                legs: 0,
                secure_legs: 0,
                origins: 0
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_secure_leg_leaves_the_origin_handshake_as_configured() {
    timeout(DEADLINE, async {
        for origin in [PLAIN_ORIGIN, SECURE_ORIGIN] {
            let fixture = Fixture::start(LegTls::PerRoute);
            fixture
                .get(Case::new(origin, SOCKS_PROXY).asking(Asked::Bag))
                .await;

            assert_eq!(
                fixture.counts(),
                Counts {
                    legs: 1,
                    secure_legs: 1,
                    origins: 1
                },
                "{origin}",
            );
        }
    })
    .await
    .unwrap();
}

/// A hop bag configures the connection to the proxy, so the same ask on the request configures the origin
/// instead: connection scope keeps each on its own side of the nesting boundary.
#[tokio::test]
async fn tls_required_on_the_request_does_not_reach_the_leg() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start(LegTls::PerRoute);
        fixture
            .get(Case::new(SECURE_ORIGIN, SOCKS_PROXY).asking(Asked::Request))
            .await;

        assert_eq!(
            fixture.counts(),
            Counts {
                legs: 1,
                secure_legs: 0,
                origins: 1
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_secure_leg_and_a_plain_leg_to_one_proxy_do_not_share_a_connection() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start(LegTls::PerRoute);
        fixture.get(Case::new(PLAIN_ORIGIN, SOCKS_PROXY)).await;
        fixture.get(Case::new(PLAIN_ORIGIN, SOCKS_PROXY)).await;
        assert_eq!(
            fixture.counts(),
            Counts {
                legs: 1,
                secure_legs: 0,
                origins: 1
            },
            "two plain requests over one proxy share the connection they made",
        );

        let mut wrong = Vec::new();
        for (name, first, second) in [
            ("secure then plain", true, false),
            ("plain then secure", false, true),
        ] {
            let case = |secure: bool| {
                Case::new(PLAIN_ORIGIN, SOCKS_PROXY).asking(if secure {
                    Asked::Bag
                } else {
                    Asked::Nothing
                })
            };
            let fixture = Fixture::start(LegTls::PerRoute);
            fixture.get(case(first)).await;
            fixture.get(case(second)).await;
            let counts = fixture.counts();
            let expected = Counts {
                legs: 2,
                secure_legs: 1,
                origins: 2,
            };
            if counts != expected {
                wrong.push(format!("{name}: expected {expected:?}, got {counts:?}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    })
    .await
    .unwrap();
}

/// The client over `$proxy`, whose type follows the proxy connector's.
macro_rules! client_over {
    ($client:expr, $proxy:expr, $tls:expr) => {
        $client
            .with_proxy_support($proxy)
            .with_tls_support_using_boringssl($tls)
            .with_default_http_connector()
            .with_default_connection_pool()
            .without_alt_svc()
            .build_client()
            .boxed()
    };
}

#[derive(Clone, Copy)]
enum LegTls {
    /// Every TCP connection to a proxy is secured, by mapping the TLS connector to its
    /// secure kind.
    Required,
    /// Each connection to a proxy is secured when its own input asks for it.
    PerRoute,
    /// The connector has no TLS at all, see `ProxyConnectorBuilder::without_tls_support`.
    None,
}

/// Where a request puts its [`TlsRequired`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Asked {
    Nothing,
    /// The request's own level, which configures the connection to the origin.
    Request,
    /// A hop bag on the request, which configures the connection to the proxy.
    Bag,
    /// A hop bag on one route of a [`ProxyRoutes`] plan.
    Route,
}

struct Case {
    origin: &'static str,
    proxy: ProxyAddress,
    asked: Asked,
}

impl Case {
    fn new(origin: &'static str, proxy: &str) -> Self {
        Self {
            origin,
            proxy: ProxyAddress::try_from(proxy).unwrap(),
            asked: Asked::Nothing,
        }
    }

    fn with_http_version(mut self, version: Version) -> Self {
        self.proxy = with_version(self.proxy, version);
        self
    }

    const fn asking(mut self, asked: Asked) -> Self {
        self.asked = asked;
        self
    }

    fn request(&self) -> Request {
        let request = Request::builder()
            .uri(self.origin)
            .body(Body::empty())
            .unwrap();
        let extensions = request.extensions();
        if self.asked == Asked::Request {
            extensions.insert(TlsRequired::new());
        }
        let bag = Extensions::new();
        if matches!(self.asked, Asked::Bag | Asked::Route) {
            bag.insert(TlsRequired::new());
        }
        let bag = ProxyConnectionExtensions(bag);
        if self.asked == Asked::Route {
            let route = Extensions::new();
            route.insert(bag);
            extensions.insert(ProxyRoutes::from_iter([(self.proxy.clone(), route)]));
        } else {
            extensions.insert(bag);
            extensions.insert(ProxyRoute::Proxy(self.proxy.clone()));
        }
        request
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Counts {
    legs: usize,
    secure_legs: usize,
    origins: usize,
}

struct Fixture {
    legs: Arc<AtomicUsize>,
    secure_legs: Arc<AtomicUsize>,
    origins: Arc<AtomicUsize>,
    client: BoxService<Request, Response, OpaqueError>,
}

impl Fixture {
    fn start(leg_tls: LegTls) -> Self {
        let scope = WeakScope::detached();
        let legs = Arc::new(AtomicUsize::new(0));
        let secure_legs = Arc::new(AtomicUsize::new(0));
        let origins = Arc::new(AtomicUsize::new(0));
        let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);

        let leg_transport = MockConnectorService::new({
            let always_secure = matches!(leg_tls, LegTls::Required);
            let legs = Arc::clone(&legs);
            let secure_legs = Arc::clone(&secure_legs);
            let origins = Arc::clone(&origins);
            move |input: &ConnectRequest| {
                legs.fetch_add(1, Ordering::Relaxed);
                let secure = always_secure || leg_asks_for_tls(input);
                if secure {
                    secure_legs.fetch_add(1, Ordering::Relaxed);
                }
                leg_server(
                    secure,
                    matches!(
                        input.protocol(),
                        Some(&Protocol::SOCKS5 | &Protocol::SOCKS5H)
                    ),
                    Arc::clone(&origins),
                )
            }
        })
        .with_max_buffer_size(BUFFER);

        let quic_leg = MockQuicConnectorService::new(quic_server_config(), {
            let legs = Arc::clone(&legs);
            let origins = Arc::clone(&origins);
            move || {
                legs.fetch_add(1, Ordering::Relaxed);
                h3_proxy_server(Arc::clone(&origins))
            }
        });

        let no_direct_route = MockConnectorService::new(service_fn(async |_: MockSocket| {
            Err::<(), BoxError>("this client reaches origins through a proxy only".into())
        }));

        let proxy = ProxyConnector::builder(scope.clone())
            .with_custom_tcp_connector(leg_transport)
            .with_custom_quic_connector(quic_leg)
            .without_dns_connector();
        let client = EasyHttpWebClient::connector_builder(scope)
            .with_custom_tcp_connector(no_direct_route)
            .without_dns_connector();

        // The TLS stage decides the connector type, so each variant finishes its own chain.
        let client = match leg_tls {
            LegTls::Required => {
                let proxy = proxy
                    .with_tls_support_using_boringssl(tls.clone())
                    .map_connector(|tls| tls.into_secure())
                    .with_default_http_connector::<Body>()
                    .with_default_connection_pool()
                    .with_all_proxy_protocols()
                    .build();
                client_over!(client, proxy, tls)
            }
            LegTls::PerRoute => {
                let proxy = proxy
                    .with_tls_support_using_boringssl(tls.clone())
                    .with_default_http_connector::<Body>()
                    .with_default_connection_pool()
                    .with_all_proxy_protocols()
                    .build();
                client_over!(client, proxy, tls)
            }
            LegTls::None => {
                let proxy = proxy
                    .without_tls_support()
                    .with_default_http_connector::<Body>()
                    .with_default_connection_pool()
                    .with_all_proxy_protocols()
                    .build();
                client_over!(client, proxy, tls)
            }
        };

        Self {
            legs,
            secure_legs,
            origins,
            client: ProxyRoutesLayer::new().into_layer(client).boxed(),
        }
    }

    async fn get(&self, case: Case) {
        let response = self.try_get(case).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "ok");
    }

    async fn try_get(&self, case: Case) -> Result<Response, OpaqueError> {
        self.client.serve(case.request()).await
    }

    fn counts(&self) -> Counts {
        Counts {
            legs: self.legs.load(Ordering::Relaxed),
            secure_legs: self.secure_legs.load(Ordering::Relaxed),
            origins: self.origins.load(Ordering::Relaxed),
        }
    }
}

const BUFFER: usize = 64 * 1024;

fn leg_asks_for_tls(input: &ConnectRequest) -> bool {
    input.extensions.get_ref::<TlsRequired>().is_some()
        || input.protocol().is_some_and(Protocol::is_secure)
}

static AUTH: LazyLock<ServerAuthData> =
    LazyLock::new(|| ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap());

fn server_tls(alpn: impl IntoIterator<Item = ApplicationProtocol>) -> TlsServerConfig {
    TlsServerConfig::new()
        .with_server_auth(AUTH.clone())
        .with_alpn(alpn.into_iter().collect())
}

fn origin_server(secure: bool) -> BoxService<MockSocket, (), BoxError> {
    let http =
        HttpServer::new_http1(WeakScope::detached()).service(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        }));
    if secure {
        TlsAcceptorLayer::new(server_tls([ApplicationProtocol::HTTP_11]))
            .into_layer(http)
            .boxed()
    } else {
        MapErrLayer::into_box_error().into_layer(http).boxed()
    }
}

fn origin_transport(
    origins: Arc<AtomicUsize>,
) -> MockConnectorService<
    impl Fn(&ConnectRequest) -> BoxService<MockSocket, (), BoxError> + Clone,
    fn(&ConnectRequest) -> BoxService<MockSocket, (), BoxError>,
> {
    MockConnectorService::new(move |input: &ConnectRequest| {
        origins.fetch_add(1, Ordering::Relaxed);
        origin_server(input.authority.port == 443)
    })
    .with_max_buffer_size(BUFFER)
}

fn leg_server(
    secure: bool,
    socks: bool,
    origins: Arc<AtomicUsize>,
) -> BoxService<MockSocket, (), BoxError> {
    let scope = WeakScope::detached();
    let tls = || TlsAcceptorLayer::new(server_tls([ApplicationProtocol::HTTP_11]));
    if socks {
        let connector = Socks5Connector::new(
            origin_transport(origins),
            IoForwardService::new(scope.clone()),
        );
        let server = MapErrLayer::into_box_error()
            .into_layer(Socks5Acceptor::new(scope).with_connector(connector));
        if secure {
            tls().into_layer(server).boxed()
        } else {
            server.boxed()
        }
    } else {
        let server = HttpServer::new_http1(scope).service(connect_proxy_service(origins));
        if secure {
            tls().into_layer(server).boxed()
        } else {
            server.boxed()
        }
    }
}

fn connect_proxy_service(
    origins: Arc<AtomicUsize>,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let scope = WeakScope::detached();
    UpgradeLayer::new(
        scope.clone(),
        HttpProxyConnectMatcher::new(),
        EagerHttpProxyConnector::new(origin_transport(origins), IoForwardService::new(scope)),
    )
    .into_layer(service_fn(async |_: Request| {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::BAD_GATEWAY;
        Ok::<_, Infallible>(response)
    }))
}

fn quic_server_config() -> ServerConfig {
    let mut transport = TransportConfig::default();
    HttpServer::new_http3(WeakScope::detached())
        .http3()
        .configure_transport(&mut transport)
        .unwrap();
    let mut config = ServerConfig::try_from_rama_tls_with_provider(
        &server_tls([ApplicationProtocol::HTTP_3]),
        TlsOptions::default(),
        &BoringTlsProvider::new(),
    )
    .unwrap();
    config.set_transport_config(Arc::new(transport));
    config
}

fn h3_proxy_server(
    origins: Arc<AtomicUsize>,
) -> impl Service<Connection, Error: Into<BoxError>> + Clone {
    let mut h3 = HttpServer::new_http3(WeakScope::detached());
    h3.http3_mut().extended_connect = true;
    h3.service(connect_proxy_service(origins))
}

fn with_version(mut proxy: ProxyAddress, version: Version) -> ProxyAddress {
    let ProxyProtocol::Http {
        version: pinned, ..
    } = &mut proxy.protocol
    else {
        panic!("only an HTTP proxy speaks an HTTP version");
    };
    *pinned = Some(version);
    proxy
}
