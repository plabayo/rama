//! What a second request through the real client reuses of the first: the connection to
//! the proxy and the tunnel to the origin over it.

use parking_lot::Mutex;
use rama::{
    Layer as _, Service,
    error::{BoxError, extra::OpaqueError},
    extensions::{Extension, Extensions, ExtensionsRef as _},
    graceful::WeakScope,
    http::{
        Body, Method, Request, Response, StatusCode, Version,
        body::util::BodyExt as _,
        client::{EasyHttpWebClient, ProxyConnector},
        header,
        layer::upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        proxy::HttpProxyConnectMatcher,
        server::HttpServer,
    },
    layer::MapInputLayer,
    net::{
        Protocol,
        address::{ProxyAddress, ProxyProtocol},
        client::{
            ConnectRequest, ProxyConnectionExtensions, ProxyRoute, ProxyRoutes, ProxyRoutesLayer,
            pool::{PoolPartition, ReuseKey},
        },
        proxy::IoForwardService,
        test_utils::client::{MockConnectorService, MockSocket},
        tls::{ApplicationProtocol, ServerName},
    },
    quic::{
        Connection, ServerConfig, TransportConfig,
        test_utils::MockQuicConnectorService,
        tls::{BoringTlsProvider, TlsOptions},
    },
    service::{BoxService, service_fn},
    tls::{
        boring::server::TlsAcceptorLayer,
        client::{ServerVerifyMode, TlsClientConfig, TlsServerVerify},
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

const ORIGIN: &str = "https://origin.test/";
const PLAIN_PROXY: &str = "http://plain-proxy.test:8080";
const SECURE_PROXY: &str = "https://secure-proxy.test:443";
const OTHER_SECURE_PROXY: &str = "https://other-secure-proxy.test:443";
const QUIC_PROXY: &str = "https://127.0.0.1:443";

#[tokio::test]
async fn the_second_request_reuses_what_it_may() {
    timeout(DEADLINE, async {
        let mut wrong = Vec::new();
        for row in rows() {
            let fixture = Fixture::start();
            fixture.get(&row.first).await;
            fixture.get(&row.second).await;
            let expected = row.expect;
            let counts = fixture.counts();
            if counts != expected {
                wrong.push(format!(
                    "{}: {:?} then {:?}, credentials {:?}\n  expected {expected:?}\n  got      {counts:?}",
                    row.name,
                    row.first,
                    row.second,
                    fixture.credentials(),
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    })
    .await
    .unwrap();
}

struct Row {
    name: &'static str,
    first: Case,
    second: Case,
    expect: Counts,
}

fn rows() -> Vec<Row> {
    use Bag::{
        Empty, Forked, Marker, Name, NoHop, Partition, PartitionAndVerify, PerCredential,
        PerCredentialAndPartition, TenantPartition, Verify,
    };
    use Route::{Direct, Other, Plain, SameAddressH2, SameAddressH3, Secure, SecureH2};
    use ServerVerifyMode::{Auto, Disable};
    use Tenant::{A, B};

    vec![
        Row {
            name: "same everything",
            first: Case::new(A, NoHop, Plain("c1")),
            second: Case::new(A, NoHop, Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "other tenant",
            first: Case::new(A, NoHop, Plain("c1")),
            second: Case::new(B, NoHop, Plain("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "same hop partition",
            first: Case::new(A, Partition, Plain("c1")),
            second: Case::new(A, Partition, Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "hop partition, other tenant",
            first: Case::new(A, Partition, Plain("c1")),
            second: Case::new(B, Partition, Plain("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "hop partition appears",
            first: Case::new(A, NoHop, Plain("c1")),
            second: Case::new(A, Partition, Plain("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "same hop verify over a plain proxy",
            first: Case::new(A, Verify(Disable), Plain("c1")),
            second: Case::new(A, Verify(Disable), Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "other hop verify over a plain proxy",
            first: Case::new(A, Verify(Disable), Plain("c1")),
            second: Case::new(A, Verify(Auto), Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "same hop partition, other hop verify over a plain proxy",
            first: Case::new(A, PartitionAndVerify(Disable), Plain("c1")),
            second: Case::new(A, PartitionAndVerify(Auto), Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "an origin name appears, over an h1 proxy",
            first: Case::new(A, NoHop, Plain("c1")),
            second: Case::new(A, NoHop, Plain("c1")).with_origin_name("other-origin.test"),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "an origin name appears, over an h2 proxy",
            first: Case::new(A, NoHop, SecureH2("c1")),
            second: Case::new(A, NoHop, SecureH2("c1")).with_origin_name("other-origin.test"),
            expect: Counts {
                legs: 1,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "other credential over an h1 proxy",
            first: Case::new(A, NoHop, Plain("c1")),
            second: Case::new(A, NoHop, Plain("c2")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "other credential over an h2 proxy",
            first: Case::new(A, NoHop, SecureH2("c1")),
            second: Case::new(A, NoHop, SecureH2("c2")),
            expect: Counts {
                legs: 1,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "other credential, per credential",
            first: Case::new(A, PerCredential, SecureH2("c1")),
            second: Case::new(A, PerCredential, SecureH2("c2")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "same credential, per credential",
            first: Case::new(A, PerCredential, SecureH2("c1")),
            second: Case::new(A, PerCredential, SecureH2("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "same credential, per credential, other origin",
            first: Case::new(A, PerCredential, SecureH2("c1")),
            second: Case::new(A, PerCredential, SecureH2("c1"))
                .with_origin_name("other-origin.test"),
            expect: Counts {
                legs: 1,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "a credential partition keeps the hop partition",
            first: Case::new(A, PerCredentialAndPartition, SecureH2("c1")),
            second: Case::new(A, PerCredential, SecureH2("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "per credential appears, same credential",
            first: Case::new(A, NoHop, SecureH2("c1")),
            second: Case::new(A, PerCredential, SecureH2("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "per credential appears, other credential",
            first: Case::new(A, NoHop, SecureH2("c1")),
            second: Case::new(A, PerCredential, SecureH2("c2")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "per credential and a hop partition",
            first: Case::new(A, PerCredentialAndPartition, SecureH2("c1")),
            second: Case::new(A, PerCredentialAndPartition, SecureH2("c2")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "other tenant over an h2 proxy",
            first: Case::new(A, NoHop, SecureH2("c1")),
            second: Case::new(B, NoHop, SecureH2("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "hop partition appears over an h2 proxy",
            first: Case::new(A, NoHop, SecureH2("c1")),
            second: Case::new(A, Partition, SecureH2("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "a forked bag asks over an h2 proxy",
            first: Case::new(A, Forked, SecureH2("c1")),
            second: Case::new(A, NoHop, SecureH2("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "other proxy",
            first: Case::new(A, NoHop, SecureH2("c1")),
            second: Case::new(A, NoHop, Other("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "direct twice",
            first: Case::new(A, NoHop, Direct),
            second: Case::new(A, NoHop, Direct),
            expect: Counts {
                legs: 0,
                tunnels: 0,
                origins: 1,
            },
        },
        Row {
            name: "direct then proxied",
            first: Case::new(A, NoHop, Direct),
            second: Case::new(A, NoHop, Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 2,
            },
        },
        Row {
            name: "direct with a hop partition appearing",
            first: Case::new(A, NoHop, Direct),
            second: Case::new(A, Partition, Direct),
            expect: Counts {
                legs: 0,
                tunnels: 0,
                origins: 1,
            },
        },
        Row {
            name: "no bag, empty bag",
            first: Case::new(A, NoHop, Plain("c1")),
            second: Case::new(A, Empty, Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "empty bag, bag without partition",
            first: Case::new(A, Empty, Plain("c1")),
            second: Case::new(A, Marker, Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "a bag forked from a base",
            first: Case::new(A, Forked, Plain("c1")),
            second: Case::new(A, Forked, Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "a forked bag asks what its base asks",
            first: Case::new(A, Forked, Plain("c1")),
            second: Case::new(A, Partition, Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "a route bag asks what a request bag asks",
            first: Case::new(A, Partition, Plain("c1")).on_route(),
            second: Case::new(A, Partition, Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "a route bag appears",
            first: Case::new(A, NoHop, Plain("c1")),
            second: Case::new(A, Partition, Plain("c1")).on_route(),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "same everything over an h2 proxy",
            first: Case::new(A, Name("secure-proxy.test"), SecureH2("c1")),
            second: Case::new(A, Name("secure-proxy.test"), SecureH2("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "same hop name",
            first: Case::new(A, Name("secure-proxy.test"), Secure("c1")),
            second: Case::new(A, Name("secure-proxy.test"), Secure("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "other hop name",
            first: Case::new(A, Name("secure-proxy.test"), Secure("c1")),
            second: Case::new(A, Name("other-name.test"), Secure("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "hop name disappears",
            first: Case::new(A, Name("secure-proxy.test"), Secure("c1")),
            second: Case::new(A, NoHop, Secure("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "hop name appears",
            first: Case::new(A, NoHop, Secure("c1")),
            second: Case::new(A, Name("secure-proxy.test"), Secure("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "hop name and origin both match",
            first: Case::new(A, Name("secure-proxy.test"), Secure("c1"))
                .with_origin_name("origin.test"),
            second: Case::new(A, Name("secure-proxy.test"), Secure("c1"))
                .with_origin_name("origin.test"),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
        Row {
            name: "hop name matches, explicit origin name then default",
            first: Case::new(A, Name("secure-proxy.test"), Secure("c1"))
                .with_origin_name("origin.test"),
            second: Case::new(A, Name("secure-proxy.test"), Secure("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "origin matches, hop name does not",
            first: Case::new(A, Name("secure-proxy.test"), Secure("c1"))
                .with_origin_name("origin.test"),
            second: Case::new(A, Name("other-name.test"), Secure("c1"))
                .with_origin_name("origin.test"),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "other credential over an h3 proxy",
            first: Case::new(A, NoHop, SameAddressH3("c1")),
            second: Case::new(A, NoHop, SameAddressH3("c2")),
            expect: Counts {
                legs: 1,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "an h3 proxy at the address of an h2 proxy",
            first: Case::new(A, NoHop, SameAddressH2("c1")),
            second: Case::new(A, NoHop, SameAddressH3("c1")),
            expect: Counts {
                legs: 2,
                tunnels: 2,
                origins: 2,
            },
        },
        Row {
            name: "a hop partition the tenant already asks for",
            first: Case::new(A, NoHop, Plain("c1")),
            second: Case::new(A, TenantPartition, Plain("c1")),
            expect: Counts {
                legs: 1,
                tunnels: 1,
                origins: 1,
            },
        },
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tenant {
    A,
    B,
}

#[derive(Debug, Clone, Copy)]
enum Bag {
    NoHop,
    Empty,
    Marker,
    Forked,
    Partition,
    PartitionAndVerify(ServerVerifyMode),
    TenantPartition,
    Name(&'static str),
    Verify(ServerVerifyMode),
    PerCredential,
    PerCredentialAndPartition,
}

#[derive(Debug, Clone, Copy)]
enum Route {
    Direct,
    Plain(&'static str),
    Secure(&'static str),
    SecureH2(&'static str),
    Other(&'static str),
    SameAddressH2(&'static str),
    SameAddressH3(&'static str),
}

impl Route {
    fn address(self) -> Option<ProxyAddress> {
        let (address, version) = match self {
            Self::Direct => return None,
            Self::Plain(_) => (PLAIN_PROXY, Version::HTTP_11),
            Self::Secure(_) => (SECURE_PROXY, Version::HTTP_11),
            Self::SecureH2(_) => (SECURE_PROXY, Version::HTTP_2),
            Self::Other(_) => (OTHER_SECURE_PROXY, Version::HTTP_2),
            Self::SameAddressH2(_) => (QUIC_PROXY, Version::HTTP_2),
            Self::SameAddressH3(_) => (QUIC_PROXY, Version::HTTP_3),
        };
        let user = self.credential();
        let (scheme, authority) = address.split_once("://").unwrap();
        Some(with_version(
            ProxyAddress::try_from(format!("{scheme}://{user}:secret@{authority}").as_str())
                .unwrap(),
            version,
        ))
    }

    fn credential(self) -> &'static str {
        match self {
            Self::Direct => "",
            Self::Plain(user)
            | Self::Secure(user)
            | Self::SecureH2(user)
            | Self::Other(user)
            | Self::SameAddressH2(user)
            | Self::SameAddressH3(user) => user,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Case {
    tenant: Tenant,
    hop: Bag,
    hop_on_route: bool,
    origin_name: Option<&'static str>,
    route: Route,
}

struct TenantA;
struct TenantB;
struct HopPartition;

fn credential_partition(user: &str) -> PoolPartition {
    PoolPartition::new(ReuseKey::new(user.to_owned()))
}

#[derive(Debug, Clone, Copy, Extension)]
struct HopMarker;

impl Case {
    const fn new(tenant: Tenant, hop: Bag, route: Route) -> Self {
        Self {
            tenant,
            hop,
            hop_on_route: false,
            origin_name: None,
            route,
        }
    }

    const fn with_origin_name(mut self, name: &'static str) -> Self {
        self.origin_name = Some(name);
        self
    }

    const fn on_route(mut self) -> Self {
        self.hop_on_route = true;
        self
    }

    fn bag(&self) -> Option<Extensions> {
        let bag = Extensions::new();
        match self.hop {
            Bag::NoHop => return None,
            Bag::Empty => {}
            Bag::Marker => {
                bag.insert(HopMarker);
            }
            Bag::Forked => {
                bag.insert(PoolPartition::of::<HopPartition>());
                let forked = bag.fork();
                forked.insert(HopMarker);
                return Some(forked);
            }
            Bag::Partition => {
                bag.insert(PoolPartition::of::<HopPartition>());
            }
            Bag::PartitionAndVerify(mode) => {
                bag.insert(PoolPartition::of::<HopPartition>());
                bag.insert(TlsServerVerify(mode));
            }
            Bag::TenantPartition => {
                bag.insert(PoolPartition::of::<TenantA>());
            }
            Bag::Name(name) => {
                bag.insert(name.parse::<ServerName>().unwrap());
            }
            Bag::Verify(mode) => {
                bag.insert(TlsServerVerify(mode));
            }
            Bag::PerCredential => {
                bag.insert(credential_partition(self.route.credential()));
            }
            Bag::PerCredentialAndPartition => {
                bag.insert(
                    credential_partition(self.route.credential())
                        .and(&PoolPartition::of::<HopPartition>()),
                );
            }
        }
        Some(bag)
    }

    fn request(&self) -> Request {
        let request = Request::builder().uri(ORIGIN).body(Body::empty()).unwrap();
        let extensions = request.extensions();
        extensions.insert(match self.tenant {
            Tenant::A => PoolPartition::of::<TenantA>(),
            Tenant::B => PoolPartition::of::<TenantB>(),
        });
        if let Some(name) = self.origin_name {
            extensions.insert(name.parse::<ServerName>().unwrap());
        }
        let bag = self.bag().map(ProxyConnectionExtensions);
        match (self.route.address(), self.hop_on_route) {
            (None, _) => {
                extensions.insert(ProxyRoute::Direct);
                if let Some(bag) = bag {
                    extensions.insert(bag);
                }
            }
            (Some(address), false) => {
                if let Some(bag) = bag {
                    extensions.insert(bag);
                }
                extensions.insert(ProxyRoute::Proxy(address));
            }
            (Some(address), true) => {
                let route = Extensions::new();
                if let Some(bag) = bag {
                    route.insert(bag);
                }
                extensions.insert([(address, route)].into_iter().collect::<ProxyRoutes>());
            }
        }
        request
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Counts {
    legs: usize,
    tunnels: usize,
    origins: usize,
}

struct Fixture {
    legs: Arc<AtomicUsize>,
    origins: Arc<AtomicUsize>,
    tunnels: Arc<Mutex<Vec<Option<String>>>>,
    client: BoxService<Request, Response, OpaqueError>,
}

impl Fixture {
    fn start() -> Self {
        let scope = WeakScope::detached();
        let legs = Arc::new(AtomicUsize::new(0));
        let origins = Arc::new(AtomicUsize::new(0));
        let tunnels = Arc::new(Mutex::new(Vec::new()));
        let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);

        let leg_transport = MockConnectorService::new({
            let seen = Seen::new(&tunnels, &origins);
            let legs = Arc::clone(&legs);
            move |input: &ConnectRequest| {
                legs.fetch_add(1, Ordering::Relaxed);
                proxy_server(
                    input
                        .application_protocol
                        .as_ref()
                        .is_some_and(Protocol::is_secure),
                    seen.clone(),
                )
            }
        });

        let origin_transport = MockConnectorService::new({
            let origins = Arc::clone(&origins);
            move || {
                origins.fetch_add(1, Ordering::Relaxed);
                origin_server()
            }
        });

        let quic_leg = MockQuicConnectorService::new(quic_server_config(), {
            let seen = Seen::new(&tunnels, &origins);
            let legs = Arc::clone(&legs);
            move || {
                legs.fetch_add(1, Ordering::Relaxed);
                h3_proxy_server(seen.clone())
            }
        });

        let proxy_connector = ProxyConnector::builder(scope.clone())
            .with_custom_tcp_connector(leg_transport)
            .with_custom_quic_connector(quic_leg)
            .without_dns_connector()
            .with_tls_support_using_boringssl(tls.clone())
            .with_default_http_connector::<Body>()
            .with_default_connection_pool()
            .with_http_connect()
            .build();

        let client = EasyHttpWebClient::connector_builder(scope)
            .with_custom_tcp_connector(origin_transport)
            .without_dns_connector()
            .with_proxy_support(proxy_connector)
            .with_tls_support_using_boringssl(tls)
            .with_default_http_connector()
            .with_default_connection_pool()
            .without_alt_svc()
            .build_client();

        Self {
            legs,
            origins,
            tunnels,
            client: ProxyRoutesLayer::new().into_layer(client).boxed(),
        }
    }

    async fn get(&self, case: &Case) {
        let response = self.client.serve(case.request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{case:?}");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "ok", "{case:?}");
    }

    fn credentials(&self) -> Vec<Option<String>> {
        self.tunnels.lock().clone()
    }

    fn counts(&self) -> Counts {
        Counts {
            legs: self.legs.load(Ordering::Relaxed),
            tunnels: self.tunnels.lock().len(),
            origins: self.origins.load(Ordering::Relaxed),
        }
    }
}

static AUTH: LazyLock<ServerAuthData> =
    LazyLock::new(|| ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap());

fn server_tls(alpn: impl IntoIterator<Item = ApplicationProtocol>) -> TlsServerConfig {
    TlsServerConfig::new()
        .with_server_auth(AUTH.clone())
        .with_alpn(alpn.into_iter().collect())
}

fn origin_server() -> impl Service<MockSocket, Error: Into<BoxError>> {
    let http =
        HttpServer::new_http1(WeakScope::detached()).service(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        }));
    TlsAcceptorLayer::new(server_tls([ApplicationProtocol::HTTP_11])).into_layer(http)
}

#[derive(Clone)]
struct Seen {
    tunnels: Arc<Mutex<Vec<Option<String>>>>,
    origins: Arc<AtomicUsize>,
}

impl Seen {
    fn new(tunnels: &Arc<Mutex<Vec<Option<String>>>>, origins: &Arc<AtomicUsize>) -> Self {
        Self {
            tunnels: Arc::clone(tunnels),
            origins: Arc::clone(origins),
        }
    }
}

fn proxy_service(
    seen: Seen,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let scope = WeakScope::detached();
    let origins = Arc::clone(&seen.origins);
    (
        MapInputLayer::new(move |request: Request| {
            if request.method() == Method::CONNECT {
                seen.tunnels.lock().push(
                    request
                        .headers()
                        .get(header::PROXY_AUTHORIZATION)
                        .map(|value| value.to_str().unwrap().to_owned()),
                );
            }
            request
        }),
        UpgradeLayer::new(
            scope.clone(),
            HttpProxyConnectMatcher::new(),
            EagerHttpProxyConnector::new(
                MockConnectorService::new(move || {
                    origins.fetch_add(1, Ordering::Relaxed);
                    origin_server()
                }),
                IoForwardService::new(scope),
            ),
        ),
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

fn h3_proxy_server(seen: Seen) -> impl Service<Connection, Error: Into<BoxError>> + Clone {
    let mut h3 = HttpServer::new_http3(WeakScope::detached());
    h3.http3_mut().extended_connect = true;
    h3.service(proxy_service(seen))
}

fn proxy_server(secure: bool, seen: Seen) -> BoxService<MockSocket, (), BoxError> {
    let service = proxy_service(seen);
    if secure {
        let mut http = HttpServer::auto(WeakScope::detached());
        http.h2_mut().set_enable_connect_protocol();
        let tls = server_tls([ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]);
        TlsAcceptorLayer::new(tls)
            .into_layer(http.service(service))
            .boxed()
    } else {
        HttpServer::new_http1(WeakScope::detached())
            .service(service)
            .boxed()
    }
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
