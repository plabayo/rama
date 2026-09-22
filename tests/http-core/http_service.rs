//! Real TCP/TLS coverage of protocol-independent alternative-service selection.

use rama::{
    Layer, Service,
    bytes::Bytes,
    dns::client::DnsConnector,
    extensions::ExtensionsRef,
    graceful::Shutdown,
    http::{
        Body, HeaderMap, Method, Request, Response, StatusCode, Version,
        body::util::BodyExt as _,
        client::EasyHttpConnectorBuilder,
        conn::HttpOrigin,
        header,
        layer::{
            alt_svc::AltSvcCache,
            upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    layer::MapInputLayer,
    net::{
        Protocol,
        address::{HostWithPort, ProxyAddress, SocketAddress},
        client::{ProxyRoute, ProxyRoutes},
        proxy::IoForwardService,
    },
    rt::Executor,
    service::service_fn,
    tcp::{TcpStream, client::service::TcpConnector, server::TcpListener},
    tls::{
        SecureTransport,
        client::{
            ServerVerifyMode, TlsClientConfig, TlsServerCertPin, TlsServerCertPins, TlsServerVerify,
        },
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
};
use std::{
    collections::VecDeque,
    convert::Infallible,
    fmt::Debug,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[cfg(feature = "boring")]
use rama::tls::boring::server::TlsAcceptorLayer;
#[cfg(not(feature = "boring"))]
use rama::tls::rustls::server::TlsAcceptorLayer;

use parking_lot::Mutex;
use tokio::{
    net::TcpListener as TokioTcpListener,
    task::{JoinHandle, spawn},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

const TEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
struct Observation {
    version: Version,
    authority: String,
    sni: Option<String>,
    alt_used: Option<String>,
    body: Bytes,
}

#[derive(Default)]
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
}

impl Reply {
    fn advertise(value: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(header::ALT_SVC, value.parse().unwrap());
        Self {
            headers,
            ..Self::default()
        }
    }
}

struct Server {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    observations: Arc<Mutex<Vec<Observation>>>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
    shutdown: Shutdown,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(auth: ServerAuthData, version: Version) -> Self {
        let cancel = CancellationToken::new();
        let shutdown = Shutdown::new(cancel.clone().cancelled_owned());
        let executor = Executor::graceful(shutdown.guard());
        let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), executor.clone())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(VecDeque::<Reply>::new()));
        let accepted = Arc::new(AtomicUsize::new(0));
        let handler = service_fn({
            let observations = observations.clone();
            let replies = replies.clone();
            move |request: Request| {
                let observations = observations.clone();
                let replies = replies.clone();
                async move {
                    let observation = Observation {
                        version: request.version(),
                        authority: request
                            .uri()
                            .authority()
                            .map(|authority| authority.to_string())
                            .or_else(|| {
                                request
                                    .headers()
                                    .get(header::HOST)
                                    .map(|host| host.to_str().unwrap().to_owned())
                            })
                            .unwrap(),
                        sni: request
                            .extensions()
                            .get_ref::<SecureTransport>()
                            .and_then(|tls| tls.client_hello())
                            .and_then(|hello| hello.ext_server_name())
                            .map(ToString::to_string),
                        alt_used: request
                            .headers()
                            .get(header::ALT_USED)
                            .map(|value| value.to_str().unwrap().to_owned()),
                        body: request.into_body().collect().await.unwrap().to_bytes(),
                    };
                    observations.lock().push(observation);
                    let reply = replies.lock().pop_front().unwrap_or_default();
                    let mut response = Response::new(Body::from("delivered"));
                    *response.status_mut() = reply.status;
                    *response.headers_mut() = reply.headers;
                    Ok::<_, Infallible>(response)
                }
            }
        });
        let config = TlsServerConfig::new().with_server_auth(auth);
        let config = match version {
            Version::HTTP_11 => config.with_alpn_http_1(),
            Version::HTTP_2 => config.with_alpn_http_2(),
            _ => panic!("test server only supports HTTP/1.1 and HTTP/2"),
        };
        let service = (
            MapInputLayer::new({
                let accepted = accepted.clone();
                move |input: TcpStream| {
                    accepted.fetch_add(1, Ordering::SeqCst);
                    input
                }
            }),
            TlsAcceptorLayer::new(config).with_store_client_hello(true),
        )
            .into_layer(HttpServer::auto(executor).service(handler));
        let task = spawn(listener.serve(service));
        Self {
            address,
            accepted,
            observations,
            replies,
            shutdown,
            cancel,
            task,
        }
    }

    fn origin(&self) -> HttpOrigin {
        HttpOrigin::new(
            Protocol::HTTPS,
            HostWithPort::localhost_domain_with_port(self.address.port()),
        )
        .unwrap()
    }

    fn request(&self) -> Request {
        Request::builder()
            .method(Method::POST)
            .uri(format!(
                "https://localhost:{}/resource",
                self.address.port()
            ))
            .body(Body::from("dispatched once"))
            .unwrap()
    }

    fn reply(&self, reply: Reply) {
        self.replies.lock().push_back(reply);
    }

    fn request_count(&self) -> usize {
        self.observations.lock().len()
    }

    async fn close(self) {
        self.cancel.cancel();
        self.shutdown
            .shutdown_with_limit(TEST_TIMEOUT)
            .await
            .unwrap();
        self.task.await.unwrap();
    }
}

fn client(
    tls: TlsClientConfig,
    cache: AltSvcCache,
) -> impl Service<Request, Output = Response, Error: Debug> {
    let builder = EasyHttpConnectorBuilder::new()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_http_proxy_support();
    #[cfg(feature = "boring")]
    let builder = builder.with_tls_support_using_boringssl(tls);
    #[cfg(not(feature = "boring"))]
    let builder = builder.with_tls_support_using_rustls(tls);
    builder
        .with_default_http_connector(Executor::new())
        .with_default_connection_pool()
        .with_alt_svc_cache(cache)
        .build_client()
}

fn credentials() -> (ServerAuthData, TlsClientConfig) {
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let tls = TlsClientConfig::default_http()
        .try_with_server_trust_anchors(auth.cert_chain.clone())
        .unwrap();
    (auth, tls)
}

async fn complete(
    client: &impl Service<Request, Output = Response, Error: Debug>,
    request: Request,
) -> (StatusCode, Version) {
    let response = timeout(TEST_TIMEOUT, client.serve(request))
        .await
        .unwrap()
        .unwrap();
    let result = (response.status(), response.version());
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "delivered"
    );
    result
}

fn seed(cache: &AltSvcCache, origin: &HttpOrigin, advertisement: &str) {
    let mut headers = HeaderMap::new();
    headers.insert(header::ALT_SVC, advertisement.parse().unwrap());
    cache.record_authenticated(origin, &headers, Duration::ZERO);
}

#[tokio::test]
async fn learns_h1_and_h2_alternatives_and_preserves_origin_and_sni() {
    for (protocol, version) in [("http%2F1.1", Version::HTTP_11), ("h2", Version::HTTP_2)] {
        let (auth, tls) = credentials();
        let origin = Server::start(auth.clone(), Version::HTTP_2).await;
        let alternative = Server::start(auth, version).await;
        origin.reply(Reply::advertise(&format!(
            "unknown=\":444\", {protocol}=\"{}\"",
            alternative.address
        )));
        let cache = AltSvcCache::default();
        let client = client(tls, cache.clone());
        assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);
        assert!(cache.lookup(&origin.origin()).is_some());
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(origin.request_count(), 1);
        {
            let observations = alternative.observations.lock();
            let observed = &observations[0];
            assert_eq!(observed.version, version);
            assert_eq!(
                observed.authority,
                format!("localhost:{}", origin.address.port())
            );
            assert_eq!(observed.sni.as_deref(), Some("localhost"));
            assert_eq!(
                observed.alt_used.as_deref(),
                Some(alternative.address.to_string().as_str())
            );
            assert_eq!(observed.body, "dispatched once");
        }
        drop(client);
        origin.close().await;
        alternative.close().await;
    }
}

#[tokio::test]
async fn misdirected_response_suppresses_only_its_service_without_replaying_body() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let first = Server::start(auth.clone(), Version::HTTP_2).await;
    let second = Server::start(auth, Version::HTTP_11).await;
    first.reply(Reply {
        status: StatusCode::MISDIRECTED_REQUEST,
        ..Reply::default()
    });
    let cache = AltSvcCache::default();
    seed(
        &cache,
        &origin.origin(),
        &format!(
            "h2=\"{}\", http%2F1.1=\"{}\"",
            first.address, second.address
        ),
    );
    let client = client(tls, cache.clone());
    assert_eq!(
        complete(&client, origin.request()).await.0,
        StatusCode::MISDIRECTED_REQUEST
    );
    assert_eq!(first.request_count(), 1);
    assert_eq!(second.request_count(), 0);
    assert_eq!(origin.request_count(), 0);
    assert_eq!(
        complete(&client, origin.request()).await,
        (StatusCode::OK, Version::HTTP_11)
    );
    assert_eq!(second.request_count(), 1);
    assert_eq!(first.request_count(), 1);
    drop(client);
    origin.close().await;
    first.close().await;
    second.close().await;
}

#[tokio::test]
async fn pooled_service_refreshes_advertisement_generation_before_421() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth, Version::HTTP_2).await;
    let cache = AltSvcCache::default();
    let advertisement = format!("h2=\"{}\"; ma=600", alternative.address);
    seed(&cache, &origin.origin(), &advertisement);
    alternative.reply(Reply::advertise(&advertisement));
    alternative.reply(Reply {
        status: StatusCode::MISDIRECTED_REQUEST,
        ..Reply::default()
    });
    let client = client(tls, cache.clone());
    assert_eq!(complete(&client, origin.request()).await.0, StatusCode::OK);
    let snapshot = cache.lookup(&origin.origin()).unwrap();
    assert_eq!(
        complete(&client, origin.request()).await.0,
        StatusCode::MISDIRECTED_REQUEST
    );
    assert_eq!(alternative.accepted.load(Ordering::SeqCst), 1);
    assert!(
        !cache.is_usable(&snapshot, 0),
        "421 must apply to the current lookup, including on a pooled connection"
    );
    assert_eq!(complete(&client, origin.request()).await.0, StatusCode::OK);
    assert_eq!(origin.request_count(), 1);
    assert_eq!(alternative.request_count(), 2);
    drop(client);
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn advertised_protocol_mismatch_never_falls_back_to_origin() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth, Version::HTTP_11).await;
    let cache = AltSvcCache::default();
    seed(
        &cache,
        &origin.origin(),
        &format!("h2=\"{}\"", alternative.address),
    );
    let client = client(tls, cache);
    assert!(
        timeout(TEST_TIMEOUT, client.serve(origin.request()))
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(origin.request_count(), 0);
    assert_eq!(alternative.request_count(), 0);
    drop(client);
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn cached_alternative_authentication_failure_never_falls_back() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth, Version::HTTP_2).await;
    let (untrusted, _) = credentials();
    let alternative = Server::start(untrusted, Version::HTTP_2).await;
    let cache = AltSvcCache::default();
    seed(
        &cache,
        &origin.origin(),
        &format!("h2=\"{}\"", alternative.address),
    );
    let client = client(tls, cache);
    assert!(
        timeout(TEST_TIMEOUT, client.serve(origin.request()))
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(origin.request_count(), 0);
    assert_eq!(alternative.request_count(), 0);
    drop(client);
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn changed_certificate_pins_cannot_reuse_alternative_connection() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth, Version::HTTP_2).await;
    let cache = AltSvcCache::default();
    seed(
        &cache,
        &origin.origin(),
        &format!("h2=\"{}\"", alternative.address),
    );
    let client = client(tls, cache);
    complete(&client, origin.request()).await;
    complete(&client, origin.request()).await;
    assert_eq!(alternative.accepted.load(Ordering::SeqCst), 1);
    let request = origin.request();
    request
        .extensions()
        .insert(TlsServerCertPins::new(TlsServerCertPin::SpkiSha256(
            [1; 32],
        )));
    assert!(
        timeout(TEST_TIMEOUT, client.serve(request))
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(alternative.request_count(), 2);
    assert_eq!(origin.request_count(), 0);
    drop(client);
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn timed_out_alternative_cannot_bypass_new_pins_on_pooled_origin() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth, Version::HTTP_2).await;
    let listener = TokioTcpListener::bind(SocketAddr::from(SocketAddress::local_ipv4(0)))
        .await
        .unwrap();
    let stalled_address = listener.local_addr().unwrap();
    let stalled = spawn(async move {
        let mut sockets = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            sockets.push(socket);
        }
    });
    let cache = AltSvcCache::default();
    let client = client(tls, cache.clone());
    for _ in 0..2 {
        seed(
            &cache,
            &origin.origin(),
            &format!("h2=\"{stalled_address}\""),
        );
        complete(&client, origin.request()).await;
    }
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);
    seed(
        &cache,
        &origin.origin(),
        &format!("h2=\"{stalled_address}\""),
    );
    let request = origin.request();
    request
        .extensions()
        .insert(TlsServerCertPins::new(TlsServerCertPin::SpkiSha256(
            [1; 32],
        )));
    assert!(
        timeout(TEST_TIMEOUT, client.serve(request))
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(
        origin.request_count(),
        2,
        "the pin-restricted body must never be dispatched"
    );
    stalled.abort();
    drop(client);
    origin.close().await;
}

#[tokio::test]
async fn alternative_target_is_reached_through_selected_proxy_route() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth, Version::HTTP_2).await;
    let cancel = CancellationToken::new();
    let shutdown = Shutdown::new(cancel.clone().cancelled_owned());
    let executor = Executor::graceful(shutdown.guard());
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), executor.clone())
        .await
        .unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let connect = EagerHttpProxyConnector::new(
        DnsConnector::new(TcpConnector::new()),
        IoForwardService::new(executor.clone()),
    );
    let service = (
        MapInputLayer::new({
            let targets = targets.clone();
            move |request: Request| {
                assert_eq!(request.method(), Method::CONNECT);
                targets.lock().push(request.uri().to_string());
                request
            }
        }),
        UpgradeLayer::new(executor.clone(), MethodMatcher::CONNECT, connect),
    )
        .into_layer(service_fn(async |_request: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::empty())
                    .unwrap(),
            )
        }));
    let task = spawn(listener.serve(HttpServer::auto(executor).service(service)));
    let unavailable = TokioTcpListener::bind(SocketAddr::from(SocketAddress::local_ipv4(0)))
        .await
        .unwrap();
    let unavailable_address = unavailable.local_addr().unwrap();
    drop(unavailable);

    let cache = AltSvcCache::default();
    seed(
        &cache,
        &origin.origin(),
        &format!("h2=\"{}\"", alternative.address),
    );
    let client = client(tls, cache);
    let request = origin.request();
    request.extensions().insert(ProxyRoutes::new([
        ProxyRoute::from(
            format!("http://{unavailable_address}")
                .parse::<ProxyAddress>()
                .unwrap(),
        ),
        ProxyRoute::from(
            format!("http://{proxy_address}")
                .parse::<ProxyAddress>()
                .unwrap(),
        ),
    ]));
    assert_eq!(complete(&client, request).await.1, Version::HTTP_2);
    assert_eq!(*targets.lock(), [alternative.address.to_string()]);
    assert_eq!(origin.request_count(), 0);
    assert_eq!(alternative.request_count(), 1);
    {
        let observations = alternative.observations.lock();
        assert_eq!(observations[0].sni.as_deref(), Some("localhost"));
        assert_eq!(
            observations[0].authority,
            format!("localhost:{}", origin.address.port())
        );
    }
    drop(client);
    cancel.cancel();
    shutdown.shutdown_with_limit(TEST_TIMEOUT).await.unwrap();
    task.await.unwrap();
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn ordinary_origin_pool_does_not_bypass_new_certificate_pins() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let (auth, tls) = credentials();
        let origin = Server::start(auth, version).await;
        let client = client(tls, AltSvcCache::default());
        for _ in 0..2 {
            assert_eq!(complete(&client, origin.request()).await.1, version);
        }
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);

        let request = origin.request();
        request
            .extensions()
            .insert(TlsServerCertPins::new(TlsServerCertPin::SpkiSha256(
                [1; 32],
            )));
        assert!(
            timeout(TEST_TIMEOUT, client.serve(request))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(
            origin.request_count(),
            2,
            "a pooled connection must not bypass newly requested pins"
        );
        assert_eq!(
            origin.accepted.load(Ordering::SeqCst),
            2,
            "the changed pin policy requires a fresh handshake"
        );

        // An isolated failure must not corrupt the still-compatible original pool.
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 2);
        drop(client);
        origin.close().await;
    }
}

#[tokio::test]
async fn ordinary_origin_pool_does_not_reuse_unverified_connection_for_verified_request() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let (auth, _) = credentials();
        let origin = Server::start(auth, version).await;
        let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
        let client = client(tls, AltSvcCache::default());
        for _ in 0..2 {
            assert_eq!(complete(&client, origin.request()).await.1, version);
        }
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);

        let request = origin.request();
        request
            .extensions()
            .insert(TlsServerVerify(ServerVerifyMode::Auto));
        assert!(
            timeout(TEST_TIMEOUT, client.serve(request))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(
            origin.request_count(),
            2,
            "verified requests must not use an unverified pooled connection"
        );
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 2);

        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 2);
        drop(client);
        origin.close().await;
    }
}
