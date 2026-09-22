//! Real TCP/TLS coverage of protocol-independent alternative-service selection.

use rama::{
    Layer, Service,
    bytes::Bytes,
    dns::client::DnsConnector,
    extensions::ExtensionsRef,
    futures::stream,
    graceful::Shutdown,
    http::{
        Body, HeaderMap, Method, Request, Response, StatusCode, Version,
        body::{Frame, util::BodyExt as _},
        client::{EasyHttpConnectorBuilder, Http3Connector, Http3Transport, http_connect},
        conn::{HttpOrigin, TargetHttpVersion},
        core::h3::connection::Config as Http3Config,
        header,
        layer::{
            alt_svc::AltSvcCache,
            upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        },
        matcher::MethodMatcher,
        proto::h2::{
            alt_svc::AltSvcSender,
            frame::{AltSvc as AltSvcFrame, StreamId},
        },
        server::HttpServer,
    },
    layer::MapInputLayer,
    net::{
        Protocol,
        address::{Host, HostWithPort, ProxyAddress, SocketAddress},
        client::{ConnectRequest, ProxyRoute, ProxyRoutes},
        conn::MaxConcurrency,
        proxy::IoForwardService,
        tls::ApplicationProtocol,
    },
    quic::{ClientConfig, Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tcp::{TcpStream, client::service::TcpConnector, server::TcpListener},
    tls::{
        SecureTransport,
        client::{
            NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig, TlsServerCertPin,
            TlsServerCertPins, TlsServerVerify,
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

#[cfg(not(feature = "boring"))]
use rama::tls::rustls::{
    client::{RustlsClientConfigExt as _, TlsConnectorLayer},
    server::TlsAcceptorLayer,
};
#[cfg(feature = "boring")]
use rama::{
    quic::tls::BoringTlsProvider,
    tls::boring::{
        client::{BoringClientConfigExt as _, TlsConnectorLayer},
        core::x509::{X509, store::X509StoreBuilder},
        server::TlsAcceptorLayer,
    },
};

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
    alt_svc_frame: Option<AltSvcFrame>,
    body: Option<Body>,
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
    version: Version,
    endpoint: Option<Endpoint>,
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
                    let alt_svc_sender = request.extensions().get_ref::<AltSvcSender>().cloned();
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
                            .map(ToString::to_string)
                            .or_else(|| {
                                request
                                    .extensions()
                                    .get_ref::<NegotiatedTlsParameters>()
                                    .and_then(|parameters| {
                                        parameters.server_name.as_ref().map(ToString::to_string)
                                    })
                            }),
                        alt_used: request
                            .headers()
                            .get(header::ALT_USED)
                            .map(|value| value.to_str().unwrap().to_owned()),
                        body: request.into_body().collect().await.unwrap().to_bytes(),
                    };
                    observations.lock().push(observation);
                    let reply = replies.lock().pop_front().unwrap_or_default();
                    if let Some(frame) = reply.alt_svc_frame {
                        alt_svc_sender
                            .expect("H2 server advertisement sender")
                            .try_send(frame)
                            .unwrap();
                    }
                    let mut response =
                        Response::new(reply.body.unwrap_or_else(|| Body::from("delivered")));
                    *response.status_mut() = reply.status;
                    *response.headers_mut() = reply.headers;
                    Ok::<_, Infallible>(response)
                }
            }
        });
        let config = TlsServerConfig::new().with_server_auth(auth);
        if version == Version::HTTP_3 {
            let config = config.with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
            let endpoint = Endpoint::build(executor.clone())
                .with_server_config(
                    ServerConfig::try_from_rama_tls(&config, TlsOptions::default()).unwrap(),
                )
                .bind_address(SocketAddress::local_ipv4(0))
                .await
                .unwrap();
            let address = endpoint.local_addr().unwrap();
            let task = spawn({
                let endpoint = endpoint.clone();
                let accepted = accepted.clone();
                let server = HttpServer::new_http3(executor.clone());
                async move {
                    while let Some(incoming) = endpoint.accept().await {
                        accepted.fetch_add(1, Ordering::SeqCst);
                        let server = server.clone();
                        let handler = handler.clone();
                        executor.spawn_task(async move {
                            if let Ok(connection) = incoming.await {
                                _ = server.serve(connection, handler).await;
                            }
                        });
                    }
                }
            });
            return Self {
                version,
                endpoint: Some(endpoint),
                address,
                accepted,
                observations,
                replies,
                shutdown,
                cancel,
                task,
            };
        }
        let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), executor.clone())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let config = match version {
            Version::HTTP_11 => config.with_alpn_http_1(),
            Version::HTTP_2 => config.with_alpn_http_2(),
            _ => panic!("test server only supports HTTP/1.1 and HTTP/2"),
        };
        let mut http = HttpServer::auto(executor);
        http.h2_mut().set_alt_svc(true);
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
            .into_layer(http.service(handler));
        let task = spawn(listener.serve(service));
        Self {
            version,
            endpoint: None,
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
            .version(if self.version == Version::HTTP_3 {
                Version::HTTP_3
            } else {
                Version::HTTP_11
            })
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
        if let Some(endpoint) = self.endpoint {
            endpoint.close(0u32, b"done");
            timeout(TEST_TIMEOUT, endpoint.shutdown()).await.unwrap();
        }
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

async fn client_with_http3(
    tls: TlsClientConfig,
) -> (
    impl Service<Request, Output = Response, Error: Debug>,
    Endpoint,
) {
    client_with_http3_cache(tls, AltSvcCache::default()).await
}

async fn client_with_http3_cache(
    tls: TlsClientConfig,
    cache: AltSvcCache,
) -> (
    impl Service<Request, Output = Response, Error: Debug>,
    Endpoint,
) {
    let endpoint = Endpoint::build(Executor::new())
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let h3 = Http3Connector::builder(Executor::new())
        .with_endpoint(endpoint.clone())
        .with_tls_config(tls.clone());
    // Match the stream provider so native overrides exercise both transports.
    #[cfg(feature = "boring")]
    let h3 = h3.with_tls_provider(Arc::new(BoringTlsProvider));
    let h3 = h3.build().await.unwrap();
    let builder = EasyHttpConnectorBuilder::new()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_http_proxy_support();
    #[cfg(feature = "boring")]
    let builder = builder.with_tls_support_using_boringssl(tls);
    #[cfg(not(feature = "boring"))]
    let builder = builder.with_tls_support_using_rustls(tls);
    let client = builder
        .with_default_http_connector(Executor::new())
        .with_http3_support(h3)
        .with_default_connection_pool()
        .with_alt_svc_cache(cache)
        .build_client();
    (client, endpoint)
}

async fn close_client_endpoint(endpoint: Endpoint) {
    endpoint.close(0u32, b"done");
    timeout(TEST_TIMEOUT, endpoint.shutdown()).await.unwrap();
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
    cache.record(origin, &headers, Duration::ZERO);
}

#[tokio::test]
async fn h2_altsvc_frame_discovers_h3_without_a_response_header() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth, Version::HTTP_3).await;
    origin.reply(Reply {
        alt_svc_frame: Some(
            AltSvcFrame::new(
                StreamId::zero(),
                Bytes::from(format!("https://localhost:{}", origin.address.port())),
                Bytes::from(format!("h3=\"{}\"", alternative.address)),
            )
            .unwrap(),
        ),
        ..Reply::default()
    });
    let cache = AltSvcCache::default();
    let (client, endpoint) = client_with_http3_cache(tls, cache.clone()).await;
    let response = timeout(TEST_TIMEOUT, client.serve(origin.request()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.version(), Version::HTTP_2);
    assert!(!response.headers().contains_key(header::ALT_SVC));
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "delivered"
    );

    // No second HTTP exchange is needed to deliver the connection-level hint.
    timeout(TEST_TIMEOUT, async {
        while cache.lookup(&origin.origin()).is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_3);
    assert_eq!(origin.request_count(), 1);
    {
        let observations = alternative.observations.lock();
        let observed = &observations[0];
        assert_eq!(observed.version, Version::HTTP_3);
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
    close_client_endpoint(endpoint).await;
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn h2_alt_svc_headers_and_frames_replace_and_clear_the_same_cache() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth, Version::HTTP_2).await;
    let cache = AltSvcCache::default();
    // This client cannot use H3, so each exchange stays on the origin while
    // still recording its advertisements, independently of supported protocols.
    let client = client(tls, cache.clone());

    for (frame, advertisement, expected_port) in [
        (false, "h3=\":8443\"", Some(8443)),
        (true, "h3=\":9443\"", Some(9443)),
        (false, "clear", None),
        (true, "h3=\":8443\"", Some(8443)),
        (false, "h3=\":9443\"", Some(9443)),
        (true, "clear", None),
    ] {
        let reply = if frame {
            Reply {
                alt_svc_frame: Some(
                    AltSvcFrame::new(
                        StreamId::zero(),
                        Bytes::from(format!("https://localhost:{}", origin.address.port())),
                        Bytes::from_static(advertisement.as_bytes()),
                    )
                    .unwrap(),
                ),
                ..Reply::default()
            }
        } else {
            Reply::advertise(advertisement)
        };
        origin.reply(reply);
        assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);

        // Frames are connection-level events; wait for observation before the
        // next exchange so this tests replacement, not task scheduling order.
        timeout(TEST_TIMEOUT, async {
            loop {
                let snapshot = cache.lookup(&origin.origin());
                let actual = snapshot.as_ref().map(|snapshot| {
                    assert_eq!(snapshot.len(), 1, "advertisements must replace, not merge");
                    snapshot.get(0).unwrap().target.port
                });
                if actual == expected_port {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    assert_eq!(origin.request_count(), 6);
    drop(client);
    origin.close().await;
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
async fn advertised_protocol_mismatch_falls_back_without_dispatching_to_alternative() {
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
    assert_eq!(complete(&client, origin.request()).await.0, StatusCode::OK);
    let attempted = alternative.accepted.load(Ordering::SeqCst);
    assert!(attempted > 0);
    assert_eq!(complete(&client, origin.request()).await.0, StatusCode::OK);
    assert_eq!(alternative.accepted.load(Ordering::SeqCst), attempted);
    assert_eq!(origin.request_count(), 2);
    assert_eq!(alternative.request_count(), 0);
    drop(client);
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn cached_alternative_authentication_failure_falls_back_to_verified_origin() {
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
    assert_eq!(complete(&client, origin.request()).await.0, StatusCode::OK);
    let attempted = alternative.accepted.load(Ordering::SeqCst);
    assert!(attempted > 0);
    assert_eq!(complete(&client, origin.request()).await.0, StatusCode::OK);
    assert_eq!(alternative.accepted.load(Ordering::SeqCst), attempted);
    assert_eq!(origin.request_count(), 2);
    assert_eq!(alternative.request_count(), 0);
    drop(client);
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn request_tls_overrides_do_not_poison_shared_alternatives() {
    for (protocol, version) in [("h2", Version::HTTP_2), ("h3", Version::HTTP_3)] {
        let (auth, tls) = credentials();
        let origin = Server::start(auth.clone(), Version::HTTP_2).await;
        let alternative = Server::start(auth, version).await;
        let cache = AltSvcCache::default();
        seed(
            &cache,
            &origin.origin(),
            &format!("{protocol}=\"{}\"", alternative.address),
        );
        let (client, endpoint) = client_with_http3_cache(tls, cache).await;

        let insecure = origin.request();
        insecure
            .extensions()
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        assert_eq!(complete(&client, insecure).await.1, Version::HTTP_2);
        assert_eq!(alternative.accepted.load(Ordering::SeqCst), 0);
        assert_eq!(complete(&client, origin.request()).await.1, version);

        let mismatched_name = origin.request();
        mismatched_name.extensions().extend(
            TlsClientConfig::new()
                .with_server_name(Host::EXAMPLE_NAME)
                .as_extensions(),
        );
        let before = alternative.accepted.load(Ordering::SeqCst);
        assert!(
            timeout(TEST_TIMEOUT, client.serve(mismatched_name))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(alternative.accepted.load(Ordering::SeqCst), before);
        assert_eq!(complete(&client, origin.request()).await.1, version);

        let invalid_pins = origin.request();
        invalid_pins
            .extensions()
            .insert(TlsServerCertPins::new(TlsServerCertPin::SpkiSha256(
                [1; 32],
            )));
        assert!(
            timeout(TEST_TIMEOUT, client.serve(invalid_pins))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(alternative.request_count(), 3);
        assert_eq!(origin.request_count(), 1);

        drop(client);
        close_client_endpoint(endpoint).await;
        origin.close().await;
        alternative.close().await;
    }
}

#[tokio::test]
async fn connector_tls_defaults_control_alternative_eligibility() {
    for (protocol, version) in [("h2", Version::HTTP_2), ("h3", Version::HTTP_3)] {
        let (auth, tls) = credentials();
        let origin = Server::start(auth.clone(), Version::HTTP_2).await;
        let alternative = Server::start(auth, version).await;
        let cache = AltSvcCache::default();
        seed(
            &cache,
            &origin.origin(),
            &format!("{protocol}=\"{}\"", alternative.address),
        );
        let (client, endpoint) =
            client_with_http3_cache(tls.with_server_verify(ServerVerifyMode::Disable), cache).await;

        assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);
        assert_eq!(alternative.accepted.load(Ordering::SeqCst), 0);
        let verified = origin.request();
        verified
            .extensions()
            .insert(TlsServerVerify(ServerVerifyMode::Auto));
        assert_eq!(complete(&client, verified).await.1, version);
        assert_eq!(origin.request_count(), 1);
        assert_eq!(alternative.request_count(), 1);

        drop(client);
        close_client_endpoint(endpoint).await;
        origin.close().await;
        alternative.close().await;
    }
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
    let alternative = Server::start(auth.clone(), Version::HTTP_2).await;
    let quic_alternative = Server::start(auth, Version::HTTP_3).await;
    let cancel = CancellationToken::new();
    let shutdown = Shutdown::new(cancel.clone().cancelled_owned());
    let executor = Executor::graceful(shutdown.guard());
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), executor.clone())
        .await
        .unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let refused = Arc::new(Mutex::new(None::<(u16, StatusCode)>));
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
    let service = service_fn({
        let refused = refused.clone();
        let targets = targets.clone();
        move |request: Request| {
            let service = service.clone();
            let rejection = *refused.lock();
            let targets = targets.clone();
            async move {
                if let Some((port, status)) = rejection
                    && request.uri().port_u16() == Some(port)
                {
                    targets.lock().push(request.uri().to_string());
                    return Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Body::empty())
                            .unwrap(),
                    );
                }
                service.serve(request).await
            }
        }
    });
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
    let initial_client = client(tls.clone(), cache);
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
    assert_eq!(complete(&initial_client, request).await.1, Version::HTTP_2);
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
    drop(initial_client);

    // A real CONNECT refusal concerns the alternative's endpoint, not the
    // origin or the proxy's ability to reach it. Keep both selector and proxy
    // failure caches in this path, including a second request after failure.
    for status in [
        StatusCode::FORBIDDEN,
        StatusCode::BAD_GATEWAY,
        StatusCode::GATEWAY_TIMEOUT,
    ] {
        *refused.lock() = Some((alternative.address.port(), status));
        let cache = AltSvcCache::default();
        seed(
            &cache,
            &origin.origin(),
            &format!("h2=\"{}\"", alternative.address),
        );
        let client = client(tls.clone(), cache);
        let before = targets.lock().len();
        for _ in 0..2 {
            let request = origin.request();
            request
                .extensions()
                .insert(ProxyRoutes::new([ProxyRoute::from(
                    format!("http://{proxy_address}")
                        .parse::<ProxyAddress>()
                        .unwrap(),
                )]));
            assert_eq!(complete(&client, request).await.0, StatusCode::OK);
        }
        assert_eq!(targets.lock().len(), before + 2);
        assert_eq!(targets.lock()[before], alternative.address.to_string());
        assert_eq!(
            targets.lock()[before + 1],
            format!("localhost:{}", origin.address.port())
        );
        drop(client);
    }
    *refused.lock() = None;

    // An unsupported local QUIC proxy capability must leave the working proxy
    // available for origin fallback, including on the next request. An explicit
    // DIRECT backup must not bypass it merely because H3 was advertised.
    let proxy = ProxyRoute::from(
        format!("http://{proxy_address}")
            .parse::<ProxyAddress>()
            .unwrap(),
    );
    for routes in [vec![proxy.clone()], vec![proxy, ProxyRoute::Direct]] {
        let cache = AltSvcCache::default();
        seed(
            &cache,
            &origin.origin(),
            &format!("h3=\"{}\"", quic_alternative.address),
        );
        let (client, endpoint) = client_with_http3_cache(tls.clone(), cache).await;
        let before = targets.lock().len();
        for _ in 0..2 {
            let request = origin.request();
            request
                .extensions()
                .insert(ProxyRoutes::new(routes.clone()));
            assert_eq!(complete(&client, request).await.1, Version::HTTP_2);
        }
        assert_eq!(
            targets.lock().len(),
            before + 1,
            "origin connection must traverse the proxy and then be pooled"
        );
        assert_eq!(
            targets.lock().last().unwrap(),
            &format!("localhost:{}", origin.address.port())
        );
        assert_eq!(
            quic_alternative.request_count(),
            0,
            "the direct QUIC connector must never bypass the selected proxy"
        );
        drop(client);
        close_client_endpoint(endpoint).await;
    }
    assert_eq!(origin.request_count(), 10);
    quic_alternative.close().await;
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

#[tokio::test]
async fn fixed_custom_tls_connector_reuses_connections() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let (auth, tls) = credentials();
        let origin = Server::start(auth, version).await;
        // Native settings belong to this connector's fixed policy. Their presence
        // alone must not disable reuse of connections created by that connector.
        #[cfg(feature = "boring")]
        let tls = tls.with_grease(true);
        #[cfg(not(feature = "boring"))]
        let tls = tls.with_modify_rustls_config(Ok);
        let client = EasyHttpConnectorBuilder::new()
            .with_default_transport_connector()
            .with_default_dns_connector()
            .without_tls_proxy_support()
            .with_http_proxy_support()
            .with_custom_tls_connector(TlsConnectorLayer::auto().with_base_config(tls))
            .with_default_http_connector(Executor::new())
            .with_default_connection_pool()
            .build_client();

        for _ in 0..3 {
            assert_eq!(complete(&client, origin.request()).await.1, version);
        }
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(origin.request_count(), 3);
        drop(client);
        origin.close().await;
    }
}

fn explicit_tls_policy(auth: &ServerAuthData) -> TlsClientConfig {
    TlsClientConfig::new()
        .try_with_server_trust_anchors(auth.cert_chain.clone())
        .unwrap()
        .with_server_verify(ServerVerifyMode::Auto)
        .with_server_name(Host::LOCALHOST_NAME)
        .with_server_cert_pins(TlsServerCertPins::new(TlsServerCertPin::ExactDer(
            auth.cert_chain[0].clone(),
        )))
        .with_store_server_cert_chain(false)
}

#[derive(Debug, Clone, Copy)]
enum PolicyVariation {
    Original,
    Pins,
    Trust,
    Verification,
    CaptureChain,
}

#[tokio::test]
async fn equivalent_request_tls_policies_reuse_only_compatible_connections() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let (auth, tls) = credentials();
        let (other_auth, _) = credentials();
        let origin = Server::start(auth.clone(), version).await;
        let (client, endpoint) = client_with_http3(tls).await;
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);

        for (policy_index, variation) in [
            PolicyVariation::Original,
            PolicyVariation::Pins,
            PolicyVariation::Trust,
            PolicyVariation::Verification,
            PolicyVariation::CaptureChain,
        ]
        .into_iter()
        .enumerate()
        {
            for _ in 0..2 {
                // Rebuild every config and its certificate collections independently.
                let policy = explicit_tls_policy(&auth);
                let policy = match variation {
                    PolicyVariation::Original => policy,
                    PolicyVariation::Pins => policy.with_server_cert_pins(TlsServerCertPins::new(
                        TlsServerCertPin::spki_sha256_of(&auth.cert_chain[0]).unwrap(),
                    )),
                    PolicyVariation::Trust => policy
                        .try_with_server_trust_anchors(
                            auth.cert_chain
                                .iter()
                                .chain(other_auth.cert_chain.iter())
                                .cloned(),
                        )
                        .unwrap(),
                    PolicyVariation::Verification => {
                        policy.with_server_verify(ServerVerifyMode::Disable)
                    }
                    PolicyVariation::CaptureChain => policy.with_store_server_cert_chain(true),
                };
                let request = origin.request();
                request.extensions().extend(policy.as_extensions());
                assert_eq!(complete(&client, request).await.1, version);
                assert_eq!(origin.accepted.load(Ordering::SeqCst), policy_index + 2);
            }
        }
        // Both the original override pool and the connector baseline remain reusable.
        let request = origin.request();
        request
            .extensions()
            .extend(explicit_tls_policy(&auth).as_extensions());
        assert_eq!(complete(&client, request).await.1, version);
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 6);
        drop(client);
        close_client_endpoint(endpoint).await;
        origin.close().await;
    }
}

#[tokio::test]
async fn changed_request_tls_identity_cannot_borrow_an_authenticated_connection() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let (auth, tls) = credentials();
        let (untrusted, _) = credentials();
        let origin = Server::start(auth.clone(), version).await;
        let (client, endpoint) = client_with_http3(tls).await;
        let request = origin.request();
        request
            .extensions()
            .extend(explicit_tls_policy(&auth).as_extensions());
        assert_eq!(complete(&client, request).await.1, version);

        let invalid_policies = [
            explicit_tls_policy(&auth).with_server_cert_pins(TlsServerCertPins::new(
                TlsServerCertPin::SpkiSha256([1; 32]),
            )),
            explicit_tls_policy(&auth)
                .try_with_server_trust_anchors(untrusted.cert_chain)
                .unwrap(),
            explicit_tls_policy(&auth).with_server_name(Host::EXAMPLE_NAME),
        ];
        for (index, policy) in invalid_policies.into_iter().enumerate() {
            let request = origin.request();
            request.extensions().extend(policy.as_extensions());
            assert!(
                timeout(TEST_TIMEOUT, client.serve(request))
                    .await
                    .unwrap()
                    .is_err()
            );
            assert_eq!(
                origin.request_count(),
                index + 1,
                "failed authentication must not dispatch a body"
            );
            assert_eq!(origin.accepted.load(Ordering::SeqCst), index + 2);
            let request = origin.request();
            request
                .extensions()
                .extend(explicit_tls_policy(&auth).as_extensions());
            assert_eq!(complete(&client, request).await.1, version);
            assert_eq!(origin.accepted.load(Ordering::SeqCst), index + 2);
        }
        drop(client);
        close_client_endpoint(endpoint).await;
        origin.close().await;
    }
}

#[tokio::test]
async fn explicit_default_tls_overrides_remain_distinct_from_nondefault_baseline() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let (auth, _) = credentials();
        let origin = Server::start(auth, version).await;
        let tls = TlsClientConfig::default_http()
            .with_server_verify(ServerVerifyMode::Disable)
            .with_store_server_cert_chain(true);
        let (client, endpoint) = client_with_http3(tls).await;
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);

        // Explicit false replaces the fixed true; repeated false overrides reuse.
        for _ in 0..2 {
            let request = origin.request();
            request.extensions().extend(
                TlsClientConfig::new()
                    .with_store_server_cert_chain(false)
                    .as_extensions(),
            );
            assert_eq!(complete(&client, request).await.1, version);
            assert_eq!(origin.accepted.load(Ordering::SeqCst), 2);
        }
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
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 3);
        assert_eq!(origin.request_count(), 3);
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 3);
        drop(client);
        close_client_endpoint(endpoint).await;
        origin.close().await;
    }
}

#[tokio::test]
async fn http3_unknown_length_trailers_and_head_preserve_the_pooled_connection() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth, Version::HTTP_3).await;
    let (client, endpoint) = client_with_http3(tls).await;
    let mut trailers = HeaderMap::new();
    trailers.insert("x-complete", "yes".parse().unwrap());
    origin.reply(Reply {
        body: Some(Body::from_frame_stream(stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"streamed "))),
            Ok(Frame::data(Bytes::from_static(b"body"))),
            Ok(Frame::trailers(trailers)),
        ]))),
        ..Default::default()
    });
    let response = timeout(TEST_TIMEOUT, client.serve(origin.request()))
        .await
        .unwrap()
        .unwrap();
    assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
    let body = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(body.trailers().unwrap()["x-complete"], "yes");
    assert_eq!(body.to_bytes(), "streamed body");

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_LENGTH, "9".parse().unwrap());
    origin.reply(Reply {
        headers,
        body: Some(Body::empty()),
        ..Default::default()
    });
    let mut request = origin.request();
    *request.method_mut() = Method::HEAD;
    *request.body_mut() = Body::empty();
    let response = timeout(TEST_TIMEOUT, client.serve(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "9");
    assert!(
        timeout(TEST_TIMEOUT, response.into_body().collect())
            .await
            .unwrap()
            .unwrap()
            .to_bytes()
            .is_empty()
    );
    assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_3);
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);
    drop(client);
    close_client_endpoint(endpoint).await;
    origin.close().await;
}

#[tokio::test]
async fn opaque_request_tls_hooks_remain_unpooled() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let (auth, tls) = credentials();
        let origin = Server::start(auth.clone(), version).await;
        let (client, endpoint) = client_with_http3(tls).await;
        #[cfg(feature = "boring")]
        let policy = {
            let mut store = X509StoreBuilder::new().unwrap();
            for certificate in &auth.cert_chain {
                store
                    .add_cert(X509::from_der(certificate).unwrap())
                    .unwrap();
            }
            TlsClientConfig::new().with_server_verify_cert_store(Arc::new(store.build()))
        };
        #[cfg(not(feature = "boring"))]
        let policy = TlsClientConfig::new().with_modify_rustls_config(Ok);
        for expected_connections in 1..=2 {
            let request = origin.request();
            request.extensions().extend(policy.as_extensions());
            assert_eq!(complete(&client, request).await.1, version);
            assert_eq!(origin.accepted.load(Ordering::SeqCst), expected_connections);
        }
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(origin.accepted.load(Ordering::SeqCst), 3);
        drop(client);
        close_client_endpoint(endpoint).await;
        origin.close().await;
    }
}

#[tokio::test]
async fn custom_quic_transport_validates_negotiation_and_concurrency() {
    for (alpn, required, expected_error) in [
        (
            ApplicationProtocol::HTTP_2,
            Version::HTTP_3,
            Some("QUIC transport did not negotiate h3 ALPN"),
        ),
        (
            ApplicationProtocol::HTTP_3,
            Version::HTTP_2,
            Some("established transport conflicts with required HTTP version"),
        ),
        (ApplicationProtocol::HTTP_3, Version::HTTP_3, None),
    ] {
        let (auth, tls) = credentials();
        let server_tls = TlsServerConfig::new()
            .with_server_auth(auth)
            .with_alpn([alpn.clone()].into_iter().collect());
        let server = Endpoint::build(Executor::new())
            .with_server_config(
                ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap(),
            )
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let client = Endpoint::build(Executor::new())
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let client_config = ClientConfig::try_from_rama_tls(
            &tls.with_alpn([alpn].into_iter().collect()),
            TlsOptions::default(),
        )
        .unwrap();
        let connecting = client
            .connect_with(client_config, server.local_addr().unwrap(), "localhost")
            .unwrap();
        let (connection, peer) = timeout(TEST_TIMEOUT, async {
            tokio::join!(connecting, async { server.accept().await.unwrap().await })
        })
        .await
        .unwrap();
        let peer = peer.unwrap();
        let connection = connection.unwrap();
        // Connection metadata cannot replace the actual negotiated QUIC ALPN.
        connection
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        connection.extensions().insert(MaxConcurrency::new(100));
        let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(
            server.local_addr().unwrap().port(),
        ));
        input.extensions.insert(TargetHttpVersion(required));
        let transport = Http3Transport {
            connection,
            config: Http3Config {
                max_requests: 1,
                max_pushes: 0,
                ..Default::default()
            },
        };
        let result = timeout(
            TEST_TIMEOUT,
            http_connect::<_, _, Body>(transport, input, Executor::new()),
        )
        .await
        .unwrap();
        if let Some(expected_error) = expected_error {
            let Err(error) = result else {
                panic!("invalid QUIC transport must be rejected");
            };
            assert!(error.to_string().contains(expected_error), "{error}");
        } else {
            let established = result.unwrap();
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<MaxConcurrency>()
                    .unwrap()
                    .get(),
                1,
                "HTTP configuration must replace stale transport concurrency hints"
            );
        }

        drop(peer);
        client.close(0u32, b"done");
        server.close(0u32, b"done");
        timeout(TEST_TIMEOUT, async {
            tokio::join!(client.shutdown(), server.shutdown());
        })
        .await
        .unwrap();
    }
}
