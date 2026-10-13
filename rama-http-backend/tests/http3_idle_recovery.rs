//! A pooled HTTP/3 client replaces connections retired by the server's idle timer.

#![expect(
    clippy::expect_used,
    reason = "integration test failures identify the failed handshake or request"
)]

use rama_core::{
    Service,
    error::{BoxError, error_chain},
    extensions::{Extensions, ExtensionsRef as _},
    rt::Executor,
    service::service_fn,
};
use rama_http::{
    Body, Method, Request, Response, Version,
    body::util::BodyExt as _,
    layer::retry::{ManagedPolicy, Retry, RetryBody},
};
use rama_http_backend::{
    client::{Http3Transport, HttpConnectRequestAdapter, HttpConnector, HttpPooledConnectorConfig},
    server::HttpServer,
};
use rama_http_core::{
    h3::{Error as Http3Error, connection::Config},
    server::conn::IdleTimeout,
};
use rama_net::{
    address::SocketAddress,
    client::{
        ConnectRequest, ConnectionError, ConnectorService as _, EstablishedClientConnection,
        pool::{ConnectionReuse, ConnectionReusePolicy, ReuseKey},
    },
    conn::{ConnectionHealth, ConnectionHealthWatcher},
};
use rama_quic::{ClientConfig, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::MemoryDatagramSocket;
use std::{
    convert::Infallible,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);
const IDLE: Duration = Duration::from_secs(30);

// This fixture's connector always uses the same origin, identity and trust anchors.
#[derive(Debug)]
struct FixedTlsPolicy;

impl ConnectionReusePolicy for FixedTlsPolicy {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::of::<Self>())
    }

    fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
        self.connection_key()
    }
}

#[tokio::test(start_paused = true)]
async fn pooled_http3_reconnects_after_server_idle_timeout() {
    idle_recovery(false).await;
}

#[tokio::test(start_paused = true)]
async fn pooled_http3_reconnects_after_reserved_request_is_rejected() {
    idle_recovery(true).await;
}

async fn idle_recovery(reserve_before_timeout: bool) {
    let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())
        .expect("server identity");
    let alpn = || [b"h3".as_slice().into()].into_iter().collect();
    let server_tls = TlsServerConfig::new()
        .with_alpn(alpn())
        .with_server_auth(identity.clone());
    let client_tls = TlsClientConfig::new()
        .with_alpn(alpn())
        .try_with_server_trust_anchors([identity.cert_chain.last().expect("certificate").clone()])
        .expect("trust anchors");
    let transport = || {
        let mut transport = TransportConfig::default();
        transport.maybe_set_max_idle_timeout(None);
        Config::default()
            .configure_transport(&mut transport)
            .expect("HTTP/3 transport config");
        Arc::new(transport)
    };
    let mut server_config = ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())
        .expect("server TLS config");
    server_config.set_transport_config(transport());
    let mut client_config = ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default())
        .expect("client TLS config");
    client_config.set_transport_config(transport());
    let (server_socket, client_socket) = MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(443),
        SocketAddress::local_ipv4(444),
        NonZeroUsize::MIN,
    );
    let server_endpoint = Endpoint::build(Executor::new())
        .with_server_config(server_config)
        .with_datagram_socket(server_socket)
        .expect("server endpoint");
    let client_endpoint = Endpoint::build(Executor::new())
        .with_datagram_socket(client_socket)
        .expect("client endpoint");
    let address = server_endpoint.local_addr().expect("server address");
    let (finished_tx, mut finished_rx) = mpsc::unbounded_channel();
    let accepted = Arc::new(AtomicUsize::new(0));
    let application_requests = Arc::new(AtomicUsize::new(0));
    let server_task = tokio::spawn({
        let endpoint = server_endpoint.clone();
        let accepted = accepted.clone();
        let application_requests = application_requests.clone();
        async move {
            let mut connections = JoinSet::new();
            while let Some(incoming) = endpoint.accept().await {
                let connection = incoming.await.expect("accepted QUIC connection");
                let index = accepted.fetch_add(1, Ordering::SeqCst) + 1;
                let finished = finished_tx.clone();
                let application_requests = application_requests.clone();
                connections.spawn(async move {
                    let mut server = HttpServer::new_http3(Executor::new());
                    server.http3_mut().idle_timeout = Some(IdleTimeout {
                        first_request: Duration::from_mins(1),
                        idle: IDLE,
                    });
                    server
                        .serve(
                            connection,
                            service_fn(move |request: Request| {
                                application_requests.fetch_add(1, Ordering::SeqCst);
                                async move {
                                    if request.uri().path_or_root() == "/reserved" {
                                        let body = request
                                            .into_body()
                                            .collect()
                                            .await
                                            .expect("retried request body")
                                            .to_bytes();
                                        assert_eq!(body.as_ref(), b"replay once");
                                    }
                                    Ok::<_, Infallible>(Response::new(Body::from(
                                        index.to_string(),
                                    )))
                                }
                            }),
                        )
                        .await
                        .expect("server completed gracefully");
                    _ = finished.send(index);
                });
            }
            while let Some(result) = connections.join_next().await {
                result.expect("server connection task");
            }
        }
    });
    let dials = Arc::new(AtomicUsize::new(0));
    let connector = service_fn({
        let endpoint = client_endpoint.clone();
        let dials = dials.clone();
        move |input: ConnectRequest| {
            let endpoint = endpoint.clone();
            let client_config = client_config.clone();
            let dials = dials.clone();
            async move {
                dials.fetch_add(1, Ordering::SeqCst);
                let connection = endpoint
                    .connect_with(client_config, address, "localhost")
                    .expect("start QUIC connection")
                    .await
                    .expect("connect QUIC");
                connection
                    .extensions()
                    .insert(ConnectionReuse::new(FixedTlsPolicy));
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    conn: Http3Transport {
                        connection,
                        config: Arc::new(Config::default()),
                    },
                    input,
                })
            }
        }
    });
    let client = Arc::new(HttpConnectRequestAdapter::new(
        HttpPooledConnectorConfig {
            // Only the server's timeout may retire this fixture's idle connection.
            idle_timeout: None,
            ..Default::default()
        }
        .build_connector(HttpConnector::<_, Body>::new(connector, Executor::new())),
    ));
    let mut first_health = None;
    for (request_index, expected_connection) in [1, 1, 2, 2].into_iter().enumerate() {
        let request = Request::builder()
            .version(Version::HTTP_3)
            .uri("https://localhost/connection")
            .body(Body::empty())
            .expect("request");
        let EstablishedClientConnection { conn, input } = timeout(LIMIT, client.connect(request))
            .await
            .expect("pool checkout deadline")
            .expect("pool checkout");
        if first_health.is_none() {
            first_health = Some(
                conn.extensions()
                    .get_arc::<ConnectionHealthWatcher>()
                    .expect("connection health watcher"),
            );
        }
        let response = timeout(LIMIT, conn.serve(input))
            .await
            .expect("request deadline")
            .expect("request succeeds without caller retry");
        assert_eq!(response.version(), Version::HTTP_3);
        let body = timeout(LIMIT, response.into_body().collect())
            .await
            .expect("response body deadline")
            .expect("response body")
            .to_bytes();
        assert_eq!(body.as_ref(), expected_connection.to_string().as_bytes());
        assert_eq!(dials.load(Ordering::SeqCst), expected_connection);
        assert_eq!(accepted.load(Ordering::SeqCst), expected_connection);

        // Retire the first connection after proving one successful pool reuse.
        if request_index == 1 {
            let reserved = if reserve_before_timeout {
                let request = Request::builder()
                    .version(Version::HTTP_3)
                    .method(Method::POST)
                    .uri("https://localhost/reserved")
                    .body(Body::from("replay once"))
                    .expect("reserved request");
                Some(
                    timeout(LIMIT, client.connect(request))
                        .await
                        .expect("reserved pool checkout deadline")
                        .expect("reserved pool checkout"),
                )
            } else {
                None
            };
            let health = first_health.as_ref().expect("first connection health");
            assert_eq!(health.health(), ConnectionHealth::Healthy);
            let mut changes = health.watch();
            assert!(finished_rx.try_recv().is_err(), "server remains reusable");
            assert_eq!(
                timeout(IDLE + LIMIT, changes.changed())
                    .await
                    .expect("GOAWAY reaches the pool")
                    .expect("health update"),
                ConnectionHealth::Broken
            );
            assert_eq!(
                timeout(LIMIT, finished_rx.recv())
                    .await
                    .expect("server idle shutdown deadline"),
                Some(1)
            );
            if let Some(EstablishedClientConnection { conn, input }) = reserved {
                let rejected_attempts = Arc::new(AtomicUsize::new(0));
                let policy = ManagedPolicy::new({
                    let rejected_attempts = rejected_attempts.clone();
                    move |request: Request<RetryBody>, result: Result<Response, BoxError>| {
                        let rejected = result.as_ref().err().is_some_and(|error| {
                            error_chain(error.as_ref()).any(|error| {
                                error
                                    .downcast_ref::<Http3Error>()
                                    .is_some_and(|error| error.is_rejected())
                            })
                        });
                        if rejected {
                            assert_eq!(rejected_attempts.fetch_add(1, Ordering::SeqCst), 0);
                        }
                        async move { (request, result, rejected) }
                    }
                });
                let retry = Retry::new(
                    policy,
                    service_fn({
                        let client = client.clone();
                        let reserved = Arc::new(Mutex::new(Some(conn)));
                        move |request: Request<RetryBody>| {
                            let client = client.clone();
                            let reserved = reserved.clone();
                            async move {
                                let request = request.map(Body::new);
                                let conn = reserved.lock().await.take();
                                if let Some(conn) = conn {
                                    conn.serve(request).await
                                } else {
                                    let EstablishedClientConnection { conn, input } =
                                        client.connect(request).await?;
                                    conn.serve(input).await
                                }
                            }
                        }
                    }),
                );
                let response = timeout(LIMIT, retry.serve(input))
                    .await
                    .expect("retry deadline")
                    .expect("rejected request transparently retried");
                let body = timeout(LIMIT, response.into_body().collect())
                    .await
                    .expect("retried response body deadline")
                    .expect("retried response body")
                    .to_bytes();
                assert_eq!(body.as_ref(), b"2");
                assert_eq!(rejected_attempts.load(Ordering::SeqCst), 1);
                assert_eq!(application_requests.load(Ordering::SeqCst), 3);
                assert_eq!(dials.load(Ordering::SeqCst), 2);
            }
        }
    }
    assert_eq!(
        application_requests.load(Ordering::SeqCst),
        4 + usize::from(reserve_before_timeout)
    );
    drop(client);
    client_endpoint.close(0_u32, b"test complete");
    server_endpoint.close(0_u32, b"test complete");
    timeout(LIMIT, server_task)
        .await
        .expect("server shutdown deadline")
        .expect("server accept task");
}
