//! ```sh
//! cargo bench --bench e2e_http_client_server --features http-full,rustls,aws-lc,boring,socks5,quic,unix
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use rama::{
    Layer, Service,
    bytes::Bytes,
    combinators::Either,
    error::{BoxError, extra::OpaqueError},
    extensions::{Extensions, ExtensionsRef},
    http::{
        HeaderName, HeaderValue, Request, Response, Version,
        body::util::BodyExt,
        client::{EasyHttpWebClient, Http3Connector},
        layer::{
            compression::CompressionLayer,
            cors::CorsLayer,
            decompression::DecompressionLayer,
            error_handling::ErrorHandlerLayer,
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::{AddRequiredRequestHeadersLayer, AddRequiredResponseHeadersLayer},
            set_header::SetResponseHeaderLayer,
            trace::TraceLayer,
            upgrade::{EagerHttpProxyConnector, UpgradeLayer, mitm::HttpUpgradeMitmRelayLayer},
        },
        matcher::{HttpMatcher, MethodMatcher},
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
        server::HttpServer,
        service::{
            client::HttpClientExt as _,
            web::{Router, WebService, response::IntoResponse as _},
        },
        ws::{
            Message,
            handshake::{
                client::HttpClientWebSocketExt as _,
                matcher::{HttpWebSocketRelayServiceRequestMatcher, WebSocketMatcher},
                server::WebSocketAcceptor,
            },
        },
    },
    io::Io,
    layer::{ArcLayer, ConsumeErrLayer, MapOutputLayer, TimeoutLayer},
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        client::ProxyRoute,
        http::server::HttpPeekRouter,
        proxy::IoForwardService,
        socket::SocketOptions,
        stream::layer::TcpStreamOptionsLayer,
        tls::ApplicationProtocol,
        user::credentials::{ProxyCredential, basic},
    },
    proxy::socks5::Socks5Acceptor,
    quic::{
        Endpoint, ServerConfig as QuicServerConfig, TransportConfig,
        tls::{BoringTlsProvider, TlsOptions},
    },
    rt::Executor,
    service::{BoxService, service_fn},
    tcp::{client::service::TcpConnector, server::TcpListener},
    telemetry::tracing::{self},
    tls::{
        boring,
        client::{ServerVerifyMode, TlsClientConfig},
        rustls,
        server::{
            GeneratedServerAuthConfig, PeekTlsClientHelloService, SelfSignedCaConfig,
            TlsServerConfig,
        },
    },
    utils::collections::smallvec::smallvec,
};

use rand::prelude::*;
pub mod e2e_utils;

mod bench_alloc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Size {
    Small,
    Large,
}

impl Size {
    fn rnd_bytes(self) -> Bytes {
        let mut rng = rand::rng();
        let len = match self {
            Self::Small => 5_000,
            Self::Large => 1_000_000,
        };
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        Bytes::from(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpVersion {
    Http1,
    Http2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tls {
    None,
    Rustls,
    Boring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proxy {
    None,
    Http,
    Socks5,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct TestParameters {
    version: HttpVersion,
    tls: Tls,
    proxy: Proxy,
    server: Size,
    client: Size,
}

const VERSIONS: [HttpVersion; 2] = [HttpVersion::Http1, HttpVersion::Http2];
const TLSES: [Tls; 3] = [Tls::None, Tls::Rustls, Tls::Boring];
const PROXIES: [Proxy; 3] = [Proxy::None, Proxy::Http, Proxy::Socks5];
const SIZES: [Size; 2] = [Size::Small, Size::Large];

const N: usize = VERSIONS.len() * TLSES.len() * PROXIES.len() * SIZES.len() * SIZES.len();

const fn build_test_matrix() -> [TestParameters; N] {
    let placeholder = TestParameters {
        version: VERSIONS[0],
        tls: TLSES[0],
        proxy: PROXIES[0],
        server: SIZES[0],
        client: SIZES[0],
    };

    let mut out = [placeholder; N];

    let mut i = 0usize;
    let mut vi = 0usize;
    while vi < VERSIONS.len() {
        let mut ti = 0usize;
        while ti < TLSES.len() {
            let mut pi = 0usize;
            while pi < PROXIES.len() {
                let mut si = 0usize;
                while si < SIZES.len() {
                    let mut ci = 0usize;
                    while ci < SIZES.len() {
                        out[i] = TestParameters {
                            version: VERSIONS[vi],
                            tls: TLSES[ti],
                            proxy: PROXIES[pi],
                            server: SIZES[si],
                            client: SIZES[ci],
                        };
                        i += 1;
                        ci += 1;
                    }
                    si += 1;
                }
                pi += 1;
            }
            ti += 1;
        }
        vi += 1;
    }

    out
}

const TEST_MATRIX: [TestParameters; N] = build_test_matrix();
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Per load bench row: how many connections the origins accepted, printed
/// after the run so it does not interleave with divan's table.
static LOAD_STATS: parking_lot::Mutex<Vec<String>> = parking_lot::Mutex::new(Vec::new());

fn main() {
    let _appender_guard = e2e_utils::setup_tracing("e2e_http_client_server");
    // The load rows hold about four sockets per simulated client.
    #[cfg(unix)]
    {
        _ = rama::unix::utils::raise_nofile(16_384);
    }
    divan::main();
    for line in LOAD_STATS.lock().iter() {
        eprintln!("{line}");
    }
}

fn get_http_service_boxed<Input>(
    params: TestParameters,
    body_content: Bytes,
) -> BoxService<Input, (), BoxError>
where
    Input: ExtensionsRef + Io,
{
    let handler = move |req: Request| {
        let body_content = body_content.clone();
        async move {
            _ = req.into_body().collect().await;
            Ok::<_, Infallible>(body_content.clone().into_response())
        }
    };

    let http_service = (
        TraceLayer::new_for_http(),
        CompressionLayer::new(),
        AddRequiredResponseHeadersLayer::default()
            .with_server_header_value(HeaderValue::from_static("foo")),
        SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("res-header"),
            HeaderValue::from_static("res-bar"),
        ),
        CorsLayer::permissive(),
    )
        .layer(WebService::default().with_post(
            match params.server {
                Size::Small => "small",
                Size::Large => "large",
            },
            handler,
        ));

    match params.version {
        HttpVersion::Http1 => HttpServer::new_http1(Executor::default())
            .service(http_service)
            .boxed(),
        HttpVersion::Http2 => HttpServer::new_h2(Executor::default())
            .service(http_service)
            .boxed(),
    }
}

fn get_config_tls_data(params: TestParameters) -> TlsServerConfig {
    let tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .expect("self signed");
    match params.version {
        HttpVersion::Http1 => tls.with_alpn_http_1(),
        HttpVersion::Http2 => tls.with_alpn_http_2(),
    }
}

fn get_http_proxy_service_boxed<Input>(params: TestParameters) -> BoxService<Input, (), BoxError>
where
    Input: ExtensionsRef + Io,
{
    let handler = move |req: Request| async move {
        let client = get_inner_client(params.version, params.tls);
        match client.serve(req).await {
            Ok(resp) => {
                tracing::info!(status_code = %resp.status(), "proxy received response");
                Ok(resp)
            }
            Err(err) => {
                tracing::error!("error in client request: {err:?}");
                Ok(rama::http::StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        }
    };

    let connect = EagerHttpProxyConnector::new(
        TimeoutLayer::new(Duration::from_secs(30)).into_layer(TcpConnector::new()),
        IoForwardService::new(Executor::default()),
    );
    let http_service = (
        TraceLayer::new_for_http(),
        CompressionLayer::new(),
        UpgradeLayer::new(Executor::default(), MethodMatcher::CONNECT, connect),
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
    )
        .layer(service_fn(handler));

    HttpServer::auto(Executor::default())
        .service(http_service)
        .boxed()
}

fn spawn_http_proxy(params: TestParameters) -> SocketAddress {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let async_listener =
                TcpListener::try_from_std_tcp_listener(listener, Executor::default()).unwrap();
            ready_tx.send(Ok(())).unwrap();

            match params.proxy {
                Proxy::Http => {
                    let service = get_http_proxy_service_boxed(params);
                    async_listener.serve(service).await
                }
                Proxy::Socks5 => {
                    let socks5_acceptor = Socks5Acceptor::new(Executor::default())
                        .with_authorizer(basic!("john", "secret").into_authorizer())
                        .with_default_connector();
                    async_listener.serve(socks5_acceptor).await
                }
                #[expect(clippy::unreachable, reason = "proxy listener only spawned for non-None Proxy variants — see the filter above")]
                Proxy::None => unreachable!("proxy listener only spawned for proxy rows"),
            }
        });
    });

    match ready_rx.recv_timeout(STARTUP_TIMEOUT) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("proxy failed to start: {err}"),
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("proxy startup timed out"),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("proxy thread exited before signaling readiness")
        }
    }
    addr.into()
}

fn spawn_http_server(params: TestParameters, body_content: Bytes) -> SocketAddress {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let async_listener =
                TcpListener::try_from_std_tcp_listener(listener, Executor::default()).unwrap();

            match params.tls {
                Tls::None => {
                    let service = get_http_service_boxed(params, body_content);

                    ready_tx.send(Ok(())).unwrap();

                    async_listener.serve(service).await
                }
                Tls::Rustls => {
                    let service = get_http_service_boxed(params, body_content);

                    let config = get_config_tls_data(params);

                    ready_tx.send(Ok(())).unwrap();

                    async_listener
                        .serve(rustls::server::TlsAcceptorLayer::new(config).into_layer(service))
                        .await
                }
                Tls::Boring => {
                    let service = get_http_service_boxed(params, body_content);

                    let config = get_config_tls_data(params);

                    ready_tx.send(Ok(())).unwrap();

                    async_listener
                        .serve(boring::server::TlsAcceptorLayer::new(config).into_layer(service))
                        .await
                }
            }
        });
    });

    match ready_rx.recv_timeout(STARTUP_TIMEOUT) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("server failed to start: {err}"),
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("server startup timed out"),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("server thread exited before signaling readiness")
        }
    }
    addr.into()
}

fn get_inner_client(
    http: HttpVersion,
    tls: Tls,
) -> impl Service<Request, Output = Response, Error = OpaqueError> {
    let b = EasyHttpWebClient::connector_builder().with_default_transport_connector();

    let proto = match http {
        HttpVersion::Http1 => ApplicationProtocol::HTTP_11,
        HttpVersion::Http2 => ApplicationProtocol::HTTP_2,
    };

    match tls {
        Tls::None => b
            .without_dns_connector()
            .without_tls_proxy_support()
            .with_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .without_connection_pool()
            .build_client(),
        Tls::Rustls => {
            let tls_config = TlsClientConfig::new()
                .with_keylog(rama::tls::KeyLogIntent::Environment)
                .with_alpn(smallvec![proto])
                .with_server_verify(ServerVerifyMode::Disable)
                .with_store_server_cert_chain(true);
            b.without_dns_connector()
                .without_tls_proxy_support()
                .with_proxy_support()
                .with_tls_support_using_rustls(tls_config)
                .with_default_http_connector(Executor::default())
                .without_connection_pool()
                .build_client()
        }
        Tls::Boring => {
            let tls_config = TlsClientConfig::new()
                .with_keylog(rama::tls::KeyLogIntent::Environment)
                .with_alpn(smallvec![proto])
                .with_server_verify(ServerVerifyMode::Disable)
                .with_store_server_cert_chain(true);
            b.without_dns_connector()
                .without_tls_proxy_support()
                .with_proxy_support()
                .with_tls_support_using_boringssl(tls_config)
                .with_default_http_connector(Executor::default())
                .without_connection_pool()
                .build_client()
        }
    }
}

#[divan::bench(args = TEST_MATRIX, sample_count = 200)]
fn bench_http_transport(bencher: divan::Bencher, params: TestParameters) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let server_bytes = params.server.rnd_bytes();
    let server_bytes_count = server_bytes.len();

    let client_bytes = params.client.rnd_bytes();
    let client_bytes_count = client_bytes.len();

    let scheme = if matches!(params.tls, Tls::None) {
        "http"
    } else {
        "https"
    };
    let endpoint = if matches!(params.server, Size::Small) {
        "small"
    } else {
        "large"
    };

    let address = spawn_http_server(params, server_bytes);
    let url = format!("{scheme}://{address}/{endpoint}");

    let mut address_proxy = SocketAddress::default_ipv4(0);
    if params.proxy != Proxy::None {
        address_proxy = spawn_http_proxy(params);
    }

    bencher
        .with_inputs(|| {
            let client = (
                MapResponseBodyLayer::new_boxed_streaming_body(),
                TraceLayer::new_for_http(),
                DecompressionLayer::new(),
                AddRequiredRequestHeadersLayer::default(),
            )
                .into_layer(get_inner_client(params.version, params.tls));
            (client, client_bytes.clone())
        })
        .input_counter(move |_| {
            divan::counter::BytesCount::new(client_bytes_count + server_bytes_count)
        })
        .bench_local_values(|(client, body)| {
            rt.block_on(async {
                let req = client
                    .post(&url)
                    .version(match params.version {
                        HttpVersion::Http1 => Version::HTTP_11,
                        HttpVersion::Http2 => Version::HTTP_2,
                    })
                    .body(body);

                let req_with_maybe_proxy = match params.proxy {
                    Proxy::None => req,
                    Proxy::Http => req.extension(ProxyRoute::Proxy(
                        ProxyAddress::try_from(format!("http://{}", address_proxy.clone()))
                            .unwrap(),
                    )),
                    Proxy::Socks5 => req.extension(ProxyRoute::Proxy(ProxyAddress {
                        protocol: Some(Protocol::SOCKS5),
                        address: address_proxy.into(),
                        credential: Some(ProxyCredential::Basic(basic!("john", "secret"))),
                    })),
                };

                let resp = tokio::time::timeout(REQUEST_TIMEOUT, req_with_maybe_proxy.send())
                    .await
                    .expect("request timed out")
                    .expect("Request failed");
                let body = tokio::time::timeout(REQUEST_TIMEOUT, resp.into_body().collect())
                    .await
                    .expect("response body collection timed out")
                    .expect("response body")
                    .to_bytes();
                assert_eq!(body.len(), server_bytes_count);
            });
        });
}

// Load: many concurrent keep-alive clients through a proxy built from stock
// parts, to many origins. Unlike `bench_http_transport` (a fresh client per
// request), the connections are pooled and reused on both legs, so this
// measures the steady state of a busy proxy: pool checkout and waiting,
// extensions lookups, relaying, long-lived WebSockets.

/// What the proxy between the clients and the origins does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadMode {
    /// Plain HTTP forward proxy (absolute-form requests), egress through a shared pool.
    Forward,
    /// CONNECT tunnel, TLS end to end.
    Tunnel,
    /// CONNECT, TLS and HTTP relayed by the stock MITM relays (one egress per
    /// tunnel), WebSockets by the stock upgrade relay.
    MitmRelay,
    /// TLS-terminating reverse proxy, egress (TLS) through a shared pool.
    Reverse,
    /// TLS-terminating reverse proxy, egress over HTTP/3 through a shared pool.
    ReverseH3,
}

/// What every client does per sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Workload {
    /// POST 5 KB, 5 KB back, [`LOAD_ROUNDS`] times.
    Small,
    /// POST 1 MB, 1 MB back, [`LOAD_ROUNDS`] times.
    Large,
    /// [`LOAD_ROUNDS`] 5 KB echoes over one long-lived WebSocket.
    WebSocket,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct LoadParameters {
    mode: LoadMode,
    /// Between the clients and the proxy, and (but for `ReverseH3`) beyond it.
    version: HttpVersion,
    workload: Workload,
    clients: usize,
    origins: usize,
}

const fn load(
    mode: LoadMode,
    version: HttpVersion,
    workload: Workload,
    clients: usize,
    origins: usize,
) -> LoadParameters {
    LoadParameters {
        mode,
        version,
        workload,
        clients,
        origins,
    }
}

use HttpVersion::{Http1 as H1, Http2 as H2};
use LoadMode::{Forward, MitmRelay, Reverse, ReverseH3, Tunnel};
use Workload::{Large, Small, WebSocket};

const LOAD_MATRIX: [LoadParameters; 32] = [
    load(Forward, H1, Small, 1, 1),
    load(Forward, H1, Small, 64, 1),
    load(Forward, H1, Small, 64, 16),
    load(Forward, H1, Small, 256, 16),
    load(Forward, H1, Large, 64, 1),
    load(Tunnel, H1, Small, 1, 1),
    load(Tunnel, H1, Small, 64, 16),
    load(Tunnel, H2, Small, 64, 16),
    load(Tunnel, H1, Large, 64, 16),
    load(Tunnel, H1, WebSocket, 64, 16),
    load(Tunnel, H2, WebSocket, 64, 16),
    load(MitmRelay, H1, Small, 1, 1),
    load(MitmRelay, H1, Small, 64, 16),
    load(MitmRelay, H2, Small, 64, 16),
    load(MitmRelay, H1, Large, 64, 16),
    load(MitmRelay, H1, WebSocket, 64, 16),
    load(MitmRelay, H2, WebSocket, 64, 16),
    load(Reverse, H1, Small, 1, 1),
    load(Reverse, H1, Small, 64, 1),
    load(Reverse, H1, Small, 64, 16),
    load(Reverse, H1, Small, 256, 16),
    load(Reverse, H1, Large, 64, 1),
    load(Reverse, H2, Small, 1, 1),
    load(Reverse, H2, Small, 64, 1),
    load(Reverse, H2, Small, 64, 16),
    load(Reverse, H2, Small, 256, 16),
    load(Reverse, H2, Large, 64, 16),
    load(ReverseH3, H2, Small, 1, 1),
    load(ReverseH3, H2, Small, 64, 1),
    load(ReverseH3, H2, Small, 64, 16),
    load(ReverseH3, H2, Small, 256, 16),
    load(ReverseH3, H2, Large, 64, 16),
];

/// Requests (or WebSocket echoes) every client does per sample.
const LOAD_ROUNDS: usize = 16;

/// Header naming the origin (by index) a reverse-proxied request goes to.
const ORIGIN_HEADER: &str = "x-bench-origin";

/// Sockets of the bench's own clients and of the proxy's egress: `TCP_NODELAY`,
/// and closed with a reset (linger 0) so connection churn cannot exhaust the
/// ephemeral ports through `TIME_WAIT`.
fn client_socket() -> Arc<SocketOptions> {
    Arc::new(SocketOptions {
        tcp_no_delay: Some(true),
        linger: Some(Duration::ZERO),
        ..Default::default()
    })
}

/// Accepted sockets: `TCP_NODELAY`.
fn server_socket() -> Arc<SocketOptions> {
    Arc::new(SocketOptions {
        tcp_no_delay: Some(true),
        ..Default::default()
    })
}

fn load_alpn(version: HttpVersion) -> ApplicationProtocol {
    match version {
        HttpVersion::Http1 => ApplicationProtocol::HTTP_11,
        HttpVersion::Http2 => ApplicationProtocol::HTTP_2,
    }
}

fn load_tls_client_config(alpn: ApplicationProtocol) -> TlsClientConfig {
    TlsClientConfig::new()
        .with_alpn(smallvec![alpn])
        .with_server_verify(ServerVerifyMode::Disable)
}

/// The stock client used on both legs: pooled, any certificate accepted.
fn load_client(
    version: HttpVersion,
    tls: bool,
) -> impl Service<Request, Output = Response, Error = OpaqueError> + Clone {
    let builder = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(TcpConnector::new().with_connector(client_socket()))
        .without_dns_connector()
        .without_tls_proxy_support()
        .with_proxy_support();
    if tls {
        Either::A(
            builder
                .with_tls_support_using_boringssl(load_tls_client_config(load_alpn(version)))
                .with_default_http_connector(Executor::default())
                .with_default_connection_pool()
                .build_client(),
        )
    } else {
        Either::B(
            builder
                .without_tls_support()
                .with_default_http_connector(Executor::default())
                .with_default_connection_pool()
                .build_client(),
        )
    }
}

/// The stock client with HTTP/3 support: pooled, any certificate accepted.
fn load_h3_client() -> impl Service<Request, Output = Response, Error = OpaqueError> + Clone {
    let h3 = Http3Connector::builder(Executor::default())
        .with_tls_config(load_tls_client_config(ApplicationProtocol::HTTP_3))
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .build_lazy()
        .unwrap();
    EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(TcpConnector::new().with_connector(client_socket()))
        .without_dns_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_boringssl(load_tls_client_config(ApplicationProtocol::HTTP_2))
        .with_default_http_connector(Executor::default())
        .with_http3_support(h3)
        .with_default_connection_pool()
        .build_client()
}

/// Run `serve` on its own 4 thread runtime, returning what it reports once ready.
fn spawn_load_runtime<T, F, Fut>(serve: F) -> T
where
    T: Send + 'static,
    F: FnOnce(mpsc::SyncSender<T>) -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let (ready_tx, ready_rx) = mpsc::sync_channel::<T>(1);
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(serve(ready_tx));
    });
    ready_rx
        .recv_timeout(STARTUP_TIMEOUT)
        .expect("server start")
}

fn spawn_load_server<F>(serve: F) -> SocketAddress
where
    F: FnOnce(TcpListener) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
{
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    spawn_load_runtime(move |ready| async move {
        let listener =
            TcpListener::try_from_std_tcp_listener(listener, Executor::default()).unwrap();
        ready.send(()).unwrap();
        serve(listener).await;
    });
    addr.into()
}

/// What the origins serve: a payload for POST `/payload` and a WebSocket echo
/// at `/echo`.
fn load_origin_service(
    body: Bytes,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    Arc::new(
        ErrorHandlerLayer::new().into_layer(
            Router::new()
                .with_post("/payload", move |req: Request| {
                    let body = body.clone();
                    async move {
                        _ = req.into_body().collect().await;
                        body.into_response()
                    }
                })
                .with_match_route(
                    "/echo",
                    HttpMatcher::custom(WebSocketMatcher::new()),
                    ConsumeErrLayer::trace_as_debug()
                        .into_layer(WebSocketAcceptor::new().into_echo_service()),
                ),
        ),
    )
}

/// An origin on TCP (TLS or not, h1 and h2 with WebSockets over both) that
/// counts the connections it accepts.
fn spawn_load_origin(tls: bool, body: Bytes, accepted: Arc<AtomicUsize>) -> SocketAddress {
    spawn_load_server(move |listener| {
        Box::pin(async move {
            let mut http = HttpServer::auto(Executor::default());
            http.h2_mut().set_enable_connect_protocol();
            let http = http.service(load_origin_service(body));
            let service: BoxService<rama::tcp::TcpStream, (), BoxError> = if tls {
                let config = TlsServerConfig::new()
                    .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
                    .expect("self signed")
                    .with_alpn_http_1()
                    .with_alpn_http_2();
                boring::server::TlsAcceptorLayer::new(config)
                    .into_layer(http)
                    .boxed()
            } else {
                http.boxed()
            };
            let service = Arc::new(service);
            listener
                .serve(
                    TcpStreamOptionsLayer::new(server_socket()).into_layer(service_fn(
                        move |stream| {
                            accepted.fetch_add(1, Ordering::Relaxed);
                            let service = service.clone();
                            async move { service.serve(stream).await }
                        },
                    )),
                )
                .await;
        })
    })
}

/// An HTTP/3 origin that counts the connections it accepts.
fn spawn_h3_origin(body: Bytes, accepted: Arc<AtomicUsize>) -> SocketAddress {
    spawn_load_runtime(move |ready| async move {
        let tls = TlsServerConfig::new()
            .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
            .expect("self signed")
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let server = HttpServer::new_http3(Executor::default());
        let mut transport = TransportConfig::default();
        server.http3().configure_transport(&mut transport).unwrap();
        let mut config = QuicServerConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
        config.set_transport_config(Arc::new(transport));
        let endpoint = Endpoint::build(Executor::default())
            .with_server_config(config)
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        ready
            .send(SocketAddress::from(endpoint.local_addr().unwrap()))
            .unwrap();
        let service = server.service(load_origin_service(body));
        while let Some(incoming) = endpoint.accept().await {
            accepted.fetch_add(1, Ordering::Relaxed);
            let service = service.clone();
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    _ = service.serve(connection).await;
                }
            });
        }
    })
}

fn spawn_load_proxy(params: LoadParameters, origins: Arc<Vec<SocketAddress>>) -> SocketAddress {
    spawn_load_server(move |listener| {
        Box::pin(async move {
            let options = TcpStreamOptionsLayer::new(server_socket());
            match params.mode {
                LoadMode::Forward | LoadMode::Tunnel => {
                    let egress = load_client(params.version, false);
                    let connect = EagerHttpProxyConnector::new(
                        TcpConnector::new().with_connector(client_socket()),
                        IoForwardService::new(Executor::default()),
                    );
                    let service = HttpServer::auto(Executor::default()).service(Arc::new(
                        (
                            UpgradeLayer::new(Executor::default(), MethodMatcher::CONNECT, connect),
                            ConsumeErrLayer::default(),
                            RemoveResponseHeaderLayer::hop_by_hop(),
                            RemoveRequestHeaderLayer::hop_by_hop(),
                        )
                            .into_layer(egress),
                    ));
                    listener.serve(options.into_layer(service)).await;
                }
                LoadMode::MitmRelay => {
                    let http_relay = HttpPeekRouter::new(
                        HttpMitmRelay::new(Executor::default()).with_http_middleware((
                            ConsumeErrLayer::trace_as_debug()
                                .with_response(DefaultErrorResponse::new()),
                            MapResponseBodyLayer::new_boxed_streaming_body(),
                            HttpUpgradeMitmRelayLayer::new(
                                Executor::default(),
                                HttpWebSocketRelayServiceRequestMatcher::default(),
                            ),
                            ArcLayer::new(),
                        )),
                    )
                    .with_fallback(
                        MapOutputLayer::new(drop)
                            .into_layer(IoForwardService::new(Executor::default())),
                    );
                    let tls_relay =
                        boring::proxy::TlsMitmRelay::try_new_with_cached_self_signed_issuer(
                            &SelfSignedCaConfig::default(),
                        )
                        .unwrap();
                    let relay = Arc::new(
                        ConsumeErrLayer::trace_as_debug().into_layer(
                            PeekTlsClientHelloService::new(
                                tls_relay.into_layer(http_relay.clone()),
                            )
                            .with_fallback(http_relay),
                        ),
                    );
                    let connect = EagerHttpProxyConnector::new(
                        TcpConnector::new().with_connector(client_socket()),
                        relay,
                    );
                    let service = HttpServer::auto(Executor::default()).service(Arc::new(
                        UpgradeLayer::new(Executor::default(), MethodMatcher::CONNECT, connect)
                            .into_layer(service_fn(async |_: Request| {
                                Ok::<_, Infallible>(
                                    rama::http::StatusCode::METHOD_NOT_ALLOWED.into_response(),
                                )
                            })),
                    ));
                    listener.serve(options.into_layer(service)).await;
                }
                LoadMode::Reverse | LoadMode::ReverseH3 => {
                    let egress = if params.mode == LoadMode::ReverseH3 {
                        Either::A(load_h3_client())
                    } else {
                        Either::B(load_client(params.version, true))
                    };
                    let egress_version = match (params.mode, params.version) {
                        (LoadMode::ReverseH3, _) => Version::HTTP_3,
                        (_, HttpVersion::Http1) => Version::HTTP_11,
                        (_, HttpVersion::Http2) => Version::HTTP_2,
                    };
                    let handler = service_fn(move |mut req: Request| {
                        let egress = egress.clone();
                        let origins = origins.clone();
                        async move {
                            let index: usize = req
                                .headers()
                                .get(ORIGIN_HEADER)
                                .and_then(|v| v.to_str().ok()?.parse().ok())
                                .unwrap_or(0);
                            let path = req.uri().request_target().into_owned();
                            *req.uri_mut() =
                                format!("https://{}{path}", origins[index]).parse().unwrap();
                            *req.version_mut() = egress_version;
                            match egress.serve(req).await {
                                Ok(resp) => Ok::<_, Infallible>(resp),
                                Err(err) => {
                                    tracing::error!("reverse proxy egress: {err:?}");
                                    Ok(rama::http::StatusCode::BAD_GATEWAY.into_response())
                                }
                            }
                        }
                    });
                    let service = HttpServer::auto(Executor::default()).service(Arc::new(
                        (
                            RemoveResponseHeaderLayer::hop_by_hop(),
                            RemoveRequestHeaderLayer::hop_by_hop(),
                        )
                            .into_layer(handler),
                    ));
                    let tls = TlsServerConfig::new()
                        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
                        .expect("self signed")
                        .with_alpn_http_1()
                        .with_alpn_http_2();
                    listener
                        .serve(options.into_layer(
                            boring::server::TlsAcceptorLayer::new(tls).into_layer(service),
                        ))
                        .await;
                }
            }
        })
    })
}

/// One simulated client: a pooled HTTP client (one connection) or a WebSocket.
enum LoadClient<C, W> {
    Http(C),
    WebSocket(tokio::sync::Mutex<W>),
}

#[divan::bench(args = LOAD_MATRIX, sample_count = 20)]
fn bench_http_proxy_load(bencher: divan::Bencher, params: LoadParameters) {
    let size = if params.workload == Workload::Large {
        Size::Large
    } else {
        Size::Small
    };
    let body = size.rnd_bytes();
    let accepted = Arc::new(AtomicUsize::new(0));
    let rounds_done = Arc::new(AtomicUsize::new(0));
    let origins: Arc<Vec<SocketAddress>> = Arc::new(
        (0..params.origins)
            .map(|_| match params.mode {
                LoadMode::ReverseH3 => spawn_h3_origin(body.clone(), accepted.clone()),
                LoadMode::Forward => spawn_load_origin(false, body.clone(), accepted.clone()),
                _ => spawn_load_origin(true, body.clone(), accepted.clone()),
            })
            .collect(),
    );
    let proxy = spawn_load_proxy(params, origins.clone());
    let proxy_route = ProxyRoute::Proxy(ProxyAddress::try_from(format!("http://{proxy}")).unwrap());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let client_tls = params.mode != LoadMode::Forward;
    let scheme = if client_tls { "https" } else { "http" };
    let target = |client_index: usize, path: &str| match params.mode {
        LoadMode::Reverse | LoadMode::ReverseH3 => format!("{scheme}://{proxy}{path}"),
        _ => format!("{scheme}://{}{path}", origins[client_index % origins.len()]),
    };
    let request_extensions = || {
        let extensions = Extensions::new();
        if !matches!(params.mode, LoadMode::Reverse | LoadMode::ReverseH3) {
            extensions.insert(proxy_route.clone());
        }
        extensions
    };
    // one keep-alive client (and so connection) per simulated client
    let clients: Arc<Vec<_>> = Arc::new(
        (0..params.clients)
            .map(|client_index| {
                let client = (
                    MapResponseBodyLayer::new_boxed_streaming_body(),
                    AddRequiredRequestHeadersLayer::default(),
                )
                    .into_layer(load_client(params.version, client_tls));
                if params.workload != Workload::WebSocket {
                    return LoadClient::Http(client);
                }
                let url = target(client_index, "/echo").replacen("http", "ws", 1);
                let socket = rt.block_on(async {
                    let builder = match params.version {
                        HttpVersion::Http1 => client.websocket(url),
                        HttpVersion::Http2 => client.websocket_h2(url),
                    };
                    builder
                        .handshake(request_extensions())
                        .await
                        .expect("websocket handshake")
                });
                LoadClient::WebSocket(tokio::sync::Mutex::new(socket))
            })
            .collect(),
    );
    let request_body = size.rnd_bytes();

    bencher
        .counter(divan::counter::ItemsCount::new(
            params.clients * LOAD_ROUNDS,
        ))
        .bench_local(|| {
            rt.block_on(async {
                let mut tasks = Vec::with_capacity(params.clients);
                for client_index in 0..params.clients {
                    let clients = clients.clone();
                    let body = request_body.clone();
                    let rounds_done = rounds_done.clone();
                    let url = target(client_index, "/payload");
                    let proxy_route = proxy_route.clone();
                    let origin = client_index % origins.len();
                    tasks.push(tokio::spawn(async move {
                        match &clients[client_index] {
                            LoadClient::Http(client) => {
                                for _ in 0..LOAD_ROUNDS {
                                    let req = client
                                        .post(&url)
                                        .version(match params.version {
                                            HttpVersion::Http1 => Version::HTTP_11,
                                            HttpVersion::Http2 => Version::HTTP_2,
                                        })
                                        .header(ORIGIN_HEADER, origin.to_string())
                                        .body(body.clone());
                                    let req = match params.mode {
                                        LoadMode::Reverse | LoadMode::ReverseH3 => req,
                                        _ => req.extension(proxy_route.clone()),
                                    };
                                    let resp = tokio::time::timeout(REQUEST_TIMEOUT, req.send())
                                        .await
                                        .expect("request timed out")
                                        .expect("request failed");
                                    assert!(resp.status().is_success(), "{}", resp.status());
                                    let received = tokio::time::timeout(
                                        REQUEST_TIMEOUT,
                                        resp.into_body().collect(),
                                    )
                                    .await
                                    .expect("response body collection timed out")
                                    .expect("response body")
                                    .to_bytes();
                                    assert_eq!(received.len(), body.len());
                                    rounds_done.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            LoadClient::WebSocket(socket) => {
                                let mut socket = socket.lock().await;
                                for _ in 0..LOAD_ROUNDS {
                                    socket
                                        .send_message(Message::binary(body.clone()))
                                        .await
                                        .expect("websocket send");
                                    let echo = tokio::time::timeout(
                                        REQUEST_TIMEOUT,
                                        socket.recv_message(),
                                    )
                                    .await
                                    .expect("websocket echo timed out")
                                    .expect("websocket echo");
                                    assert_eq!(echo.len(), body.len());
                                    rounds_done.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }));
                }
                for task in tasks {
                    task.await.unwrap();
                }
            });
        });
    // How often the origins saw a new connection: pool reuse (or the lack of it).
    LOAD_STATS.lock().push(format!(
        "{params:?}: origins accepted {} connections for {} rounds",
        accepted.load(Ordering::Relaxed),
        rounds_done.load(Ordering::Relaxed),
    ));
}
