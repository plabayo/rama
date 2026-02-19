//! ```sh
//! cargo bench --bench e2e_http_client_server --features http-full,rustls,boring,socks5
//! ```

use std::{
    convert::Infallible,
    slice,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use rama::{
    Layer, Service,
    bytes::Bytes,
    error::BoxError,
    extensions::ExtensionsMut,
    http::{
        Body, HeaderName, HeaderValue, Request, Response, StatusCode, Version,
        body::util::BodyExt,
        client::EasyHttpWebClient,
        io::upgrade::Upgraded,
        layer::{
            compression::CompressionLayer,
            cors::CorsLayer,
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::{AddRequiredRequestHeadersLayer, AddRequiredResponseHeadersLayer},
            set_header::SetResponseHeaderLayer,
            trace::TraceLayer,
            upgrade::UpgradeLayer,
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::{
            client::HttpClientExt as _,
            web::{WebService, response::IntoResponse as _},
        },
    },
    layer::ConsumeErrLayer,
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        http::RequestContext,
        proxy::ProxyTarget,
        tls::{
            ApplicationProtocol,
            client::ServerVerifyMode,
            server::{SelfSignedData, ServerAuth, ServerConfig},
        },
        user::credentials::{ProxyCredential, basic},
    },
    proxy::socks5::{Socks5Acceptor, server::LazyConnector},
    rt::Executor,
    service::{BoxService, service_fn},
    tcp::client::service::Forwarder,
    tcp::server::TcpListener,
    telemetry::tracing::{self},
    tls::{boring, rustls},
};

use rand::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod e2e_utils;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Size {
    Small,
    Large,
}

impl Size {
    fn rnd_bytes(self) -> Bytes {
        let mut rng = rand::rng();
        match self {
            Self::Small => {
                let mut bytes = [0u8; 5_000];
                rng.fill_bytes(&mut bytes);
                Bytes::from(bytes.to_vec())
            }
            Self::Large => {
                let mut bytes = [0u8; 1_000_000];
                rng.fill_bytes(&mut bytes);
                Bytes::from(bytes.to_vec())
            }
        }
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
    Http(bool),
    Socks5(bool),
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
const PROXIES: [Proxy; 5] = [
    Proxy::None,
    Proxy::Http(false),
    Proxy::Http(true),
    Proxy::Socks5(false),
    Proxy::Socks5(true),
];
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

fn main() {
    let _appender_guard = e2e_utils::setup_tracing("e2e_http_client_server");
    divan::main();
}

fn get_http_service_boxed<Input>(
    params: TestParameters,
    body_content: Bytes,
) -> BoxService<Input, (), BoxError>
where
    Input: ExtensionsMut + AsyncRead + AsyncWrite + Send + 'static,
{
    let handler = move |req: Request| {
        let body_content = body_content.clone();
        async move {
            let _ = req.into_body().collect().await;
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
        HttpVersion::Http1 => HttpServer::http1(Executor::default())
            .service(http_service)
            .boxed(),
        HttpVersion::Http2 => HttpServer::h2(Executor::default())
            .service(http_service)
            .boxed(),
    }
}

fn get_rustls_tls_data(params: TestParameters) -> rustls::server::TlsAcceptorData {
    let proto = match params.version {
        HttpVersion::Http1 => ApplicationProtocol::HTTP_11,
        HttpVersion::Http2 => ApplicationProtocol::HTTP_2,
    };

    rustls::server::TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData::default())
        .unwrap()
        .with_alpn_protocols(&[proto])
        .build()
}

fn get_boring_tls_data(params: TestParameters) -> boring::server::TlsAcceptorData {
    let proto = match params.version {
        HttpVersion::Http1 => ApplicationProtocol::HTTP_11,
        HttpVersion::Http2 => ApplicationProtocol::HTTP_2,
    };

    let config = ServerConfig {
        application_layer_protocol_negotiation: Some(vec![proto]),
        ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()))
    };
    boring::server::TlsAcceptorData::try_from(config).unwrap()
}

async fn http_connect_accept(mut req: Request) -> Result<(Response, Request), Response> {
    match RequestContext::try_from(&req).map(|ctx| ctx.host_with_port()) {
        Ok(authority) => {
            tracing::info!(
                server.address = %authority.host,
                server.port = authority.port,
                "accept CONNECT (lazy): insert proxy target into context",
            );
            req.extensions_mut().insert(ProxyTarget(authority));
        }
        Err(err) => {
            tracing::error!("error extracting authority: {err:?}");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), req))
}

fn get_http_proxy_service_boxed<Input>(params: TestParameters) -> BoxService<Input, (), BoxError>
where
    Input: ExtensionsMut + AsyncRead + AsyncWrite + Send + 'static,
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
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap())
            }
        }
    };

    let new_http_proxy = move || async move {
        (
            MapResponseBodyLayer::new_boxed_streaming_body(),
            TraceLayer::new_for_http(),
            ConsumeErrLayer::default(),
            RemoveResponseHeaderLayer::hop_by_hop(),
            RemoveRequestHeaderLayer::hop_by_hop(),
            CompressionLayer::new(),
            AddRequiredRequestHeadersLayer::new(),
        )
            .into_layer(service_fn(handler))
    };

    let connect_proxy = move |upgraded: Upgraded| async move {
        let http_service = new_http_proxy().await;
        let http_transport_service = HttpServer::auto(Executor::default()).service(http_service);

        match params.tls {
            Tls::Rustls => {
                let data = get_rustls_tls_data(params);
                let https_service =
                    rustls::server::TlsAcceptorLayer::new(data).into_layer(http_transport_service);
                https_service.serve(upgraded).await.expect("infallible");
            }
            Tls::Boring => {
                let data = get_boring_tls_data(params);
                let https_service =
                    boring::server::TlsAcceptorLayer::new(data).into_layer(http_transport_service);
                https_service.serve(upgraded).await.expect("infallible");
            }
            Tls::None => panic!("Cannot be called with TLS none"),
        };

        Ok::<(), Infallible>(())
    };

    let http_service = (
        TraceLayer::new_for_http(),
        CompressionLayer::new(),
        match params.proxy {
            Proxy::Http(true) | Proxy::Socks5(true) => UpgradeLayer::new(
                Executor::default(),
                MethodMatcher::CONNECT,
                service_fn(http_connect_accept),
                service_fn(connect_proxy),
            ),
            Proxy::Http(false) | Proxy::Socks5(false) => UpgradeLayer::new(
                Executor::default(),
                MethodMatcher::CONNECT,
                service_fn(http_connect_accept),
                ConsumeErrLayer::default().into_layer(Forwarder::ctx(Executor::default())),
            ),
            Proxy::None => panic!("Cannot be called for Tls::None"),
        },
    )
        .layer(service_fn(handler));

    HttpServer::auto(Executor::default())
        .service(http_service)
        .boxed()
}

fn spawn_http_server(params: TestParameters, body_content: Bytes, is_proxy: bool) -> SocketAddress {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let ready = Arc::new(AtomicBool::new(false));
    let ready_worker = ready.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let async_listener =
                TcpListener::try_from_std_tcp_listener(listener, Executor::default()).unwrap();

            let socks5_acceptor_base = Socks5Acceptor::new(Executor::default())
                .with_authorizer(basic!("john", "secret").into_authorizer());

            match params.tls {
                Tls::None => {
                    let service = if is_proxy {
                        get_http_proxy_service_boxed(params)
                    } else {
                        get_http_service_boxed(params, body_content)
                    };

                    ready_worker.store(true, Ordering::Release);

                    if let Proxy::Socks5(_) = params.proxy
                        && is_proxy
                    {
                        let socks5_acceptor =
                            socks5_acceptor_base.with_connector(LazyConnector::new(service));
                        async_listener.serve(socks5_acceptor).await
                    } else {
                        async_listener.serve(service).await
                    }
                }
                Tls::Rustls => {
                    let service = if is_proxy {
                        get_http_proxy_service_boxed(params)
                    } else {
                        get_http_service_boxed(params, body_content)
                    };

                    let data = get_rustls_tls_data(params);
                    ready_worker.store(true, Ordering::Release);
                    let tls_acceptor =
                        rustls::server::TlsAcceptorLayer::new(data).into_layer(service);

                    if let Proxy::Socks5(_) = params.proxy
                        && is_proxy
                    {
                        let socks5_acceptor =
                            socks5_acceptor_base.with_connector(LazyConnector::new(tls_acceptor));
                        async_listener.serve(socks5_acceptor).await
                    } else {
                        async_listener.serve(tls_acceptor).await
                    }
                }
                Tls::Boring => {
                    let service = if is_proxy {
                        get_http_proxy_service_boxed(params)
                    } else {
                        get_http_service_boxed(params, body_content)
                    };

                    let data = get_boring_tls_data(params);
                    ready_worker.store(true, Ordering::Release);
                    let tls_acceptor =
                        boring::server::TlsAcceptorLayer::new(data).into_layer(service);

                    if let Proxy::Socks5(_) = params.proxy
                        && is_proxy
                    {
                        let socks5_acceptor =
                            socks5_acceptor_base.with_connector(LazyConnector::new(tls_acceptor));
                        async_listener.serve(socks5_acceptor).await
                    } else {
                        async_listener.serve(tls_acceptor).await
                    }
                }
            }
        });
    });

    while !ready.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    addr.into()
}

fn get_inner_client(
    http: HttpVersion,
    tls: Tls,
) -> impl Service<Request, Output = Response, Error = BoxError> {
    let b = EasyHttpWebClient::connector_builder().with_default_transport_connector();

    let proto = match http {
        HttpVersion::Http1 => ApplicationProtocol::HTTP_11,
        HttpVersion::Http2 => ApplicationProtocol::HTTP_2,
    };

    match tls {
        Tls::None => b
            .without_tls_proxy_support()
            .with_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .build_client(),
        Tls::Rustls => {
            let tls_config = rustls::client::TlsConnectorDataBuilder::new()
                .try_with_env_key_logger()
                .unwrap()
                .with_alpn_protocols(slice::from_ref(&proto))
                .with_no_cert_verifier()
                .with_store_server_certificate_chain(true)
                .build();
            let proxy_tls_config = rustls::client::TlsConnectorDataBuilder::new()
                .try_with_env_key_logger()
                .unwrap()
                .with_alpn_protocols(&[proto])
                .with_no_cert_verifier()
                .build();
            b.with_tls_proxy_support_using_rustls_config(proxy_tls_config)
                .with_proxy_support()
                .with_tls_support_using_rustls(Some(tls_config))
                .with_default_http_connector(Executor::default())
                .build_client()
        }
        Tls::Boring => {
            let tls_config = boring::client::TlsConnectorDataBuilder::new()
                .try_with_rama_alpn_protos(slice::from_ref(&proto))
                .unwrap()
                .with_server_verify_mode(ServerVerifyMode::Disable)
                .with_store_server_certificate_chain(true)
                .into_shared_builder();
            let proxy_tls_config = boring::client::TlsConnectorDataBuilder::new()
                .try_with_rama_alpn_protos(&[proto])
                .unwrap()
                .with_server_verify_mode(ServerVerifyMode::Disable)
                .into_shared_builder();
            b.with_tls_proxy_support_using_boringssl_config(proxy_tls_config)
                .with_proxy_support()
                .with_tls_support_using_boringssl(Some(tls_config))
                .with_default_http_connector(Executor::default())
                .build_client()
        }
    }
}

#[divan::bench(args = TEST_MATRIX, sample_count = 50)]
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

    let address = spawn_http_server(params, server_bytes.clone(), false);
    let url = format!("{scheme}://{address}/{endpoint}");

    let mut address_proxy = SocketAddress::default_ipv4(0);
    if params.proxy != Proxy::None {
        address_proxy = spawn_http_server(params, server_bytes, true);
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
                    Proxy::Http(_) => req.extension(
                        ProxyAddress::try_from(format!("{scheme}://{}", address_proxy.clone()))
                            .unwrap(),
                    ),
                    Proxy::Socks5(_) => req.extension(ProxyAddress {
                        protocol: Some(Protocol::SOCKS5),
                        address: address_proxy.into(),
                        credential: Some(ProxyCredential::Basic(basic!("john", "secret"))),
                    }),
                };

                let resp = req_with_maybe_proxy.send().await.expect("Request failed");
                let _ = resp.into_body().collect().await;
            });
        });
}
