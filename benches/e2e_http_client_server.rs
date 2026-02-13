//! ```sh
//! cargo bench --bench e2e_http_client_server --features http-full,rustls,boring
//! ```

use std::{
    convert::Infallible,
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
        HeaderName, HeaderValue, Request, Response, Version,
        body::util::BodyExt,
        client::EasyHttpWebClient,
        layer::{
            compression::CompressionLayer,
            cors::CorsLayer,
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            required_header::{AddRequiredRequestHeadersLayer, AddRequiredResponseHeadersLayer},
            set_header::SetResponseHeaderLayer,
            trace::TraceLayer,
        },
        server::HttpServer,
        service::{
            client::HttpClientExt as _,
            web::{WebService, response::IntoResponse as _},
        },
    },
    net::{
        address::SocketAddress,
        tls::{
            ApplicationProtocol,
            client::ServerVerifyMode,
            server::{SelfSignedData, ServerAuth, ServerConfig},
        },
    },
    rt::Executor,
    service::BoxService,
    tcp::server::TcpListener,
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct TestParameters {
    version: HttpVersion,
    tls: Tls,
    server: Size,
    client: Size,
}

const VERSIONS: [HttpVersion; 2] = [HttpVersion::Http1, HttpVersion::Http2];
const TLSES: [Tls; 3] = [Tls::None, Tls::Rustls, Tls::Boring];
const SIZES: [Size; 2] = [Size::Small, Size::Large];

const N: usize = VERSIONS.len() * TLSES.len() * SIZES.len() * SIZES.len();

const fn build_test_matrix() -> [TestParameters; N] {
    let placeholder = TestParameters {
        version: VERSIONS[0],
        tls: TLSES[0],
        server: SIZES[0],
        client: SIZES[0],
    };

    let mut out = [placeholder; N];

    let mut i = 0usize;
    let mut vi = 0usize;
    while vi < VERSIONS.len() {
        let mut ti = 0usize;
        while ti < TLSES.len() {
            let mut si = 0usize;
            while si < SIZES.len() {
                let mut ci = 0usize;
                while ci < SIZES.len() {
                    out[i] = TestParameters {
                        version: VERSIONS[vi],
                        tls: TLSES[ti],
                        server: SIZES[si],
                        client: SIZES[ci],
                    };
                    i += 1;
                    ci += 1;
                }
                si += 1;
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

fn spawn_http_server(params: TestParameters, body_content: Bytes) -> SocketAddress {
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

            let proto = match params.version {
                HttpVersion::Http1 => ApplicationProtocol::HTTP_11,
                HttpVersion::Http2 => ApplicationProtocol::HTTP_2,
            };

            match params.tls {
                Tls::None => {
                    let service = get_http_service_boxed(params, body_content);

                    ready_worker.store(true, Ordering::Release);

                    async_listener.serve(service).await
                }
                Tls::Rustls => {
                    let service = get_http_service_boxed(params, body_content);

                    let data = rustls::server::TlsAcceptorDataBuilder::try_new_self_signed(
                        SelfSignedData::default(),
                    )
                    .unwrap()
                    .with_alpn_protocols(&[proto])
                    .build();

                    ready_worker.store(true, Ordering::Release);

                    async_listener
                        .serve(rustls::server::TlsAcceptorLayer::new(data).into_layer(service))
                        .await
                }
                Tls::Boring => {
                    let service = get_http_service_boxed(params, body_content);

                    let config = ServerConfig {
                        application_layer_protocol_negotiation: Some(vec![proto]),
                        ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()))
                    };
                    let data = boring::server::TlsAcceptorData::try_from(config).unwrap();

                    ready_worker.store(true, Ordering::Release);

                    async_listener
                        .serve(boring::server::TlsAcceptorLayer::new(data).into_layer(service))
                        .await
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
    let b = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support();

    let proto = match http {
        HttpVersion::Http1 => ApplicationProtocol::HTTP_11,
        HttpVersion::Http2 => ApplicationProtocol::HTTP_2,
    };

    match tls {
        Tls::None => b
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .build_client(),
        Tls::Rustls => b
            .with_tls_support_using_rustls(Some(
                rustls::client::TlsConnectorDataBuilder::new()
                    .try_with_env_key_logger()
                    .unwrap()
                    .with_alpn_protocols(&[proto])
                    .with_no_cert_verifier()
                    .build(),
            ))
            .with_default_http_connector(Executor::default())
            .build_client(),
        Tls::Boring => b
            .with_tls_support_using_boringssl(Some(
                boring::client::TlsConnectorDataBuilder::new()
                    .try_with_rama_alpn_protos(&[proto])
                    .unwrap()
                    .with_server_verify_mode(ServerVerifyMode::Disable)
                    .into_shared_builder(),
            ))
            .with_default_http_connector(Executor::default())
            .build_client(),
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

    let address = spawn_http_server(params, server_bytes);
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
    let url = format!("{scheme}://{address}/{endpoint}");

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
                let resp = client
                    .post(&url)
                    .version(match params.version {
                        HttpVersion::Http1 => Version::HTTP_11,
                        HttpVersion::Http2 => Version::HTTP_2,
                    })
                    .body(body)
                    .send()
                    .await
                    .expect("Request failed");
                let _ = resp.into_body().collect().await;
            });
        });
}
