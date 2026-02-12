use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use rama::{
    Layer, Service,
    error::{BoxError, OpaqueError},
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
            set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
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
            server::{SelfSignedData, ServerAuth, ServerConfig},
        },
    },
    rt::Executor,
    service::BoxService,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::{boring, rustls},
};

use rand::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod e2e_utils;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    let _appender_guard = e2e_utils::setup_tracing("e2e_http_client_server");
    divan::main();
}

#[derive(Debug, Clone, Copy)]
enum Size {
    Small,
    Large,
}

#[derive(Debug, Clone, Copy)]
enum HttpVersion {
    Http1,
    Http2,
}

#[derive(Debug, Clone, Copy)]
enum Tls {
    None,
    Rustls,
    Boring,
}

#[derive(Debug, Clone, Copy)]
struct TestParameters {
    version: HttpVersion,
    tls: Tls,
    server: Size,
    client: Size,
}

fn random_bytes_by_size(rng: &mut ThreadRng, size: Size) -> Vec<u8> {
    match size {
        Size::Small => {
            let mut bytes = [0u8; 1_000];
            rng.fill_bytes(&mut bytes);
            bytes.to_vec()
        }
        Size::Large => {
            let mut bytes = [0u8; 500_000];
            rng.fill_bytes(&mut bytes);
            bytes.to_vec()
        }
    }
}

fn get_endpoint_for_size(size: Size) -> &'static str {
    match size {
        Size::Small => "small",
        Size::Large => "large",
    }
}

fn get_http_service_boxed<Input>(
    params: TestParameters,
    body_content: Vec<u8>,
) -> BoxService<Input, (), BoxError>
where
    Input: ExtensionsMut + AsyncRead + AsyncWrite + Send + 'static,
{
    let body_content: &[u8] = body_content.leak();
    let handler = async move |req: Request| {
        if let Err(err) = req.into_body().collect().await {
            tracing::error!("failed to read payload from client (request): {err}");
        }
        Ok::<_, Infallible>(body_content.into_response())
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
        .layer(WebService::default().with_post(get_endpoint_for_size(params.server), handler));

    match params.version {
        HttpVersion::Http1 => HttpServer::http1(Executor::default())
            .service(http_service)
            .boxed(),
        HttpVersion::Http2 => HttpServer::h2(Executor::default())
            .service(http_service)
            .boxed(),
    }
}

fn get_rustls_acceptor_data() -> rustls::server::TlsAcceptorData {
    rustls::server::TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData {
        organisation_name: Some("Example Server Acceptor".to_owned()),
        ..Default::default()
    })
    .unwrap()
    .with_alpn_protocols_http_auto()
    .build()
}

fn get_boring_acceptor_data() -> boring::server::TlsAcceptorData {
    let tls_server_config = ServerConfig {
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_11,
            ApplicationProtocol::HTTP_2,
        ]),
        ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()))
    };
    boring::server::TlsAcceptorData::try_from(tls_server_config).expect("create acceptor data")
}

fn spawn_http_server(params: TestParameters, body_content: Vec<u8>) -> SocketAddress {
    let listener = std::net::TcpListener::bind(SocketAddress::local_ipv4(0).into_std()).unwrap();
    let addr = listener.local_addr().unwrap();

    tracing::info!(
        "{:?} server running in multi-thread runtime at {addr}",
        params.version
    );

    let ready = Arc::new(AtomicBool::new(false));
    let ready_worker = ready.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let async_listener =
                TcpListener::try_from_std_tcp_listener(listener, Executor::default()).unwrap();

            ready_worker.store(true, Ordering::Release);

            match params.tls {
                Tls::None => {
                    let server = get_http_service_boxed(params, body_content);
                    async_listener.serve(server).await
                }
                Tls::Rustls => {
                    let service = get_http_service_boxed(params, body_content);
                    let tls_service =
                        rustls::server::TlsAcceptorLayer::new(get_rustls_acceptor_data())
                            .into_layer(service);
                    async_listener.serve(tls_service).await
                }
                Tls::Boring => {
                    let service = get_http_service_boxed(params, body_content);
                    let tls_service =
                        boring::server::TlsAcceptorLayer::new(get_boring_acceptor_data())
                            .into_layer(service);
                    async_listener.serve(tls_service).await
                }
            }
        });
    });

    while !ready.load(Ordering::Acquire) {
        std::thread::yield_now();
    }

    addr.into()
}

async fn request_payload(
    client: impl Service<Request, Output = Response, Error = BoxError>,
    params: TestParameters,
    body_content: Vec<u8>,
    address: SocketAddress,
) {
    let endpoint = get_endpoint_for_size(params.server);

    let http_protocol = match params.tls {
        Tls::None => "http",
        _ => "https",
    };

    let result = client
        .post(format!("{http_protocol}://{address}/{endpoint}"))
        .version(match params.version {
            HttpVersion::Http1 => Version::HTTP_11,
            HttpVersion::Http2 => Version::HTTP_2,
        })
        .body(body_content)
        .send()
        .await;

    match result {
        Ok(resp) => {
            if let Err(err) = resp.into_body().collect().await {
                tracing::error!("failed to recv response payload: {err}")
            }
        }
        Err(err) => tracing::error!("failed to recv response: {err}"),
    }
}

fn get_inner_client(tls: Tls) -> impl Service<Request, Output = Response, Error = OpaqueError> {
    match tls {
        Tls::None => EasyHttpWebClient::connector_builder()
            .with_default_transport_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .build_client(),
        Tls::Rustls => {
            let tls_config = rustls::client::TlsConnectorData::try_new_http_auto()
                .expect("connector data with http auto");

            EasyHttpWebClient::connector_builder()
                .with_default_transport_connector()
                .without_tls_proxy_support()
                .without_proxy_support()
                .with_tls_support_using_rustls(Some(tls_config))
                .with_default_http_connector(Executor::default())
                .build_client()
        }
        Tls::Boring => {
            let tls_config =
                boring::client::TlsConnectorDataBuilder::new_http_auto().into_shared_builder();

            EasyHttpWebClient::connector_builder()
                .with_default_transport_connector()
                .without_tls_proxy_support()
                .without_proxy_support()
                .with_tls_support_using_boringssl(Some(tls_config))
                .with_default_http_connector(Executor::default())
                .build_client()
        }
    }
}

const SAMPLE_COUNT: u32 = 1000;

#[divan::bench(sample_count = SAMPLE_COUNT, args = [
    // http1
    TestParameters { version: HttpVersion::Http1, tls: Tls::None, server: Size::Small, client: Size::Small },
    TestParameters { version: HttpVersion::Http1, tls: Tls::None, server: Size::Large, client: Size::Small },
    TestParameters { version: HttpVersion::Http1, tls: Tls::None, server: Size::Small, client: Size::Large },
    TestParameters { version: HttpVersion::Http1, tls: Tls::None, server: Size::Large, client: Size::Large },
    TestParameters { version: HttpVersion::Http1, tls: Tls::Rustls, server: Size::Small, client: Size::Small },
    TestParameters { version: HttpVersion::Http1, tls: Tls::Rustls, server: Size::Large, client: Size::Small },
    TestParameters { version: HttpVersion::Http1, tls: Tls::Rustls, server: Size::Small, client: Size::Large },
    TestParameters { version: HttpVersion::Http1, tls: Tls::Rustls, server: Size::Large, client: Size::Large },
    TestParameters { version: HttpVersion::Http1, tls: Tls::Boring, server: Size::Small, client: Size::Small },
    TestParameters { version: HttpVersion::Http1, tls: Tls::Boring, server: Size::Large, client: Size::Small },
    TestParameters { version: HttpVersion::Http1, tls: Tls::Boring, server: Size::Small, client: Size::Large },
    TestParameters { version: HttpVersion::Http1, tls: Tls::Boring, server: Size::Large, client: Size::Large },
    // http2 (h2)
    TestParameters { version: HttpVersion::Http2, tls: Tls::None, server: Size::Small, client: Size::Small },
    TestParameters { version: HttpVersion::Http2, tls: Tls::None, server: Size::Large, client: Size::Small },
    TestParameters { version: HttpVersion::Http2, tls: Tls::None, server: Size::Small, client: Size::Large },
    TestParameters { version: HttpVersion::Http2, tls: Tls::None, server: Size::Large, client: Size::Large },
    TestParameters { version: HttpVersion::Http2, tls: Tls::Rustls, server: Size::Small, client: Size::Small },
    TestParameters { version: HttpVersion::Http2, tls: Tls::Rustls, server: Size::Large, client: Size::Small },
    TestParameters { version: HttpVersion::Http2, tls: Tls::Rustls, server: Size::Small, client: Size::Large },
    TestParameters { version: HttpVersion::Http2, tls: Tls::Rustls, server: Size::Large, client: Size::Large },
    TestParameters { version: HttpVersion::Http2, tls: Tls::Boring, server: Size::Small, client: Size::Small },
    TestParameters { version: HttpVersion::Http2, tls: Tls::Boring, server: Size::Large, client: Size::Small },
    TestParameters { version: HttpVersion::Http2, tls: Tls::Boring, server: Size::Small, client: Size::Large },
    TestParameters { version: HttpVersion::Http2, tls: Tls::Boring, server: Size::Large, client: Size::Large },
])]
fn h1_client_server(bencher: divan::Bencher, params: TestParameters) {
    let mut rng = rand::rng();

    let server_random_bytes = random_bytes_by_size(&mut rng, params.server);
    let address = spawn_http_server(params, server_random_bytes);

    bencher
        .with_inputs(|| {
            let client_random_bytes = random_bytes_by_size(&mut rng, params.client);

            let client = (
                MapResponseBodyLayer::new_boxed_streaming_body(),
                TraceLayer::new_for_http(),
                DecompressionLayer::new(),
                AddRequiredRequestHeadersLayer::default(),
                SetRequestHeaderLayer::if_not_present(
                    HeaderName::from_static("req-header"),
                    HeaderValue::from_static("req-bar"),
                ),
            )
                .into_layer(get_inner_client(params.tls));

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            (client, rt, client_random_bytes)
        })
        .bench_local_values(|(client, rt, body_content)| {
            rt.block_on(request_payload(client, params, body_content, address))
        });
}
