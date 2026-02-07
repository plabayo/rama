use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use rama::{
    Layer, Service,
    error::BoxError,
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
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
};

use rand::prelude::*;

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
struct TestParameters {
    version: HttpVersion,
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

fn spawn_http_server(params: TestParameters, body_content: Vec<u8>) -> SocketAddress {
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

            match params.version {
                HttpVersion::Http1 => {
                    async_listener
                        .serve(HttpServer::http1(Executor::default()).service(http_service))
                        .await
                }
                HttpVersion::Http2 => {
                    async_listener
                        .serve(HttpServer::h2(Executor::default()).service(http_service))
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

async fn request_payload(
    client: impl Service<Request, Output = Response, Error = BoxError>,
    params: TestParameters,
    body_content: Vec<u8>,
    address: SocketAddress,
) {
    let endpoint = get_endpoint_for_size(params.server);

    let result = client
        .post(format!("http://{address}/{endpoint}"))
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

const SAMPLE_COUNT: u32 = 1000;

#[divan::bench(sample_count = SAMPLE_COUNT, args = [
    // http1
    TestParameters { version: HttpVersion::Http1, server: Size::Small, client: Size::Small },
    TestParameters { version: HttpVersion::Http1, server: Size::Large, client: Size::Small },
    TestParameters { version: HttpVersion::Http1, server: Size::Small, client: Size::Large },
    TestParameters { version: HttpVersion::Http1, server: Size::Large, client: Size::Large },
    // http2 (h2)
    TestParameters { version: HttpVersion::Http2, server: Size::Small, client: Size::Small },
    TestParameters { version: HttpVersion::Http2, server: Size::Large, client: Size::Small },
    TestParameters { version: HttpVersion::Http2, server: Size::Small, client: Size::Large },
    TestParameters { version: HttpVersion::Http2, server: Size::Large, client: Size::Large },
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
                .into_layer(EasyHttpWebClient::default());

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
