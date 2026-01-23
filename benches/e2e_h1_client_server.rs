use rama::{
    Layer, Service,
    http::{
        Body, Request,
        client::EasyHttpWebClient,
        layer::{
            compression::CompressionLayer, decompression::DecompressionLayer, trace::TraceLayer,
        },
        server::HttpServer,
        service::web::WebService,
    },
    net::address::SocketAddress,
};

use rama_http::{
    HeaderName, HeaderValue,
    layer::{
        catch_panic::CatchPanicLayer,
        cors::CorsLayer,
        required_header::{AddRequiredRequestHeadersLayer, AddRequiredResponseHeadersLayer},
        set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
    },
};

use tokio_test::block_on;

pub mod e2e_utils;

const ADDRESS: SocketAddress = SocketAddress::local_ipv4(62004);

// uncomment to enable allocator profiler
// #[global_allocator]
// static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    // Make Tokio available for the duration of the process:
    let executor = tokio::runtime::Runtime::new().unwrap();
    let _guard = executor.enter();

    e2e_utils::setup_tracing("e2e_h1_client_server");
    tokio::spawn(run_server());

    // Run registered benchmarks.
    divan::main();
}

#[derive(Debug)]
enum Size {
    Empty,
    Small,
    Medium,
    Large,
}

#[derive(Debug)]
struct Payload {
    server: Size,
    client: Size,
}

fn get_body_for_size(size: &Size) -> &'static [u8] {
    match size {
        Size::Empty => &[b'x'; 0],
        Size::Small => &[b'x'; 1000],
        Size::Medium => &[b'x'; 100_000],
        Size::Large => &[b'x'; 10_000_000],
    }
}

fn get_endpoint_for_size(size: &Size) -> &'static str {
    match size {
        Size::Empty => "empty",
        Size::Small => "small",
        Size::Medium => "medium",
        Size::Large => "large",
    }
}

async fn run_server() {
    let http_service = (
        TraceLayer::new_for_http(),
        CompressionLayer::new(),
        CatchPanicLayer::new(),
        AddRequiredResponseHeadersLayer::default()
            .with_server_header_value(HeaderValue::from_static("foo")),
        SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("res-header"),
            HeaderValue::from_static("res-bar"),
        ),
        CorsLayer::permissive(),
    )
        .into_layer(
            WebService::default()
                .with_post(
                    get_endpoint_for_size(&Size::Empty),
                    get_body_for_size(&Size::Empty),
                )
                .with_post(
                    get_endpoint_for_size(&Size::Small),
                    get_body_for_size(&Size::Small),
                )
                .with_post(
                    get_endpoint_for_size(&Size::Medium),
                    get_body_for_size(&Size::Medium),
                )
                .with_post(
                    get_endpoint_for_size(&Size::Large),
                    get_body_for_size(&Size::Large),
                ),
        );

    HttpServer::http1()
        .listen(ADDRESS, http_service)
        .await
        .unwrap();
}

async fn request_payload(client: impl Service<Request>, payload: &Payload) {
    let endpoint = get_endpoint_for_size(&payload.server);

    let req = Request::builder()
        .uri(format!("http://{ADDRESS}/{endpoint}"))
        .method("POST")
        .body(Body::from(get_body_for_size(&payload.client)))
        .unwrap();

    let _ = client.serve(req).await;
}

#[divan::bench(args = [
    Payload { server: Size::Empty, client: Size::Empty },
    Payload { server: Size::Small, client: Size::Empty },
    Payload { server: Size::Medium, client: Size::Empty },
    Payload { server: Size::Large, client: Size::Empty },

    Payload { server: Size::Empty, client: Size::Small },
    Payload { server: Size::Small, client: Size::Small },
    Payload { server: Size::Medium, client: Size::Small },
    Payload { server: Size::Large, client: Size::Small },

    Payload { server: Size::Empty, client: Size::Medium },
    Payload { server: Size::Small, client: Size::Medium },
    Payload { server: Size::Medium, client: Size::Medium },
    Payload { server: Size::Large, client: Size::Medium },

    Payload { server: Size::Empty, client: Size::Large },
    Payload { server: Size::Small, client: Size::Large },
    Payload { server: Size::Medium, client: Size::Large },
    Payload { server: Size::Large, client: Size::Large },
])]
fn h1_client_server(b: divan::Bencher, payload: &Payload) {
    let client = (
        TraceLayer::new_for_http(),
        DecompressionLayer::new(),
        AddRequiredRequestHeadersLayer::default()
            .with_user_agent_header_value(HeaderValue::from_static("chrome")),
        SetRequestHeaderLayer::if_not_present(
            HeaderName::from_static("req-header"),
            HeaderValue::from_static("req-bar"),
        ),
    )
        .into_layer(EasyHttpWebClient::default());

    b.bench_local(|| block_on(request_payload(client.clone(), payload)));
}
