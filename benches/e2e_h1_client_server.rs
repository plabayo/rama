use std::{thread, time::Duration};

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
    rt::Executor,
};

use rama_http::{
    HeaderName, HeaderValue,
    layer::{
        cors::CorsLayer,
        required_header::{AddRequiredRequestHeadersLayer, AddRequiredResponseHeadersLayer},
        set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
    },
};

use rand::RngCore;
use tokio_test::block_on;

pub mod e2e_utils;

const ADDRESS: SocketAddress = SocketAddress::local_ipv4(62004);

// uncomment to enable allocator profiler
// #[global_allocator]
// static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    // Spawn thread with explicit stack size
    let large_stack_thread = thread::Builder::new()
        .stack_size(1024 * 1024 * 25) // 25MB
        .spawn(|| {
            // Make Tokio available for the duration of the process:
            let executor = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(1024 * 1024 * 15) // 15MB
                .build()
                .unwrap();
            let _guard = executor.enter();

            // non_blocking trace appender guard needs to live for the
            // duration of the process
            let _appender_guard = e2e_utils::setup_tracing("e2e_h1_client_server");

            // Run registered benchmarks.
            divan::main();
        })
        .unwrap();

    // Wait for thread to join
    large_stack_thread.join().unwrap();
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

#[derive(Debug, Clone)]
struct RandomBytes {
    empty: [u8; 0],
    small: [u8; 1000],
    medium: [u8; 100_000],
    large: [u8; 10_000_000],
}

fn get_endpoint_for_size(size: &Size) -> &'static str {
    match size {
        Size::Empty => "empty",
        Size::Small => "small",
        Size::Medium => "medium",
        Size::Large => "large",
    }
}

async fn run_server(random_bytes: RandomBytes) {
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
        .layer(
            WebService::default()
                .with_post(get_endpoint_for_size(&Size::Empty), random_bytes.empty)
                .with_post(get_endpoint_for_size(&Size::Small), random_bytes.small)
                .with_post(get_endpoint_for_size(&Size::Medium), random_bytes.medium)
                .with_post(get_endpoint_for_size(&Size::Large), random_bytes.large),
        );

    HttpServer::http1(Executor::default())
        .listen(ADDRESS, http_service)
        .await
        .unwrap();
}

async fn request_payload(client: impl Service<Request>, payload: &Payload, body_content: Vec<u8>) {
    let endpoint = get_endpoint_for_size(&payload.server);

    let req = Request::builder()
        .uri(format!("http://{ADDRESS}/{endpoint}"))
        .method("POST")
        .body(Body::from(body_content))
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
    let mut server_random_bytes = RandomBytes {
        empty: [0u8; 0],
        small: [0u8; 1000],
        medium: [0u8; 100_000],
        large: [0u8; 10_000_000],
    };
    let mut client_random_bytes = server_random_bytes.clone();

    let mut rng = rand::rng();
    rng.fill_bytes(&mut server_random_bytes.small);
    rng.fill_bytes(&mut server_random_bytes.medium);
    rng.fill_bytes(&mut server_random_bytes.large);
    rng.fill_bytes(&mut client_random_bytes.small);
    rng.fill_bytes(&mut client_random_bytes.medium);
    rng.fill_bytes(&mut client_random_bytes.large);

    let server_thread = tokio::spawn(run_server(server_random_bytes));

    // wait for server to come online
    block_on(tokio::time::sleep(Duration::from_secs(1)));

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

    let body_content = match payload.client {
        Size::Empty => client_random_bytes.empty.to_vec(),
        Size::Small => client_random_bytes.small.to_vec(),
        Size::Medium => client_random_bytes.medium.to_vec(),
        Size::Large => client_random_bytes.large.to_vec(),
    };
    b.bench_local(|| {
        block_on(request_payload(
            client.clone(),
            payload,
            body_content.clone(),
        ))
    });

    server_thread.abort();
}
