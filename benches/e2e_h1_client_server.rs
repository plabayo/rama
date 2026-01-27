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

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use tokio_test::block_on;

pub mod e2e_utils;

const ADDRESS: SocketAddress = SocketAddress::local_ipv4(62004);

// uncomment to enable allocator profiler
// #[global_allocator]
// static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    // Spawn thread with explicit stack size
    let large_stack_thread = thread::Builder::new()
        .stack_size(1024 * 1024 * 30) // 30MB
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

#[derive(Debug, Clone, Copy)]
enum Size {
    Small,
    Large,
}

#[derive(Debug, Clone, Copy)]
struct Payload {
    server: Size,
    client: Size,
}

fn random_bytes_by_size(rng: &mut ChaCha12Rng, size: &Size) -> Vec<u8> {
    match size {
        Size::Small => {
            let mut bytes = [0u8; 10_000];
            rng.fill_bytes(&mut bytes);
            bytes.to_vec()
        },
        Size::Large => {
            let mut bytes = [0u8; 10_000_000];
            rng.fill_bytes(&mut bytes);
            bytes.to_vec()
        },
    }
}

fn get_endpoint_for_size(size: &Size) -> &'static str {
    match size {
        Size::Small => "small",
        Size::Large => "large",
    }
}

async fn run_server(size: Size, body_content: Vec<u8>) {
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
                .with_post(get_endpoint_for_size(&size), body_content),
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

// make sure SAMPLE_COUNT is divisible by SEEDS.len()
const SAMPLE_COUNT: u32 = 10_000;
const SEEDS: [u64; 5] = [42, 10191, 451, 73, 8128];

#[divan::bench(sample_count = SAMPLE_COUNT, args = [
    Payload { server: Size::Small, client: Size::Small },
    Payload { server: Size::Large, client: Size::Small },
    Payload { server: Size::Small, client: Size::Large },
    Payload { server: Size::Large, client: Size::Large },
])]
fn h1_client_server(bencher: divan::Bencher, payload: Payload) {
    let mut iter_num = 0;
    let mut seed_num = 0;
    
    let mut rng = ChaCha12Rng::seed_from_u64(SEEDS[seed_num]);
    let mut server_random_bytes = random_bytes_by_size(&mut rng, &payload.server);
    let mut client_random_bytes = random_bytes_by_size(&mut rng, &payload.client);

    let mut server_thread = tokio::spawn(run_server(payload.server.clone(), server_random_bytes.clone()));
    block_on(tokio::time::sleep(Duration::from_micros(10)));

    bencher
        .with_inputs(|| {
            if iter_num > 0 && iter_num % (SAMPLE_COUNT / SEEDS.len() as u32) == 0 {
                seed_num += 1;

                server_thread.abort();
                block_on(tokio::time::sleep(Duration::from_micros(10)));

                rng = ChaCha12Rng::seed_from_u64(SEEDS[seed_num]);
                server_random_bytes = random_bytes_by_size(&mut rng, &payload.server);
                client_random_bytes = random_bytes_by_size(&mut rng, &payload.client);

                server_thread = tokio::spawn(run_server(payload.server.clone(), server_random_bytes.clone()));
                block_on(tokio::time::sleep(Duration::from_micros(10)));
            }
            iter_num += 1;

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

            (client, client_random_bytes.clone())
        })
        .bench_local_values(|(client, body_content)| {
            block_on(request_payload(
                client,
                &payload,
                body_content,
            ))
        });

    server_thread.abort();
}
