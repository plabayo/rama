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
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

use tokio_test::block_on;

const ADDRESS: SocketAddress = SocketAddress::local_ipv4(62004);

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    // Make Tokio available for the duration of the process:
    let executor = tokio::runtime::Runtime::new().unwrap();
    let _guard = executor.enter();

    // Run registered benchmarks.
    divan::main();
}

#[divan::bench]
fn h1_client_server_small_payload(b: divan::Bencher) {
    setup_tracing();
    tokio::spawn(run_server());

    let client = (TraceLayer::new_for_http(), DecompressionLayer::new())
        .into_layer(EasyHttpWebClient::default());

    b.bench_local(|| block_on(get_small_payload(client.clone())));
}

fn setup_tracing() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
}

async fn run_server() {
    let http_service = (CompressionLayer::new(), TraceLayer::new_for_http())
        .into_layer(WebService::default().with_get("/small-payload", "Super small payload"));

    HttpServer::http1()
        .listen(ADDRESS, http_service)
        .await
        .unwrap();
}

async fn get_small_payload(client: impl Service<Request>) {
    let req = Request::builder()
        .uri(format!("http://{ADDRESS}/small-payload"))
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let _ = client.serve(req).await;
}
