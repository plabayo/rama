use super::utils;

use rama::{
    Layer,
    extensions::{Extension, Extensions},
    http::{BodyExtractExt, StatusCode, server::HttpServer, service::web::WebService},
    layer::AddInputExtensionLayer,
    rt::Executor,
    tcp::server::TcpListener,
};

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Extension)]
struct CollectorState {
    metrics_received: AtomicU32,
}

#[tokio::test]
#[ignore]
async fn test_http_telemetry() {
    utils::init_tracing();

    let state = Arc::new(CollectorState {
        metrics_received: AtomicU32::new(0),
    });
    spawn_fake_otlp_collector(Arc::clone(&state)).await;

    let runner = utils::ExampleRunner::interactive("http_telemetry", Some("opentelemetry"));

    let homepage = runner
        .get("http://127.0.0.1:62012")
        .send()
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();
    assert!(homepage.contains("<h1>Hello!</h1>"));

    // Give enough time for everything to flush and export
    let deadline = Instant::now() + Duration::from_secs(10);
    while state.metrics_received.load(Ordering::SeqCst) == 0 {
        if Instant::now() > deadline {
            panic!("no OTLP /v1/metrics POST reached the fake collector within 10s");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn spawn_fake_otlp_collector(state: Arc<CollectorState>) {
    let exec = Executor::default();
    let web = WebService::default().with_post("/v1/metrics", async |ext: Extensions| {
        ext.get_ref::<CollectorState>()
            .unwrap()
            .metrics_received
            .fetch_add(1, Ordering::SeqCst);
        StatusCode::OK
    });
    let http_service = HttpServer::auto(exec.clone()).service(web);

    let listener = TcpListener::build(exec)
        .bind_address("127.0.0.1:4318")
        .await
        .expect("bind fake OTLP collector on 127.0.0.1:4318 (port already in use?)");

    tokio::spawn(listener.serve(AddInputExtensionLayer::new_arc(state).into_layer(http_service)));
}
