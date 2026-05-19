use super::utils;

use rama::{
    bytes::Bytes,
    extensions::Extension,
    http::{
        BodyExtractExt, Request, StatusCode,
        body::util::BodyExt,
        grpc::{
            protobuf::prost::Message,
            service::opentelemetry::proto::{
                collector::{
                    logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest,
                },
                common::v1::{KeyValue, any_value::Value},
            },
        },
        server::HttpServer,
        service::web::{WebService, extract::State},
    },
    rt::Executor,
    tcp::server::TcpListener,
};

use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Default, Extension)]
struct CollectorState {
    metrics: Mutex<Vec<Bytes>>,
    logs: Mutex<Vec<Bytes>>,
}

#[tokio::test]
#[ignore]
async fn test_http_telemetry() {
    utils::init_tracing();

    let state = Arc::new(CollectorState::default());
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
    let (metric_bodies, log_bodies) = loop {
        let metric_bodies = state.metrics.lock().clone();
        let log_bodies = state.logs.lock().clone();
        if !metric_bodies.is_empty() && !log_bodies.is_empty() {
            break (metric_bodies, log_bodies);
        }
        if Instant::now() > deadline {
            panic!(
                "fake collector did not receive both signals within 10s (metrics={}, logs={})",
                metric_bodies.len(),
                log_bodies.len()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    assert_metrics_payloads(&metric_bodies);
    assert_logs_payloads(&log_bodies);
}

fn assert_metrics_payloads(bodies: &[Bytes]) {
    let mut saw_visitor_counter = false;
    let mut saw_service_name = false;
    for body in bodies {
        let req = ExportMetricsServiceRequest::decode(body.clone()).expect("decode");
        for rm in &req.resource_metrics {
            if let Some(resource) = &rm.resource
                && find_string_attr(&resource.attributes, "service.name")
                    .is_some_and(|v| v == "http_telemetry")
            {
                saw_service_name = true;
            }
            for sm in &rm.scope_metrics {
                for metric in &sm.metrics {
                    if metric.name == "visitor_counter" {
                        saw_visitor_counter = true;
                    }
                }
            }
        }
    }
    assert!(
        saw_service_name,
        "metrics export must carry resource attribute service.name=http_telemetry"
    );
    assert!(
        saw_visitor_counter,
        "metrics export must contain a visitor_counter metric"
    );
}

fn assert_logs_payloads(bodies: &[Bytes]) {
    let mut saw_visitor_log = false;
    let mut saw_service_name = false;
    for body in bodies {
        let req = ExportLogsServiceRequest::decode(body.clone()).expect("decode");
        for rl in &req.resource_logs {
            if let Some(resource) = &rl.resource
                && find_string_attr(&resource.attributes, "service.name")
                    .is_some_and(|v| v == "http_telemetry")
            {
                saw_service_name = true;
            }
            for sl in &rl.scope_logs {
                for record in &sl.log_records {
                    let body_str = record.body.as_ref().and_then(|v| match v.value.as_ref()? {
                        Value::StringValue(s) => Some(s.as_str()),
                        _ => None,
                    });
                    if body_str == Some("visitor") {
                        saw_visitor_log = true;
                    }
                }
            }
        }
    }
    assert!(
        saw_service_name,
        "logs export must carry resource attribute service.name=http_telemetry"
    );
    assert!(
        saw_visitor_log,
        "logs export must contain a log record with body \"visitor\""
    );
}

fn find_string_attr<'a>(attrs: &'a [KeyValue], key: &str) -> Option<&'a str> {
    attrs.iter().find(|kv| kv.key == key).and_then(|kv| {
        kv.value.as_ref().and_then(|v| match v.value.as_ref()? {
            Value::StringValue(s) => Some(s.as_str()),
            _ => None,
        })
    })
}

async fn spawn_fake_otlp_collector(state: Arc<CollectorState>) {
    let exec = Executor::default();
    let web = WebService::new_with_state(state)
        .with_post(
            "/v1/metrics",
            async |State(state): State<Arc<CollectorState>>, req: Request| {
                if let Ok(body) = req.into_body().collect().await {
                    state.metrics.lock().push(body.to_bytes());
                }
                StatusCode::OK
            },
        )
        .with_post(
            "/v1/logs",
            async |State(state): State<Arc<CollectorState>>, req: Request| {
                if let Ok(body) = req.into_body().collect().await {
                    state.logs.lock().push(body.to_bytes());
                }
                StatusCode::OK
            },
        );
    let http_service = HttpServer::auto(exec.clone()).service(web);

    let listener = TcpListener::build(exec)
        .bind_address("127.0.0.1:4318")
        .await
        .expect("bind fake OTLP collector on 127.0.0.1:4318 (port already in use?)");

    tokio::spawn(listener.serve(http_service));
}
