//! An example to show how to expose your [`opentelemetry`] metrics over HTTP.
//! It also sets up [`tracing`] in a basic manner.
//!
//! Learn more about telemetry at <https://ramaproxy.org/book/intro/telemetry.html>.
//! In this book chapter you'll also find more information on how you can
//! consume the metrics of this example in tools such as Prometheus and Grafana.
//!
//! [`opentelemetry`]: https://opentelemetry.io/
//! [`tracing`]: https://tracing.rs/
//!
//! This example will create a server that listens on `127.0.0.1:62012.
//!
//! It also expects you to run the OT collector, e.g.:
//!
//! ```
//! docker run \
//!   -p 127.0.0.1:4317:4317 \
//!   otel/opentelemetry-collector:latest
//! ```
//!
//! # Run the example
//!
//! ```sh
//! cargo run --features=telemetry --example http_telemetry
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62012`. You can use `curl`:
//!
//! ```sh
//! curl -v http://127.0.0.1:62012
//! ```
//!
//! With the seecoresponse you should see a response with `HTTP/1.1 200` and a greeting.
//!
//! You can now use tools like grafana to collect metrics from the collector running at 127.0.0.1:4317 over GRPC.

use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
use opentelemetry_sdk::{
    metrics::reader::{DefaultAggregationSelector, DefaultTemporalitySelector},
    Resource,
};
use rama::{
    http::{
        layer::{opentelemetry::RequestMetricsLayer, trace::TraceLayer},
        response::Html,
        server::HttpServer,
        service::web::{extract::State, WebService},
    },
    rt::Executor,
    stream::layer::opentelemetry::NetworkMetricsLayer,
    tcp::server::TcpListener,
    telemetry::opentelemetry::{
        self,
        metrics::UpDownCounter,
        semantic_conventions::{
            self,
            resource::{HOST_ARCH, OS_NAME},
        },
        KeyValue,
    },
    Layer,
};
use std::time::Duration;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug)]
struct Metrics {
    counter: UpDownCounter<i64>,
}

impl Metrics {
    pub fn new() -> Self {
        let meter = opentelemetry::global::meter_with_version(
            "example.http_telemetry",
            Some(env!("CARGO_PKG_VERSION")),
            Some(semantic_conventions::SCHEMA_URL),
            Some(vec![
                KeyValue::new(OS_NAME, std::env::consts::OS),
                KeyValue::new(HOST_ARCH, std::env::consts::ARCH),
            ]),
        );
        let counter = meter.i64_up_down_counter("visitor_counter").init();
        Self { counter }
    }
}

#[tokio::main]
async fn main() {
    // tracing setup
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    // configure OT metrics exporter
    let export_config = ExportConfig {
        endpoint: "http://localhost:4317".to_string(),
        timeout: Duration::from_secs(3),
        protocol: Protocol::Grpc,
    };

    let meter = opentelemetry_otlp::new_pipeline()
        .metrics(opentelemetry_sdk::runtime::Tokio)
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_export_config(export_config),
            // can also config it using with_* functions like the tracing part above.
        )
        .with_resource(Resource::new(vec![KeyValue::new(
            "service.name",
            "http_telemetry",
        )]))
        .with_period(Duration::from_secs(3))
        .with_timeout(Duration::from_secs(10))
        .with_aggregation_selector(DefaultAggregationSelector::new())
        .with_temporality_selector(DefaultTemporalitySelector::new())
        .build()
        .expect("build OT meter");

    opentelemetry::global::set_meter_provider(meter);

    // state for our custom app metrics
    let state = Metrics::new();

    let graceful = rama::graceful::Shutdown::default();

    // http web service
    graceful.spawn_task_fn(|guard| async move {
        // http service
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(
            (TraceLayer::new_for_http(), RequestMetricsLayer::default()).layer(
                WebService::default().get("/", |State(metrics): State<Metrics>| async move {
                    metrics.counter.add(1, &[]);
                    Html("<h1>Hello!</h1>")
                }),
            ),
        );

        // service setup & go
        TcpListener::build_with_state(state)
            .bind("127.0.0.1:62012")
            .await
            .unwrap()
            .serve_graceful(guard, NetworkMetricsLayer::default().layer(http_service))
            .await;
    });

    // wait for graceful shutdown
    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .unwrap();
}
