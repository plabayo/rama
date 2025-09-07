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
//! cargo run --example http_telemetry --features=http-full,opentelemetry
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

use rama::{
    Context, Layer,
    http::{
        client::EasyHttpWebClient,
        layer::{opentelemetry::RequestMetricsLayer, trace::TraceLayer},
        server::HttpServer,
        service::{
            opentelemetry::OtelExporter,
            web::{WebService, response::Html},
        },
    },
    layer::AddExtensionLayer,
    net::stream::layer::opentelemetry::NetworkMetricsLayer,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::{
        opentelemetry::{
            self, InstrumentationScope, KeyValue,
            metrics::UpDownCounter,
            sdk::{
                Resource,
                metrics::{PeriodicReader, SdkMeterProvider},
            },
            semantic_conventions::{
                self,
                resource::{HOST_ARCH, OS_NAME},
            },
        },
        tracing::level_filters::LevelFilter,
    },
};

use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use std::{sync::Arc, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug)]
struct Metrics {
    counter: UpDownCounter<i64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = opentelemetry::global::meter_with_scope(
            InstrumentationScope::builder("example.http_telemetry")
                .with_version(env!("CARGO_PKG_VERSION"))
                .with_schema_url(semantic_conventions::SCHEMA_URL)
                .with_attributes(vec![
                    KeyValue::new(OS_NAME, std::env::consts::OS),
                    KeyValue::new(HOST_ARCH, std::env::consts::ARCH),
                ])
                .build(),
        );

        let counter = meter.i64_up_down_counter("visitor_counter").build();
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

    let exporter_http_svc = EasyHttpWebClient::default();
    let exporter_http_client = OtelExporter::new(exporter_http_svc);

    let meter_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_http_client(exporter_http_client)
        .with_endpoint("http://localhost:4317")
        .with_timeout(Duration::from_secs(10))
        .build()
        .expect("build OT exporter");

    let meter_reader = PeriodicReader::builder(meter_exporter)
        .with_interval(Duration::from_secs(3))
        .build();

    let meter = SdkMeterProvider::builder()
        .with_resource(
            Resource::builder()
                .with_attribute(KeyValue::new("service.name", "http_telemetry"))
                .build(),
        )
        .with_reader(meter_reader)
        .build();

    opentelemetry::global::set_meter_provider(meter);

    // state for our custom app metrics
    let state = Arc::new(Metrics::new());

    let graceful = rama::graceful::Shutdown::default();

    // http web service
    graceful.spawn_task_fn(async |guard| {
        // http service
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(
            (TraceLayer::new_for_http(), RequestMetricsLayer::default()).into_layer(
                WebService::default().get("/", async |ctx: Context| {
                    ctx.get::<Arc<Metrics>>().unwrap().counter.add(1, &[]);
                    Html("<h1>Hello!</h1>")
                }),
            ),
        );

        // service setup & go
        TcpListener::build()
            .bind("127.0.0.1:62012")
            .await
            .unwrap()
            .serve_graceful(
                guard,
                (
                    AddExtensionLayer::new(state),
                    NetworkMetricsLayer::default(),
                )
                    .into_layer(http_service),
            )
            .await;
    });

    // wait for graceful shutdown
    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .unwrap();
}
