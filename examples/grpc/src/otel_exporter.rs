//! An example to show how to export your [`opentelemetry`] metrics over gRPC.
//! It also sets up [`tracing`] in a basic manner.
//!
//! Learn more about telemetry at <https://ramaproxy.org/book/intro/telemetry.html>.
//! In this book chapter you'll also find more information on how you can
//! consume the metrics of this example in tools such as Prometheus and Grafana.
//!
//! [`opentelemetry`]: https://opentelemetry.io/
//! [`tracing`]: https://tracing.rs/
//!
//! This example will create a server that listens on `127.0.0.1:62013`.
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
//! cargo run -p rama-grpc-examples --bin otel-exporter
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62013`. You can use `curl`:
//!
//! ```sh
//! curl -v http://127.0.0.1:62013
//! ```
//!
//! With the response you should see a response with `HTTP/1.1 200` and a greeting.
//!
//! You can now use tools like grafana to collect metrics from the collector running at 127.0.0.1:4317 over GRPC.

use rama::{
    Layer,
    extensions::Extensions,
    http::{
        client::EasyHttpWebClient,
        grpc,
        layer::{opentelemetry::RequestMetricsLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::{WebService, response::Html},
    },
    layer::AddInputExtensionLayer,
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
                resource::{HOST_ARCH, OS_NAME, SERVICE_NAME, SERVICE_VERSION},
            },
        },
        tracing::{
            self,
            level_filters::LevelFilter,
            subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
        },
    },
};

use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct Metrics {
    counter: UpDownCounter<i64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = opentelemetry::global::meter_with_scope(
            InstrumentationScope::builder("example.otel_exporter")
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
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let exporter_grpc_svc = EasyHttpWebClient::default();
    let exporter_grpc_client = grpc::service::opentelemetry::OtelExporter::new(exporter_grpc_svc)
        .with_endpoint(rama::http::Uri::from_static("http://localhost:4317"))
        .with_timeout(Duration::from_secs(10));

    let meter_reader = PeriodicReader::builder(exporter_grpc_client)
        .with_interval(Duration::from_secs(3))
        .build();

    let resource = Resource::builder()
        .with_attribute(KeyValue::new(SERVICE_NAME, "otel_exporter"))
        .with_attribute(KeyValue::new(SERVICE_VERSION, rama::utils::info::VERSION))
        .build();

    let meter = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(meter_reader)
        .build();

    opentelemetry::global::set_meter_provider(meter);

    // state for our custom app metrics
    let state = Arc::new(Metrics::new());

    let graceful = rama::graceful::Shutdown::default();

    // http web service
    graceful.spawn_task_fn(async |guard| {
        // http service
        let exec = Executor::graceful(guard);
        let http_service = HttpServer::auto(exec.clone()).service(
            (TraceLayer::new_for_http(), RequestMetricsLayer::default()).into_layer(
                WebService::default().with_get("/", async |ext: Extensions| {
                    ext.get::<Arc<Metrics>>().unwrap().counter.add(1, &[]);
                    Html("<h1>Hello!</h1>")
                }),
            ),
        );

        // service setup & go
        TcpListener::build(exec)
            .bind("127.1:62013")
            .await
            .unwrap()
            .serve(
                (
                    AddInputExtensionLayer::new(state),
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
