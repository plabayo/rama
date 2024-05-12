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
//! This example will create a server that listens on `127.0.0.1:40012 for the http service
//! and on `127.0.0.1:41012` for the prometheus exportor.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --features=telemetry --example http_telemetry
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:40012` and `:41012`. You can use `curl`:
//!
//! ```sh
//! curl -v http://127.0.0.1:40012
//! curl -v http://127.0.0.1:41012/metrics
//! ```
//!
//! With the seecoresponse you should see a response with `HTTP/1.1 200` and the `

use std::{sync::Arc, time::Duration};

use rama::{
    http::{
        layer::{opentelemetry::RequestMetricsLayer, trace::TraceLayer},
        response::Html,
        server::HttpServer,
        service::web::{extract::State, PrometheusMetricsHandler, WebService},
    },
    opentelemetry::{
        self,
        metrics::{Meter, MeterProvider, UpDownCounter},
        prometheus,
        semantic_conventions::{
            self,
            resource::{HOST_ARCH, OS_NAME},
        },
        KeyValue,
    },
    rt::Executor,
    service::ServiceBuilder,
    stream::layer::opentelemetry::NetworkMetricsLayer,
    tcp::server::TcpListener,
};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug)]
struct Metrics {
    _meter: Meter,
    counter: UpDownCounter<i64>,
}

impl Metrics {
    pub fn new(provider: impl MeterProvider) -> Self {
        let meter = provider.versioned_meter(
            "example.http_prometheus",
            Some(env!("CARGO_PKG_VERSION")),
            Some(semantic_conventions::SCHEMA_URL),
            Some(vec![
                KeyValue::new(OS_NAME, std::env::consts::OS),
                KeyValue::new(HOST_ARCH, std::env::consts::ARCH),
            ]),
        );
        let counter = meter.i64_up_down_counter("visitor_counter").init();
        Self {
            _meter: meter,
            counter,
        }
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

    // prometheus registry & exporter
    let registry = prometheus::Registry::new();
    let exporter = prometheus::exporter()
        .with_registry(registry.clone())
        .build()
        .unwrap();

    // set up a meter meter to create instruments
    let provider = opentelemetry::sdk::metrics::SdkMeterProvider::builder()
        .with_reader(exporter)
        .build();

    // open telemetry middleware
    let network_metrics = NetworkMetricsLayer::with_provider(provider.clone());
    let http_metrics = RequestMetricsLayer::with_provider(provider.clone());

    // state for our custom app metrics
    let state = Metrics::new(provider);

    // prometheus metrics http handler (exporter)
    let metrics_http_handler = Arc::new(PrometheusMetricsHandler::new().with_registry(registry));

    let graceful = rama::graceful::Shutdown::default();

    // http web service
    graceful.spawn_task_fn(|guard| async move {
        // http service
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(http_metrics)
                .service(WebService::default().get(
                    "/",
                    |State(metrics): State<Metrics>| async move {
                        metrics.counter.add(1, &[]);
                        Html("<h1>Hello!</h1>")
                    },
                )),
        );

        // service setup & go
        TcpListener::build_with_state(state)
            .bind("127.0.0.1:40012")
            .await
            .unwrap()
            .serve_graceful(
                guard,
                ServiceBuilder::new()
                    .layer(network_metrics)
                    .service(http_service),
            )
            .await;
    });

    // prometheus web exporter
    graceful.spawn_task_fn(|guard| async move {
        let exec = Executor::graceful(guard.clone());
        HttpServer::auto(exec)
            .listen_graceful(
                guard,
                "127.0.0.1:41012",
                WebService::default().get("/metrics", metrics_http_handler),
            )
            .await
            .unwrap();
    });

    // wait for graceful shutdown
    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .unwrap();
}
