//! An example to show how to expose your [`prometheus`] metrics over HTTP
//! using the [`HttpServer`] and [`Executor`] from Rama.
//!
//! [`prometheus`]: https://crates.io/crates/prometheus
//! [`HttpServer`]: crate::http::server::HttpServer
//! [`Executor`]: crate::rt::Executor
//!
//! This example will create a server that listens on `127.0.0.1:8080.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_prometheus
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:8080`. You can use `curl` to check if the server is ready:
//!
//! ```sh
//! curl -v http://127.0.0.1:8080
//! curl -v http://127.0.0.1:8080/metrics
//! ```
//!
//! With the seecoresponse you should see a response with `HTTP/1.1 200` and the `

use prometheus::{default_registry, Counter};
use rama::{
    http::{
        response::Html,
        server::HttpServer,
        service::web::{extract::State, prometheus_metrics, WebService},
    },
    rt::Executor,
};

#[derive(Debug)]
struct Metrics {
    counter: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        let this = Self {
            counter: Counter::new("example_counter", "example counter").unwrap(),
        };
        let registry = default_registry();
        registry.register(Box::new(this.counter.clone())).unwrap();
        this
    }
}

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen_with_state(
            Metrics::default(),
            "127.0.0.1:8080",
            // by default the k8s health service is always ready and alive,
            // optionally you can define your own conditional closures to define
            // more accurate health checks
            WebService::default()
                .get("/", |State(metrics): State<Metrics>| async move {
                    metrics.counter.inc();
                    Html(format!("<h1>Hello, #{}!", metrics.counter.get()))
                })
                .get("/metrics", prometheus_metrics),
        )
        .await
        .unwrap();
}
