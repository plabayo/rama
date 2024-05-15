//! An example to show how to create a k8s health check server,
//! using the [`HttpServer`] and [`Executor`] from Rama.
//!
//! [`HttpServer`]: crate::http::server::HttpServer
//! [`Executor`]: crate::rt::Executor
//!
//! This example will create a server that listens on `127.0.0.1:62005.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_k8s_health
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62005`. You can use `curl` to check if the server is ready:
//!
//! ```sh
//! curl -v http://127.0.0.1:62005/k8s/ready
//! ```
//!
//! You should see a response with `HTTP/1.1 503 Service Unavailable` and an empty body.
//! When running that same curl command, at least 1 second after your started the service,
//! you should see a response with `HTTP/1.1 200 OK` and an empty body.

use rama::{
    http::{server::HttpServer, service::web::k8s_health_builder},
    rt::Executor,
};

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    let startup_time = std::time::Instant::now();
    HttpServer::auto(exec)
        .listen(
            "127.0.0.1:62005",
            // by default the k8s health service is always ready and alive,
            // optionally you can define your own conditional closures to define
            // more accurate health checks
            k8s_health_builder()
                .ready(move || {
                    // simulate a service only ready after 1s for w/e reason
                    let uptime = startup_time.elapsed().as_secs();
                    uptime > 1
                })
                .build(),
        )
        .await
        .unwrap();
}
