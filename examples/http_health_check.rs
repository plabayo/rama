//! An example to show how to create a minimal health check server,
//! using the [`HttpServer`] and [`Executor`] from Rama.
//!
//! [`HttpServer`]: crate::http::server::HttpServer
//! [`Executor`]: crate::rt::Executor
//!
//! This example will create a server that listens on `127.0.0.1:62003`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_health_check --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62003`. You can use `curl` to check if the server is running:
//!
//! ```sh
//! curl -v http://127.0.0.1:62003
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and an empty body.

use rama::http::{StatusCode, server::HttpServer, service::web::IntoEndpointService};

#[tokio::main]
async fn main() {
    HttpServer::default()
        .listen("127.0.0.1:62003", StatusCode::OK.into_endpoint_service())
        .await
        .unwrap();
}
