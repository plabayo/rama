//! This example demonstrates how to serve files from the file system over HTTP.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_service_fs --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62009`. You can use your browser to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62009/test-files/index.html
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and the content of the `index.html` file.

#![expect(
    clippy::expect_used,
    reason = "example: panic-on-error is the standard pattern for demos"
)]

use rama::{
    Layer,
    http::{server::HttpServer, service::fs::ServeDir},
    layer::TraceErrLayer,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let listener = TcpListener::bind_address("127.0.0.1:62009", Executor::default())
        .await
        .expect("bind TCP Listener");

    // This will serve files in the current working dir
    let cwd = std::env::current_dir().expect("current working dir");
    tracing::info!(?cwd, "serving files");
    let http_fs_server = HttpServer::default().service(ServeDir::new(cwd));

    // Serve the HTTP server over TCP,
    // ...once running you can go in browser for example to:
    tracing::info!("open: http://127.0.0.1:62009/test-files/index.html");
    listener
        .serve(TraceErrLayer::new().into_layer(http_fs_server))
        .await;
}
