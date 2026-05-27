//! A Hello World example of a TCP listener.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tcp_listener_hello --features=tcp
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62500`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62500
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a body with the source code of this example.

#![expect(
    clippy::expect_used,
    reason = "example: panic-on-error is the standard pattern for demos"
)]

use rama::{
    io::Io,
    net::{address::SocketAddress, stream::Socket},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

use std::convert::Infallible;
use tokio::io::AsyncWriteExt;

const SRC: &str = include_str!("./tcp_listener_hello.rs");
// The below &str type will also work!
// const ADDR: &str = "127.0.0.1:62500";
const ADDR: SocketAddress = SocketAddress::local_ipv4(62500);

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

    tracing::info!("listening on: {ADDR}");
    TcpListener::bind_address(ADDR, Executor::default())
        .await
        .expect("bind TCP Listener")
        .serve(service_fn(handle))
        .await;
}

async fn handle(mut stream: impl Socket + Io + Unpin) -> Result<(), Infallible> {
    tracing::info!(
        "incoming connection from: {}",
        stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "???".to_owned())
    );

    let resp = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/plain",
        format!("Content-Length: {}", SRC.len()).as_str(),
        "",
        SRC,
        "",
    ]
    .join("\r\n");

    stream
        .write_all(resp.as_bytes())
        .await
        .expect("write to stream");

    Ok::<_, std::convert::Infallible>(())
}
