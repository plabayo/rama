//! An example on how to add layers to a TCP listener.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tcp_listener_layers --features=tcp
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62501`. You can use `curl` to interact with the service:
//!
//! ```sh
//! telnet 127.0.0.1 62501
//! ```
//!
//! Within the telnet session, you can type anything and it will be echoed back to you.
//! After 8 seconds the connection will be closed by the server.
//! This is because of the `TimeoutLayer` that was added to the server.

use rama::{
    Layer,
    layer::{HijackLayer, TimeoutLayer, TraceErrLayer},
    net::stream::{Socket, matcher::SocketMatcher, service::EchoService},
    service::service_fn,
    tcp::TcpStream,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
};
use std::{convert::Infallible, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    graceful.spawn_task_fn(async |guard| {
        TcpListener::bind("0.0.0.0:62501")
            .await
            .expect("bind TCP Listener")
            .serve_graceful(
                guard,
                (
                    HijackLayer::new(
                        SocketMatcher::loopback().negate(),
                        service_fn(async |stream: TcpStream| {
                            match stream.peer_addr() {
                                Ok(addr) => {
                                    tracing::debug!(
                                        network.peer.address = %addr.ip(),
                                        network.peer.port = %addr.port(),
                                        "blocked incoming connection",
                                    )
                                }
                                Err(err) => tracing::error!(
                                    "blocked incoming connection with unknown peer address: {err:?}",
                                ),
                            }
                            Ok::<u64, Infallible>(0)
                        }),
                    ),
                    TraceErrLayer::new(),
                    TimeoutLayer::new(Duration::from_secs(8)),
                )
                    .into_layer(EchoService::new()),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
