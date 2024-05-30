//! An example on how to add layers to a TCP listener.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tcp_listener_layers
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
    service::{
        layer::{HijackLayer, TimeoutLayer},
        service_fn, ServiceBuilder,
    },
    stream::{matcher::SocketMatcher, service::EchoService},
    tcp::server::TcpListener,
};
use std::{convert::Infallible, time::Duration};
use tokio::net::TcpStream;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

    let graceful = rama::utils::graceful::Shutdown::default();

    graceful.spawn_task_fn(|guard| async {
        TcpListener::bind("0.0.0.0:62501")
            .await
            .expect("bind TCP Listener")
            .serve_graceful(
                guard,
                ServiceBuilder::new()
                    .layer(HijackLayer::new(
                        SocketMatcher::loopback().negate(),
                        service_fn(|stream: TcpStream| async move {
                            match stream.peer_addr() {
                                Ok(addr) => tracing::warn!("blocked incoming connection: {}", addr),
                                Err(err) => tracing::error!(
                                    error = %err,
                                    "blocked incoming connection with unknown peer address",
                                ),
                            }
                            Ok::<u64, Infallible>(0)
                        }),
                    ))
                    .trace_err()
                    .layer(TimeoutLayer::new(Duration::from_secs(8)))
                    .service(EchoService::new()),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
