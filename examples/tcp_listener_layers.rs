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
    rt::Executor,
    service::service_fn,
    tcp::{TcpStream, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

use std::{convert::Infallible, time::Duration};

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(graceful.guard());

    let listener = TcpListener::bind("0.0.0.0:62501", exec)
        .await
        .expect("bind TCP Listener");

    let svc = (
        HijackLayer::new(
            SocketMatcher::loopback().negate(),
            service_fn(async |stream: TcpStream| {
                match stream.peer_addr() {
                    Ok(addr) => {
                        tracing::debug!(
                            network.peer.address = %addr.ip_addr,
                            network.peer.port = %addr.port,
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
        .into_layer(EchoService::new());

    graceful.spawn_task(listener.serve(svc));

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
