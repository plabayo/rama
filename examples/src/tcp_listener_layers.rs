//! An example on how to add layers to a TCP listener.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin tcp_listener_layers --features=tcp
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:12501`. You can use `curl` to interact with the service:
//!
//! ```sh
//! telnet 127.0.0.1 12501
//! ```
//!
//! Within the telnet session, you can type anything and it will be echoed back to you.
//! After 8 seconds the connection will be closed by the server.
//! This is because of the `ScopeLayer` that was added to the server: it cancels the
//! connection's scope after 6 seconds and aborts it 2 seconds later.
//!
//! Echoed output is also paced at 8 KiB/s per connection by the
//! `ThrottleLayer`: bulk data comes back visibly rate-shaped.

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer,
    graceful::Scope,
    layer::{HijackLayer, ScopeLayer, TraceErrLayer},
    net::stream::{
        Socket,
        layer::{ThrottleLayer, ThrottleMode},
        matcher::SocketMatcher,
        service::EchoService,
    },
    service::service_fn,
    tcp::{TcpStream, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    utils::{octets::kib_u64, rate::Rate},
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

    let scope = Scope::new()
        .with_default_signal()
        .with_grace(Duration::from_secs(30));
    let weak_scope = scope.clone_weak();

    let listener = TcpListener::bind_address("0.0.0.0:12501", weak_scope)
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
        // Cancel each connection after 6s so it can wind down, and abort it 2s later.
        ScopeLayer::new()
            .with_max_age(Duration::from_secs(6))
            .with_grace(Duration::from_secs(2)),
        // pace what we echo back at 8 KiB/s per connection
        ThrottleLayer::write_only(ThrottleMode::per_conn(Rate::per_sec(kib_u64(8)))),
    )
        .into_layer(EchoService::new());

    scope.spawn_task(listener.serve(svc));

    scope.join().await.expect("graceful shutdown");
}
