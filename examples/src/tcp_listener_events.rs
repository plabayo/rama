//! A TCP listener that does its own thing with the events rama emits.
//!
//! Two ways to use them, next to rama's own tracing spans:
//!
//! - listeners that count the connections that are open right now;
//! - a span adapter that writes a wide log: one line per connection, with how
//!   long it was busy (it times every poll) next to how long it lived.
//!   Listeners only see the start and end, a span adapter is around the work
//!   itself.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin tcp_listener_events --features=tcp
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62502`. Connect with `nc`:
//!
//! ```sh
//! nc 127.0.0.1 62502
//! ```
//!
//! You get `hello` back, and the server logs the open connections and, per
//! closed connection, its lifetime and busy time.

#![expect(
    clippy::expect_used,
    reason = "example: panic-on-error is the standard pattern for demos"
)]

use rama::{
    io::Io,
    net::{address::SocketAddress, id::ConnectionId},
    rt::Executor,
    service::service_fn,
    tcp::server::{TcpListener, TcpServerConnectionClosed, TcpServerConnectionOpened},
    telemetry::{
        DefaultListeners, DefaultSpanAdapters,
        event::{Emitted, EventDispatcher, Listeners, SpanAdapter, SpanAdapters},
        tracing::{
            self,
            level_filters::LevelFilter,
            subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
        },
    },
};

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::{io::AsyncWriteExt, time::Instant};

const ADDR: SocketAddress = SocketAddress::local_ipv4(62502);

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

    let _span_adapters = SpanAdapters::new(EventDispatcher::global())
        .with_group(DefaultSpanAdapters::tracing)
        .with(WideTcpLog)
        .build();

    let open_connections = Arc::new(AtomicUsize::new(0));
    let _listeners = Listeners::new(EventDispatcher::global())
        .with_group(DefaultListeners::tracing)
        .with({
            let open_connections = open_connections.clone();
            move |_: &Emitted<'_, TcpServerConnectionOpened>| {
                let open_connections = open_connections.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::info!(open_connections, "connection opened");
            }
        })
        .with(move |_: &Emitted<'_, TcpServerConnectionClosed>| {
            let open_connections = open_connections.fetch_sub(1, Ordering::Relaxed) - 1;
            tracing::info!(open_connections, "connection closed");
        })
        .build();

    tracing::info!("listening on: {ADDR}");
    TcpListener::bind_address(ADDR, Executor::default())
        .await
        .expect("bind TCP Listener")
        .serve(service_fn(handle))
        .await;
}

async fn handle(mut stream: impl Io + Unpin) -> Result<(), Infallible> {
    stream.write_all(b"hello\n").await.expect("write to stream");
    stream.shutdown().await.expect("shut down stream");
    Ok(())
}

/// A wide log: one log line per connection, written when it closes, with
/// everything known about it, instead of many small lines along the way.
struct WideTcpLog;

struct WideTcpLine {
    connection: ConnectionId,
    local: Option<SocketAddress>,
    peer: SocketAddress,
    opened_at: Instant,
    busy_ns: AtomicU64,
}

impl SpanAdapter<TcpServerConnectionOpened> for WideTcpLog {
    type State = WideTcpLine;

    fn open(&self, start: &Emitted<'_, TcpServerConnectionOpened>) -> Option<WideTcpLine> {
        let opened = start.event();
        Some(WideTcpLine {
            connection: opened.connection,
            local: opened.local,
            peer: opened.peer,
            opened_at: start.at(),
            busy_ns: AtomicU64::new(0),
        })
    }

    fn enter(&self, line: &WideTcpLine, poll: &mut dyn FnMut()) {
        let polled_at = Instant::now();
        poll();
        let busy_ns = u64::try_from(polled_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
        line.busy_ns.fetch_add(busy_ns, Ordering::Relaxed);
    }

    fn close(&self, line: WideTcpLine, end: &Emitted<'_, TcpServerConnectionClosed>) {
        tracing::info!(
            connection = %line.connection,
            local = line.local.as_ref().map(tracing::field::display),
            peer = %line.peer,
            duration_us = end.at().duration_since(line.opened_at).as_micros(),
            busy_us = line.busy_ns.into_inner() / 1_000,
            "tcp connection"
        );
    }
}
