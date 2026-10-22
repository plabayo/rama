#[cfg(feature = "dial9")]
use rama_core::telemetry::dial9::{Dial9Operations, Outcome};
use rama_core::telemetry::event::{Event, SpanStart};
use rama_core::telemetry::tracing::{TracingSpans, trace_root_span};
use rama_net::address::SocketAddress;
use rama_net::id::ConnectionId;

/// A tcp server accepted a connection.
#[derive(Clone, Debug, Event, SpanStart)]
#[span(end = TcpServerConnectionClosed)]
pub struct TcpServerConnectionOpened {
    pub connection: ConnectionId,
    pub local: Option<SocketAddress>,
    pub peer: SocketAddress,
}

/// A connection a tcp server accepted is gone, for whatever reason.
#[derive(Clone, Debug, Event)]
pub struct TcpServerConnectionClosed {
    pub connection: ConnectionId,
}

impl TcpServerConnectionOpened {
    /// A `tcp::serve_graceful` tracing span for every accepted connection.
    #[must_use]
    pub fn tracing_spans() -> TracingSpans<Self> {
        TracingSpans::new(
            |start| {
                let local = start
                    .local
                    .unwrap_or_else(|| SocketAddress::default_ipv4(0));
                trace_root_span!(
                    "tcp::serve_graceful",
                    otel.kind = "server",
                    network.local.port = local.port,
                    network.local.address = %local.ip_addr,
                    network.peer.port = %start.peer.port,
                    network.peer.address = %start.peer.ip_addr,
                    network.protocol.name = "tcp",
                )
            },
            |_, _| {},
        )
    }

    /// A `tcp.connection` dial9 operation for every accepted connection.
    #[cfg(feature = "dial9")]
    #[must_use]
    pub fn dial9_operations() -> Dial9Operations<Self> {
        Dial9Operations::new("tcp.connection", |_| (Outcome::Success, 0, 0))
    }
}
