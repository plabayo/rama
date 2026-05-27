//! Pre-defined [dial9] events for the SOCKS5 client handshake.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry

use dial9_tokio_telemetry::telemetry::{TelemetryHandle, clock_monotonic_ns, record_event};
use dial9_trace_format::TraceEvent;
use rama_net::address::Host;

/// Auth-method negotiation outcome.
#[derive(TraceEvent)]
pub struct Socks5HandshakeAuth {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Negotiated auth method code, per RFC 1928 §3. See
    /// [`crate::proto::SocksMethod`] for the canonical name → byte
    /// mapping.
    pub auth_method: u32,
    /// Whether the handshake completed successfully (auth accepted).
    pub success: bool,
}

/// CONNECT reply outcome carried in a SOCKS5 server reply.
#[derive(TraceEvent)]
pub struct Socks5HandshakeConnect {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Destination host the client requested.
    pub destination_host: Host,
    /// Destination port the client requested.
    pub destination_port: u32,
    /// Server reply kind, per RFC 1928 §6. See
    /// [`crate::proto::ReplyKind`] for the canonical name → byte
    /// mapping.
    pub reply_kind: u32,
}

#[inline]
pub(crate) fn record_handshake_auth(auth_method: u8, success: bool) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            Socks5HandshakeAuth {
                timestamp_ns: clock_monotonic_ns(),
                auth_method: auth_method as u32,
                success,
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_handshake_connect(host: Host, port: u16, reply_kind: u8) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            Socks5HandshakeConnect {
                timestamp_ns: clock_monotonic_ns(),
                destination_host: host,
                destination_port: port as u32,
                reply_kind: reply_kind as u32,
            },
            &handle,
        );
    }
}
