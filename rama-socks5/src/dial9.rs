//! Pre-defined [dial9] runtime-telemetry events for SOCKS5 handshake
//! lifecycle, plus tiny recording helpers that emit them when a
//! `dial9-tokio-telemetry::TracedRuntime` is active.
//!
//! Two events are exposed:
//!
//! - [`Socks5HandshakeAuth`] — emitted at the moment the auth method
//!   negotiation completes (success or fail).
//! - [`Socks5HandshakeConnect`] — emitted when the server's reply to
//!   `CONNECT` arrives, carrying the structured reply kind
//!   (`Succeeded`, `HostUnreachable`, `ConnectionRefused`, …).
//!
//! Recording goes through `dial9_tokio_telemetry::telemetry::TelemetryHandle::current`
//! and silently no-ops when no `TracedRuntime` is in effect — so wiring
//! the events into the engine here is safe even when the consumer
//! application doesn't enable dial9 telemetry.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry

use dial9_tokio_telemetry::telemetry::{TelemetryHandle, clock_monotonic_ns, record_event};
use dial9_trace_format::TraceEvent;

/// Auth-method negotiation outcome.
#[derive(TraceEvent)]
pub struct Socks5HandshakeAuth {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Negotiated auth method code, per RFC 1928 §3 (e.g. `0x00` =
    /// no auth, `0x02` = username/password). `0xff` = no acceptable
    /// methods (handshake failed).
    pub auth_method: u32,
    /// Whether the handshake completed successfully (auth accepted).
    pub success: bool,
}

/// CONNECT reply outcome carried in a SOCKS5 server reply.
#[derive(TraceEvent)]
pub struct Socks5HandshakeConnect {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Destination host string the client requested.
    pub destination_host: String,
    /// Destination port the client requested.
    pub destination_port: u32,
    /// Server reply kind, per RFC 1928 §6:
    /// 0=Succeeded, 1=GeneralFailure, 2=ConnectionNotAllowed,
    /// 3=NetworkUnreachable, 4=HostUnreachable, 5=ConnectionRefused,
    /// 6=TtlExpired, 7=CommandNotSupported, 8=AddressTypeNotSupported.
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
pub(crate) fn record_handshake_connect(host: &str, port: u16, reply_kind: u8) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            Socks5HandshakeConnect {
                timestamp_ns: clock_monotonic_ns(),
                destination_host: host.to_owned(),
                destination_port: port as u32,
                reply_kind: reply_kind as u32,
            },
            &handle,
        );
    }
}
