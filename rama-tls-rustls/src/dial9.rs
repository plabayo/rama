//! Pre-defined [dial9] runtime-telemetry events for TLS handshake
//! lifecycle on the rustls connector, plus tiny recording helpers that
//! emit them when a `dial9-tokio-telemetry::TracedRuntime` is active.
//!
//! Three events:
//!
//! - [`TlsHandshakeStarted`] — emitted right before
//!   `RustlsConnector::connect`.
//! - [`TlsHandshakeCompleted`] — emitted on successful negotiation,
//!   carrying the negotiated TLS protocol version, the ALPN selection,
//!   and the peer cert chain depth.
//! - [`TlsHandshakeFailed`] — emitted when the handshake errors out.
//!
//! Recording goes through `dial9_tokio_telemetry::telemetry::TelemetryHandle`
//! and silently no-ops when no `TracedRuntime` is in effect.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry

use dial9_tokio_telemetry::telemetry::{TelemetryHandle, clock_monotonic_ns, record_event};
use dial9_trace_format::TraceEvent;

/// TLS handshake initiation.
#[derive(TraceEvent)]
pub struct TlsHandshakeStarted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Server name (SNI) the client is negotiating against.
    pub server_name: String,
}

/// TLS handshake completed successfully.
#[derive(TraceEvent)]
pub struct TlsHandshakeCompleted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub server_name: String,
    /// Stable display string for the negotiated protocol version
    /// (e.g. `"TLSv1_3"`).
    pub protocol_version: String,
    /// ALPN protocol the server selected, if any.
    pub alpn_selected: String,
    /// Peer certificate chain depth (0 if not stored / not negotiated).
    pub peer_cert_chain_depth: u32,
}

/// TLS handshake failed.
#[derive(TraceEvent)]
pub struct TlsHandshakeFailed {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub server_name: String,
    /// Display string of the underlying error (`format!("{err:#}")`).
    pub error: String,
}

#[inline]
pub(crate) fn record_handshake_started(server_name: &str) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TlsHandshakeStarted {
                timestamp_ns: clock_monotonic_ns(),
                server_name: server_name.to_owned(),
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_handshake_completed(
    server_name: &str,
    protocol_version: &str,
    alpn_selected: Option<&[u8]>,
    peer_cert_chain_depth: usize,
) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TlsHandshakeCompleted {
                timestamp_ns: clock_monotonic_ns(),
                server_name: server_name.to_owned(),
                protocol_version: protocol_version.to_owned(),
                alpn_selected: alpn_selected
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default(),
                peer_cert_chain_depth: u32::try_from(peer_cert_chain_depth).unwrap_or(u32::MAX),
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_handshake_failed(server_name: &str, error: &dyn std::fmt::Display) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TlsHandshakeFailed {
                timestamp_ns: clock_monotonic_ns(),
                server_name: server_name.to_owned(),
                error: format!("{error:#}"),
            },
            &handle,
        );
    }
}
