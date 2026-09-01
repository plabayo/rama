//! Pre-defined [dial9] events for the BoringSSL client handshake.
//!
//! [dial9]: https://github.com/dial9-rs/dial9

use dial9::Dial9Handle;
use dial9::core::clock_monotonic_ns;
use dial9_trace_format::{EventEncoder, TraceEvent, TraceField, types::FieldType};
use rama_net::{address::Host, tls::ApplicationProtocol};
use rama_tls::ProtocolVersion;
use std::io::{self, Write};

#[derive(Debug, Clone)]
pub struct MaybeServerName(Option<Host>);

impl TraceField for MaybeServerName {
    fn field_type() -> FieldType {
        FieldType::String
    }

    fn encode<W: Write>(&self, enc: &mut EventEncoder<'_, W>) -> io::Result<()> {
        match self.0.as_ref() {
            Some(host) => {
                let host = host.to_str();
                enc.write_string(host.as_ref())
            }
            None => enc.write_string(""),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MaybeAlpnSelected(Option<ApplicationProtocol>);

impl TraceField for MaybeAlpnSelected {
    fn field_type() -> FieldType {
        FieldType::Bytes
    }

    fn encode<W: Write>(&self, enc: &mut EventEncoder<'_, W>) -> io::Result<()> {
        match self.0.as_ref() {
            Some(protocol) => enc.write_bytes(protocol.as_bytes()),
            None => enc.write_bytes(&[]),
        }
    }
}

/// TLS handshake initiation.
#[derive(TraceEvent)]
pub struct TlsHandshakeStarted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Server certificate identity the client is negotiating against.
    pub server_name: MaybeServerName,
}

/// TLS handshake completed successfully.
#[derive(TraceEvent)]
pub struct TlsHandshakeCompleted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub server_name: MaybeServerName,
    pub protocol_version: ProtocolVersion,
    /// ALPN protocol the server selected, if any.
    pub alpn_selected: MaybeAlpnSelected,
    /// Peer certificate chain depth (0 if not stored / not negotiated).
    pub peer_cert_chain_depth: u32,
}

/// Error category for [`TlsHandshakeFailed::error_kind`]. Encoded as
/// `u32` because dial9 trace fields are primitives; the named variants
/// here are the only valid values.
pub mod tls_handshake_error_kind {
    /// `TlsConnectError::Builder(_)` — builder failed before the
    /// handshake started.
    pub const BUILDER: u32 = 1;
    /// Handshake failed with an underlying `std::io::Error`. Inspect
    /// `io_error_kind` for the encoded `ErrorKind`.
    pub const HANDSHAKE_IO: u32 = 2;
    /// Handshake failed with an OpenSSL/BoringSSL error stack. Inspect
    /// the structured error from the call site for diagnostics.
    pub const HANDSHAKE_SSL_STACK: u32 = 3;
    /// Handshake failed without an `io::Error` or SSL stack — fallback
    /// catch-all. Should be rare.
    pub const HANDSHAKE_OTHER: u32 = 4;
}

/// TLS handshake failed.
#[derive(TraceEvent)]
pub struct TlsHandshakeFailed {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub server_name: MaybeServerName,
    /// One of [`tls_handshake_error_kind`].
    pub error_kind: u32,
    /// Encoded `std::io::ErrorKind`, set when `error_kind ==
    /// [`tls_handshake_error_kind::HANDSHAKE_IO`].
    pub io_error_kind: Option<u32>,
}

#[inline]
pub(crate) fn record_handshake_started(server_name: Option<Host>) {
    let handle = Dial9Handle::current();
    if handle.is_enabled() {
        handle.record_event(TlsHandshakeStarted {
            timestamp_ns: clock_monotonic_ns(),
            server_name: MaybeServerName(server_name),
        });
    }
}

#[inline]
pub(crate) fn record_handshake_completed(
    server_name: Option<Host>,
    protocol_version: ProtocolVersion,
    alpn_selected: Option<ApplicationProtocol>,
    peer_cert_chain_depth: usize,
) {
    let handle = Dial9Handle::current();
    if handle.is_enabled() {
        handle.record_event(TlsHandshakeCompleted {
            timestamp_ns: clock_monotonic_ns(),
            server_name: MaybeServerName(server_name),
            protocol_version,
            alpn_selected: MaybeAlpnSelected(alpn_selected),
            peer_cert_chain_depth: u32::try_from(peer_cert_chain_depth).unwrap_or(u32::MAX),
        });
    }
}

#[inline]
pub(crate) fn record_handshake_failed(
    server_name: Option<Host>,
    error_kind: u32,
    io_error_kind: Option<u32>,
) {
    let handle = Dial9Handle::current();
    if handle.is_enabled() {
        handle.record_event(TlsHandshakeFailed {
            timestamp_ns: clock_monotonic_ns(),
            server_name: MaybeServerName(server_name),
            error_kind,
            io_error_kind,
        });
    }
}
