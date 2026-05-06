//! Pre-defined [dial9] events for the rustls client handshake.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry

use dial9_tokio_telemetry::telemetry::{TelemetryHandle, clock_monotonic_ns, record_event};
use dial9_trace_format::{
    EventEncoder, TraceEvent, TraceField,
    types::{FieldType, FieldValueRef},
};
use rama_net::{
    address::Host,
    dial9::{io_error_kind_code, io_error_raw_os_code},
    tls::{ApplicationProtocol, ProtocolVersion},
};
use std::io::{self, Write};

#[derive(Debug, Clone)]
pub struct MaybeAlpnSelected(Option<ApplicationProtocol>);

impl TraceField for MaybeAlpnSelected {
    type Ref<'a> = &'a [u8];

    fn field_type() -> FieldType {
        FieldType::Bytes
    }

    fn encode<W: Write>(&self, enc: &mut EventEncoder<'_, W>) -> io::Result<()> {
        match self.0.as_ref() {
            Some(protocol) => enc.write_bytes(protocol.as_bytes()),
            None => enc.write_bytes(&[]),
        }
    }

    fn decode_ref<'a>(val: &FieldValueRef<'a>) -> Option<Self::Ref<'a>> {
        match val {
            FieldValueRef::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }
}

/// TLS handshake initiation.
#[derive(TraceEvent)]
pub struct TlsHandshakeStarted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Server name (SNI) the client is negotiating against.
    pub server_name: Host,
}

/// TLS handshake completed successfully.
#[derive(TraceEvent)]
pub struct TlsHandshakeCompleted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub server_name: Host,
    pub protocol_version: ProtocolVersion,
    /// ALPN protocol the server selected, if any.
    pub alpn_selected: MaybeAlpnSelected,
    /// Peer certificate chain depth (0 if not stored / not negotiated).
    pub peer_cert_chain_depth: u32,
}

/// TLS handshake failed.
#[derive(TraceEvent)]
pub struct TlsHandshakeFailed {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub server_name: Host,
    /// Encoded `std::io::ErrorKind`.
    pub error_kind: u32,
    /// Raw OS error code, if available.
    pub error_raw_os: Option<i64>,
}

#[inline]
pub(crate) fn record_handshake_started(server_name: Host) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TlsHandshakeStarted {
                timestamp_ns: clock_monotonic_ns(),
                server_name,
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_handshake_completed(
    server_name: Host,
    protocol_version: ProtocolVersion,
    alpn_selected: Option<ApplicationProtocol>,
    peer_cert_chain_depth: usize,
) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TlsHandshakeCompleted {
                timestamp_ns: clock_monotonic_ns(),
                server_name,
                protocol_version,
                alpn_selected: MaybeAlpnSelected(alpn_selected),
                peer_cert_chain_depth: u32::try_from(peer_cert_chain_depth).unwrap_or(u32::MAX),
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_handshake_failed(server_name: Host, error: &std::io::Error) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TlsHandshakeFailed {
                timestamp_ns: clock_monotonic_ns(),
                server_name,
                error_kind: io_error_kind_code(error.kind()),
                error_raw_os: io_error_raw_os_code(error),
            },
            &handle,
        );
    }
}
