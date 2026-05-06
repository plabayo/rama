//! Pre-defined [dial9] events for the BoringSSL client handshake.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry

use dial9_tokio_telemetry::telemetry::{TelemetryHandle, clock_monotonic_ns, record_event};
use dial9_trace_format::{
    EventEncoder, TraceEvent, TraceField,
    types::{FieldType, FieldValueRef},
};
use rama_net::{
    address::Domain,
    tls::{ApplicationProtocol, ProtocolVersion},
};
use std::io::{self, Write};

#[derive(Debug, Clone)]
pub struct MaybeServerName(Option<Domain>);

impl TraceField for MaybeServerName {
    type Ref<'a> = &'a str;

    fn field_type() -> FieldType {
        FieldType::String
    }

    fn encode<W: Write>(&self, enc: &mut EventEncoder<'_, W>) -> io::Result<()> {
        match self.0.as_ref() {
            Some(domain) => enc.write_string(domain.as_str()),
            None => enc.write_string(""),
        }
    }

    fn decode_ref<'a>(val: &FieldValueRef<'a>) -> Option<Self::Ref<'a>> {
        match val {
            FieldValueRef::String(s) => Some(s),
            _ => None,
        }
    }
}

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

/// TLS handshake failed.
#[derive(TraceEvent)]
pub struct TlsHandshakeFailed {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub server_name: MaybeServerName,
    /// `1` for builder errors, `2` for handshake errors with an I/O cause,
    /// `3` for handshake errors with an SSL stack, `4` otherwise.
    pub error_kind: u32,
    /// Encoded `std::io::ErrorKind`, if the handshake surfaced one.
    pub io_error_kind: Option<u32>,
}

#[inline]
pub(crate) fn record_handshake_started(server_name: Option<Domain>) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TlsHandshakeStarted {
                timestamp_ns: clock_monotonic_ns(),
                server_name: MaybeServerName(server_name),
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_handshake_completed(
    server_name: Option<Domain>,
    protocol_version: ProtocolVersion,
    alpn_selected: Option<ApplicationProtocol>,
    peer_cert_chain_depth: usize,
) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TlsHandshakeCompleted {
                timestamp_ns: clock_monotonic_ns(),
                server_name: MaybeServerName(server_name),
                protocol_version,
                alpn_selected: MaybeAlpnSelected(alpn_selected),
                peer_cert_chain_depth: u32::try_from(peer_cert_chain_depth).unwrap_or(u32::MAX),
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_handshake_failed(
    server_name: Option<Domain>,
    error_kind: u32,
    io_error_kind: Option<u32>,
) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TlsHandshakeFailed {
                timestamp_ns: clock_monotonic_ns(),
                server_name: MaybeServerName(server_name),
                error_kind,
                io_error_kind,
            },
            &handle,
        );
    }
}
