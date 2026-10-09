//! Reading a first flight back from the wire: what any observer sees, and what one that can
//! open the Initial packets sees.
//!
//! The pipeline here needs no cryptography of its own: it splits datagrams, and — given a
//! [`KeyProvider`] — removes Initial protection, reassembles the ClientHello and reads the
//! transport parameters. Initial keys derive from the destination connection ID and version salt
//! (RFC 9001 §5.2), so both a passive observer and the destination server can supply them; the
//! keys themselves come from the engine's TLS backend behind that seam.
//!
//! Most callers hand a client's first datagrams (the ones sent before it hears from the server)
//! and a [`KeyProvider`] to [`first_flight`], which runs the whole pipeline and returns a
//! [`FirstFlight`] summary to fingerprint or turn into a [`crate::profile::QuicProfile`]. The
//! steps are also public for finer control: [`observe`] splits one datagram with no keys;
//! [`ObservedDatagram::unprotect_initials`] opens that datagram's Initial packets into
//! [`InitialPacket`]s; [`client_hello`] takes those `InitialPacket`s from across the whole flight
//! and reassembles the ClientHello from their CRYPTO frames; [`transport_parameters`] reads it,
//! and [`version_information`] pulls the negotiated/available versions out of those. So the
//! packets `client_hello` wants are simply the `InitialPacket`s `unprotect_initials` returned.

use alloc::vec::Vec;
use core::{fmt, ops::Range};

use rama_core::{
    bytes::{Buf, BytesMut},
    extensions::Extension,
};
use rama_tls::{
    ExtensionId,
    client::{
        ClientHello, ClientHelloExtension, ClientHelloHandshakePrefix,
        parse_client_hello_message_prefix,
    },
};
use rama_utils::octets;
use serde::{Deserialize, Serialize};

use crate::{
    MAX_CID_SIZE, Side, Version,
    coding::{BufExt, bounded_len},
    crypto::{HeaderKey, PacketKey},
    frame::{self, Frame},
    packet::{FixedLengthConnectionIdParser, PartialDecode},
    profile::{PaddingPlacement, ParameterId},
    version::{LongKind, VersionInformation},
};

/// The Initial keys that open one direction of a captured flight.
///
/// The key types are the provider's own: an observer built on a concrete AEAD passes them through
/// unboxed, while the engine, whose TLS backend hands back erased keys, sets them to `Box<dyn …>`.
pub struct InitialKeys<H, P> {
    pub header: H,
    pub packet: P,
}

/// Supplies the Initial keys needed to open a captured first flight.
///
/// A passive observer and the destination server both derive Initial keys from the destination
/// connection ID and version salt (RFC 9001 §5.2), so both can implement this. The key types are
/// associated so a provider yields whatever it holds without a forced allocation.
pub trait KeyProvider {
    /// The header-protection key this provider yields.
    type Header: HeaderKey;
    /// The packet-protection key this provider yields.
    type Packet: PacketKey;

    /// Initial keys for `dcid` under `version`, as `side` opens them: a server opens the client's
    /// Initials, a client the server's.
    fn initial_keys(
        &self,
        version: Version,
        dcid: &[u8],
        side: Side,
    ) -> Result<InitialKeys<Self::Header, Self::Packet>, CaptureError>;
}

/// Why a datagram or packet could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaptureError {
    /// The bytes do not form a QUIC packet.
    Malformed(&'static str),
    /// A long header carries a version this crate does not implement.
    UnknownVersion(Version),
    /// The Initial keys could not be derived or did not open the packet.
    Undecryptable,
    /// A configured observation budget was exhausted.
    LimitExceeded(&'static str),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed QUIC datagram: {what}"),
            Self::UnknownVersion(version) => write!(f, "unknown QUIC version {version}"),
            Self::Undecryptable => f.write_str("the Initial packet did not decrypt"),
            Self::LimitExceeded(what) => write!(f, "QUIC capture limit exceeded: {what}"),
        }
    }
}

impl core::error::Error for CaptureError {}

/// Retention and work budgets for a first-flight observation.
///
/// Limits are local policy, independent of the transport's admission limits. Exhaustion
/// stops capture, never the connection. The default ClientHello bound matches server peeking.
#[derive(Debug, Clone, Copy)]
pub struct CaptureLimits {
    /// Maximum datagrams inspected per attempt, including non-Initial datagrams.
    pub datagrams: usize,
    /// Maximum total datagram bytes inspected per attempt.
    pub bytes: usize,
    /// Maximum Initial packets retained, including retransmissions.
    pub packets: usize,
    /// Maximum retained frame classifications; adjacent PADDING counts once.
    pub frames: usize,
    /// Maximum CRYPTO fragments retained across Initial packets.
    pub crypto_fragments: usize,
    /// Maximum assembled ClientHello message bytes, including the handshake header.
    pub client_hello_bytes: usize,
    /// Maximum transport parameter entries, including unknown identifiers.
    pub parameters: usize,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            datagrams: 32,
            bytes: octets::kib(256),
            packets: 128,
            frames: 2048,
            crypto_fragments: 128,
            client_hello_bytes: octets::kib(16),
            parameters: 256,
        }
    }
}

/// Which parts of an observation are suitable as exact comparison inputs.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct CaptureCompleteness {
    pub datagrams: bool,
    pub frames: bool,
    pub client_hello: bool,
    pub transport_parameters: bool,
    /// False when only the accepted, post-Retry attempt was observed.
    pub original_attempt: bool,
}

impl CaptureCompleteness {
    #[must_use]
    pub fn is_complete(self) -> bool {
        self.datagrams
            && self.frames
            && self.client_hello
            && self.transport_parameters
            && self.original_attempt
    }
}

/// A bounded server observation of one attempt, including its Retry lineage.
///
/// The parsed ClientHello belongs to the connection's SecureTransport extension.
#[derive(Debug, Clone, Serialize)]
pub struct QuicObservation {
    pub connection_id: Vec<u8>,
    pub attempt_id: Vec<u8>,
    pub retry_parent: Option<Vec<u8>>,
    pub first_flight: Option<FirstFlight>,
    pub transport_parameters: Vec<RawParameter>,
    /// Retained internally; display and profile serialization omit the raw handshake.
    #[serde(skip)]
    pub client_hello_message: Vec<u8>,
    pub completeness: CaptureCompleteness,
}

impl Extension for QuicObservation {}

fn within(value: usize, limit: usize, name: &'static str) -> Result<(), CaptureError> {
    if value > limit {
        Err(CaptureError::LimitExceeded(name))
    } else {
        Ok(())
    }
}

/// What kind of packet a header announces (RFC 8999 §5, RFC 9000 §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketKind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    /// A short header: 1-RTT.
    Short,
    VersionNegotiation,
}

impl From<LongKind> for PacketKind {
    fn from(kind: LongKind) -> Self {
        match kind {
            LongKind::Initial => Self::Initial,
            LongKind::ZeroRtt => Self::ZeroRtt,
            LongKind::Handshake => Self::Handshake,
            LongKind::Retry => Self::Retry,
        }
    }
}

/// One packet of a datagram as an observer without keys sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedPacket {
    pub first_byte: u8,
    pub kind: PacketKind,
    pub version: Option<Version>,
    pub dcid: Vec<u8>,
    /// Long headers only.
    pub scid: Option<Vec<u8>>,
    /// Initial packets only.
    pub token: Option<Vec<u8>>,
    /// Where the packet sits in the datagram.
    pub range: Range<usize>,
}

/// A datagram split into its packets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedDatagram {
    pub len: usize,
    pub packets: Vec<ObservedPacket>,
    /// Bytes after the last packet that are not a packet, such as zero padding.
    pub trailing: usize,
}

fn varint(buf: &[u8], at: &mut usize) -> Result<u64, CaptureError> {
    let first = *buf
        .get(*at)
        .ok_or(CaptureError::Malformed("truncated varint"))?;
    let len = 1usize << (first >> 6);
    let bytes = buf
        .get(*at..*at + len)
        .ok_or(CaptureError::Malformed("truncated varint"))?;
    *at += len;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = value << 8 | u64::from(*byte);
    }
    Ok(value)
}

fn cid(buf: &[u8], at: &mut usize) -> Result<Vec<u8>, CaptureError> {
    let len = usize::from(
        *buf.get(*at)
            .ok_or(CaptureError::Malformed("truncated connection ID length"))?,
    );
    let id = buf
        .get(*at + 1..*at + 1 + len)
        .ok_or(CaptureError::Malformed("truncated connection ID"))?
        .to_vec();
    *at += 1 + len;
    Ok(id)
}

/// Split a datagram into packets using only the invariant layout (RFC 8999 §5) and each
/// version's type bits and Length fields. A short header takes the rest of the datagram; bytes
/// after a packet that cannot start another one are reported as trailing.
pub fn observe(datagram: &[u8]) -> Result<ObservedDatagram, CaptureError> {
    observe_with_limits(datagram, &CaptureLimits::default())
}

/// Split one datagram under explicit local observation budgets.
pub fn observe_with_limits(
    datagram: &[u8],
    limits: &CaptureLimits,
) -> Result<ObservedDatagram, CaptureError> {
    within(datagram.len(), limits.bytes, "bytes")?;
    let mut packets = Vec::new();
    let mut at = 0;
    let mut trailing = 0;
    while at < datagram.len() {
        if datagram[at] == 0 && !packets.is_empty() {
            trailing = datagram.len() - at;
            break;
        }
        within(packets.len().saturating_add(1), limits.packets, "packets")?;
        let start = at;
        let first_byte = datagram[at];
        if first_byte & 0x80 == 0 {
            if packets.is_empty() {
                // A first byte of zero is not a packet; a 1-RTT packet cannot lead a first
                // flight either, but it is a packet.
                if first_byte == 0 {
                    return Err(CaptureError::Malformed("datagram starts with padding"));
                }
            }
            packets.push(ObservedPacket {
                first_byte,
                kind: PacketKind::Short,
                version: None,
                dcid: Vec::new(),
                scid: None,
                token: None,
                range: start..datagram.len(),
            });
            break;
        }
        let version = Version::from_be_bytes(
            datagram
                .get(at + 1..at + 5)
                .ok_or(CaptureError::Malformed("truncated version"))?
                .try_into()
                .map_err(|_error| CaptureError::Malformed("truncated version"))?,
        );
        at += 5;
        let dcid = cid(datagram, &mut at)?;
        let scid = cid(datagram, &mut at)?;
        if version.is_negotiation() {
            packets.push(ObservedPacket {
                first_byte,
                kind: PacketKind::VersionNegotiation,
                version: Some(version),
                dcid,
                scid: Some(scid),
                token: None,
                range: start..datagram.len(),
            });
            break;
        }
        let wire = version
            .wire()
            .ok_or(CaptureError::UnknownVersion(version))?;
        let kind = wire.long_kind(first_byte);
        let mut token = None;
        if kind == LongKind::Retry {
            packets.push(ObservedPacket {
                first_byte,
                kind: PacketKind::Retry,
                version: Some(version),
                dcid,
                scid: Some(scid),
                token: None,
                range: start..datagram.len(),
            });
            break;
        }
        if kind == LongKind::Initial {
            let len = bounded_len(
                varint(datagram, &mut at)?,
                datagram.len().saturating_sub(at),
            )
            .map_err(|_error| CaptureError::Malformed("truncated token"))?;
            token = Some(
                datagram
                    .get(at..at + len)
                    .ok_or(CaptureError::Malformed("truncated token"))?
                    .to_vec(),
            );
            at += len;
        }
        let length = bounded_len(
            varint(datagram, &mut at)?,
            datagram.len().saturating_sub(at),
        )
        .map_err(|_error| CaptureError::Malformed("packet length exceeds datagram"))?;
        let end = at + length;
        packets.push(ObservedPacket {
            first_byte,
            kind: kind.into(),
            version: Some(version),
            dcid,
            scid: Some(scid),
            token,
            range: start..end,
        });
        at = end;
    }
    Ok(ObservedDatagram {
        len: datagram.len(),
        packets,
        trailing,
    })
}

/// A frame as an observer with Initial keys sees it; consecutive PADDING bytes are one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservedFrame {
    Padding { len: usize },
    Ping,
    Ack,
    Crypto { offset: u64, len: usize },
    Other { ty: u64 },
}

/// An Initial packet after its protection is removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialPacket {
    pub header: ObservedPacket,
    pub packet_number: u64,
    pub packet_number_len: u8,
    pub frames: Vec<ObservedFrame>,
    /// The CRYPTO data, by offset.
    pub crypto: Vec<(u64, Vec<u8>)>,
}

impl ObservedDatagram {
    /// Remove the protection of every Initial packet in `datagram` with keys from `provider`,
    /// as `side` receives them: a server opens a client's Initials, a client a server's.
    /// `original_dcid` is the destination connection ID the keys derive from, which is the
    /// packet's own for a client's first flight.
    pub fn unprotect_initials<P: KeyProvider>(
        &self,
        datagram: &[u8],
        provider: &P,
        side: Side,
        original_dcid: Option<&[u8]>,
    ) -> Result<Vec<InitialPacket>, CaptureError> {
        self.unprotect_initials_with_limits(
            datagram,
            provider,
            side,
            original_dcid,
            &CaptureLimits::default(),
        )
    }

    /// Remove Initial protection without exceeding the supplied capture budgets.
    pub fn unprotect_initials_with_limits<P: KeyProvider>(
        &self,
        datagram: &[u8],
        provider: &P,
        side: Side,
        original_dcid: Option<&[u8]>,
        limits: &CaptureLimits,
    ) -> Result<Vec<InitialPacket>, CaptureError> {
        within(datagram.len(), limits.bytes, "bytes")?;
        within(self.packets.len(), limits.packets, "packets")?;
        let mut frame_count = 0usize;
        let mut fragment_count = 0usize;
        let mut copied_bytes = 0usize;
        let mut initials = Vec::new();
        for observed in &self.packets {
            let metadata_bytes = observed
                .dcid
                .len()
                .saturating_add(observed.scid.as_ref().map_or(0, Vec::len))
                .saturating_add(observed.token.as_ref().map_or(0, Vec::len));
            copied_bytes = copied_bytes
                .saturating_add(metadata_bytes)
                .saturating_add(observed.range.end.saturating_sub(observed.range.start));
            within(copied_bytes, limits.bytes, "retained bytes")?;
            if observed.kind != PacketKind::Initial {
                continue;
            }
            let Some(version) = observed.version else {
                continue;
            };
            let seed = original_dcid.unwrap_or(&observed.dcid);
            // Every version this crate implements limits connection IDs to 20 bytes (RFC 9000
            // §17.2); a longer one is refused before it reaches key derivation.
            if seed.len() > MAX_CID_SIZE {
                return Err(CaptureError::Malformed(
                    "Initial connection ID longer than 20 bytes",
                ));
            }
            let keys = provider.initial_keys(version, seed, side)?;
            let header_key: &dyn HeaderKey = &keys.header;
            // The observation may come from elsewhere (it is serializable), so its range is not
            // trusted to fit the datagram handed in.
            let bytes = BytesMut::from(
                datagram
                    .get(observed.range.clone())
                    .ok_or(CaptureError::Malformed("packet range outside the datagram"))?,
            );
            let (decode, _) = PartialDecode::new(
                bytes,
                &FixedLengthConnectionIdParser::new(0),
                &[version],
                true,
            )
            .map_err(|_error| CaptureError::Malformed("Initial header"))?;
            let mut packet = decode
                .finish_protected(header_key)
                .map_err(|_error| CaptureError::Undecryptable)?;
            let number = packet.header.number().ok_or(CaptureError::Undecryptable)?;
            let packet_number_len = number.len() as u8;
            let packet_number = number.expand(0);
            keys.packet
                .decrypt(packet_number, &packet.header_data, &mut packet.payload)
                .map_err(|_error| CaptureError::Undecryptable)?;
            let mut frames = Vec::new();
            let mut crypto = Vec::new();
            let iter = frame::Iter::new(packet.payload.freeze())
                .map_err(|_error| CaptureError::Malformed("empty Initial payload"))?;
            for item in iter {
                let item = item.map_err(|_error| CaptureError::Malformed("frame"))?;
                if !matches!(item, Frame::Padding)
                    || !matches!(frames.last(), Some(ObservedFrame::Padding { .. }))
                {
                    frame_count = frame_count.saturating_add(1);
                    within(frame_count, limits.frames, "frames")?;
                }
                match item {
                    Frame::Padding => match frames.last_mut() {
                        Some(ObservedFrame::Padding { len }) => *len += 1,
                        _ => frames.push(ObservedFrame::Padding { len: 1 }),
                    },
                    Frame::Ping => frames.push(ObservedFrame::Ping),
                    Frame::Ack(_) => frames.push(ObservedFrame::Ack),
                    Frame::Crypto(frame) => {
                        fragment_count = fragment_count.saturating_add(1);
                        within(fragment_count, limits.crypto_fragments, "CRYPTO fragments")?;
                        copied_bytes = copied_bytes.saturating_add(frame.data.len());
                        within(copied_bytes, limits.bytes, "retained bytes")?;
                        frames.push(ObservedFrame::Crypto {
                            offset: frame.offset,
                            len: frame.data.len(),
                        });
                        crypto.push((frame.offset, frame.data.to_vec()));
                    }
                    other => frames.push(ObservedFrame::Other {
                        ty: other.ty().as_u64(),
                    }),
                }
            }
            initials.push(InitialPacket {
                header: observed.clone(),
                packet_number,
                packet_number_len,
                frames,
                crypto,
            });
        }
        Ok(initials)
    }
}

/// The ClientHello reassembled from Initial packets, when the CRYPTO data covers it from
/// offset zero through its length.
#[must_use]
pub fn client_hello(initials: &[InitialPacket]) -> Option<Vec<u8>> {
    client_hello_with_limits(initials, &CaptureLimits::default())
        .ok()
        .flatten()
}

/// Reassemble a bounded ClientHello, including for caller-supplied packet records.
/// Missing or invalid handshake data returns `Ok(None)`; exhausted budgets return an error.
pub fn client_hello_with_limits(
    initials: &[InitialPacket],
    limits: &CaptureLimits,
) -> Result<Option<Vec<u8>>, CaptureError> {
    within(initials.len(), limits.packets, "packets")?;
    let fragments = initials
        .iter()
        .try_fold(0usize, |n, packet| n.checked_add(packet.crypto.len()))
        .ok_or(CaptureError::LimitExceeded("CRYPTO fragments"))?;
    within(fragments, limits.crypto_fragments, "CRYPTO fragments")?;
    let mut chunks: Vec<(u64, &[u8])> = initials
        .iter()
        .flat_map(|packet| {
            packet
                .crypto
                .iter()
                .map(|(offset, data)| (*offset, &data[..]))
        })
        .collect();
    chunks.sort_by_key(|(offset, _)| *offset);
    let mut stream: Vec<u8> = Vec::new();
    for (offset, data) in chunks {
        let Ok(offset) = usize::try_from(offset) else {
            return Ok(None);
        };
        if offset > stream.len() {
            return Ok(None);
        }
        if let Some(new) = data.get(stream.len() - offset..) {
            let room = limits.client_hello_bytes.saturating_sub(stream.len());
            stream.extend_from_slice(&new[..new.len().min(room)]);
            if stream.len() < 4 && new.len() > room {
                return Err(CaptureError::LimitExceeded("ClientHello bytes"));
            }
        }
        if let Some(&[kind, a, b, c]) = stream.get(..4) {
            if kind != 0x01 {
                return Ok(None);
            }
            let len = 4 + (usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c));
            within(len, limits.client_hello_bytes, "ClientHello bytes")?;
            if stream.len() >= len {
                stream.truncate(len);
                return Ok(Some(stream));
            }
        }
    }
    Ok(None)
}

/// A transport parameter as it was sent: identifier and raw value, in wire order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawParameter {
    pub id: ParameterId,
    pub value: Vec<u8>,
}

/// The transport parameters of a ClientHello handshake message, in the order they were sent.
pub fn transport_parameters(client_hello: &[u8]) -> Result<Vec<RawParameter>, CaptureError> {
    transport_parameters_with_limits(client_hello, &CaptureLimits::default())
}

/// Read ordered parameter values under a byte and entry budget.
pub fn transport_parameters_with_limits(
    client_hello: &[u8],
    limits: &CaptureLimits,
) -> Result<Vec<RawParameter>, CaptureError> {
    within(
        client_hello.len(),
        limits.client_hello_bytes,
        "ClientHello bytes",
    )?;
    let ClientHelloHandshakePrefix::Complete(hello) =
        parse_client_hello_message_prefix(client_hello)
    else {
        return Err(CaptureError::Malformed("ClientHello"));
    };
    transport_parameters_from_hello(&hello, limits)
}

/// Read parameter values from an already parsed hello without parsing it again.
pub fn transport_parameters_from_hello(
    hello: &ClientHello,
    limits: &CaptureLimits,
) -> Result<Vec<RawParameter>, CaptureError> {
    let data = hello
        .extensions()
        .iter()
        .find_map(|ext| match ext {
            ClientHelloExtension::Opaque { id, data }
                if *id == ExtensionId::QUIC_TRANSPORT_PARAMETERS =>
            {
                Some(data)
            }
            _ => None,
        })
        .ok_or(CaptureError::Malformed("no quic_transport_parameters"))?;
    within(
        data.len(),
        limits.client_hello_bytes,
        "transport parameter bytes",
    )?;
    let mut reader = &data[..];
    let mut parameters = Vec::new();
    while reader.has_remaining() {
        within(
            parameters.len().saturating_add(1),
            limits.parameters,
            "transport parameters",
        )?;
        let id = reader
            .get_var()
            .map_err(|_error| CaptureError::Malformed("transport parameter id"))?;
        let len = reader
            .get_var()
            .map_err(|_error| CaptureError::Malformed("transport parameter length"))?;
        let len = bounded_len(len, reader.remaining())
            .map_err(|_error| CaptureError::Malformed("transport parameter value"))?;
        let value = reader[..len].to_vec();
        reader.advance(len);
        parameters.push(RawParameter {
            id: ParameterId(id),
            value,
        });
    }
    Ok(parameters)
}

/// The `version_information` parameter among `parameters`, decoded as a client's.
#[must_use]
pub fn version_information(parameters: &[RawParameter]) -> Option<VersionInformation> {
    let raw = parameters
        .iter()
        .find(|parameter| parameter.id == ParameterId::VERSION_INFORMATION)?;
    VersionInformation::read(true, raw.value.len(), &mut &raw.value[..]).ok()
}

/// What a client's first flight looks like, as the profile tests compare it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstFlight {
    pub datagram_sizes: Vec<usize>,
    pub trailing_bytes: Vec<usize>,
    pub version: Version,
    pub dcid_len: usize,
    pub scid_len: usize,
    pub token_len: usize,
    pub first_packet_number: u64,
    pub packet_number_len: u8,
    /// Frames per Initial packet, in order.
    pub frames: Vec<Vec<ObservedFrame>>,
    /// Where padding went.
    pub padding: PaddingPlacement,
    /// Whether the datagram coalesces packets of different kinds.
    pub coalesced: bool,
    pub parameters: Vec<ParameterId>,
    pub chosen_version: Option<Version>,
    pub available_versions: Vec<Version>,
    /// Packet numbers in observed order; duplicates are retained as retransmission evidence.
    pub packet_numbers: Vec<u64>,
    /// Whether the complete ClientHello and its parameters were available.
    pub complete: bool,
}

/// Read a client's first flight: the datagrams it sent before hearing from the server.
pub fn first_flight<P: KeyProvider>(
    datagrams: &[&[u8]],
    provider: &P,
) -> Result<FirstFlight, CaptureError> {
    first_flight_with_limits(datagrams, provider, &CaptureLimits::default())
}

/// Read a flight with explicit budgets applied before retaining peer-controlled data.
pub fn first_flight_with_limits<P: KeyProvider>(
    datagrams: &[&[u8]],
    provider: &P,
    limits: &CaptureLimits,
) -> Result<FirstFlight, CaptureError> {
    if datagrams.is_empty() {
        return Err(CaptureError::Malformed("no datagrams"));
    }
    within(datagrams.len(), limits.datagrams, "datagrams")?;
    let bytes = datagrams
        .iter()
        .try_fold(0usize, |n, d| n.checked_add(d.len()))
        .ok_or(CaptureError::LimitExceeded("bytes"))?;
    within(bytes, limits.bytes, "bytes")?;
    let mut observed = Vec::new();
    let mut admission = *limits;
    for datagram in datagrams {
        let value = observe_with_limits(datagram, &admission)?;
        admission.packets = admission.packets.saturating_sub(value.packets.len());
        observed.push(value);
    }
    let lead = observed[0]
        .packets
        .first()
        .filter(|packet| packet.kind == PacketKind::Initial)
        .ok_or(CaptureError::Malformed(
            "the first packet is not an Initial",
        ))?
        .clone();
    let packet_count = observed
        .iter()
        .try_fold(0usize, |n, d| n.checked_add(d.packets.len()))
        .ok_or(CaptureError::LimitExceeded("packets"))?;
    within(packet_count, limits.packets, "packets")?;
    let mut initials = Vec::new();
    let mut remaining = *limits;
    for (datagram, observed) in datagrams.iter().zip(&observed) {
        let packets = observed.unprotect_initials_with_limits(
            datagram,
            provider,
            Side::Server,
            Some(&lead.dcid),
            &remaining,
        )?;
        for packet in &packets {
            remaining.frames = remaining.frames.saturating_sub(packet.frames.len());
            remaining.crypto_fragments = remaining
                .crypto_fragments
                .saturating_sub(packet.crypto.len());
        }
        initials.extend(packets);
    }
    let hello = client_hello_with_limits(&initials, limits)?;
    let parameters = hello
        .as_deref()
        .map(|hello| transport_parameters_with_limits(hello, limits))
        .transpose()?
        .unwrap_or_default();
    let info = version_information(&parameters);
    let padding = if observed.iter().any(|datagram| datagram.trailing > 0) {
        PaddingPlacement::DatagramTail
    } else {
        PaddingPlacement::Frames
    };
    let coalesced = observed.iter().any(|datagram| {
        datagram
            .packets
            .iter()
            .any(|packet| packet.kind != PacketKind::Initial)
    });
    let first_initial = initials
        .first()
        .ok_or(CaptureError::Malformed("no Initial packets"))?;
    Ok(FirstFlight {
        datagram_sizes: observed.iter().map(|datagram| datagram.len).collect(),
        trailing_bytes: observed.iter().map(|datagram| datagram.trailing).collect(),
        version: lead.version.unwrap_or(Version::V1),
        dcid_len: lead.dcid.len(),
        scid_len: lead.scid.as_ref().map_or(0, Vec::len),
        token_len: lead.token.as_ref().map_or(0, Vec::len),
        first_packet_number: first_initial.packet_number,
        packet_number_len: first_initial.packet_number_len,
        frames: initials
            .iter()
            .enumerate()
            .filter(|(i, packet)| {
                !initials[..*i]
                    .iter()
                    .any(|earlier| earlier.packet_number == packet.packet_number)
            })
            .map(|(_, packet)| packet.frames.clone())
            .collect(),
        padding,
        coalesced,
        parameters: parameters.iter().map(|parameter| parameter.id).collect(),
        chosen_version: info.as_ref().map(VersionInformation::chosen),
        available_versions: info.map_or_else(Vec::new, |info| info.available().to_vec()),
        packet_numbers: initials.iter().map(|packet| packet.packet_number).collect(),
        complete: hello.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VarInt;
    use rama_core::bytes::BufMut;
    use std::slice;

    fn hello_with_parameter_len(len: u64, value: &[u8]) -> Vec<u8> {
        let mut parameters = vec![0x21];
        parameters.put_u64(len | (0b11 << 62));
        parameters.extend_from_slice(value);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&((parameters.len() + 4) as u16).to_be_bytes());
        body.extend_from_slice(&[0, 0x39]);
        body.extend_from_slice(&(parameters.len() as u16).to_be_bytes());
        body.extend_from_slice(&parameters);
        let len = body.len() as u32;
        let mut hello = vec![1, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        hello.extend_from_slice(&body);
        hello
    }

    #[test]
    fn captured_parameter_lengths_are_bounded_before_narrowing() {
        for len in [1u64 << 32, (1u64 << 32) + 1, VarInt::MAX.into_inner()] {
            transport_parameters(&hello_with_parameter_len(len, &[])).unwrap_err();
        }
        for value in [b"".as_slice(), b"a", b"abc"] {
            let parameters =
                transport_parameters(&hello_with_parameter_len(value.len() as u64, value)).unwrap();
            assert_eq!(parameters.len(), 1);
            assert_eq!(parameters[0].id.0, 0x21);
            assert_eq!(parameters[0].value, value);
        }
    }
    #[test]
    fn observation_budgets_bound_bytes_packets_hello_and_parameters() {
        let wire = [0x40, 1, 2, 3];
        observe_with_limits(
            &wire,
            &CaptureLimits {
                bytes: wire.len(),
                ..CaptureLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            observe_with_limits(
                &wire,
                &CaptureLimits {
                    bytes: wire.len() - 1,
                    ..CaptureLimits::default()
                }
            ),
            Err(CaptureError::LimitExceeded("bytes"))
        );
        assert_eq!(
            observe_with_limits(
                &wire,
                &CaptureLimits {
                    packets: 0,
                    ..CaptureLimits::default()
                }
            ),
            Err(CaptureError::LimitExceeded("packets"))
        );
        let hello = hello_with_parameter_len(3, b"abc");
        let packet = InitialPacket {
            header: ObservedPacket {
                first_byte: 0xc0,
                kind: PacketKind::Initial,
                version: Some(Version::V1),
                dcid: vec![],
                scid: None,
                token: None,
                range: 0..0,
            },
            packet_number: 0,
            packet_number_len: 1,
            frames: vec![],
            crypto: vec![(0, hello.clone())],
        };
        assert_eq!(
            client_hello_with_limits(
                slice::from_ref(&packet),
                &CaptureLimits {
                    client_hello_bytes: hello.len(),
                    ..CaptureLimits::default()
                }
            ),
            Ok(Some(hello.clone()))
        );
        for limits in [
            CaptureLimits {
                packets: 0,
                ..CaptureLimits::default()
            },
            CaptureLimits {
                crypto_fragments: 0,
                ..CaptureLimits::default()
            },
            CaptureLimits {
                client_hello_bytes: hello.len() - 1,
                ..CaptureLimits::default()
            },
        ] {
            assert!(matches!(
                client_hello_with_limits(slice::from_ref(&packet), &limits),
                Err(CaptureError::LimitExceeded(_))
            ));
        }
        assert_eq!(
            transport_parameters_with_limits(
                &hello,
                &CaptureLimits {
                    parameters: 0,
                    ..CaptureLimits::default()
                }
            ),
            Err(CaptureError::LimitExceeded("transport parameters"))
        );
        assert_eq!(
            transport_parameters_with_limits(
                &hello,
                &CaptureLimits {
                    client_hello_bytes: hello.len() - 1,
                    ..CaptureLimits::default()
                }
            ),
            Err(CaptureError::LimitExceeded("ClientHello bytes"))
        );
        let huge_offset = InitialPacket {
            crypto: vec![(u64::MAX, vec![0])],
            ..packet
        };
        assert!(client_hello(&[huge_offset]).is_none());
    }
}
