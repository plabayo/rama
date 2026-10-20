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
    bytes::{Buf, Bytes, BytesMut},
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
use serde::{
    Deserialize, Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

use crate::{
    MAX_CID_SIZE, Side, VarInt, Version,
    coding::{BufExt, bounded_len},
    crypto::{HeaderKey, PacketKey},
    frame::{self, Frame},
    packet::{FixedLengthConnectionIdParser, PartialDecode},
    profile::PaddingPlacement,
    transport_parameters::TransportParameterId,
    version::{LongKind, VersionInformation},
};

mod assembly;
pub use assembly::ClientHelloAssembly;

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
    /// A local reconstruction policy requires minimal parameter framing.
    NonminimalParameterEncoding,
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed QUIC datagram: {what}"),
            Self::UnknownVersion(version) => write!(f, "unknown QUIC version {version}"),
            Self::Undecryptable => f.write_str("the Initial packet did not decrypt"),
            Self::LimitExceeded(what) => write!(f, "QUIC capture limit exceeded: {what}"),
            Self::NonminimalParameterEncoding => {
                f.write_str("transport parameter framing violates the minimal-encoding policy")
            }
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
/// Debug output contains shape metadata only. Serialization omits connection IDs
/// and raw ClientHello bytes, and replaces connection-specific parameter values
/// with their lengths. Explicit field access remains available to capture consumers.
#[derive(Clone, Serialize)]
pub struct QuicObservation {
    #[serde(skip)]
    pub connection_id: Vec<u8>,
    #[serde(skip)]
    pub attempt_id: Vec<u8>,
    #[serde(skip)]
    pub retry_parent: Option<Vec<u8>>,
    pub first_flight: Option<FirstFlight>,
    #[serde(serialize_with = "serialize_observation_parameters")]
    pub transport_parameters: Vec<RawParameter>,
    /// Retained internally; display and profile serialization omit the raw handshake.
    #[serde(skip)]
    pub client_hello_message: Vec<u8>,
    pub completeness: CaptureCompleteness,
}

impl fmt::Debug for QuicObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicObservation")
            .field("connection_id_len", &self.connection_id.len())
            .field("attempt_id_len", &self.attempt_id.len())
            .field(
                "retry_parent_len",
                &self.retry_parent.as_ref().map(Vec::len),
            )
            .field("first_flight", &self.first_flight)
            .field(
                "transport_parameter_count",
                &self.transport_parameters.len(),
            )
            .field("client_hello_len", &self.client_hello_message.len())
            .field("completeness", &self.completeness)
            .finish()
    }
}

// RawParameter remains the explicit wire codec. The observation's automatic
// output follows the same connection-value classification as reusable profiles.
struct ObservationParameter<'a>(&'a RawParameter);

impl Serialize for ObservationParameter<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("ObservationParameter", 2)?;
        value.serialize_field("id", &self.0.id)?;
        if self.0.id.has_connection_specific_value() {
            value.serialize_field("length", &self.0.value.len())?;
        } else {
            value.serialize_field("value", &self.0.value)?;
        }
        value.end()
    }
}

fn serialize_observation_parameters<S: Serializer>(
    parameters: &[RawParameter],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut values = serializer.serialize_seq(Some(parameters.len()))?;
    for parameter in parameters {
        values.serialize_element(&ObservationParameter(parameter))?;
    }
    values.end()
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

/// Retain one native frame's structural facts without copying its body.
pub(crate) fn record_frame(frames: &mut Vec<ObservedFrame>, frame: &Frame) {
    match frame {
        Frame::Padding => match frames.last_mut() {
            Some(ObservedFrame::Padding { len }) => *len += 1,
            _ => frames.push(ObservedFrame::Padding { len: 1 }),
        },
        Frame::Ping => frames.push(ObservedFrame::Ping),
        Frame::Ack(_) => frames.push(ObservedFrame::Ack),
        Frame::Crypto(frame) => frames.push(ObservedFrame::Crypto {
            offset: frame.offset,
            len: frame.data.len(),
        }),
        other => frames.push(ObservedFrame::Other {
            ty: other.ty().as_u64(),
        }),
    }
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
            let keys = initial_keys(
                provider,
                version,
                original_dcid.unwrap_or(&observed.dcid),
                side,
            )?;
            let OpenedInitial {
                packet_number,
                packet_number_len,
                payload,
            } = open_initial(datagram, observed, version, &keys)?;
            let mut frames = Vec::new();
            let mut crypto = Vec::new();
            let iter = frame::Iter::new(payload)
                .map_err(|_error| CaptureError::Malformed("empty Initial payload"))?;
            for item in iter {
                let item = item.map_err(|_error| CaptureError::Malformed("frame"))?;
                if !matches!(item, Frame::Padding)
                    || !matches!(frames.last(), Some(ObservedFrame::Padding { .. }))
                {
                    frame_count = frame_count.saturating_add(1);
                    within(frame_count, limits.frames, "frames")?;
                }
                if let Frame::Crypto(frame) = &item {
                    fragment_count = fragment_count.saturating_add(1);
                    within(fragment_count, limits.crypto_fragments, "CRYPTO fragments")?;
                    copied_bytes = copied_bytes.saturating_add(frame.data.len());
                    within(copied_bytes, limits.bytes, "retained bytes")?;
                    crypto.push((frame.offset, frame.data.to_vec()));
                }
                record_frame(&mut frames, &item);
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

/// Initial keys for `dcid`, refusing an identifier no implemented version allows.
pub(crate) fn initial_keys<P: KeyProvider>(
    provider: &P,
    version: Version,
    dcid: &[u8],
    side: Side,
) -> Result<InitialKeys<P::Header, P::Packet>, CaptureError> {
    // Every version this crate implements limits connection IDs to 20 bytes (RFC 9000 §17.2);
    // a longer one is refused before it reaches key derivation.
    if dcid.len() > MAX_CID_SIZE {
        return Err(CaptureError::Malformed(
            "Initial connection ID longer than 20 bytes",
        ));
    }
    provider.initial_keys(version, dcid, side)
}

/// An Initial packet with its protection removed.
pub(crate) struct OpenedInitial {
    pub(crate) packet_number: u64,
    pub(crate) packet_number_len: u8,
    pub(crate) payload: Bytes,
}

/// Remove header and packet protection from the Initial `observed` found in `datagram`.
pub(crate) fn open_initial<H: HeaderKey, P: PacketKey>(
    datagram: &[u8],
    observed: &ObservedPacket,
    version: Version,
    keys: &InitialKeys<H, P>,
) -> Result<OpenedInitial, CaptureError> {
    let header_key: &dyn HeaderKey = &keys.header;
    // The observation may come from elsewhere (it is serializable), so its range is not trusted
    // to fit the datagram handed in.
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
    let packet_number = number.expand(0);
    keys.packet
        .decrypt(packet_number, &packet.header_data, &mut packet.payload)
        .map_err(|_error| CaptureError::Undecryptable)?;
    Ok(OpenedInitial {
        packet_number,
        packet_number_len: number.len() as u8,
        payload: packet.payload.freeze(),
    })
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
/// Missing handshake data returns `Ok(None)`. Malformed data, contradictory
/// retransmissions, and exhausted budgets return an error.
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
    let mut remaining = limits.bytes;
    for (_, data) in initials.iter().flat_map(|packet| &packet.crypto) {
        remaining = remaining
            .checked_sub(data.len())
            .ok_or(CaptureError::LimitExceeded("CRYPTO bytes"))?;
    }
    let mut assembly = ClientHelloAssembly::new(limits);
    for (offset, data) in initials.iter().flat_map(|packet| &packet.crypto) {
        assembly.take_in(*offset, data)?;
    }
    Ok(assembly.client_hello().map(<[u8]>::to_vec))
}

pub use crate::transport_parameters::RawParameter;

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
    transport_parameters_iter_from_hello(hello, limits)?
        .map(|parameter| {
            parameter.map(|(id, value)| RawParameter {
                id,
                value: value.to_vec(),
            })
        })
        .collect()
}

/// Borrow the QUIC transport parameter body from an already parsed ClientHello.
/// The byte limit is checked before callers decode or retain its contents.
fn transport_parameter_bytes<'a>(
    hello: &'a ClientHello,
    limits: &CaptureLimits,
) -> Result<&'a [u8], CaptureError> {
    let data = hello
        .extensions()
        .iter()
        .find_map(|ext| match ext {
            ClientHelloExtension::Opaque { id, data }
                if *id == ExtensionId::QUIC_TRANSPORT_PARAMETERS =>
            {
                Some(data.as_slice())
            }
            _ => None,
        })
        .ok_or(CaptureError::Malformed("no quic_transport_parameters"))?;
    within(
        data.len(),
        limits.client_hello_bytes,
        "transport parameter bytes",
    )?;
    Ok(data)
}

/// Borrow each transport parameter body in wire order, with byte and entry limits.
/// Values are slices of the parsed ClientHello; the reader copies none of their contents.
pub fn transport_parameters_iter_from_hello<'a>(
    hello: &'a ClientHello,
    limits: &CaptureLimits,
) -> Result<TransportParameterIter<'a>, CaptureError> {
    Ok(TransportParameterIter {
        reader: transport_parameter_bytes(hello, limits)?,
        remaining: limits.parameters,
        require_minimal_encoding: false,
    })
}

/// A bounded borrowed reader for transport parameters in their original wire order.
#[derive(Debug)]
pub struct TransportParameterIter<'a> {
    reader: &'a [u8],
    remaining: usize,
    require_minimal_encoding: bool,
}

impl<'a> TransportParameterIter<'a> {
    /// Require the shortest identifier and length encodings for subsequent parameters.
    /// This is an optional reconstruction policy: QUIC itself permits wider encodings,
    /// which the default reader continues to accept.
    #[must_use]
    pub fn require_minimal_encoding(mut self) -> Self {
        self.require_minimal_encoding = true;
        self
    }

    /// The unconsumed parameter body, borrowed from the ClientHello.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.reader
    }
}

impl<'a> Iterator for TransportParameterIter<'a> {
    type Item = Result<(TransportParameterId, &'a [u8]), CaptureError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        let parameter = (|| {
            self.remaining = self
                .remaining
                .checked_sub(1)
                .ok_or(CaptureError::LimitExceeded("transport parameters"))?;
            let before = self.reader.remaining();
            let id = BufExt::get::<VarInt>(&mut self.reader)
                .map_err(|_error| CaptureError::Malformed("transport parameter id"))?;
            let len = BufExt::get::<VarInt>(&mut self.reader)
                .map_err(|_error| CaptureError::Malformed("transport parameter length"))?;
            if self.require_minimal_encoding
                && before - self.reader.remaining() != id.size() + len.size()
            {
                return Err(CaptureError::NonminimalParameterEncoding);
            }
            let len = bounded_len(len.into_inner(), self.reader.remaining())
                .map_err(|_error| CaptureError::Malformed("transport parameter value"))?;
            let (value, rest) = self.reader.split_at(len);
            self.reader = rest;
            Ok((TransportParameterId::from(id.into_inner()), value))
        })();
        // Any refused field terminates the walk; callers cannot resume after an error.
        if parameter.is_err() {
            self.reader = &[];
        }
        Some(parameter)
    }
}

/// The `version_information` parameter among `parameters`, decoded as a client's.
#[must_use]
pub fn version_information(parameters: &[RawParameter]) -> Option<VersionInformation> {
    let raw = parameters.iter().find(|parameter| {
        TransportParameterId::from(u64::from(parameter.id))
            == TransportParameterId::VersionInformation
    })?;
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
    /// Encoded widths in observed packet order, including retransmissions.
    /// The first entry equals `packet_number_len`.
    pub packet_number_lengths: Vec<u8>,
    /// Frames per Initial packet, in order.
    pub frames: Vec<Vec<ObservedFrame>>,
    /// Where padding went.
    pub padding: PaddingPlacement,
    /// Whether the datagram coalesces packets of different kinds.
    pub coalesced: bool,
    pub parameters: Vec<TransportParameterId>,
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
        packet_number_lengths: initials
            .iter()
            .map(|packet| packet.packet_number_len)
            .collect(),
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

    #[test]
    fn sent_version_information_alias_preserves_decode_and_validation() {
        for version in [Version::V1, Version::V2] {
            let expected = VersionInformation::new(version, vec![Version::V2, Version::V1]);
            let mut value = Vec::new();
            expected.write(&mut value);
            for id in [
                TransportParameterId::VersionInformation,
                TransportParameterId::Unknown(u64::from(TransportParameterId::VersionInformation)),
            ] {
                let raw = RawParameter {
                    id,
                    value: value.clone(),
                };
                let decoded = version_information(slice::from_ref(&raw)).unwrap();
                assert_eq!(decoded.chosen(), expected.chosen());
                assert_eq!(decoded.available(), expected.available());
                for end in 0..4 {
                    let malformed = RawParameter {
                        id,
                        value: value[..end].to_vec(),
                    };
                    assert!(version_information(&[malformed]).is_none());
                }
            }
        }
    }

    #[test]
    fn observation_output_omits_connection_material() {
        let sensitive = vec![211, 212, 213, 214, 215];
        let connection_parameters = [
            TransportParameterId::OriginalDestinationConnectionId,
            TransportParameterId::StatelessResetToken,
            TransportParameterId::PreferredAddress,
            TransportParameterId::InitialSourceConnectionId,
            TransportParameterId::RetrySourceConnectionId,
            TransportParameterId::GoogleHandshakeMessage,
            TransportParameterId::GoogleLegacyCustomParameters,
            TransportParameterId::DebuggingSni,
        ]
        .into_iter()
        .flat_map(|id| [id, TransportParameterId::Unknown(u64::from(id))])
        .collect::<Vec<_>>();
        let mut parameters: Vec<_> = connection_parameters
            .iter()
            .map(|&id| RawParameter {
                id,
                value: sensitive.clone(),
            })
            .collect();
        parameters.push(RawParameter {
            id: TransportParameterId::InitialMaxData,
            value: vec![42],
        });
        let observation = QuicObservation {
            connection_id: sensitive.clone(),
            attempt_id: sensitive.clone(),
            retry_parent: Some(sensitive.clone()),
            first_flight: None,
            transport_parameters: parameters,
            client_hello_message: sensitive.clone(),
            completeness: CaptureCompleteness::default(),
        };
        let debug = format!("{observation:?}");
        assert!(!debug.contains("211"));
        assert!(!debug.contains("client_hello_message"));
        assert!(debug.contains("client_hello_len: 5"));
        let json = serde_json::to_value(&observation).unwrap();
        for omitted in [
            "connection_id",
            "attempt_id",
            "retry_parent",
            "client_hello_message",
        ] {
            assert!(json.get(omitted).is_none(), "{omitted}");
        }
        let parameters = json["transport_parameters"].as_array().unwrap();
        for (parameter, id) in parameters.iter().zip(connection_parameters) {
            assert_eq!(
                parameter,
                &serde_json::json!({"id": u64::from(id), "length": sensitive.len()})
            );
        }
        assert_eq!(
            parameters.last().unwrap(),
            &serde_json::json!({"id": u64::from(TransportParameterId::InitialMaxData), "value": [42]})
        );
        // Explicit consumers still receive the original capture; formatting and
        // serialization neither mutate nor erase the in-memory evidence.
        assert_eq!(observation.client_hello_message, sensitive);
        assert_eq!(observation.transport_parameters[0].value, sensitive);
    }

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
    fn borrowed_parameters_share_the_hello_body_and_match_owned_capture() {
        for value in [b"".as_slice(), b"a", b"a longer opaque value"] {
            let message = hello_with_parameter_len(value.len() as u64, value);
            let ClientHelloHandshakePrefix::Complete(hello) =
                parse_client_hello_message_prefix(&message)
            else {
                panic!("the fixture constructs a complete ClientHello");
            };
            let original = hello
                .extensions()
                .iter()
                .find_map(|extension| match extension {
                    ClientHelloExtension::Opaque { id, data }
                        if *id == ExtensionId::QUIC_TRANSPORT_PARAMETERS =>
                    {
                        Some(data.as_slice())
                    }
                    _ => None,
                })
                .unwrap();
            let limits = CaptureLimits::default();
            let owned = transport_parameters_from_hello(&hello, &limits).unwrap();
            let mut borrowed = transport_parameters_iter_from_hello(&hello, &limits).unwrap();
            let (id, bytes) = borrowed.next().unwrap().unwrap();
            assert_eq!(owned.len(), 1);
            assert_eq!(id, owned[0].id);
            assert_eq!(bytes, owned[0].value);
            assert_eq!(
                bytes.as_ptr(),
                original[original.len() - value.len()..].as_ptr()
            );
            assert!(borrowed.next().is_none());
            assert!(borrowed.next().is_none());

            let mut limited = transport_parameters_iter_from_hello(
                &hello,
                &CaptureLimits {
                    parameters: 0,
                    ..limits
                },
            )
            .unwrap();
            assert!(matches!(
                limited.next(),
                Some(Err(CaptureError::LimitExceeded("transport parameters")))
            ));
            assert!(limited.next().is_none());
        }
    }

    #[test]
    fn minimal_parameter_framing_is_optional_and_refusal_terminates_iteration() {
        let message = hello_with_parameter_len(0, &[]);
        let ClientHelloHandshakePrefix::Complete(template) =
            parse_client_hello_message_prefix(&message)
        else {
            panic!("the fixture constructs a complete ClientHello");
        };
        for (name, bytes) in [
            ("wide identifier", vec![0x40, 0x21, 0]),
            ("wide length", vec![0x21, 0x40, 0]),
        ] {
            let hello = ClientHello::new(
                template.protocol_version(),
                template.cipher_suites().to_vec(),
                template.compression_algorithms().to_vec(),
                vec![ClientHelloExtension::Opaque {
                    id: ExtensionId::QUIC_TRANSPORT_PARAMETERS,
                    data: bytes,
                }],
            );
            let limits = CaptureLimits::default();
            let owned = transport_parameters_from_hello(&hello, &limits).unwrap();
            assert_eq!(
                owned.len(),
                1,
                "{name}: ordinary QUIC capture stays permissive"
            );
            let mut strict = transport_parameters_iter_from_hello(&hello, &limits)
                .unwrap()
                .require_minimal_encoding();
            strict.next().unwrap().expect_err(name);
            assert!(
                strict.next().is_none(),
                "{name}: refusal terminates the reader"
            );
        }
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
            assert_eq!(u64::from(parameters[0].id), 0x21);
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

    fn crypto_packet(crypto: Vec<(u64, Vec<u8>)>) -> InitialPacket {
        InitialPacket {
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
            crypto,
        }
    }

    #[test]
    fn client_hello_overlap_agreement_is_required_before_and_after_completion() {
        let hello = hello_with_parameter_len(3, b"abc");
        let limits = CaptureLimits::default();
        for first_length in [12, hello.len()] {
            let correct = hello[5..].to_vec();
            let mut conflicting = correct.clone();
            conflicting[1] ^= 1;
            for overlap in [correct, conflicting] {
                let equal = overlap == hello[5..];
                let packet = crypto_packet(vec![(0, hello[..first_length].to_vec()), (5, overlap)]);
                let actual = client_hello_with_limits(slice::from_ref(&packet), &limits);
                if equal {
                    assert_eq!(actual, Ok(Some(hello.clone())));
                } else {
                    assert_eq!(
                        actual,
                        Err(CaptureError::Malformed("conflicting CRYPTO overlap"))
                    );
                }
            }
        }
        let packet = crypto_packet(vec![
            (12, hello[12..].to_vec()),
            (0, hello[..16].to_vec()),
            (0, hello.clone()),
        ]);
        assert_eq!(
            client_hello_with_limits(&[packet], &limits),
            Ok(Some(hello.clone()))
        );
        let packet = crypto_packet(vec![(0, hello[..8].to_vec()), (9, hello[9..].to_vec())]);
        assert_eq!(client_hello_with_limits(&[packet], &limits), Ok(None));
    }

    #[test]
    fn client_hello_fragment_bytes_are_bounded_before_overlap_work() {
        let hello = hello_with_parameter_len(3, b"abc");
        let length = hello.len();
        let packet = crypto_packet(vec![(0, hello.clone()), (0, hello.clone())]);
        let limits = CaptureLimits {
            bytes: length * 2 - 1,
            ..CaptureLimits::default()
        };
        assert_eq!(
            client_hello_with_limits(slice::from_ref(&packet), &limits),
            Err(CaptureError::LimitExceeded("CRYPTO bytes"))
        );
        let limits = CaptureLimits {
            bytes: length * 2,
            ..limits
        };
        assert_eq!(
            client_hello_with_limits(&[packet], &limits),
            Ok(Some(hello))
        );
    }
}
