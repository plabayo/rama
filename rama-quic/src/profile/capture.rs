//! Reading a first flight back from the wire: what any observer sees, and what one that
//! derives the Initial keys from the destination connection ID (RFC 9001 §5.2) sees.
//!
//! This is the oracle behind the profile tests, and the same view a server or proxy has of a
//! client before the handshake authenticates anything.

use std::{fmt, ops::Range};

use rama_core::bytes::{Buf, BytesMut};
use rama_tls::{
    ExtensionId,
    client::{ClientHelloExtension, ClientHelloHandshakePrefix, parse_client_hello_message_prefix},
};
use serde::{Deserialize, Serialize};

use crate::proto::{
    Side, Version,
    coding::BufExt,
    crypto::ServerConfig as CryptoServerConfig,
    frame::{self, Frame},
    packet::{FixedLengthConnectionIdParser, PartialDecode},
    version::{LongKind, VersionInformation},
};

use super::{PaddingPlacement, ParameterId};

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
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed QUIC datagram: {what}"),
            Self::UnknownVersion(version) => write!(f, "unknown QUIC version {version}"),
            Self::Undecryptable => f.write_str("the Initial packet did not decrypt"),
        }
    }
}

impl std::error::Error for CaptureError {}

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
    /// Where the packet number starts, for long headers.
    pn_offset: Option<usize>,
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
    let mut packets = Vec::new();
    let mut at = 0;
    let mut trailing = 0;
    while at < datagram.len() {
        let start = at;
        let first_byte = datagram[at];
        if first_byte & 0x80 == 0 {
            if packets.is_empty() {
                // A first byte of zero is not a packet; a 1-RTT packet cannot lead a first
                // flight either, but it is a packet.
                if first_byte == 0 {
                    return Err(CaptureError::Malformed("datagram starts with padding"));
                }
            } else if first_byte == 0 {
                trailing = datagram.len() - at;
                break;
            }
            packets.push(ObservedPacket {
                first_byte,
                kind: PacketKind::Short,
                version: None,
                dcid: Vec::new(),
                scid: None,
                token: None,
                range: start..datagram.len(),
                pn_offset: None,
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
                pn_offset: None,
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
                pn_offset: None,
            });
            break;
        }
        if kind == LongKind::Initial {
            let len = varint(datagram, &mut at)? as usize;
            token = Some(
                datagram
                    .get(at..at + len)
                    .ok_or(CaptureError::Malformed("truncated token"))?
                    .to_vec(),
            );
            at += len;
        }
        let length = varint(datagram, &mut at)? as usize;
        let end = at + length;
        if end > datagram.len() {
            return Err(CaptureError::Malformed("packet length exceeds datagram"));
        }
        packets.push(ObservedPacket {
            first_byte,
            kind: match kind {
                LongKind::Initial => PacketKind::Initial,
                LongKind::ZeroRtt => PacketKind::ZeroRtt,
                LongKind::Handshake => PacketKind::Handshake,
                LongKind::Retry => PacketKind::Retry,
            },
            version: Some(version),
            dcid,
            scid: Some(scid),
            token,
            range: start..end,
            pn_offset: Some(at),
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

impl InitialPacket {
    /// How many PADDING bytes the packet carries.
    #[must_use]
    pub fn padding(&self) -> usize {
        self.frames
            .iter()
            .map(|frame| match frame {
                ObservedFrame::Padding { len } => *len,
                _ => 0,
            })
            .sum()
    }

    /// Whether every PADDING byte comes after every other frame.
    #[must_use]
    pub fn padding_trails(&self) -> bool {
        let last_other = self
            .frames
            .iter()
            .rposition(|frame| !matches!(frame, ObservedFrame::Padding { .. }));
        let first_padding = self
            .frames
            .iter()
            .position(|frame| matches!(frame, ObservedFrame::Padding { .. }));
        match (last_other, first_padding) {
            (Some(other), Some(padding)) => padding > other,
            _ => true,
        }
    }
}

impl ObservedDatagram {
    /// Remove the protection of every Initial packet in `datagram` with keys from `provider`,
    /// as `side` receives them: a server opens a client's Initials, a client a server's.
    /// `original_dcid` is the destination connection ID the keys derive from, which is the
    /// packet's own for a client's first flight.
    pub fn unprotect_initials(
        &self,
        datagram: &[u8],
        provider: &dyn CryptoServerConfig,
        side: Side,
        original_dcid: Option<&[u8]>,
    ) -> Result<Vec<InitialPacket>, CaptureError> {
        let mut initials = Vec::new();
        for observed in &self.packets {
            if observed.kind != PacketKind::Initial {
                continue;
            }
            let Some(version) = observed.version else {
                continue;
            };
            let seed = original_dcid.unwrap_or(&observed.dcid);
            let keys = provider
                .initial_keys(version, &crate::proto::ConnectionId::new(seed))
                .map_err(|_error| CaptureError::Undecryptable)?;
            // The provider gives keys as a server holds them: `remote` opens what the client
            // sent, `local` what the server sent.
            let keys = match side {
                Side::Server => keys.remote.ok_or(CaptureError::Undecryptable)?,
                Side::Client => keys.local,
            };
            let bytes = BytesMut::from(&datagram[observed.range.clone()]);
            let (decode, _) = PartialDecode::new(
                bytes,
                &FixedLengthConnectionIdParser::new(0),
                &[version],
                true,
            )
            .map_err(|_error| CaptureError::Malformed("Initial header"))?;
            let mut packet = decode
                .finish(Some(&*keys.header))
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
                match item {
                    Frame::Padding => match frames.last_mut() {
                        Some(ObservedFrame::Padding { len }) => *len += 1,
                        _ => frames.push(ObservedFrame::Padding { len: 1 }),
                    },
                    Frame::Ping => frames.push(ObservedFrame::Ping),
                    Frame::Ack(_) => frames.push(ObservedFrame::Ack),
                    Frame::Crypto(frame) => {
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
        let offset = usize::try_from(offset).ok()?;
        if offset > stream.len() {
            return None;
        }
        stream.extend_from_slice(data.get(stream.len() - offset..)?);
    }
    let header: [u8; 4] = stream.get(..4)?.try_into().ok()?;
    if header[0] != 0x01 {
        return None;
    }
    let len = usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
    stream.get(..4 + len).map(<[u8]>::to_vec)
}

/// A transport parameter as it was sent: identifier and raw value, in wire order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawParameter {
    pub id: ParameterId,
    pub value: Vec<u8>,
}

/// The transport parameters of a ClientHello handshake message, in the order they were sent.
pub fn transport_parameters(client_hello: &[u8]) -> Result<Vec<RawParameter>, CaptureError> {
    let ClientHelloHandshakePrefix::Complete(hello) =
        parse_client_hello_message_prefix(client_hello)
    else {
        return Err(CaptureError::Malformed("ClientHello"));
    };
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
    let mut reader = &data[..];
    let mut parameters = Vec::new();
    while reader.has_remaining() {
        let id = reader
            .get_var()
            .map_err(|_error| CaptureError::Malformed("transport parameter id"))?;
        let len = reader
            .get_var()
            .map_err(|_error| CaptureError::Malformed("transport parameter length"))?
            as usize;
        if reader.remaining() < len {
            return Err(CaptureError::Malformed("transport parameter value"));
        }
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
}

/// Read a client's first flight: the datagrams it sent before hearing from the server.
pub fn first_flight(
    datagrams: &[&[u8]],
    provider: &dyn CryptoServerConfig,
) -> Result<FirstFlight, CaptureError> {
    if datagrams.is_empty() {
        return Err(CaptureError::Malformed("no datagrams"));
    }
    let observed: Vec<ObservedDatagram> = datagrams
        .iter()
        .map(|datagram| observe(datagram))
        .collect::<Result<_, _>>()?;
    let lead = observed[0]
        .packets
        .first()
        .filter(|packet| packet.kind == PacketKind::Initial)
        .ok_or(CaptureError::Malformed(
            "the first packet is not an Initial",
        ))?
        .clone();
    let mut initials = Vec::new();
    for (datagram, observed) in datagrams.iter().zip(&observed) {
        initials.extend(observed.unprotect_initials(
            datagram,
            provider,
            Side::Server,
            Some(&lead.dcid),
        )?);
    }
    let hello = client_hello(&initials);
    let parameters = hello
        .as_deref()
        .map(transport_parameters)
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
            .map(|packet| packet.frames.clone())
            .collect(),
        padding,
        coalesced,
        parameters: parameters.iter().map(|parameter| parameter.id).collect(),
        chosen_version: info.as_ref().map(VersionInformation::chosen),
        available_versions: info.map_or_else(Vec::new, |info| info.available().to_vec()),
    })
}

impl FirstFlight {
    /// The bytes of `datagrams` as hex, for fixtures.
    #[must_use]
    pub fn hex(datagram: &[u8]) -> String {
        rama_utils::fmt::hex(datagram).to_string()
    }
}
