use alloc::vec::Vec;
use core::{cmp::Ordering, ops::Range};

use rama_core::bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    ConnectionId, VarInt, Version,
    coding::{self, BufExt, BufMutExt, bounded_len},
    crypto,
    version::{LongKind, Wire, WireVersion},
};

/// A no_std stand-in for `std::io::Cursor`: an owned buffer with a read position, offering the
/// slice of methods the packet decoder needs. Reads through [`Buf`] advance the position, matching
/// `std::io::Cursor`'s `bytes::Buf` semantics.
#[derive(Clone, Debug)]
pub(crate) struct Cursor<T> {
    inner: T,
    pos: usize,
}

impl<T> Cursor<T> {
    fn new(inner: T) -> Self {
        Self { inner, pos: 0 }
    }

    fn position(&self) -> u64 {
        self.pos as u64
    }

    fn get_ref(&self) -> &T {
        &self.inner
    }

    fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsRef<[u8]>> Buf for Cursor<T> {
    fn remaining(&self) -> usize {
        self.inner.as_ref().len().saturating_sub(self.pos)
    }

    fn chunk(&self) -> &[u8] {
        let slice = self.inner.as_ref();
        &slice[self.pos.min(slice.len())..]
    }

    fn advance(&mut self, cnt: usize) {
        // Every reader here checks `remaining()` first, so this only ever moves within the buffer;
        // a bug that overshoots clamps to the end, and later reads then fail as unexpected end.
        debug_assert!(cnt <= self.remaining(), "cursor advanced past the end");
        self.pos = self.inner.as_ref().len().min(self.pos.saturating_add(cnt));
    }
}

/// Decodes a QUIC packet's invariant header
///
/// Due to packet number encryption, it is impossible to fully decode a header
/// (which includes a variable-length packet number) without crypto context.
/// The crypto context (the packet protection keys) is usually
/// part of the `Connection`, or can be derived from the destination CID for
/// Initial packets.
///
/// To cope with this, we decode the invariant header (which should be stable
/// across QUIC versions), which gives us the destination CID and allows us
/// to inspect the version and packet type (which depends on the version).
/// This information allows us to fully decode and decrypt the packet.
#[derive(Clone, Debug)]
pub struct PartialDecode {
    plain_header: ProtectedHeader,
    buf: Cursor<BytesMut>,
    /// What this packet's bytes keep allocated, see [`Packet::allocated`].
    allocated: usize,
}

impl PartialDecode {
    /// Begin decoding a QUIC packet from `bytes`, a datagram in an allocation of its own size,
    /// returning any trailing data not part of that packet.
    pub fn new(
        bytes: BytesMut,
        cid_parser: &(impl ConnectionIdParser + ?Sized),
        supported_versions: &[Version],
        grease_quic_bit: bool,
    ) -> Result<(Self, Option<BytesMut>), PacketDecodeError> {
        let allocated = bytes.len();
        Self::new_within(
            bytes,
            allocated,
            cid_parser,
            supported_versions,
            grease_quic_bit,
        )
    }

    /// As [`Self::new`] for `bytes` that are part of a larger allocation of `allocated` bytes,
    /// such as the trailing data an earlier call returned, which shares that allocation.
    pub fn new_within(
        bytes: BytesMut,
        allocated: usize,
        cid_parser: &(impl ConnectionIdParser + ?Sized),
        supported_versions: &[Version],
        grease_quic_bit: bool,
    ) -> Result<(Self, Option<BytesMut>), PacketDecodeError> {
        let allocated = allocated.max(bytes.len());
        let mut buf = Cursor::new(bytes);
        let plain_header =
            ProtectedHeader::decode(&mut buf, cid_parser, supported_versions, grease_quic_bit)?;
        let dgram_len = buf.get_ref().len();
        let packet_len = match plain_header.payload_len() {
            Some(len) => {
                let len = bounded_len(len, buf.remaining()).map_err(|_error| {
                    PacketDecodeError::InvalidHeader("packet too short to contain payload length")
                })?;
                buf.position() as usize + len
            }
            None => dgram_len,
        };
        match dgram_len.cmp(&packet_len) {
            Ordering::Equal => Ok((
                Self {
                    plain_header,
                    buf,
                    allocated,
                },
                None,
            )),
            Ordering::Less => Err(PacketDecodeError::InvalidHeader(
                "packet too short to contain payload length",
            )),
            Ordering::Greater => {
                // The packet is copied out so it owns its bytes; the rest stays a view of the
                // datagram, so splitting all of a datagram's packets copies it only once.
                let position = buf.pos;
                let mut bytes = buf.into_inner();
                let rest = bytes.split_off(packet_len);
                let mut buf = Cursor::new(BytesMut::from(&bytes[..]));
                buf.pos = position;
                Ok((
                    Self {
                        plain_header,
                        buf,
                        allocated: packet_len,
                    },
                    Some(rest),
                ))
            }
        }
    }

    /// The underlying partially-decoded packet data
    pub fn data(&self) -> &[u8] {
        self.buf.get_ref()
    }

    pub fn initial_header(&self) -> Option<&ProtectedInitialHeader> {
        self.plain_header.as_initial()
    }

    pub fn has_long_header(&self) -> bool {
        !matches!(self.plain_header, ProtectedHeader::Short { .. })
    }

    pub fn is_initial(&self) -> bool {
        self.space() == Some(SpaceId::Initial)
    }

    pub fn space(&self) -> Option<SpaceId> {
        match self.plain_header {
            ProtectedHeader::Initial { .. } => Some(SpaceId::Initial),
            ProtectedHeader::Long {
                ty: LongType::Handshake,
                ..
            } => Some(SpaceId::Handshake),
            ProtectedHeader::Long {
                ty: LongType::ZeroRtt,
                ..
            }
            | ProtectedHeader::Short { .. } => Some(SpaceId::Data),
            _ => None,
        }
    }

    pub fn is_0rtt(&self) -> bool {
        match self.plain_header {
            ProtectedHeader::Long { ty, .. } => ty == LongType::ZeroRtt,
            _ => false,
        }
    }

    /// The version a long header carries; short headers have none.
    pub fn version(&self) -> Option<Version> {
        self.wire_version().map(WireVersion::version)
    }

    /// The wire-bearing version a long header carries; short headers have none.
    pub fn wire_version(&self) -> Option<WireVersion> {
        match self.plain_header {
            ProtectedHeader::Initial(ProtectedInitialHeader { version, .. })
            | ProtectedHeader::Long { version, .. }
            | ProtectedHeader::Retry { version, .. } => Some(version),
            ProtectedHeader::Short { .. } | ProtectedHeader::VersionNegotiate { .. } => None,
        }
    }

    /// The destination connection ID of the packet
    pub fn dst_cid(&self) -> &ConnectionId {
        self.plain_header.dst_cid()
    }

    /// Length of QUIC packet being decoded
    #[expect(
        clippy::len_without_is_empty,
        reason = "the byte length of a decoded packet, never a collection that could be empty"
    )]
    pub fn len(&self) -> usize {
        self.buf.get_ref().len()
    }

    /// Finish decoding a header that carries a protected packet number (Initial, Handshake,
    /// 0-RTT, 1-RTT), removing header protection with `header_crypto`. The key is mandatory, so a
    /// caller cannot reach a number-bearing header without one.
    pub fn finish_protected(
        self,
        header_crypto: &dyn crypto::HeaderKey,
    ) -> Result<Packet, PacketDecodeError> {
        self.finish_inner(Some(header_crypto))
    }

    /// Finish decoding a header that carries no packet number (Retry, Version Negotiation), which
    /// needs no key. A number-bearing header handed here is reported as an invalid header rather
    /// than decoded without protection.
    pub fn finish_unprotected(self) -> Result<Packet, PacketDecodeError> {
        self.finish_inner(None)
    }

    #[expect(
        clippy::unreachable,
        reason = "the Initial header is handled by the branch above, so it cannot reach this match"
    )]
    fn finish_inner(
        self,
        header_crypto: Option<&dyn crypto::HeaderKey>,
    ) -> Result<Packet, PacketDecodeError> {
        let Self {
            plain_header,
            mut buf,
            allocated,
        } = self;

        if let ProtectedHeader::Initial(ProtectedInitialHeader {
            dst_cid,
            src_cid,
            token_pos,
            version,
            ..
        }) = plain_header
        {
            let number = Self::decrypt_header(
                &mut buf,
                header_crypto.ok_or(PacketDecodeError::InvalidHeader(
                    "missing header protection key",
                ))?,
            )?;
            let header_len = buf.position() as usize;
            let mut bytes = buf.into_inner();

            let header_data = bytes.split_to(header_len).freeze();
            let token = header_data.slice(token_pos.start..token_pos.end);
            return Ok(Packet {
                header: Header::Initial(InitialHeader {
                    dst_cid,
                    src_cid,
                    token,
                    number,
                    version,
                }),
                header_data,
                payload: bytes,
                allocated,
            });
        }

        let header = match plain_header {
            ProtectedHeader::Long {
                ty,
                dst_cid,
                src_cid,
                version,
                ..
            } => Header::Long {
                ty,
                dst_cid,
                src_cid,
                number: Self::decrypt_header(
                    &mut buf,
                    header_crypto.ok_or(PacketDecodeError::InvalidHeader(
                        "missing header protection key",
                    ))?,
                )?,
                version,
            },
            ProtectedHeader::Retry {
                dst_cid,
                src_cid,
                version,
            } => Header::Retry {
                dst_cid,
                src_cid,
                version,
            },
            ProtectedHeader::Short { spin, dst_cid, .. } => {
                let number = Self::decrypt_header(
                    &mut buf,
                    header_crypto.ok_or(PacketDecodeError::InvalidHeader(
                        "missing header protection key",
                    ))?,
                )?;
                let key_phase = buf.get_ref()[0] & KEY_PHASE_BIT != 0;
                Header::Short {
                    spin,
                    key_phase,
                    dst_cid,
                    number,
                }
            }
            ProtectedHeader::VersionNegotiate {
                random,
                dst_cid,
                src_cid,
            } => Header::VersionNegotiate {
                random,
                dst_cid,
                src_cid,
            },
            ProtectedHeader::Initial { .. } => unreachable!(),
        };

        let header_len = buf.position() as usize;
        let mut bytes = buf.into_inner();
        Ok(Packet {
            header,
            header_data: bytes.split_to(header_len).freeze(),
            payload: bytes,
            allocated,
        })
    }

    fn decrypt_header(
        buf: &mut Cursor<BytesMut>,
        header_crypto: &dyn crypto::HeaderKey,
    ) -> Result<PacketNumber, PacketDecodeError> {
        let packet_length = buf.get_ref().len();
        let pn_offset = buf.position() as usize;
        if packet_length < pn_offset + 4 + header_crypto.sample_size() {
            return Err(PacketDecodeError::InvalidHeader(
                "packet too short to extract header protection sample",
            ));
        }

        header_crypto.decrypt(pn_offset, buf.get_mut());

        let len = PacketNumber::decode_len(buf.get_ref()[0]);
        PacketNumber::decode(len, buf)
    }
}

pub struct Packet {
    pub header: Header,
    pub header_data: Bytes,
    pub payload: BytesMut,
    /// What the packet's bytes keep allocated: its own size when it owns its buffer, or the whole
    /// datagram when it is the last of several coalesced into one. Any slice of it keeps as much.
    pub allocated: usize,
}

impl Packet {
    pub fn reserved_bits_valid(&self) -> bool {
        let mask = match self.header {
            Header::Short { .. } => SHORT_RESERVED_BITS,
            _ => LONG_RESERVED_BITS,
        };
        self.header_data[0] & mask == 0
    }
}

pub struct InitialPacket {
    pub header: InitialHeader,
    pub header_data: Bytes,
    pub payload: BytesMut,
    /// See [`Packet::allocated`].
    pub allocated: usize,
}

impl From<InitialPacket> for Packet {
    fn from(x: InitialPacket) -> Self {
        Self {
            header: Header::Initial(x.header),
            header_data: x.header_data,
            payload: x.payload,
            allocated: x.allocated,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Header {
    Initial(InitialHeader),
    Long {
        ty: LongType,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        number: PacketNumber,
        version: WireVersion,
    },
    Retry {
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        version: WireVersion,
    },
    Short {
        spin: bool,
        key_phase: bool,
        dst_cid: ConnectionId,
        number: PacketNumber,
    },
    VersionNegotiate {
        random: u8,
        src_cid: ConnectionId,
        dst_cid: ConnectionId,
    },
}

impl Header {
    pub fn encode(&self, w: &mut Vec<u8>) -> PartialEncode {
        self.encode_with_max_packet_len(w, 0)
    }

    /// Encode a header that may grow to `max_packet_len` bytes, measured from this header's
    /// first byte through the end of the protected packet.
    ///
    /// Protected long headers reserve the smallest Length varint that can represent every packet
    /// up to that limit. Callers that impose a packet capacity before writing frames should use
    /// this method so the Length field can grow beyond two bytes when needed.
    pub fn encode_with_max_packet_len(
        &self,
        w: &mut Vec<u8>,
        max_packet_len: usize,
    ) -> PartialEncode {
        let start = w.len();
        match *self {
            Self::Initial(InitialHeader {
                ref dst_cid,
                ref src_cid,
                ref token,
                number,
                version,
            }) => {
                w.write(LongHeaderType::Initial.to_byte(version) | number.tag());
                w.write(version);
                dst_cid.encode_long(w);
                src_cid.encode_long(w);
                w.write_var(token.len() as u64);
                w.put_slice(token);
                let payload_len = payload_length_width(max_packet_len, w.len() - start);
                write_payload_length_placeholder(w, payload_len);
                number.encode(w);
                PartialEncode {
                    start,
                    header_len: w.len() - start,
                    pn: Some(number.len()),
                    payload_len: Some(payload_len),
                }
            }
            Self::Long {
                ty,
                ref dst_cid,
                ref src_cid,
                number,
                version,
            } => {
                w.write(LongHeaderType::Standard(ty).to_byte(version) | number.tag());
                w.write(version);
                dst_cid.encode_long(w);
                src_cid.encode_long(w);
                let payload_len = payload_length_width(max_packet_len, w.len() - start);
                write_payload_length_placeholder(w, payload_len);
                number.encode(w);
                PartialEncode {
                    start,
                    header_len: w.len() - start,
                    pn: Some(number.len()),
                    payload_len: Some(payload_len),
                }
            }
            Self::Retry {
                ref dst_cid,
                ref src_cid,
                version,
            } => {
                w.write(LongHeaderType::Retry.to_byte(version));
                w.write(version);
                dst_cid.encode_long(w);
                src_cid.encode_long(w);
                PartialEncode {
                    start,
                    header_len: w.len() - start,
                    pn: None,
                    payload_len: None,
                }
            }
            Self::Short {
                spin,
                key_phase,
                ref dst_cid,
                number,
            } => {
                w.write(
                    FIXED_BIT
                        | if key_phase { KEY_PHASE_BIT } else { 0 }
                        | if spin { SPIN_BIT } else { 0 }
                        | number.tag(),
                );
                w.put_slice(dst_cid);
                number.encode(w);
                PartialEncode {
                    start,
                    header_len: w.len() - start,
                    pn: Some(number.len()),
                    payload_len: None,
                }
            }
            Self::VersionNegotiate {
                ref random,
                ref dst_cid,
                ref src_cid,
            } => {
                w.write(0x80u8 | random);
                w.write::<u32>(0);
                dst_cid.encode_long(w);
                src_cid.encode_long(w);
                PartialEncode {
                    start,
                    header_len: w.len() - start,
                    pn: None,
                    payload_len: None,
                }
            }
        }
    }

    /// Whether the packet is encrypted on the wire
    pub fn is_protected(&self) -> bool {
        !matches!(*self, Self::Retry { .. } | Self::VersionNegotiate { .. })
    }

    /// The version a long header carries; short headers have none.
    pub fn version(&self) -> Option<Version> {
        match *self {
            Self::Initial(InitialHeader { version, .. })
            | Self::Long { version, .. }
            | Self::Retry { version, .. } => Some(version.version()),
            Self::Short { .. } | Self::VersionNegotiate { .. } => None,
        }
    }

    /// The wire-bearing version a long header carries; short headers have none.
    pub fn wire_version(&self) -> Option<WireVersion> {
        match *self {
            Self::Initial(InitialHeader { version, .. })
            | Self::Long { version, .. }
            | Self::Retry { version, .. } => Some(version),
            Self::Short { .. } | Self::VersionNegotiate { .. } => None,
        }
    }

    pub fn number(&self) -> Option<PacketNumber> {
        Some(match *self {
            Self::Initial(InitialHeader { number, .. })
            | Self::Long { number, .. }
            | Self::Short { number, .. } => number,
            _ => {
                return None;
            }
        })
    }

    pub fn space(&self) -> SpaceId {
        match *self {
            Self::Short { .. }
            | Self::Long {
                ty: LongType::ZeroRtt,
                ..
            } => SpaceId::Data,
            Self::Long {
                ty: LongType::Handshake,
                ..
            } => SpaceId::Handshake,
            _ => SpaceId::Initial,
        }
    }

    pub fn key_phase(&self) -> bool {
        match *self {
            Self::Short { key_phase, .. } => key_phase,
            _ => false,
        }
    }

    pub fn is_short(&self) -> bool {
        matches!(*self, Self::Short { .. })
    }

    pub fn is_1rtt(&self) -> bool {
        self.is_short()
    }

    pub fn is_0rtt(&self) -> bool {
        matches!(
            *self,
            Self::Long {
                ty: LongType::ZeroRtt,
                ..
            }
        )
    }

    pub fn dst_cid(&self) -> ConnectionId {
        match *self {
            Self::Initial(InitialHeader { dst_cid, .. })
            | Self::Long { dst_cid, .. }
            | Self::Retry { dst_cid, .. }
            | Self::Short { dst_cid, .. }
            | Self::VersionNegotiate { dst_cid, .. } => dst_cid,
        }
    }

    /// Whether the payload of this packet contains QUIC frames
    pub fn has_frames(&self) -> bool {
        match *self {
            Self::Retry { .. } | Self::VersionNegotiate { .. } => false,
            Self::Initial(_) | Self::Long { .. } | Self::Short { .. } => true,
        }
    }
}

fn payload_length_width(max_packet_len: usize, length_pos: usize) -> usize {
    if max_packet_len.saturating_sub(length_pos.saturating_add(2)) < 2usize.pow(14) {
        2
    } else if max_packet_len.saturating_sub(length_pos.saturating_add(4)) < 2usize.pow(30) {
        4
    } else {
        8
    }
}

fn write_payload_length_placeholder(w: &mut Vec<u8>, width: usize) {
    w.resize(w.len() + width, 0);
}

pub struct PartialEncode {
    pub start: usize,
    pub header_len: usize,
    // Packet number length, if this is a protected packet
    pn: Option<usize>,
    // Reserved payload Length varint width, if this is a protected long header
    payload_len: Option<usize>,
}

impl PartialEncode {
    pub fn finish(
        self,
        buf: &mut [u8],
        header_crypto: &dyn crypto::HeaderKey,
        crypto: Option<(u64, &dyn crypto::PacketKey)>,
    ) -> Result<(), crypto::CryptoError> {
        let Self {
            header_len,
            pn,
            payload_len,
            ..
        } = self;
        let Some(pn_len) = pn else {
            return Ok(());
        };

        let pn_pos = header_len - pn_len;
        if let Some(width) = payload_len {
            let len = buf.len() - header_len + pn_len;
            let mut slice = &mut buf[pn_pos - width..pn_pos];
            match width {
                2 if len < 2usize.pow(14) => slice.put_u16(len as u16 | (0b01 << 14)),
                4 if len < 2usize.pow(30) => slice.put_u32(len as u32 | (0b10 << 30)),
                8 => {
                    let len = u64::try_from(len).map_err(|_error| crypto::CryptoError::new())?;
                    if len >= 2u64.pow(62) {
                        return Err(crypto::CryptoError::new());
                    }
                    slice.put_u64(len | (0b11 << 62));
                }
                _ => return Err(crypto::CryptoError::new()),
            }
        }

        if let Some((number, crypto)) = crypto {
            crypto.encrypt(number, buf, header_len)?;
        }

        debug_assert!(
            pn_pos + 4 + header_crypto.sample_size() <= buf.len(),
            "packet must be padded to at least {} bytes for header protection sampling",
            pn_pos + 4 + header_crypto.sample_size()
        );
        header_crypto.encrypt(pn_pos, buf);
        Ok(())
    }
}

/// Plain packet header
#[derive(Clone, Debug)]
pub enum ProtectedHeader {
    /// An Initial packet header
    Initial(ProtectedInitialHeader),
    /// A Long packet header, as used during the handshake
    Long {
        /// Type of the Long header packet
        ty: LongType,
        /// Destination Connection ID
        dst_cid: ConnectionId,
        /// Source Connection ID
        src_cid: ConnectionId,
        /// Length of the packet payload
        len: u64,
        /// QUIC version
        version: WireVersion,
    },
    /// A Retry packet header
    Retry {
        /// Destination Connection ID
        dst_cid: ConnectionId,
        /// Source Connection ID
        src_cid: ConnectionId,
        /// QUIC version
        version: WireVersion,
    },
    /// A short packet header, as used during the data phase
    Short {
        /// Spin bit
        spin: bool,
        /// Destination Connection ID
        dst_cid: ConnectionId,
    },
    /// A Version Negotiation packet header
    VersionNegotiate {
        /// Random value
        random: u8,
        /// Destination Connection ID
        dst_cid: ConnectionId,
        /// Source Connection ID
        src_cid: ConnectionId,
    },
}

impl ProtectedHeader {
    fn as_initial(&self) -> Option<&ProtectedInitialHeader> {
        match self {
            Self::Initial(x) => Some(x),
            _ => None,
        }
    }

    /// The destination Connection ID of the packet
    pub fn dst_cid(&self) -> &ConnectionId {
        match self {
            Self::Initial(header) => &header.dst_cid,
            Self::Long { dst_cid, .. }
            | Self::Retry { dst_cid, .. }
            | Self::Short { dst_cid, .. }
            | Self::VersionNegotiate { dst_cid, .. } => dst_cid,
        }
    }

    fn payload_len(&self) -> Option<u64> {
        match self {
            Self::Initial(ProtectedInitialHeader { len, .. }) | Self::Long { len, .. } => {
                Some(*len)
            }
            _ => None,
        }
    }

    /// Decode a plain header from given buffer, with given [`ConnectionIdParser`].
    pub(crate) fn decode(
        buf: &mut Cursor<BytesMut>,
        cid_parser: &(impl ConnectionIdParser + ?Sized),
        supported_versions: &[Version],
        grease_quic_bit: bool,
    ) -> Result<Self, PacketDecodeError> {
        let first = buf.get::<u8>()?;
        if !grease_quic_bit && first & FIXED_BIT == 0 {
            return Err(PacketDecodeError::InvalidHeader("fixed bit unset"));
        }
        if first & LONG_HEADER_FORM == 0 {
            let spin = first & SPIN_BIT != 0;

            Ok(Self::Short {
                spin,
                dst_cid: cid_parser.parse(buf)?,
            })
        } else {
            let version = buf.get::<Version>()?;

            let dst_cid = ConnectionId::decode_long(buf)
                .ok_or(PacketDecodeError::InvalidHeader("malformed cid"))?;
            let src_cid = ConnectionId::decode_long(buf)
                .ok_or(PacketDecodeError::InvalidHeader("malformed cid"))?;

            // TODO: Support long CIDs for compatibility with future QUIC versions
            if version.is_negotiation() {
                let random = first & !LONG_HEADER_FORM;
                return Ok(Self::VersionNegotiate {
                    random,
                    dst_cid,
                    src_cid,
                });
            }

            let Some(version) = version
                .to_wire()
                .filter(|_| supported_versions.contains(&version))
            else {
                return Err(PacketDecodeError::UnsupportedVersion {
                    src_cid,
                    dst_cid,
                    version,
                });
            };

            match LongHeaderType::from_byte(first, version.wire()) {
                LongHeaderType::Initial => {
                    let token_len =
                        bounded_len(buf.get_var()?, buf.remaining()).map_err(|_error| {
                            PacketDecodeError::InvalidHeader("token out of bounds")
                        })?;
                    let token_start = buf.position() as usize;
                    buf.advance(token_len);

                    let len = buf.get_var()?;
                    Ok(Self::Initial(ProtectedInitialHeader {
                        dst_cid,
                        src_cid,
                        token_pos: token_start..token_start + token_len,
                        len,
                        version,
                    }))
                }
                LongHeaderType::Retry => Ok(Self::Retry {
                    dst_cid,
                    src_cid,
                    version,
                }),
                LongHeaderType::Standard(ty) => Ok(Self::Long {
                    ty,
                    dst_cid,
                    src_cid,
                    len: buf.get_var()?,
                    version,
                }),
            }
        }
    }
}

/// Header of an Initial packet, before decryption
#[derive(Clone, Debug)]
pub struct ProtectedInitialHeader {
    /// Destination Connection ID
    pub dst_cid: ConnectionId,
    /// Source Connection ID
    pub src_cid: ConnectionId,
    /// The position of a token in the packet buffer
    pub token_pos: Range<usize>,
    /// Length of the packet payload
    pub len: u64,
    /// QUIC version
    pub version: WireVersion,
}

#[derive(Clone, Debug)]
pub struct InitialHeader {
    pub dst_cid: ConnectionId,
    pub src_cid: ConnectionId,
    pub token: Bytes,
    pub number: PacketNumber,
    pub version: WireVersion,
}

impl InitialHeader {
    /// Encoded header bytes, or `None` if its token length is not representable.
    pub fn encoded_len(&self) -> Option<usize> {
        let token_length = VarInt::try_from(self.token.len()).ok()?;
        self.token.len().checked_add(
            9 + self.dst_cid.len() + self.src_cid.len() + token_length.size() + self.number.len(),
        )
    }
}

// An encoded packet number
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PacketNumber {
    U8(u8),
    U16(u16),
    U24(u32),
    U32(u32),
}

/// The largest packet number a connection can use (RFC 9000 §12.3).
pub const MAX_PACKET_NUMBER: u64 = (1 << 62) - 1;

/// How far past the largest acknowledged packet a packet number can still be sent: its 4-byte
/// encoding must cover twice that distance (RFC 9000 §17.1).
pub const MAX_PACKET_NUMBER_DISTANCE: u64 = (1 << 31) - 1;

impl PacketNumber {
    /// The shortest encoding of `n`, or `None` when it is more than
    /// [`MAX_PACKET_NUMBER_DISTANCE`] past `largest_acked`.
    pub fn new(n: u64, largest_acked: u64) -> Option<Self> {
        Self::new_at_least(n, largest_acked, 1)
    }

    /// Like [`Self::new`], but encoded on at least `min_len` bytes (1 to 4), as a wire profile
    /// may ask for.
    pub fn new_at_least(n: u64, largest_acked: u64, min_len: u8) -> Option<Self> {
        let distance = n.saturating_sub(largest_acked);
        if distance > MAX_PACKET_NUMBER_DISTANCE {
            return None;
        }
        let range = distance * 2;
        let len = if range < 1 << 8 {
            1
        } else if range < 1 << 16 {
            2
        } else if range < 1 << 24 {
            3
        } else {
            4
        };
        Some(match len.max(min_len.clamp(1, 4)) {
            1 => Self::U8(n as u8),
            2 => Self::U16(n as u16),
            3 => Self::U24(n as u32 & 0x00ff_ffff),
            _ => Self::U32(n as u32),
        })
    }

    #[expect(
        clippy::len_without_is_empty,
        reason = "the encoded byte width of the packet number (1-4), never a collection"
    )]
    pub fn len(self) -> usize {
        match self {
            Self::U8(_) => 1,
            Self::U16(_) => 2,
            Self::U24(_) => 3,
            Self::U32(_) => 4,
        }
    }

    pub fn encode<W: BufMut>(self, w: &mut W) {
        match self {
            Self::U8(x) => w.write(x),
            Self::U16(x) => w.write(x),
            Self::U24(x) => w.put_uint(u64::from(x), 3),
            Self::U32(x) => w.write(x),
        }
    }

    /// Decode a one-to-four-byte packet number without consuming input on error.
    /// Invalid widths and truncated numbers are rejected in every build mode.
    pub fn decode<R: Buf>(len: usize, r: &mut R) -> Result<Self, PacketDecodeError> {
        if r.remaining() < len {
            return Err(PacketDecodeError::InvalidHeader("truncated packet number"));
        }
        let pn = match len {
            1 => Self::U8(r.get()?),
            2 => Self::U16(r.get()?),
            3 => Self::U24(r.get_uint(3) as u32),
            4 => Self::U32(r.get()?),
            _ => {
                return Err(PacketDecodeError::InvalidHeader(
                    "invalid packet number width",
                ));
            }
        };
        Ok(pn)
    }

    pub fn decode_len(tag: u8) -> usize {
        1 + (tag & 0x03) as usize
    }

    fn tag(self) -> u8 {
        match self {
            Self::U8(_) => 0b00,
            Self::U16(_) => 0b01,
            Self::U24(_) => 0b10,
            Self::U32(_) => 0b11,
        }
    }

    pub fn expand(self, expected: u64) -> u64 {
        // From Appendix A
        let truncated = match self {
            Self::U8(x) => u64::from(x),
            Self::U16(x) => u64::from(x),
            Self::U24(x) | Self::U32(x) => u64::from(x),
        };
        let nbits = self.len() * 8;
        let win = 1 << nbits;
        let hwin = win / 2;
        let mask = win - 1;
        // The incoming packet number should be greater than expected - hwin and less than or equal
        // to expected + hwin
        //
        // This means we can't just strip the trailing bits from expected and add the truncated
        // because that might yield a value outside the window.
        //
        // The following code calculates a candidate value and makes sure it's within the packet
        // number window.
        let candidate = (expected & !mask) | truncated;
        if expected.checked_sub(hwin).is_some_and(|x| candidate <= x)
            && candidate < (MAX_PACKET_NUMBER + 1) - win
        {
            candidate + win
        } else if candidate > expected.saturating_add(hwin) && candidate >= win {
            candidate - win
        } else {
            candidate
        }
    }
}

/// A [`ConnectionIdParser`] implementation that assumes the connection ID is of fixed length
pub struct FixedLengthConnectionIdParser {
    expected_len: usize,
}

impl FixedLengthConnectionIdParser {
    /// Create a new instance of `FixedLengthConnectionIdParser`
    pub fn new(expected_len: usize) -> Self {
        Self { expected_len }
    }
}

impl ConnectionIdParser for FixedLengthConnectionIdParser {
    fn parse(&self, buffer: &mut dyn Buf) -> Result<ConnectionId, PacketDecodeError> {
        ConnectionId::from_buf(buffer, self.expected_len)
            .map_err(|_error| PacketDecodeError::InvalidHeader("invalid connection ID length"))
    }
}

/// Parse connection id in short header packet
pub trait ConnectionIdParser {
    /// Parse a connection id from given buffer
    fn parse(&self, buf: &mut dyn Buf) -> Result<ConnectionId, PacketDecodeError>;
}

/// Long packet type including non-uniform cases
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LongHeaderType {
    Initial,
    Retry,
    Standard(LongType),
}

impl LongHeaderType {
    fn from_byte(b: u8, wire: &Wire) -> Self {
        debug_assert!(b & LONG_HEADER_FORM != 0, "not a long packet");
        match wire.long_kind(b) {
            LongKind::Initial => Self::Initial,
            LongKind::ZeroRtt => Self::Standard(LongType::ZeroRtt),
            LongKind::Handshake => Self::Standard(LongType::Handshake),
            LongKind::Retry => Self::Retry,
        }
    }

    /// The first byte of a long header of this type in `version`, without packet number bits.
    pub fn to_byte(self, version: WireVersion) -> u8 {
        let kind = match self {
            Self::Initial => LongKind::Initial,
            Self::Standard(LongType::ZeroRtt) => LongKind::ZeroRtt,
            Self::Standard(LongType::Handshake) => LongKind::Handshake,
            Self::Retry => LongKind::Retry,
        };
        LONG_HEADER_FORM | FIXED_BIT | version.wire().long_type_bits(kind)
    }
}

/// Long packet types with uniform header structure
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LongType {
    /// Handshake packet
    Handshake,
    /// 0-RTT packet
    ZeroRtt,
}

/// Packet decode error
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PacketDecodeError {
    /// Packet uses a QUIC version that is not supported
    UnsupportedVersion {
        /// Source Connection ID
        src_cid: ConnectionId,
        /// Destination Connection ID
        dst_cid: ConnectionId,
        /// The version that was unsupported
        version: Version,
    },
    /// The packet header is invalid
    InvalidHeader(&'static str),
}

impl core::fmt::Display for PacketDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion { version, .. } => {
                write!(f, "unsupported version {version}")
            }
            Self::InvalidHeader(field0) => write!(f, "invalid header: {field0}"),
        }
    }
}

impl core::error::Error for PacketDecodeError {}

impl From<coding::UnexpectedEnd> for PacketDecodeError {
    fn from(_: coding::UnexpectedEnd) -> Self {
        Self::InvalidHeader("unexpected end of packet")
    }
}

pub const LONG_HEADER_FORM: u8 = 0x80;
pub const FIXED_BIT: u8 = 0x40;
pub const SPIN_BIT: u8 = 0x20;
const SHORT_RESERVED_BITS: u8 = 0x18;
const LONG_RESERVED_BITS: u8 = 0x0c;
const KEY_PHASE_BIT: u8 = 0x04;

/// Packet number space identifiers
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum SpaceId {
    /// Unprotected packets, used to bootstrap the handshake
    Initial = 0,
    Handshake = 1,
    /// Application data space, used for 0-RTT and post-handshake/1-RTT packets
    Data = 2,
}

impl SpaceId {
    pub fn iter() -> impl Iterator<Item = Self> {
        [Self::Initial, Self::Handshake, Self::Data].iter().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_packet(version: Version, ty: LongHeaderType, token_len: u64, length: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(ty.to_byte(version.to_wire().unwrap()));
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]);
        if ty == LongHeaderType::Initial {
            bytes.write_var(token_len);
        }
        bytes.write_var(length);
        bytes.push(0);
        bytes
    }

    /// Every split of a coalesced datagram consumes at least a header, so walking one ends even
    /// when each long header claims an empty body.
    #[test]
    fn coalesced_empty_packets_always_make_progress() {
        for version in [Version::V1, Version::V2] {
            for count in [1usize, 2, 64] {
                let mut datagram = Vec::new();
                for _ in 0..count {
                    datagram.push(
                        LongHeaderType::Standard(LongType::Handshake)
                            .to_byte(version.to_wire().unwrap()),
                    );
                    datagram.extend_from_slice(&version.to_be_bytes());
                    // Empty connection IDs and a Length of zero.
                    datagram.extend_from_slice(&[0, 0, 0]);
                }
                datagram.extend_from_slice(&[0x40, 1, 2, 3, 4]);
                let mut rest = Some(BytesMut::from(datagram.as_slice()));
                let mut packets = 0;
                while let Some(bytes) = rest {
                    let before = bytes.len();
                    let (packet, next) = PartialDecode::new(
                        bytes,
                        &FixedLengthConnectionIdParser::new(0),
                        &[version],
                        false,
                    )
                    .unwrap();
                    assert!(packet.len() > 0);
                    assert!(next.as_ref().is_none_or(|next| next.len() < before));
                    packets += 1;
                    rest = next;
                }
                assert_eq!(packets, count + 1);
            }
        }
    }

    /// Splitting a datagram of many coalesced packets copies each packet once: the packet split
    /// off owns its bytes, the rest stays a view of the datagram, and the last packet, still in
    /// that view, is charged the whole datagram.
    #[test]
    fn coalesced_packets_split_in_linear_time_and_own_their_bytes() {
        for version in [Version::V1, Version::V2] {
            let count = 8_188;
            let mut datagram = Vec::with_capacity(count * 8);
            for _ in 0..count {
                datagram.push(
                    LongHeaderType::Standard(LongType::Handshake)
                        .to_byte(version.to_wire().unwrap()),
                );
                datagram.extend_from_slice(&version.to_be_bytes());
                // Empty connection IDs and a Length of zero: the smallest coalesced packet.
                datagram.extend_from_slice(&[0, 0, 0]);
            }
            let backing = BytesMut::from(datagram.as_slice());
            let start = backing.as_ptr().addr();
            let range = start..start + backing.len();
            let mut rest = Some(backing);
            let mut packets = 0;
            while let Some(bytes) = rest {
                let (packet, next) = PartialDecode::new_within(
                    bytes,
                    datagram.len(),
                    &FixedLengthConnectionIdParser::new(0),
                    &[version],
                    false,
                )
                .unwrap();
                packets += 1;
                if let Some(next) = &next {
                    assert!(
                        range.contains(&next.as_ptr().addr()),
                        "the rest is not copied"
                    );
                    assert!(!range.contains(&packet.data().as_ptr().addr()));
                    assert_eq!(packet.allocated, packet.len());
                } else {
                    assert!(range.contains(&packet.data().as_ptr().addr()));
                    assert_eq!(packet.allocated, datagram.len());
                }
                rest = next;
            }
            assert_eq!(packets, count);
        }
    }

    #[test]
    fn long_packet_lengths_are_bounded_before_narrowing() {
        for version in [Version::V1, Version::V2] {
            for ty in [
                LongHeaderType::Initial,
                LongHeaderType::Standard(LongType::Handshake),
                LongHeaderType::Standard(LongType::ZeroRtt),
            ] {
                let header_len = if ty == LongHeaderType::Initial {
                    16
                } else {
                    15
                };
                for length in [
                    (1u64 << 32) - header_len,
                    1u64 << 32,
                    VarInt::MAX.into_inner(),
                ] {
                    let bytes = long_packet(version, ty, 0, length);
                    PartialDecode::new(
                        bytes.as_slice().into(),
                        &FixedLengthConnectionIdParser::new(0),
                        &[version],
                        false,
                    )
                    .unwrap_err();
                }
                let bytes = long_packet(version, ty, 0, 1);
                let (packet, rest) = PartialDecode::new(
                    bytes.as_slice().into(),
                    &FixedLengthConnectionIdParser::new(0),
                    &[version],
                    false,
                )
                .unwrap();
                assert_eq!(packet.len(), bytes.len());
                assert!(rest.is_none());
            }
        }
    }

    #[test]
    fn token_lengths_are_bounded_before_narrowing() {
        for version in [Version::V1, Version::V2] {
            for length in [1u64 << 32, (1u64 << 32) + 1, VarInt::MAX.into_inner()] {
                let bytes = long_packet(version, LongHeaderType::Initial, length, 1);
                PartialDecode::new(
                    bytes.as_slice().into(),
                    &FixedLengthConnectionIdParser::new(0),
                    &[version],
                    false,
                )
                .unwrap_err();
            }
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn capture_lengths_are_bounded_before_narrowing() {
        for version in [Version::V1, Version::V2] {
            for ty in [
                LongHeaderType::Initial,
                LongHeaderType::Standard(LongType::Handshake),
                LongHeaderType::Standard(LongType::ZeroRtt),
            ] {
                for length in [u64::from(u32::MAX), 1u64 << 32, VarInt::MAX.into_inner()] {
                    crate::capture::observe(&long_packet(version, ty, 0, length)).unwrap_err();
                }
                let bytes = long_packet(version, ty, 0, 1);
                let observed = crate::capture::observe(&bytes).unwrap();
                assert_eq!(observed.packets.len(), 1);
                assert_eq!(observed.packets[0].range, 0..bytes.len());
            }
            for length in [1u64 << 32, (1u64 << 32) + 1, VarInt::MAX.into_inner()] {
                crate::capture::observe(&long_packet(version, LongHeaderType::Initial, length, 1))
                    .unwrap_err();
            }
        }
    }

    #[test]
    fn initial_header_budget_covers_variable_length_fields() {
        for version in [Version::V1, Version::V2] {
            for cid_len in [0, 8, 20] {
                for number in [PacketNumber::U8(0), PacketNumber::U32(0)] {
                    for token_len in [0, 63, 64, 16383, 16384, 65527] {
                        let initial = InitialHeader {
                            dst_cid: ConnectionId::new(&[1; 20][..cid_len]),
                            src_cid: ConnectionId::new(&[2; 20][..cid_len]),
                            token: Bytes::from(alloc::vec![0; token_len]),
                            number,
                            version: version.to_wire().unwrap(),
                        };
                        let budget = initial.encoded_len().unwrap();
                        let mut wire = alloc::vec![42; 100];
                        let prefix = wire.len();
                        Header::Initial(initial).encode(&mut wire);
                        assert_eq!(wire.len() - prefix, budget);
                    }
                }
            }
        }
    }

    #[test]
    fn protected_long_headers_reserve_length_for_their_packet_capacity() {
        for version in [Version::V1, Version::V2] {
            let version = version.to_wire().unwrap();
            for header in [
                Header::Initial(InitialHeader {
                    dst_cid: ConnectionId::new(&[1; 8]),
                    src_cid: ConnectionId::new(&[2; 8]),
                    token: Bytes::new(),
                    number: PacketNumber::U8(0),
                    version,
                }),
                Header::Long {
                    ty: LongType::Handshake,
                    dst_cid: ConnectionId::new(&[1; 8]),
                    src_cid: ConnectionId::new(&[2; 8]),
                    number: PacketNumber::U8(0),
                    version,
                },
                Header::Long {
                    ty: LongType::ZeroRtt,
                    dst_cid: ConnectionId::new(&[1; 8]),
                    src_cid: ConnectionId::new(&[2; 8]),
                    number: PacketNumber::U8(0),
                    version,
                },
            ] {
                let mut ordinary = Vec::new();
                let encoded = header.encode(&mut ordinary);
                let length_pos =
                    encoded.header_len - encoded.pn.unwrap() - encoded.payload_len.unwrap();

                for (max_packet_len, expected_width) in [
                    (length_pos + 2 + 16_383, 2),
                    (length_pos + 2 + 16_384, 4),
                    (65_527, 4),
                ] {
                    let mut wire = Vec::new();
                    let encoded = header.encode_with_max_packet_len(&mut wire, max_packet_len);
                    assert_eq!(encoded.payload_len, Some(expected_width));
                }
            }
        }
    }

    fn check_pn(typed: PacketNumber, encoded: &[u8]) {
        let mut buf = Vec::new();
        typed.encode(&mut buf);
        assert_eq!(&buf[..], encoded);
        let decoded = PacketNumber::decode(typed.len(), &mut Cursor::new(&buf)).unwrap();
        assert_eq!(typed, decoded);
    }

    #[test]
    fn roundtrip_packet_numbers() {
        check_pn(PacketNumber::U8(0x7f), &[0x7f]);
        check_pn(PacketNumber::U16(0x80), &[0x00, 0x80]);
        check_pn(PacketNumber::U16(0x3fff), &[0x3f, 0xff]);
        check_pn(PacketNumber::U32(0x0000_4000), &[0x00, 0x00, 0x40, 0x00]);
        check_pn(PacketNumber::U32(0xffff_ffff), &[0xff, 0xff, 0xff, 0xff]);
    }

    /// RFC 9000 Appendix A.3, including its bound at the top of the packet number space: an
    /// expansion never leaves it while the expected number is inside it.
    #[test]
    fn packet_numbers_expand_inside_their_space() {
        assert_eq!(PacketNumber::U16(0x9b32).expand(0xa82f_30eb), 0xa82f_9b32);
        for expected in [
            MAX_PACKET_NUMBER - 1000,
            MAX_PACKET_NUMBER - 1,
            MAX_PACKET_NUMBER,
        ] {
            for number in [
                PacketNumber::U8(0),
                PacketNumber::U8(0xff),
                PacketNumber::U16(0),
                PacketNumber::U24(0),
                PacketNumber::U32(0),
            ] {
                assert!(
                    number.expand(expected) <= MAX_PACKET_NUMBER,
                    "{number:?} near {expected}"
                );
            }
        }
        // Only one past the space can be expected, after the last number was received; what
        // that yields is beyond it and refused where it is received.
        assert!(PacketNumber::U8(5).expand(MAX_PACKET_NUMBER + 1) > MAX_PACKET_NUMBER);
    }

    #[test]
    fn pn_encode() {
        check_pn(PacketNumber::new(0x10, 0).unwrap(), &[0x10]);
        check_pn(PacketNumber::new(0x100, 0).unwrap(), &[0x01, 0x00]);
        check_pn(PacketNumber::new(0x10000, 0).unwrap(), &[0x01, 0x00, 0x00]);
    }

    #[test]
    fn pn_expand_roundtrip() {
        for expected in 0..1024 {
            for actual in expected..1024 {
                assert_eq!(
                    actual,
                    PacketNumber::new(actual, expected)
                        .unwrap()
                        .expand(expected)
                );
            }
        }
    }
}
