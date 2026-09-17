//! Wire vocabulary shared across the codec: connection IDs, stream IDs, ECN and reset tokens.

use core::{fmt, ops};

use rama_core::bytes::{Buf, BufMut};

use crate::{MAX_CID_SIZE, VarInt, coding::BufExt};

/// The longest stateless reset token, in bytes (RFC 9000 §10.3).
pub const RESET_TOKEN_SIZE: usize = 16;

rama_utils::macros::error::static_str_error! {
    #[doc = "connection ID was not recognized by the connection ID generator"]
    #[derive(Copy)]
    pub struct InvalidCid;
}

/// Whether an endpoint was the initiator of a connection.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Side {
    /// The initiator of a connection
    Client = 0,
    /// The acceptor of a connection
    Server = 1,
}

impl Side {
    /// Shorthand for `self == Side::Client`
    #[inline]
    #[must_use]
    pub fn is_client(self) -> bool {
        self == Self::Client
    }

    /// Shorthand for `self == Side::Server`
    #[inline]
    #[must_use]
    pub fn is_server(self) -> bool {
        self == Self::Server
    }
}

impl ops::Not for Side {
    type Output = Self;
    fn not(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// Whether a stream communicates data in both directions or only from the initiator.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Dir {
    /// Data flows in both directions
    Bi = 0,
    /// Data flows only from the stream's initiator
    Uni = 1,
}

impl Dir {
    pub fn iter() -> impl Iterator<Item = Self> {
        [Self::Bi, Self::Uni].iter().copied()
    }
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match *self {
            Self::Bi => "bidirectional",
            Self::Uni => "unidirectional",
        })
    }
}

/// Identifier for a stream within a particular connection.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(pub(crate) u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let initiator = match self.initiator() {
            Side::Client => "client",
            Side::Server => "server",
        };
        let dir = match self.dir() {
            Dir::Uni => "uni",
            Dir::Bi => "bi",
        };
        write!(
            f,
            "{} {}directional stream {}",
            initiator,
            dir,
            self.index()
        )
    }
}

impl StreamId {
    /// Create a new `StreamId`.
    #[must_use]
    pub fn new(initiator: Side, dir: Dir, index: u64) -> Self {
        Self((index << 2) | ((dir as u64) << 1) | initiator as u64)
    }
    /// Which side of a connection initiated the stream.
    #[must_use]
    pub fn initiator(self) -> Side {
        if self.0 & 0x1 == 0 {
            Side::Client
        } else {
            Side::Server
        }
    }
    /// Which directions data flows in.
    #[must_use]
    pub fn dir(self) -> Dir {
        if self.0 & 0x2 == 0 { Dir::Bi } else { Dir::Uni }
    }
    /// Distinguishes streams of the same initiator and directionality.
    #[must_use]
    pub fn index(self) -> u64 {
        self.0 >> 2
    }
}

impl From<StreamId> for VarInt {
    fn from(x: StreamId) -> Self {
        // SAFETY: `StreamId` values come from varints or from indices below 2^62.
        unsafe { Self::from_u64_unchecked(x.0) }
    }
}

impl From<VarInt> for StreamId {
    fn from(v: VarInt) -> Self {
        Self(v.into_inner())
    }
}

impl From<StreamId> for u64 {
    fn from(x: StreamId) -> Self {
        x.0
    }
}

impl crate::coding::Codec for StreamId {
    fn decode<B: Buf>(buf: &mut B) -> crate::coding::Result<Self> {
        VarInt::decode(buf).map(|x| Self(x.into_inner()))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        #[expect(
            clippy::unwrap_used,
            reason = "`StreamId` values come from varints or from indices below 2^62"
        )]
        VarInt::from_u64(self.0).unwrap().encode(buf);
    }
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId {
    /// length of CID
    len: u8,
    /// CID in byte array
    bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    /// An identifier of these bytes, at most [`MAX_CID_SIZE`] of them.
    ///
    /// Fails for anything longer, which QUIC version 1 has no room for (RFC 9000 §17.2).
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, InvalidCid> {
        if bytes.len() > MAX_CID_SIZE {
            return Err(InvalidCid::new());
        }
        Ok(Self::new(bytes))
    }

    /// Construct a cid from a byte slice.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].copy_from_slice(bytes);
        res
    }

    /// Construct a cid by reading `len` bytes from a `Buf`.
    ///
    /// Callers need to assure that `buf.remaining() >= len`.
    pub fn from_buf(buf: &mut (impl Buf + ?Sized), len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut res = Self {
            len: len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        buf.copy_to_slice(&mut res[..len]);
        res
    }

    /// Decode from long header format.
    pub fn decode_long(buf: &mut impl Buf) -> Option<Self> {
        let len = buf.get::<u8>().ok()? as usize;
        if len > MAX_CID_SIZE || buf.remaining() < len {
            None
        } else {
            Some(Self::from_buf(buf, len))
        }
    }

    /// Encode in long header format.
    pub fn encode_long(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self);
    }
}

impl ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[0..self.len as usize]
    }
}

impl ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[0..self.len as usize]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bytes[0..self.len as usize].fmt(f)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        rama_utils::fmt::hex(&self[..]).write_to(f)
    }
}

/// Explicit congestion notification codepoint.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    /// The ECT(0) codepoint, indicating that an endpoint is ECN-capable
    Ect0 = 0b10,
    /// The ECT(1) codepoint, indicating that an endpoint is ECN-capable
    Ect1 = 0b01,
    /// The CE codepoint, signalling that congestion was experienced
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Returns whether the codepoint is a CE, signalling that congestion was experienced.
    #[must_use]
    pub fn is_ce(self) -> bool {
        matches!(self, Self::Ce)
    }
}

/// Stateless reset token used to securely communicate that an endpoint has lost state for a
/// connection (RFC 9000 §10.3).
#[expect(
    clippy::derived_hash_with_manual_eq,
    reason = "the manual PartialEq compares the same bytes the derived Hash uses"
)]
#[derive(Debug, Copy, Clone, Hash)]
pub struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl PartialEq for ResetToken {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time::eq(&self.0, &other.0)
    }
}

impl Eq for ResetToken {}

impl From<[u8; RESET_TOKEN_SIZE]> for ResetToken {
    fn from(x: [u8; RESET_TOKEN_SIZE]) -> Self {
        Self(x)
    }
}

impl ops::Deref for ResetToken {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        rama_utils::fmt::hex(&self.0).write_to(f)
    }
}
