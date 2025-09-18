use serde::{Deserialize, Serialize};

/// A stream identifier, as described in [Section 5.1.1] of RFC 7540.
///
/// Streams are identified with an unsigned 31-bit integer. Streams
/// initiated by a client MUST use odd-numbered stream identifiers; those
/// initiated by the server MUST use even-numbered stream identifiers.  A
/// stream identifier of zero (0x0) is used for connection control
/// messages; the stream identifier of zero cannot be used to establish a
/// new stream.
///
/// [Section 5.1.1]: https://tools.ietf.org/html/rfc7540#section-5.1.1
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(u32);

#[derive(Debug, Copy, Clone)]
pub struct StreamIdOverflow;

const STREAM_ID_MASK: u32 = 1 << 31;

impl StreamId {
    /// Stream ID 0.
    pub const ZERO: Self = Self(0);

    /// The maximum allowed stream ID.
    pub const MAX: Self = Self(u32::MAX >> 1);

    /// Parse the stream ID
    #[inline]
    #[must_use]
    pub fn parse(buf: &[u8]) -> (Self, bool) {
        let mut ubuf = [0; 4];
        ubuf.copy_from_slice(&buf[0..4]);
        let unpacked = u32::from_be_bytes(ubuf);
        let flag = unpacked & STREAM_ID_MASK == STREAM_ID_MASK;

        // Now clear the most significant bit, as that is reserved and MUST be
        // ignored when received.
        (Self(unpacked & !STREAM_ID_MASK), flag)
    }

    /// Returns true if this stream ID corresponds to a stream that
    /// was initiated by the client.
    #[must_use]
    pub fn is_client_initiated(&self) -> bool {
        let id = self.0;
        id != 0 && id % 2 == 1
    }

    /// Returns true if this stream ID corresponds to a stream that
    /// was initiated by the server.
    #[must_use]
    pub fn is_server_initiated(&self) -> bool {
        let id = self.0;
        id != 0 && id.is_multiple_of(2)
    }

    /// Return a new `StreamId` for stream 0.
    #[inline]
    #[must_use]
    pub fn zero() -> Self {
        Self::ZERO
    }

    /// Returns true if this stream ID is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Returns the next stream ID initiated by the same peer as this stream
    /// ID, or an error if incrementing this stream ID would overflow the
    /// maximum.
    pub fn next_id(&self) -> Result<Self, StreamIdOverflow> {
        let next = self.0 + 2;
        if next > Self::MAX.0 {
            Err(StreamIdOverflow)
        } else {
            Ok(Self(next))
        }
    }
}

impl From<u32> for StreamId {
    fn from(src: u32) -> Self {
        assert_eq!(src & STREAM_ID_MASK, 0, "invalid stream ID -- MSB is set");
        Self(src)
    }
}

impl From<StreamId> for u32 {
    fn from(src: StreamId) -> Self {
        src.0
    }
}

impl PartialEq<u32> for StreamId {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl Serialize for StreamId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StreamId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let n = u32::deserialize(deserializer)?;
        Ok(Self(n))
    }
}
