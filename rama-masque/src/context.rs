//! Shared MASQUE context identifiers.
use rama_core::bytes::BufMut;
use rama_quic_proto::{VarInt, coding::Codec};
use std::fmt;

/// A MASQUE Context ID ([RFC 9298 §4], RFC 9484 section 5).
///
/// Context ID 0 carries the base protocol payload (UDP or IP). Non-zero IDs are allocated by extensions
/// (even by the client, odd by the proxy); this crate defines none, so it drops
/// datagrams carrying them.
///
/// [RFC 9298 §4]: https://datatracker.ietf.org/doc/html/rfc9298#section-4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContextId(VarInt);

impl ContextId {
    /// Context ID 0: UDP payloads.
    pub const UDP: Self = Self(VarInt::from_u32(0));

    /// Context ID 0: IP packets.
    pub const IP: Self = Self(VarInt::from_u32(0));

    /// A Context ID from its value, if it fits a variable-length integer.
    #[must_use]
    pub fn new(value: u64) -> Option<Self> {
        VarInt::from_u64(value).ok().map(Self)
    }

    /// Decode a context prefix, accepting nonminimal QUIC encodings.
    pub fn decode(input: &mut &[u8]) -> Result<Self, rama_quic_proto::coding::UnexpectedEnd> {
        VarInt::decode(input).map(Self)
    }

    /// Append the context identifier using its shortest encoding.
    pub fn encode<B: BufMut>(self, output: &mut B) {
        self.0.encode(output);
    }

    /// The raw value.
    #[must_use]
    pub fn value(self) -> u64 {
        self.0.into_inner()
    }

    /// Whether the client allocates this ID (non-zero and even).
    #[must_use]
    pub fn is_client_allocated(self) -> bool {
        self.value() != 0 && self.value().is_multiple_of(2)
    }

    /// Whether the proxy allocates this ID (odd).
    #[must_use]
    pub fn is_proxy_allocated(self) -> bool {
        !self.value().is_multiple_of(2)
    }
}

impl fmt::Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value().fmt(f)
    }
}
