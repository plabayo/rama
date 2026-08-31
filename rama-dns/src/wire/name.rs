use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};

use rama_core::bytes::{Bytes, BytesMut};
use rama_net::address::{Domain, DomainBuilder, DomainLabels as _};

/// A fully qualified DNS name in uncompressed wire format.
///
/// Unlike [`Domain`], this type preserves DNS label boundaries and arbitrary
/// label octets, including their original case, and it can represent the root
/// name. Equality, hashing, and ordering are ASCII-case-insensitive. Ordering
/// is not RFC 4034 DNSSEC canonical-name ordering.
#[derive(Clone)]
pub struct Name(Bytes);

impl Name {
    /// Maximum encoded length of a DNS name, including the root label.
    pub const MAX_WIRE_LEN: usize = 255;

    /// Return the DNS root name (`.`).
    #[must_use]
    pub fn root() -> Self {
        Self(Bytes::from_static(b"\0"))
    }

    /// Parse one complete, uncompressed DNS name.
    ///
    /// Compression pointers are invalid here. RFC 9460 requires the target
    /// name in SVCB-compatible RDATA to be uncompressed.
    pub fn from_wire(wire: &[u8]) -> Result<Self, NameParseError> {
        let consumed = validate_prefix(wire)?;
        if consumed != wire.len() {
            return Err(NameParseError(NameParseErrorKind::TrailingData));
        }
        Ok(Self(Bytes::copy_from_slice(wire)))
    }

    /// Parse one complete, uncompressed DNS name from shared bytes.
    ///
    /// Compression pointers are invalid here. The returned name shares the
    /// input allocation.
    pub fn from_wire_bytes(wire: &Bytes) -> Result<Self, NameParseError> {
        let consumed = validate_prefix(wire)?;
        if consumed != wire.len() {
            return Err(NameParseError(NameParseErrorKind::TrailingData));
        }
        Ok(Self::from_valid_wire(wire.clone()))
    }

    /// Parse a possibly compressed DNS name at `offset` in a complete message.
    ///
    /// The returned length is the number of message octets occupied by the
    /// encoded name at `offset`; bytes followed through compression pointers
    /// are not included. RFC 1035 compression pointers must refer to prior
    /// name occurrences. Enforcing a decreasing target ceiling guarantees
    /// termination without rejecting long valid chains.
    pub fn from_message(message: &[u8], offset: usize) -> Result<(Self, usize), NameParseError> {
        let mut wire = BytesMut::with_capacity(64);
        let mut cursor = offset;
        let mut encoded_end = None;
        let mut pointer_ceiling = offset;

        loop {
            let Some(&label_len) = message.get(cursor) else {
                return Err(NameParseError(NameParseErrorKind::TruncatedLabel));
            };

            if label_len & 0xc0 == 0xc0 {
                let Some(&second) = message.get(cursor + 1) else {
                    return Err(NameParseError(
                        NameParseErrorKind::TruncatedCompressionPointer,
                    ));
                };
                let target = usize::from(u16::from_be_bytes([label_len & 0x3f, second]));
                if target >= pointer_ceiling {
                    return Err(NameParseError(
                        NameParseErrorKind::NonPriorCompressionPointer,
                    ));
                }
                encoded_end.get_or_insert(cursor + 2);
                pointer_ceiling = target;
                cursor = target;
                continue;
            }
            if label_len & 0xc0 != 0 {
                return Err(NameParseError(NameParseErrorKind::InvalidLabelKind));
            }
            if label_len == 0 {
                wire.extend_from_slice(b"\0");
                let consumed = encoded_end
                    .unwrap_or(cursor + 1)
                    .checked_sub(offset)
                    .ok_or(NameParseError(
                        NameParseErrorKind::NonPriorCompressionPointer,
                    ))?;
                return Ok((Self::from_valid_wire(wire.freeze()), consumed));
            }

            let label_start = cursor + 1;
            let label_end = label_start
                .checked_add(usize::from(label_len))
                .ok_or(NameParseError(NameParseErrorKind::NameTooLong))?;
            let label = message
                .get(label_start..label_end)
                .ok_or(NameParseError(NameParseErrorKind::TruncatedLabel))?;
            if wire.len() + 1 + label.len() + 1 > Self::MAX_WIRE_LEN {
                return Err(NameParseError(NameParseErrorKind::NameTooLong));
            }
            wire.extend_from_slice(&[label_len]);
            wire.extend_from_slice(label);
            cursor = label_end;
        }
    }

    /// Return this name's case-preserving, uncompressed wire representation.
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.0
    }

    /// Return whether this is the DNS root name (`.`).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    /// Convert this wire name to Rama's presentation-domain type.
    ///
    /// The root name and names with label octets that [`Domain`] cannot
    /// represent return `None`. Conversion allocates one presentation buffer
    /// because the wire and presentation encodings differ.
    #[must_use]
    pub fn to_domain(&self) -> Option<Domain> {
        if self.is_root() {
            return None;
        }

        let mut builder = DomainBuilder::with_capacity(self.0.len().saturating_sub(1));
        // Construction guarantees a terminating root label and complete labels.
        let mut offset = 0;
        while self.0[offset] != 0 {
            let label_len = usize::from(self.0[offset]);
            let label_start = offset + 1;
            let label_end = label_start + label_len;
            let label = &self.0[label_start..label_end];
            builder.push_label_bytes(label).ok()?;
            offset = label_end;
        }
        builder.finish_fqdn().ok()
    }

    pub(super) fn parse_prefix(wire: &Bytes) -> Result<(Self, usize), NameParseError> {
        let consumed = validate_prefix(wire)?;
        Ok((Self::from_valid_wire(wire.slice(..consumed)), consumed))
    }

    fn from_valid_wire(wire: Bytes) -> Self {
        Self(wire)
    }
}

impl From<&Domain> for Name {
    fn from(domain: &Domain) -> Self {
        let mut wire = BytesMut::with_capacity(domain.as_str().len() + 2);
        for label in domain.labels() {
            wire.extend_from_slice(&[label.len() as u8]);
            wire.extend_from_slice(label.as_str().as_bytes());
        }
        wire.extend_from_slice(b"\0");
        Self::from_valid_wire(wire.freeze())
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(other.0.iter())
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }
}

impl Eq for Name {}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(other.0.iter().map(u8::to_ascii_lowercase))
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in &self.0 {
            state.write_u8(byte.to_ascii_lowercase());
        }
    }
}

impl From<Domain> for Name {
    fn from(domain: Domain) -> Self {
        Self::from(&domain)
    }
}

fn validate_prefix(wire: &[u8]) -> Result<usize, NameParseError> {
    let mut offset = 0usize;
    loop {
        let Some(&label_len) = wire.get(offset) else {
            return Err(NameParseError(NameParseErrorKind::MissingRootLabel));
        };
        if label_len == 0 {
            let consumed = offset + 1;
            if consumed > Name::MAX_WIRE_LEN {
                return Err(NameParseError(NameParseErrorKind::NameTooLong));
            }
            return Ok(consumed);
        }
        if label_len & 0xc0 == 0xc0 {
            return Err(NameParseError(NameParseErrorKind::CompressedLabel));
        }
        if label_len & 0xc0 != 0 {
            return Err(NameParseError(NameParseErrorKind::InvalidLabelKind));
        }

        let label_start = offset
            .checked_add(1)
            .ok_or(NameParseError(NameParseErrorKind::NameTooLong))?;
        let label_end = label_start
            .checked_add(usize::from(label_len))
            .ok_or(NameParseError(NameParseErrorKind::NameTooLong))?;
        if label_end <= offset || label_end > Name::MAX_WIRE_LEN {
            return Err(NameParseError(NameParseErrorKind::NameTooLong));
        }
        if label_end > wire.len() {
            return Err(NameParseError(NameParseErrorKind::TruncatedLabel));
        }
        offset = label_end;
    }
}

/// Formats a human-readable diagnostic, not DNS master-file syntax.
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }

        // Construction guarantees a terminating root label and complete labels.
        let mut offset = 0;
        while self.0[offset] != 0 {
            let label_len = usize::from(self.0[offset]);
            offset += 1;
            for &byte in &self.0[offset..offset + label_len] {
                match byte {
                    b'!'..=b'-' | b'0'..=b'[' | b']'..=b'~' => {
                        f.write_str(char::from(byte).encode_utf8(&mut [0; 4]))?;
                    }
                    _ => write!(f, "\\{byte:03}")?,
                }
            }
            offset += label_len;
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Name").field(&self.to_string()).finish()
    }
}

/// Error returned when a DNS name cannot be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameParseError(NameParseErrorKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum NameParseErrorKind {
    MissingRootLabel,
    TruncatedLabel,
    CompressedLabel,
    NameTooLong,
    TrailingData,
    TruncatedCompressionPointer,
    NonPriorCompressionPointer,
    InvalidLabelKind,
}

impl fmt::Display for NameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            NameParseErrorKind::MissingRootLabel => "DNS name has no terminating root label",
            NameParseErrorKind::TruncatedLabel => "DNS name ends within a label",
            NameParseErrorKind::CompressedLabel => {
                "compressed DNS name is not allowed in this field"
            }
            NameParseErrorKind::NameTooLong => "DNS name exceeds 255 wire octets",
            NameParseErrorKind::TrailingData => "data follows the DNS root label",
            NameParseErrorKind::TruncatedCompressionPointer => {
                "DNS name ends within a compression pointer"
            }
            NameParseErrorKind::NonPriorCompressionPointer => {
                "DNS compression pointer does not refer to a prior name occurrence"
            }
            NameParseErrorKind::InvalidLabelKind => "DNS name uses an unsupported label kind",
        })
    }
}

impl core::error::Error for NameParseError {}
