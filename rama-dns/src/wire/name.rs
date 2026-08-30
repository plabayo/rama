use core::fmt;

use rama_core::bytes::Bytes;
use rama_net::address::{Domain, DomainBuilder};

/// A fully qualified DNS name in canonical, uncompressed wire format.
///
/// Unlike [`Domain`], this type preserves DNS label boundaries and arbitrary
/// label octets, and it can represent the root name. ASCII letters are stored
/// lowercase for DNS-style equality and hashing. Ordering compares canonical
/// wire bytes; it is not RFC 4034 DNSSEC canonical-name ordering.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        Ok(Self::from_valid_wire(Bytes::copy_from_slice(wire)))
    }

    /// Return this name's canonical, uncompressed wire representation.
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
        if wire.iter().any(u8::is_ascii_uppercase) {
            let mut canonical = wire.to_vec();
            canonical.make_ascii_lowercase();
            Self(Bytes::from(canonical))
        } else {
            Self(wire)
        }
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
        if label_len & 0xc0 != 0 {
            return Err(NameParseError(NameParseErrorKind::CompressedLabel));
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

/// Error returned when an uncompressed DNS name cannot be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameParseError(NameParseErrorKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum NameParseErrorKind {
    MissingRootLabel,
    TruncatedLabel,
    CompressedLabel,
    NameTooLong,
    TrailingData,
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
        })
    }
}

impl core::error::Error for NameParseError {}
