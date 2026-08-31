use core::{fmt, iter::FusedIterator, num::NonZeroUsize};

use rama_core::bytes::Bytes;

use super::presentation::CharacterString;

const MAX_RDATA_LEN: usize = u16::MAX as usize;

/// One validated TXT-record RDATA value.
///
/// A TXT record contains one or more binary DNS character-strings. Record and
/// string boundaries are preserved in one shared, canonical wire buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Txt {
    wire: Bytes,
    string_count: NonZeroUsize,
}

impl Txt {
    /// Parse one complete borrowed TXT RDATA value.
    ///
    /// Validation occurs before one exact-sized copy. Use
    /// [`Self::parse_rdata_bytes`] when the caller already owns a
    /// proportionately sized [`Bytes`] value.
    pub fn parse_rdata(rdata: &[u8]) -> Result<Self, TxtParseError> {
        let string_count = validate_rdata(rdata)?;
        Ok(Self {
            wire: Bytes::copy_from_slice(rdata),
            string_count,
        })
    }

    /// Parse one complete owned TXT RDATA value without copying its strings.
    ///
    /// Retaining a slice also retains its parent allocation. Callers should
    /// use this only when that allocation is already proportionate to this
    /// record, and use [`Self::parse_rdata`] for slices of oversized packets or
    /// callback storage.
    pub fn parse_rdata_bytes(rdata: &Bytes) -> Result<Self, TxtParseError> {
        let string_count = validate_rdata(rdata)?;
        Ok(Self {
            wire: rdata.clone(),
            string_count,
        })
    }

    /// Construct one TXT record from decoded binary character-strings.
    ///
    /// At least one string is required. Every string may contain arbitrary
    /// octets but must be at most 255 octets long, and their complete encoded
    /// RDATA must fit the DNS 16-bit RDLENGTH field.
    pub fn try_from_strings<I, S>(strings: I) -> Result<Self, TxtParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let mut strings = strings.into_iter();
        // The hint counts strings rather than octets. Reserve one length byte
        // plus one conservative content byte per known string; `Vec` grows
        // geometrically for larger payloads without grossly over-allocating
        // records made mostly of empty strings.
        let capacity = strings.size_hint().0.saturating_mul(2).min(MAX_RDATA_LEN);
        let mut wire = Vec::with_capacity(capacity);
        let mut string_count = 0usize;

        for string in strings.by_ref() {
            let string = string.as_ref();
            let string_len = match u8::try_from(string.len()) {
                Ok(length) => length,
                Err(_invalid_length) => {
                    return Err(TxtParseError(TxtParseErrorKind::StringTooLong {
                        len: string.len(),
                    }));
                }
            };
            // Both operands are bounded above: `wire` was checked against the
            // 16-bit RDLENGTH after every previous string, and this string was
            // just proven to fit a `u8` length prefix.
            let encoded_len = wire.len() + 1 + string.len();
            if encoded_len > MAX_RDATA_LEN {
                return Err(TxtParseError(TxtParseErrorKind::RdataTooLong {
                    len: encoded_len,
                }));
            }
            wire.push(string_len);
            wire.extend_from_slice(string);
            string_count += 1;
        }

        let string_count =
            NonZeroUsize::new(string_count).ok_or(TxtParseError(TxtParseErrorKind::EmptyRdata))?;

        Ok(Self {
            wire: Bytes::from(wire),
            string_count,
        })
    }

    /// Return the number of character-strings in this record.
    #[expect(
        clippy::len_without_is_empty,
        reason = "validated TXT records always contain at least one string"
    )]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.string_count.get()
    }

    /// Return the complete length-prefixed TXT RDATA wire value.
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.wire
    }

    /// Iterate over borrowed binary character-strings.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &[u8]> + FusedIterator + Clone {
        TxtIter {
            remaining: &self.wire,
            remaining_strings: self.string_count.get(),
        }
    }

    /// Consume this record and iterate over zero-copy owned string slices.
    ///
    /// Every yielded slice shares the complete record allocation. Prefer
    /// [`Self::iter`] and copy an individual string when it must outlive a much
    /// larger record without retaining that record.
    pub fn into_strings(self) -> impl ExactSizeIterator<Item = Bytes> + FusedIterator + Clone {
        TxtIntoIter {
            remaining: self.wire,
            remaining_strings: self.string_count.get(),
        }
    }
}

/// Formats a human-readable diagnostic while preserving string boundaries.
impl fmt::Display for Txt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, string) in self.iter().take(self.string_count.get()).enumerate() {
            if index != 0 {
                f.write_str(" ")?;
            }
            CharacterString(string).fmt(f)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct TxtIter<'a> {
    remaining: &'a [u8],
    remaining_strings: usize,
}

impl<'a> Iterator for TxtIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_strings == 0 {
            return None;
        }
        let (&length, encoded_strings) = self.remaining.split_first()?;
        let length = usize::from(length);
        let string = encoded_strings.get(..length)?;
        self.remaining = encoded_strings.get(length..)?;
        self.remaining_strings -= 1;
        Some(string)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_strings, Some(self.remaining_strings))
    }
}

impl ExactSizeIterator for TxtIter<'_> {}
impl FusedIterator for TxtIter<'_> {}

#[derive(Clone)]
struct TxtIntoIter {
    remaining: Bytes,
    remaining_strings: usize,
}

impl Iterator for TxtIntoIter {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_strings == 0 {
            return None;
        }
        let length = usize::from(*self.remaining.first()?);
        let string_end = 1 + length;
        if string_end > self.remaining.len() {
            self.remaining_strings = 0;
            return None;
        }
        let string = self.remaining.slice(1..string_end);
        self.remaining = self.remaining.slice(string_end..);
        self.remaining_strings -= 1;
        Some(string)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_strings, Some(self.remaining_strings))
    }
}

impl ExactSizeIterator for TxtIntoIter {}
impl FusedIterator for TxtIntoIter {}

fn validate_rdata(rdata: &[u8]) -> Result<NonZeroUsize, TxtParseError> {
    if rdata.len() > MAX_RDATA_LEN {
        return Err(TxtParseError(TxtParseErrorKind::RdataTooLong {
            len: rdata.len(),
        }));
    }
    if rdata.is_empty() {
        return Err(TxtParseError(TxtParseErrorKind::EmptyRdata));
    }

    let mut remaining = rdata;
    let mut string_count = 0usize;
    while let Some((&length, encoded_strings)) = remaining.split_first() {
        let length = usize::from(length);
        let Some(next) = encoded_strings.get(length..) else {
            return Err(TxtParseError(TxtParseErrorKind::TruncatedString {
                index: string_count,
                expected_len: length,
                actual_len: encoded_strings.len(),
            }));
        };
        remaining = next;
        string_count += 1;
    }
    NonZeroUsize::new(string_count).ok_or(TxtParseError(TxtParseErrorKind::EmptyRdata))
}

/// Error returned when TXT RDATA or decoded strings violate RFC 1035 framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtParseError(TxtParseErrorKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum TxtParseErrorKind {
    EmptyRdata,
    RdataTooLong {
        len: usize,
    },
    StringTooLong {
        len: usize,
    },
    TruncatedString {
        index: usize,
        expected_len: usize,
        actual_len: usize,
    },
}

impl fmt::Display for TxtParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            TxtParseErrorKind::EmptyRdata => {
                f.write_str("TXT RDATA must contain at least one character-string")
            }
            TxtParseErrorKind::RdataTooLong { len } => {
                write!(f, "TXT RDATA length {len} exceeds 65535 octets")
            }
            TxtParseErrorKind::StringTooLong { len } => {
                write!(f, "TXT character-string length {len} exceeds 255 octets")
            }
            TxtParseErrorKind::TruncatedString {
                index,
                expected_len,
                actual_len,
            } => write!(
                f,
                "TXT character-string {index} declares {expected_len} octets but only {actual_len} remain"
            ),
        }
    }
}

impl core::error::Error for TxtParseError {}
