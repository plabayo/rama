//! Small ASCII-hex utilities for single-byte parse/format.
//!
//! The single-byte helpers are useful in tight inner loops (URI
//! percent-decoding, TLS keylog parsing, fingerprint formatting). The bulk
//! helpers decode/encode into caller-owned slices ([`decode_into`],
//! [`encode_into`]) or allocate for convenience ([`decode`], [`encode`]).
//! To format bytes into a `core::fmt` writer without a buffer use
//! [`crate::fmt::hex`] with `{:x}` or `{:X}`. The same deferred formatter works
//! with byte buffers and I/O writers through `write!`, without a temporary allocation.

/// ASCII hex digit → `0..=15`, `None` for non-hex bytes.
///
/// Accepts uppercase and lowercase: `'0'..='9'`, `'a'..='f'`, `'A'..='F'`.
///
/// ```
/// use rama_utils::hex::nibble;
/// assert_eq!(nibble(b'0'), Some(0));
/// assert_eq!(nibble(b'9'), Some(9));
/// assert_eq!(nibble(b'a'), Some(10));
/// assert_eq!(nibble(b'F'), Some(15));
/// assert_eq!(nibble(b'g'), None);
/// assert_eq!(nibble(0xFF), None);
/// ```
#[inline]
#[must_use]
pub const fn nibble(b: u8) -> Option<u8> {
    let d = b.wrapping_sub(b'0');
    if d < 10 {
        return Some(d);
    }
    // Case-fold by setting bit 5: `'A' | 0x20 == 'a'`.
    let l = (b | 0x20).wrapping_sub(b'a');
    if l < 6 {
        return Some(l + 10);
    }
    None
}

/// Uppercase ASCII hex digit to `0..=15`.
///
/// Decimal digits and `A` through `F` are accepted; lowercase is rejected.
#[inline]
#[must_use]
pub const fn upper_nibble(b: u8) -> Option<u8> {
    let d = b.wrapping_sub(b'0');
    if d < 10 {
        return Some(d);
    }
    let u = b.wrapping_sub(b'A');
    if u < 6 {
        return Some(u + 10);
    }
    None
}

/// Decode a `%XX`-style hex pair to its byte value, or `None` if either
/// nibble is not a valid hex digit.
///
/// ```
/// use rama_utils::hex::decode_pair;
/// assert_eq!(decode_pair(b'C', b'3'), Some(0xC3));
/// assert_eq!(decode_pair(b'a', b'9'), Some(0xA9));
/// assert_eq!(decode_pair(b'Z', b'0'), None);
/// ```
#[inline]
#[must_use]
pub const fn decode_pair(hi: u8, lo: u8) -> Option<u8> {
    match (nibble(hi), nibble(lo)) {
        (Some(h), Some(l)) => Some((h << 4) + l),
        _ => None,
    }
}

/// Decode two uppercase ASCII hex digits to one byte.
///
/// Decimal digits are accepted in either position; lowercase is rejected.
#[inline]
#[must_use]
pub const fn decode_upper_pair(hi: u8, lo: u8) -> Option<u8> {
    match (upper_nibble(hi), upper_nibble(lo)) {
        (Some(h), Some(l)) => Some((h << 4) + l),
        _ => None,
    }
}

/// Encode one byte as two uppercase ASCII hex digits.
#[inline]
#[must_use]
pub const fn encode_byte_upper(byte: u8) -> [u8; 2] {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    [DIGITS[(byte >> 4) as usize], DIGITS[(byte & 0x0f) as usize]]
}

use crate::std::{string::String, vec, vec::Vec};

/// Error returned by the bulk decoders ([`decode`], [`decode_into`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// A byte at the given input offset is not an ASCII hex digit.
    InvalidDigit {
        /// Offset of the offending byte in the input.
        position: usize,
        /// The offending byte.
        byte: u8,
    },
    /// The input holds an odd number of hex digits.
    OddLength,
    /// The destination cannot hold the decoded bytes.
    InsufficientCapacity {
        /// Number of bytes the input decodes to.
        needed: usize,
    },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidDigit { position, byte } => {
                write!(f, "invalid hex digit 0x{byte:02X} at offset {position}")
            }
            Self::OddLength => f.write_str("odd number of hex digits"),
            Self::InsufficientCapacity { needed } => {
                write!(f, "destination too small for {needed} decoded bytes")
            }
        }
    }
}

impl core::error::Error for DecodeError {}

/// Error returned by the bulk encoders ([`encode_into`], [`encode_upper_into`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The destination cannot hold the encoded digits.
    InsufficientCapacity {
        /// Number of bytes the encoding needs (two per input byte).
        needed: usize,
    },
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientCapacity { needed } => {
                write!(f, "destination too small for {needed} hex digits")
            }
        }
    }
}

impl core::error::Error for EncodeError {}

/// ASCII whitespace that may separate hex digits in bulk input.
#[inline]
const fn is_separator(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// Validate bulk hex input and return the number of bytes it decodes to.
fn decoded_len(input: &[u8]) -> Result<usize, DecodeError> {
    let mut digits = 0usize;
    for (position, &byte) in input.iter().enumerate() {
        if is_separator(byte) {
            continue;
        }
        if nibble(byte).is_none() {
            return Err(DecodeError::InvalidDigit { position, byte });
        }
        digits += 1;
    }
    if !digits.is_multiple_of(2) {
        return Err(DecodeError::OddLength);
    }
    Ok(digits / 2)
}

/// Decode already validated input into `output`, which must hold `decoded_len` bytes.
fn write_decoded(input: &[u8], output: &mut [u8]) -> usize {
    let mut written = 0usize;
    let mut pending: Option<u8> = None;
    for &byte in input {
        let Some(digit) = nibble(byte) else {
            // separators were accepted by `decoded_len`
            continue;
        };
        match pending.take() {
            Some(hi) => {
                output[written] = (hi << 4) | digit;
                written += 1;
            }
            None => pending = Some(digit),
        }
    }
    written
}

/// Decode an ASCII hex string into `output`, returning the number of bytes written.
///
/// Upper- and lowercase digits are accepted and may be mixed. ASCII whitespace
/// (space, tab, CR, LF) between digits is skipped so long fixtures can be laid
/// out readably; any other non-hex byte is an error, as is an odd digit count.
/// Error offsets refer to the original input.
///
/// `output` may be larger than needed; bytes past the returned length are left
/// untouched. The input is validated before anything is written, so on `Err`
/// the destination is unchanged.
///
/// ```
/// use rama_utils::hex::{DecodeError, decode_into};
/// let mut buf = [0xAAu8; 4];
/// assert_eq!(decode_into("c0 FF\nee", &mut buf), Ok(3));
/// assert_eq!(buf, [0xC0, 0xFF, 0xEE, 0xAA]);
/// assert_eq!(
///     decode_into("00112233", &mut buf[..2]),
///     Err(DecodeError::InsufficientCapacity { needed: 4 })
/// );
/// ```
pub fn decode_into(input: impl AsRef<[u8]>, output: &mut [u8]) -> Result<usize, DecodeError> {
    let input = input.as_ref();
    let needed = decoded_len(input)?;
    if needed > output.len() {
        return Err(DecodeError::InsufficientCapacity { needed });
    }
    Ok(write_decoded(input, output))
}

/// Decode an ASCII hex string into a new `Vec`.
///
/// Allocating convenience over [`decode_into`], with the same whitespace,
/// case and error rules.
///
/// ```
/// use rama_utils::hex::{DecodeError, decode};
/// assert_eq!(decode("c0 FF\n ee").unwrap(), vec![0xC0, 0xFF, 0xEE]);
/// assert_eq!(decode(""), Ok(Vec::new()));
/// assert_eq!(decode("abc"), Err(DecodeError::OddLength));
/// assert_eq!(
///     decode("0g"),
///     Err(DecodeError::InvalidDigit { position: 1, byte: b'g' })
/// );
/// ```
pub fn decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    let input = input.as_ref();
    let needed = decoded_len(input)?;
    let mut out = vec![0u8; needed];
    let written = write_decoded(input, &mut out);
    debug_assert_eq!(written, needed);
    Ok(out)
}

/// Encode one byte as two lowercase ASCII hex digits.
#[inline]
#[must_use]
pub const fn encode_byte(byte: u8) -> [u8; 2] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    [DIGITS[(byte >> 4) as usize], DIGITS[(byte & 0x0f) as usize]]
}

fn encode_with(
    input: &[u8],
    output: &mut [u8],
    encode_byte: fn(u8) -> [u8; 2],
) -> Result<usize, EncodeError> {
    let needed = input.len().saturating_mul(2);
    if needed > output.len() {
        return Err(EncodeError::InsufficientCapacity { needed });
    }
    let (pairs, _) = output[..needed].as_chunks_mut::<2>();
    for (pair, &byte) in pairs.iter_mut().zip(input) {
        *pair = encode_byte(byte);
    }
    Ok(needed)
}

/// Encode bytes as lowercase ASCII hex digits into `output`, returning the number
/// of digits written (two per input byte).
///
/// `output` may be larger than needed; bytes past the returned length are left
/// untouched. Nothing is written when the destination is too small. For
/// formatting into a `core::fmt` writer without a buffer, see
/// [`crate::fmt::hex`] with `{:x}` or `{:X}`; `write!` can append directly to
/// a reusable string, byte buffer, or I/O writer.
///
/// ```
/// use rama_utils::hex::{EncodeError, encode_into};
/// let mut buf = [b'.'; 8];
/// assert_eq!(encode_into([0xC0, 0xFF, 0xEE], &mut buf), Ok(6));
/// assert_eq!(&buf, b"c0ffee..");
/// assert_eq!(
///     encode_into([0u8; 8], &mut buf),
///     Err(EncodeError::InsufficientCapacity { needed: 16 })
/// );
/// ```
pub fn encode_into(input: impl AsRef<[u8]>, output: &mut [u8]) -> Result<usize, EncodeError> {
    encode_with(input.as_ref(), output, encode_byte)
}

/// [`encode_into`] with uppercase digits.
pub fn encode_upper_into(input: impl AsRef<[u8]>, output: &mut [u8]) -> Result<usize, EncodeError> {
    encode_with(input.as_ref(), output, encode_byte_upper)
}

fn encode_string(input: &[u8], encode_byte: fn(u8) -> [u8; 2]) -> String {
    let mut out = String::with_capacity(input.len().saturating_mul(2));
    for &byte in input {
        let [hi, lo] = encode_byte(byte);
        out.push(char::from(hi));
        out.push(char::from(lo));
    }
    out
}

/// Encode bytes as a lowercase ASCII hex `String`.
///
/// Allocating convenience over [`encode_into`].
///
/// ```
/// use rama_utils::hex::encode;
/// assert_eq!(encode([0xC0, 0xFF, 0xEE]), "c0ffee");
/// assert_eq!(encode([]), "");
/// ```
#[must_use]
pub fn encode(input: impl AsRef<[u8]>) -> String {
    encode_string(input.as_ref(), encode_byte)
}

/// [`encode`] with uppercase digits.
#[must_use]
pub fn encode_upper(input: impl AsRef<[u8]>) -> String {
    encode_string(input.as_ref(), encode_byte_upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_into_exact_oversized_and_undersized_destinations() {
        let mut exact = [0u8; 4];
        assert_eq!(decode_into("DeadBEEF", &mut exact), Ok(4));
        assert_eq!(exact, [0xDE, 0xAD, 0xBE, 0xEF]);

        let mut oversized = [0x55u8; 6];
        assert_eq!(decode_into("de ad\tbe\r\nef ", &mut oversized), Ok(4));
        assert_eq!(
            oversized,
            [0xDE, 0xAD, 0xBE, 0xEF, 0x55, 0x55],
            "tail untouched"
        );

        let mut undersized = [0x55u8; 3];
        assert_eq!(
            decode_into("deadbeef", &mut undersized),
            Err(DecodeError::InsufficientCapacity { needed: 4 })
        );
        assert_eq!(undersized, [0x55; 3], "nothing written on error");

        let mut empty: [u8; 0] = [];
        assert_eq!(decode_into("", &mut empty), Ok(0));
        assert_eq!(decode_into("  \n", &mut empty), Ok(0));
        assert_eq!(
            decode_into("00", &mut empty),
            Err(DecodeError::InsufficientCapacity { needed: 1 })
        );
    }

    #[test]
    fn decode_into_validates_before_writing() {
        let mut buf = [0x55u8; 4];
        assert_eq!(
            decode_into("00zz", &mut buf),
            Err(DecodeError::InvalidDigit {
                position: 2,
                byte: b'z'
            })
        );
        assert_eq!(decode_into("001", &mut buf), Err(DecodeError::OddLength));
        assert_eq!(
            buf, [0x55; 4],
            "invalid input leaves the destination unchanged"
        );
    }

    #[test]
    fn decode_mixed_case_and_whitespace() {
        assert_eq!(decode("DeadBEEF").unwrap(), [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            decode("de ad\tbe\r\nef ").unwrap(),
            [0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(decode(b"00ff"), Ok(vec![0x00, 0xFF]));
        assert_eq!(decode(""), Ok(Vec::new()));
        assert_eq!(decode("   "), Ok(Vec::new()));
    }

    #[test]
    fn decode_rejects_odd_and_invalid_input() {
        assert_eq!(decode("a"), Err(DecodeError::OddLength));
        assert_eq!(decode("abc"), Err(DecodeError::OddLength));
        assert_eq!(decode("ab c"), Err(DecodeError::OddLength));
        assert_eq!(
            decode("0x00"),
            Err(DecodeError::InvalidDigit {
                position: 1,
                byte: b'x'
            })
        );
        assert_eq!(
            decode("00-00"),
            Err(DecodeError::InvalidDigit {
                position: 2,
                byte: b'-'
            })
        );
        assert_eq!(
            decode("00\u{a0}00"),
            Err(DecodeError::InvalidDigit {
                position: 2,
                byte: 0xC2
            })
        );
    }

    #[test]
    fn encode_into_exact_oversized_and_undersized_destinations() {
        let mut exact = [0u8; 6];
        assert_eq!(encode_into([0xC0, 0xFF, 0xEE], &mut exact), Ok(6));
        assert_eq!(&exact, b"c0ffee");

        let mut oversized = [b'.'; 8];
        assert_eq!(encode_upper_into([0xC0, 0xFF, 0xEE], &mut oversized), Ok(6));
        assert_eq!(&oversized, b"C0FFEE..", "tail untouched");

        let mut undersized = [b'.'; 5];
        assert_eq!(
            encode_into([0xC0, 0xFF, 0xEE], &mut undersized),
            Err(EncodeError::InsufficientCapacity { needed: 6 })
        );
        assert_eq!(&undersized, b".....", "nothing written on error");

        let mut empty: [u8; 0] = [];
        assert_eq!(encode_into([], &mut empty), Ok(0));
        assert_eq!(encode([]), "");
        assert_eq!(encode_upper([0xAB, 0x01]), "AB01");
    }

    #[test]
    fn bulk_round_trips_every_byte_value() {
        let all: Vec<u8> = (0u8..=255).collect();
        let lower = encode(&all);
        let upper = encode_upper(&all);
        assert_eq!(lower.len(), 512);
        assert_eq!(lower.to_ascii_uppercase(), upper);
        assert_eq!(decode(&lower).unwrap(), all);
        assert_eq!(decode(&upper).unwrap(), all);

        let mut digits = [0u8; 512];
        assert_eq!(encode_into(&all, &mut digits), Ok(512));
        let mut bytes = [0u8; 256];
        assert_eq!(decode_into(digits, &mut bytes), Ok(256));
        assert_eq!(&bytes[..], &all[..]);
        for byte in 0u8..=255 {
            let [hi, lo] = encode_byte(byte);
            assert_eq!(decode_pair(hi, lo), Some(byte));
            assert!(hi.is_ascii_digit() || hi.is_ascii_lowercase());
            assert!(lo.is_ascii_digit() || lo.is_ascii_lowercase());
        }
    }

    #[test]
    fn nibble_exhaustive_256_bytes() {
        for b in 0u8..=255 {
            let got = nibble(b);
            let expected = match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            assert_eq!(got, expected, "nibble(0x{b:02X})");
        }
    }

    #[test]
    fn nibble_boundary_bytes() {
        for b in [b'/', b':', b'@', b'G', b'`', b'g', 0x80, 0xFF] {
            assert_eq!(nibble(b), None, "boundary byte 0x{b:02X}");
        }
    }

    #[test]
    fn upper_nibble_exhaustive_256_bytes() {
        for b in 0u8..=255 {
            let expected = match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            assert_eq!(upper_nibble(b), expected, "upper_nibble(0x{b:02X})");
        }
    }

    #[test]
    fn decode_pair_round_trip() {
        for b in 0u8..=255 {
            let hi_nib = b >> 4;
            let lo_nib = b & 0x0F;
            let hi_char = if hi_nib < 10 {
                b'0' + hi_nib
            } else {
                b'A' + hi_nib - 10
            };
            let lo_char = if lo_nib < 10 {
                b'0' + lo_nib
            } else {
                b'a' + lo_nib - 10
            };
            assert_eq!(decode_pair(hi_char, lo_char), Some(b));
        }
    }

    #[test]
    fn decode_pair_rejects_non_hex() {
        assert_eq!(decode_pair(b'Z', b'0'), None);
        assert_eq!(decode_pair(b'0', b'Z'), None);
        assert_eq!(decode_pair(b' ', b'0'), None);
    }

    #[test]
    fn uppercase_pair_encoding_round_trips_every_byte() {
        for byte in 0u8..=255 {
            let encoded = encode_byte_upper(byte);
            assert_eq!(decode_upper_pair(encoded[0], encoded[1]), Some(byte));
            assert!(
                encoded
                    .iter()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
            );
        }
        assert_eq!(decode_upper_pair(b'a', b'0'), None);
        assert_eq!(decode_upper_pair(b'0', b'f'), None);
    }
}
