//! QPACK prefixed integers (RFC 9204 §4.1.1) and string literals (RFC 9204 §4.1.2).
//!
//! These are the shared low-level codings under every QPACK field-line and instruction
//! representation. They are decoded from a slice cursor (`&mut &[u8]`); a decoder that needs to
//! recover from a short read treats [`PrefixError::UnexpectedEnd`] as "need more bytes" and retries
//! from the start of the (retained) buffer. This transactional style keeps the codings themselves
//! free of retained state while still supporting fragmented input.

use rama_core::bytes::{BufMut, BytesMut};

use crate::proto::h2::hpack::{DecoderError, huffman};

/// The Huffman-decoded output can be at most `8/5` the encoded length (the shortest code is 5
/// bits), so this factor bounds the decode buffer before growth.
const HUFFMAN_MAX_EXPANSION_NUM: usize = 8;
const HUFFMAN_MAX_EXPANSION_DEN: usize = 5;

/// An error decoding a prefixed integer or string.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrefixError {
    /// The buffer ended before the value was complete; feed more bytes and retry.
    UnexpectedEnd,
    /// The encoded integer does not fit in a `u64`.
    IntegerOverflow,
    /// A Huffman-encoded string contained an invalid code or padding.
    InvalidHuffman,
    /// A length field exceeded the caller-supplied bound before any allocation.
    LengthLimitExceeded,
}

impl core::fmt::Display for PrefixError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::UnexpectedEnd => "unexpected end of QPACK input",
            Self::IntegerOverflow => "QPACK integer overflow",
            Self::InvalidHuffman => "invalid QPACK Huffman string",
            Self::LengthLimitExceeded => "QPACK string length limit exceeded",
        })
    }
}

impl std::error::Error for PrefixError {}

impl From<DecoderError> for PrefixError {
    fn from(_: DecoderError) -> Self {
        // the shared Huffman decoder only fails with an invalid code or padding for our inputs.
        Self::InvalidHuffman
    }
}

/// Encode `value` as a prefixed integer with an `prefix_bits`-bit prefix, OR-ing `flags` into the
/// high `8 - prefix_bits` bits of the first byte (RFC 9204 §4.1.1).
///
/// `flags` must not set any of the low `prefix_bits` bits.
pub fn encode_int<B: BufMut>(dst: &mut B, value: u64, prefix_bits: u8, flags: u8) {
    debug_assert!((1..=8).contains(&prefix_bits));
    let mask = (1u16 << prefix_bits) - 1;
    debug_assert_eq!(flags as u16 & mask, 0, "flags overlap the integer prefix");
    let mask = mask as u64;
    if value < mask {
        dst.put_u8(flags | value as u8);
        return;
    }
    dst.put_u8(flags | mask as u8);
    let mut remainder = value - mask;
    while remainder >= 128 {
        dst.put_u8((remainder as u8 & 0x7f) | 0x80);
        remainder >>= 7;
    }
    dst.put_u8(remainder as u8);
}

/// Decode a prefixed integer with an `prefix_bits`-bit prefix from `src`, consuming the bytes it
/// uses (RFC 9204 §4.1.1). High bits of the first byte above the prefix are ignored — a caller
/// reads any representation flags from the first byte before calling this.
pub fn decode_int(src: &mut &[u8], prefix_bits: u8) -> Result<u64, PrefixError> {
    debug_assert!((1..=8).contains(&prefix_bits));
    let (&first, rest) = src.split_first().ok_or(PrefixError::UnexpectedEnd)?;
    let mask = ((1u16 << prefix_bits) - 1) as u8;
    let mut value = u64::from(first & mask);
    if (first & mask) != mask {
        *src = rest;
        return Ok(value);
    }
    // continuation bytes, 7 bits each, high bit = "more"
    let mut cursor = rest;
    let mut shift = 0u32;
    loop {
        let (&byte, next) = cursor.split_first().ok_or(PrefixError::UnexpectedEnd)?;
        cursor = next;
        if shift >= 64 {
            return Err(PrefixError::IntegerOverflow);
        }
        let digit = u64::from(byte & 0x7f);
        let shifted = digit << shift;
        // detect overflow of the shift itself
        if (shifted >> shift) != digit {
            return Err(PrefixError::IntegerOverflow);
        }
        value = value
            .checked_add(shifted)
            .ok_or(PrefixError::IntegerOverflow)?;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    *src = cursor;
    Ok(value)
}

/// Encode a string literal with an `prefix_bits`-bit length prefix (RFC 9204 §4.1.2).
///
/// `flags` occupies the bits above the Huffman bit; the Huffman bit itself is bit `prefix_bits`.
pub fn encode_string<B: BufMut>(
    dst: &mut B,
    data: &[u8],
    prefix_bits: u8,
    flags: u8,
    huffman: bool,
) {
    if huffman {
        let mut encoded = BytesMut::new();
        huffman::encode(data, &mut encoded);
        let huffman_flag = 1u8 << prefix_bits;
        encode_int(dst, encoded.len() as u64, prefix_bits, flags | huffman_flag);
        dst.put_slice(&encoded);
    } else {
        encode_int(dst, data.len() as u64, prefix_bits, flags);
        dst.put_slice(data);
    }
}

/// A decoded QPACK string literal, plus whether it was Huffman-encoded on the wire.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecodedString {
    /// The decoded bytes.
    pub value: BytesMut,
    /// Whether the wire representation used Huffman coding.
    pub huffman: bool,
}

/// Decode a string literal with an `prefix_bits`-bit length prefix, rejecting a decoded length
/// above `max_len` before allocating (RFC 9204 §4.1.2).
pub fn decode_string(
    src: &mut &[u8],
    prefix_bits: u8,
    max_len: usize,
) -> Result<DecodedString, PrefixError> {
    let first = *src.first().ok_or(PrefixError::UnexpectedEnd)?;
    let huffman = (first & (1 << prefix_bits)) != 0;
    // `decode_int` masks off the flag/Huffman bits, so it reads only the length.
    let len = decode_int(src, prefix_bits)?;

    // bound the *decoded* size before touching memory (compare in u64 to avoid a lossy cast)
    let max_len_u64 = max_len as u64;
    if huffman {
        let upper =
            len.saturating_mul(HUFFMAN_MAX_EXPANSION_NUM as u64) / HUFFMAN_MAX_EXPANSION_DEN as u64;
        if upper > max_len_u64 {
            return Err(PrefixError::LengthLimitExceeded);
        }
    } else if len > max_len_u64 {
        return Err(PrefixError::LengthLimitExceeded);
    }
    // `len <= max_len` (or its Huffman bound) at this point, so it fits `usize`.
    let len = len as usize;

    if src.len() < len {
        return Err(PrefixError::UnexpectedEnd);
    }
    let (raw, rest) = src.split_at(len);
    *src = rest;

    if huffman {
        let mut buf = BytesMut::new();
        let decoded = huffman::decode(raw, &mut buf)?;
        if decoded.len() > max_len {
            return Err(PrefixError::LengthLimitExceeded);
        }
        Ok(DecodedString {
            value: decoded,
            huffman: true,
        })
    } else {
        Ok(DecodedString {
            value: BytesMut::from(raw),
            huffman: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(value: u64, prefix_bits: u8, flags: u8) -> Vec<u8> {
        let mut out = BytesMut::new();
        encode_int(&mut out, value, prefix_bits, flags);
        out.to_vec()
    }

    #[test]
    fn rfc7541_c1_examples() {
        // RFC 7541 C.1.1: 10 with a 5-bit prefix => 0x0a
        assert_eq!(enc(10, 5, 0), vec![0x0a]);
        // C.1.2: 1337 with a 5-bit prefix => 0x1f 0x9a 0x0a
        assert_eq!(enc(1337, 5, 0), vec![0x1f, 0x9a, 0x0a]);
        // C.1.3: 42 with an 8-bit prefix => 0x2a
        assert_eq!(enc(42, 8, 0), vec![0x2a]);
    }

    #[test]
    fn int_round_trip_all_widths() {
        for prefix_bits in 1..=8u8 {
            for value in [
                0u64,
                1,
                30,
                31,
                127,
                128,
                255,
                256,
                16383,
                16384,
                u32::MAX as u64,
                u64::MAX,
            ] {
                let bytes = enc(value, prefix_bits, 0);
                let mut cursor = &bytes[..];
                assert_eq!(
                    decode_int(&mut cursor, prefix_bits),
                    Ok(value),
                    "n={prefix_bits} v={value}"
                );
                assert!(cursor.is_empty());
            }
        }
    }

    #[test]
    fn flags_preserved_and_ignored_on_decode() {
        // 5-bit prefix, high 3 bits set as an opcode
        let bytes = enc(5, 5, 0b1010_0000);
        assert_eq!(bytes[0] & 0b1110_0000, 0b1010_0000);
        let mut cursor = &bytes[..];
        assert_eq!(decode_int(&mut cursor, 5), Ok(5));
    }

    #[test]
    fn int_incomplete_is_distinct() {
        // 1337, 5-bit prefix = 0x1f 0x9a 0x0a; truncate continuation
        let mut cursor = &[0x1fu8, 0x9a][..];
        assert_eq!(decode_int(&mut cursor, 5), Err(PrefixError::UnexpectedEnd));
        let mut empty: &[u8] = &[];
        assert_eq!(decode_int(&mut empty, 5), Err(PrefixError::UnexpectedEnd));
    }

    #[test]
    fn int_overflow_rejected() {
        // 11 continuation bytes with high bits set never terminates within u64
        let mut buf = vec![0xffu8]; // prefix all-ones (8-bit)
        buf.extend(std::iter::repeat_n(0xffu8, 10));
        buf.push(0x7f);
        let mut cursor = &buf[..];
        assert_eq!(
            decode_int(&mut cursor, 8),
            Err(PrefixError::IntegerOverflow)
        );
    }

    #[test]
    fn string_plain_round_trip() {
        let mut out = BytesMut::new();
        encode_string(&mut out, b"/index.html", 7, 0, false);
        let mut cursor = &out[..];
        let decoded = decode_string(&mut cursor, 7, 1024).unwrap();
        assert!(!decoded.huffman);
        assert_eq!(&decoded.value[..], b"/index.html");
        assert!(cursor.is_empty());
    }

    #[test]
    fn string_huffman_round_trip() {
        let mut out = BytesMut::new();
        encode_string(&mut out, b"www.example.com", 7, 0, true);
        let mut cursor = &out[..];
        let decoded = decode_string(&mut cursor, 7, 1024).unwrap();
        assert!(decoded.huffman);
        assert_eq!(&decoded.value[..], b"www.example.com");
    }

    #[test]
    fn string_invalid_huffman_padding_rejected() {
        // Huffman flag set, length 1, byte 0x00: symbol '0' (00000) then 000 padding, which is not
        // the required all-ones padding => invalid.
        let mut cursor = &[0x81u8, 0x00][..];
        assert_eq!(
            decode_string(&mut cursor, 7, 1024),
            Err(PrefixError::InvalidHuffman)
        );
    }

    #[test]
    fn string_length_limit_before_alloc() {
        // advertises a huge plain length; must be rejected without buffering
        let mut out = BytesMut::new();
        encode_int(&mut out, 1_000_000, 7, 0);
        let mut cursor = &out[..];
        assert_eq!(
            decode_string(&mut cursor, 7, 64),
            Err(PrefixError::LengthLimitExceeded)
        );
    }

    #[test]
    fn string_incomplete_body() {
        let mut out = BytesMut::new();
        encode_string(&mut out, b"hello", 7, 0, false);
        let truncated = &out[..out.len() - 2];
        let mut cursor = truncated;
        assert_eq!(
            decode_string(&mut cursor, 7, 1024),
            Err(PrefixError::UnexpectedEnd)
        );
    }
}
