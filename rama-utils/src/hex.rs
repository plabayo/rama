//! Small ASCII-hex utilities for single-byte parse/format.
//!
//! For bulk encode/decode prefer the `hex` crate. These helpers are
//! useful in tight inner loops (URI percent-decoding, TLS keylog parsing,
//! fingerprint formatting) where pulling in a full crate dependency for
//! one operation is overkill.

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
        (Some(h), Some(l)) => Some((h << 4) | l),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
