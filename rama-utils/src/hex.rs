//! Hexadecimal encoding and decoding utilities.
//!
//! Use [`crate::fmt::hex`] to borrow bytes as a configurable [`Hex`] view.
//! The view supports deferred formatting, owned text output, and writing into
//! existing strings, byte buffers, or slices. Encoding defaults to lowercase
//! without a prefix and works with `no_std + alloc`.
//!
//! The byte/pair helpers are also useful in URI percent-encoding and decoding.
//! Use [`decode`] to decode into a vector or fixed-size array.

use core::fmt;

use crate::{
    macros::generate_set_and_with,
    std::{String, Vec},
};

mod decode;
#[cfg(test)]
mod tests_separators;
pub use decode::{DecodeError, FromHex, decode, decode_append, decode_into};
#[cfg(feature = "std")]
pub use decode::{DecodeWriteError, decode_write};

#[doc(inline)]
pub use crate::__hex_serde_with as serde_with;

/// Letter case for hexadecimal digits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum HexCase {
    /// Use `a` through `f` (the default).
    #[default]
    Lower,
    /// Use `A` through `F`.
    Upper,
}

impl HexCase {
    const fn encode_byte(self, byte: u8) -> [u8; 2] {
        let digits = match self {
            Self::Lower => b"0123456789abcdef",
            Self::Upper => b"0123456789ABCDEF",
        };
        [digits[(byte >> 4) as usize], digits[(byte & 0x0f) as usize]]
    }
}

/// Shared hex representation for encoding and decoding.
///
/// Defaults to lowercase without a prefix or separator. Decoding accepts either
/// digit case and requires the configured prefix and separators exactly.
/// Configuration only borrows text; it never allocates. Both strings share a
/// lifetime, shortened as needed when combining independently borrowed values.
///
/// ```
/// use rama_utils::{fmt::hex, hex::Format};
/// const FORMAT: Format<'static> = Format::new()
///     .with_upper_case().with_prefix("hash:").with_separator(":");
/// let view = hex(&[0, 0xab, 255]).with_format(FORMAT);
/// assert_eq!(view.to_string(), "hash:00:AB:FF");
/// assert_eq!(FORMAT.decode::<[u8; 3]>("hash:00:aB:ff")?, [0, 0xab, 255]);
/// # Ok::<(), rama_utils::hex::DecodeError>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[must_use]
pub struct Format<'a> {
    case: HexCase,
    prefix: &'a str,
    separator: &'a str,
}

impl<'a> Format<'a> {
    /// Lowercase, unprefixed hex.
    pub const fn new() -> Self {
        Self {
            case: HexCase::Lower,
            prefix: "",
            separator: "",
        }
    }

    generate_set_and_with!(
        /// Select lowercase hex digits. Decoding always accepts both cases.
        pub const fn lower_case(mut self) -> Self {
            self.case = HexCase::Lower;
            self
        }
    );

    generate_set_and_with!(
        /// Select uppercase hex digits. Decoding always accepts both cases.
        pub const fn upper_case(mut self) -> Self {
            self.case = HexCase::Upper;
            self
        }
    );

    generate_set_and_with!(
        /// Select a literal prefix, required exactly once when decoding.
        /// An empty string disables the prefix.
        pub const fn prefix(mut self, prefix: &'a str) -> Self {
            self.prefix = prefix;
            self
        }
    );

    generate_set_and_with!(
        /// Insert this literal separator between bytes, never at either end.
        ///
        /// Decoding requires it at every byte boundary. An empty separator selects
        /// compact hex. Any UTF-8 text, including hex digits, is supported; decoding
        /// uses fixed two-digit byte groups rather than splitting on the separator.
        pub const fn separator(mut self, separator: &'a str) -> Self {
            self.separator = separator;
            self
        }
    );
}

/// A borrowed view that encodes bytes as hex digits with optional framing.
///
/// Construct a view with [`crate::fmt::hex`]. Creating, copying, or configuring
/// it does not allocate or encode the input. Each byte is always represented by
/// two digits, in input order, including leading zero bytes.
///
/// [`Display`](fmt::Display) and the output methods use the configured case and
/// prefix and separator. [`LowerHex`](fmt::LowerHex) and [`UpperHex`](fmt::UpperHex)
/// override case and prefix: `:x` and `:X` omit the prefix, while `:#x` and `:#X`
/// include `0x`. These traits retain the configured separator.
/// Other formatting flags are ignored.
///
/// ```
/// use rama_utils::fmt::hex;
///
/// let bytes = [0x00, 0xab, 0xff];
/// let view = hex(&bytes);
/// assert_eq!(view.to_string(), "00abff");
/// assert_eq!(view.to_vec(), b"00abff");
/// assert_eq!(format!("{view:#X}"), "0x00ABFF");
/// assert_eq!(view.with_custom_prefix("bytes:").with_separator(":").to_string(), "bytes:00:ab:ff");
/// assert_eq!(view.with_upper_case().with_prefix(true).to_string(), "0x00ABFF");
///
/// let mut storage = [0; 8];
/// assert_eq!(view.encode_to_slice(&mut storage)?, b"00abff");
/// # Ok::<(), rama_utils::hex::BufferTooSmall>(())
/// ```
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Hex<'a> {
    bytes: &'a [u8],
    format: Format<'a>,
}

impl<'a> Hex<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            format: Format::new(),
        }
    }

    generate_set_and_with!(
        /// Select lowercase hex digits.
        /// Applies to [`Display`](fmt::Display) and output methods.
        pub const fn lower_case(mut self) -> Self {
            self.format.case = HexCase::Lower;
            self
        }
    );

    generate_set_and_with!(
        /// Select uppercase hex digits.
        /// Applies to [`Display`](fmt::Display) and output methods.
        pub const fn upper_case(mut self) -> Self {
            self.format.case = HexCase::Upper;
            self
        }
    );

    generate_set_and_with!(
        /// Enable or disable the `0x` prefix for [`Display`](fmt::Display) and output
        /// methods. The prefix itself is lowercase regardless of the digit case.
        pub const fn prefix(mut self, prefix: bool) -> Self {
            self.format.prefix = if prefix { "0x" } else { "" };
            self
        }
    );

    generate_set_and_with!(
        /// Set a custom literal prefix without allocating.
        pub const fn custom_prefix(mut self, prefix: &'a str) -> Self {
            self.format.prefix = prefix;
            self
        }
    );

    generate_set_and_with!(
        /// Set a literal separator between bytes without allocating.
        /// See [`Format::with_separator`] for details.
        pub const fn separator(mut self, separator: &'a str) -> Self {
            self.format.separator = separator;
            self
        }
    );

    generate_set_and_with!(
        /// Apply shared encoding/decoding configuration without allocating.
        pub const fn format(mut self, format: Format<'a>) -> Self {
            self.format = format;
            self
        }
    );

    /// Number of UTF-8 bytes in the output, including prefix and separators.
    ///
    /// # Panics
    ///
    /// Panics if the encoded length exceeds [`usize::MAX`]. Output methods that
    /// reserve or check destination space have the same restriction.
    #[expect(
        clippy::expect_used,
        reason = "reject unrepresentable encoded lengths before writing"
    )]
    pub const fn encoded_len(&self) -> usize {
        self.bytes
            .len()
            .checked_mul(2)
            .expect("hex output length overflow")
            .checked_add(self.format.prefix.len())
            .expect("hex output length overflow")
            .checked_add(
                self.bytes
                    .len()
                    .saturating_sub(1)
                    .checked_mul(self.format.separator.len())
                    .expect("hex output length overflow"),
            )
            .expect("hex output length overflow")
    }

    fn encoded_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        let prefix = self.format.prefix.as_bytes();
        prefix
            .iter()
            .copied()
            .chain(self.bytes.iter().enumerate().flat_map(|(index, &byte)| {
                let separator = if index == 0 {
                    ""
                } else {
                    self.format.separator
                };
                separator.bytes().chain(self.format.case.encode_byte(byte))
            }))
    }

    /// Encode into a new vector of UTF-8 bytes (digits, prefix, and separators).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.append_to_vec(&mut output);
        output
    }

    /// Append encoded bytes, reserving space without clearing existing data.
    pub fn append_to_vec(&self, output: &mut Vec<u8>) {
        output.reserve(self.encoded_len());
        output.extend(self.encoded_bytes());
    }

    /// Append hex text, reserving space without clearing existing contents.
    #[expect(clippy::expect_used, reason = "writing into a String is infallible")]
    pub fn append_to_string(&self, output: &mut String) {
        output.reserve(self.encoded_len());
        self.write_to(output)
            .expect("writing hex to String cannot fail");
    }

    /// Encode into the start of `output` and return the written subslice.
    ///
    /// Does not allocate. Extra destination bytes are left untouched. If the
    /// destination is too small, returns an error without changing any bytes.
    pub fn encode_to_slice<'out>(
        &self,
        output: &'out mut [u8],
    ) -> Result<&'out mut [u8], BufferTooSmall> {
        let required = self.encoded_len();
        let available = output.len();
        let output = output.get_mut(..required).ok_or(BufferTooSmall {
            required,
            available,
        })?;
        for (slot, byte) in output.iter_mut().zip(self.encoded_bytes()) {
            *slot = byte;
        }
        Ok(output)
    }

    /// Write configured hex text without allocating an intermediate string.
    ///
    /// The destination can allocate as it grows. Writer errors are propagated;
    /// on failure, the destination may contain a partially written result.
    /// For a `std::io::Write` destination, use `write!(writer, "{view}")`
    /// with the I/O trait in scope instead.
    #[expect(clippy::expect_used, reason = "hex digits are always valid ASCII")]
    pub fn write_to<W: fmt::Write + ?Sized>(&self, writer: &mut W) -> fmt::Result {
        if !self.format.prefix.is_empty() {
            writer.write_str(self.format.prefix)?;
        }
        if !self.format.separator.is_empty() {
            for (index, &byte) in self.bytes.iter().enumerate() {
                if index != 0 {
                    writer.write_str(self.format.separator)?;
                }
                let digits = self.format.case.encode_byte(byte);
                writer.write_str(core::str::from_utf8(&digits).expect("hex digits are ASCII"))?;
            }
            return Ok(());
        }
        let mut buffer = [0; 128];
        for chunk in self.bytes.chunks(buffer.len() / 2) {
            let encoded = &mut buffer[..chunk.len() * 2];
            for (pair, &byte) in encoded.as_chunks_mut::<2>().0.iter_mut().zip(chunk) {
                pair.copy_from_slice(&self.format.case.encode_byte(byte));
            }
            writer.write_str(core::str::from_utf8(encoded).expect("hex digits are ASCII"))?;
        }
        Ok(())
    }
}

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f)
    }
}

impl fmt::LowerHex for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.with_lower_case()
            .with_prefix(f.alternate())
            .write_to(f)
    }
}

impl fmt::UpperHex for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.with_upper_case()
            .with_prefix(f.alternate())
            .write_to(f)
    }
}

/// The destination cannot hold the complete hex encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall {
    /// Required destination length, including any configured prefix/separators.
    pub required: usize,
    /// Supplied destination length.
    pub available: usize,
}

impl fmt::Display for BufferTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hex output requires {} bytes, but only {} are available",
            self.required, self.available
        )
    }
}

impl core::error::Error for BufferTooSmall {}

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
    HexCase::Upper.encode_byte(byte)
}

/// Encode one byte as two lowercase ASCII hex digits.
#[inline]
#[must_use]
pub const fn encode_byte_lower(byte: u8) -> [u8; 2] {
    HexCase::Lower.encode_byte(byte)
}

#[cfg(test)]
mod tests {
    use crate::{fmt::hex, std::string::ToString as _};

    use super::*;

    #[test]
    fn output_methods_agree_for_every_byte_and_option() {
        let bytes: Vec<u8> = (0..=255).collect();
        for case in [HexCase::Lower, HexCase::Upper] {
            for prefix in [false, true] {
                // Exercise the writer's stack-buffer boundaries as well as empty input.
                for len in [0, 1, 63, 64, 65, 127, 128, 129, 255, 256] {
                    let bytes = &bytes[..len];
                    let view = match case {
                        HexCase::Lower => hex(bytes).with_lower_case(),
                        HexCase::Upper => hex(bytes).with_upper_case(),
                    }
                    .with_prefix(prefix);
                    let mut expected = String::new();
                    if prefix {
                        expected.push_str("0x");
                    }
                    for byte in bytes {
                        use core::fmt::Write as _;
                        match case {
                            HexCase::Lower => write!(&mut expected, "{byte:02x}").unwrap(),
                            HexCase::Upper => write!(&mut expected, "{byte:02X}").unwrap(),
                        }
                    }
                    assert_eq!(view.encoded_len(), expected.len());
                    assert_eq!(view.to_string(), expected);
                    assert_eq!(view.to_vec(), expected.as_bytes());

                    let mut text = String::from("existing:");
                    view.append_to_string(&mut text);
                    assert_eq!(&text[9..], expected);
                    assert!(text.starts_with("existing:"));

                    let mut output = b"existing:".to_vec();
                    view.append_to_vec(&mut output);
                    assert_eq!(&output[9..], expected.as_bytes());
                    assert!(output.starts_with(b"existing:"));

                    let mut output = crate::std::vec![b'!'; expected.len() + 3];
                    assert_eq!(
                        view.encode_to_slice(&mut output).unwrap(),
                        expected.as_bytes()
                    );
                    assert_eq!(&output[expected.len()..], b"!!!");

                    let mut written = String::new();
                    let writer: &mut dyn fmt::Write = &mut written;
                    view.write_to(writer).unwrap();
                    assert_eq!(written, expected);
                }
            }
        }
    }

    #[test]
    fn formatting_traits_override_configured_case_and_prefix() {
        for case in [HexCase::Lower, HexCase::Upper] {
            for prefix in [false, true] {
                let view = match case {
                    HexCase::Lower => hex(&[0x00, 0xab, 0xff]).with_lower_case(),
                    HexCase::Upper => hex(&[0x00, 0xab, 0xff]).with_upper_case(),
                }
                .with_prefix(prefix);
                assert_eq!(format!("{view:x}"), "00abff");
                assert_eq!(format!("{view:X}"), "00ABFF");
                assert_eq!(format!("{view:#x}"), "0x00abff");
                assert_eq!(format!("{view:#X}"), "0x00ABFF");
            }
        }
        let empty = hex(&[]);
        assert_eq!(format!("{empty:x}"), "");
        assert_eq!(format!("{empty:#X}"), "0x");
        let original = hex(&[0xab]);
        assert_eq!(
            original.with_upper_case().with_prefix(true).to_string(),
            "0xAB"
        );
        assert_eq!(original.to_string(), "ab");
    }

    #[test]
    fn slice_capacity_is_checked_before_any_write() {
        for prefix in [false, true] {
            let view = hex(&[0x00, 0xff]).with_prefix(prefix);
            for len in 0..view.encoded_len() {
                let mut output = crate::std::vec![b'!'; len];
                let error = view.encode_to_slice(&mut output).unwrap_err();
                assert_eq!(
                    error,
                    BufferTooSmall {
                        required: view.encoded_len(),
                        available: len
                    }
                );
                assert!(output.iter().all(|&byte| byte == b'!'));
            }
            let mut exact = crate::std::vec![0; view.encoded_len()];
            assert_eq!(view.encode_to_slice(&mut exact).unwrap(), view.to_vec());
        }
        assert_eq!(hex(&[]).encode_to_slice(&mut []).unwrap(), b"");
        let mut one = *b"!";
        assert_eq!(
            hex(&[])
                .with_prefix(true)
                .encode_to_slice(&mut one)
                .unwrap_err(),
            BufferTooSmall {
                required: 2,
                available: 1
            }
        );
        assert_eq!(&one, b"!");
    }

    #[test]
    fn appending_reuses_sufficient_capacity() {
        let view = hex(&[0x00, 0xab]).with_prefix(true);
        let mut text = String::with_capacity(32);
        text.push_str("prefix:");
        let pointer = text.as_ptr();
        view.append_to_string(&mut text);
        assert_eq!(text, "prefix:0x00ab");
        assert_eq!(text.as_ptr(), pointer);

        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(b"prefix:");
        let pointer = bytes.as_ptr();
        view.append_to_vec(&mut bytes);
        assert_eq!(bytes, b"prefix:0x00ab");
        assert_eq!(bytes.as_ptr(), pointer);
    }

    #[test]
    fn writing_propagates_errors_and_stops() {
        struct Limited {
            remaining: usize,
            output: String,
        }
        impl fmt::Write for Limited {
            fn write_str(&mut self, value: &str) -> fmt::Result {
                let written = self.remaining.min(value.len());
                self.output.push_str(&value[..written]);
                self.remaining -= written;
                if written < value.len() {
                    return Err(fmt::Error);
                }
                Ok(())
            }
        }

        let bytes = [0xab; 129];
        let view = hex(&bytes).with_prefix(true);
        for remaining in [0, 1, 2, 3, 64, 129, view.encoded_len() - 1] {
            let mut writer = Limited {
                remaining,
                output: String::new(),
            };
            assert_eq!(view.write_to(&mut writer), Err(fmt::Error));
            assert_eq!(writer.output, &view.to_string()[..remaining]);
        }

        use std::io::Write as _;
        let mut storage = [0; 6];
        write!(
            &mut storage.as_mut_slice(),
            "{}",
            hex(&[0x00, 0xab]).with_prefix(true)
        )
        .unwrap();
        assert_eq!(&storage, b"0x00ab");
        let mut short = &mut storage[..2];
        assert_eq!(
            write!(&mut short, "{view}").unwrap_err().kind(),
            std::io::ErrorKind::WriteZero,
        );
    }

    #[test]
    fn accepts_borrowed_byte_like_inputs() {
        let text = String::from("Hi");
        let bytes = b"Hi".to_vec();
        assert_eq!(hex(&text).to_string(), "4869");
        assert_eq!(hex(text.as_str()).to_string(), "4869");
        assert_eq!(hex(&bytes).to_string(), "4869");
        assert_eq!(hex(bytes.as_slice()).to_string(), "4869");
        assert_eq!(hex(b"Hi").to_string(), "4869");
    }

    #[test]
    fn lowercase_pair_encoding_round_trips_every_byte() {
        for byte in 0..=255 {
            let pair = encode_byte_lower(byte);
            assert_eq!(decode_pair(pair[0], pair[1]), Some(byte));
            assert!(
                pair.iter()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
            );
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
