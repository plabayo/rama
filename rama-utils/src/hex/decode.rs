use core::fmt;

use super::{Format, nibble};
use crate::std::Vec;

/// Invalid hex input or an incompatible output size.
/// Indices are byte offsets in the original input, including its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The configured literal prefix is missing or differs.
    InvalidPrefix,
    /// A byte has no matching second hex digit.
    OddLength,
    /// An input byte is not an ASCII hex digit.
    InvalidDigit { byte: u8, index: usize },
    /// The decoded length differs from the fixed-size destination.
    InvalidLength { expected: usize, actual: usize },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => {
                f.write_str("hex input does not start with the configured prefix")
            }
            Self::OddLength => f.write_str("hex input has an odd number of digits"),
            Self::InvalidDigit { byte, index } => {
                write!(f, "invalid hex byte 0x{byte:02X} at byte {index}")
            }
            Self::InvalidLength { expected, actual } => write!(
                f,
                "hex input decodes to {actual} bytes; expected {expected}"
            ),
        }
    }
}

impl core::error::Error for DecodeError {}

/// An owned destination for decoded bytes.
///
/// Implemented for [`Vec<u8>`] and arrays of any length. Implementations must
/// honor the supplied format and reject malformed or incorrectly sized input.
pub trait FromHex: Sized {
    fn from_hex(input: &[u8], format: Format<'_>) -> Result<Self, DecodeError>;
}

/// Decode compact hex into an inferred vector or fixed-size array.
///
/// Accepts either digit case, but no prefixes, whitespace, or separators.
/// Arrays require exactly their length in decoded bytes; vectors allocate only
/// their decoded output. Empty input is valid for an empty vector or array.
///
/// ```
/// use rama_utils::hex;
/// let bytes: Vec<u8> = hex::decode("00abFF")?;
/// assert_eq!(bytes, [0x00, 0xab, 0xff]);
/// assert_eq!(hex::decode::<[u8; 3]>(b"00Abff")?, [0x00, 0xab, 0xff]);
/// # Ok::<(), hex::DecodeError>(())
/// ```
pub fn decode<T: FromHex>(input: impl AsRef<[u8]>) -> Result<T, DecodeError> {
    Format::new().decode(input)
}

impl Format<'_> {
    /// Decode using this format, accepting either digit case and requiring the
    /// configured prefix. All input must be consumed.
    pub fn decode<T: FromHex>(&self, input: impl AsRef<[u8]>) -> Result<T, DecodeError> {
        T::from_hex(input.as_ref(), *self)
    }
}

impl FromHex for Vec<u8> {
    fn from_hex(input: &[u8], format: Format<'_>) -> Result<Self, DecodeError> {
        Ok(Validated::new(input, format)?.bytes().collect())
    }
}

impl<const N: usize> FromHex for [u8; N] {
    fn from_hex(input: &[u8], format: Format<'_>) -> Result<Self, DecodeError> {
        let validated = Validated::new(input, format)?;
        let bytes = validated.bytes();
        if bytes.len() != N {
            return Err(DecodeError::InvalidLength {
                expected: N,
                actual: bytes.len(),
            });
        }
        let mut output = [0; N];
        for (slot, byte) in output.iter_mut().zip(bytes) {
            *slot = byte;
        }
        Ok(output)
    }
}

/// Validation precedes allocation or modification of any destination.
struct Validated<'a> {
    input: &'a [u8],
}

impl<'a> Validated<'a> {
    fn new(input: &'a [u8], format: Format<'_>) -> Result<Self, DecodeError> {
        let input = input
            .strip_prefix(format.prefix.as_bytes())
            .ok_or(DecodeError::InvalidPrefix)?;
        if !input.len().is_multiple_of(2) {
            return Err(DecodeError::OddLength);
        }
        for (index, &byte) in input.iter().enumerate() {
            if nibble(byte).is_none() {
                return Err(DecodeError::InvalidDigit {
                    byte,
                    index: format.prefix.len() + index,
                });
            }
        }
        Ok(Self { input })
    }

    #[expect(
        clippy::expect_used,
        reason = "all digits were checked by Validated::new"
    )]
    fn bytes(&self) -> impl ExactSizeIterator<Item = u8> + '_ {
        self.input.as_chunks::<2>().0.iter().map(|&[high, low]| {
            (nibble(high).expect("validated hex digit") << 4)
                | nibble(low).expect("validated hex digit")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fmt::hex, hex::HexCase};

    #[test]
    fn owned_destinations_and_all_byte_values() {
        let bytes: Vec<_> = (0..=255).collect();
        for case in [HexCase::Lower, HexCase::Upper] {
            let text = hex(&bytes).with_case(case).to_string();
            assert_eq!(decode::<Vec<u8>>(&text).unwrap(), bytes);
            assert_eq!(decode::<[u8; 256]>(&text).unwrap().as_slice(), bytes);
        }
        assert_eq!(decode::<[u8; 3]>("00AbfF").unwrap(), [0, 0xab, 0xff]);
        assert_eq!(decode::<Vec<u8>>(b"").unwrap(), [0u8; 0]);
        assert_eq!(decode::<[u8; 0]>("").unwrap(), [0u8; 0]);
        assert_eq!(decode::<[u8; 1]>("01").unwrap(), [1]);
    }

    #[test]
    fn syntax_and_length_errors_are_precise() {
        assert_eq!(decode::<Vec<u8>>("0").unwrap_err(), DecodeError::OddLength);
        assert_eq!(
            decode::<Vec<u8>>("0x00").unwrap_err(),
            DecodeError::InvalidDigit {
                byte: b'x',
                index: 1
            }
        );
        for (text, byte, index) in [
            ("g0", b'g', 0),
            ("00z0", b'z', 2),
            ("000/", b'/', 3),
            ("00 0", b' ', 2),
            ("é", 0xc3, 0),
        ] {
            assert_eq!(
                decode::<Vec<u8>>(text).unwrap_err(),
                DecodeError::InvalidDigit { byte, index }
            );
        }
        for (text, actual) in [("", 0), ("00", 1), ("000102", 3)] {
            assert_eq!(
                decode::<[u8; 2]>(text).unwrap_err(),
                DecodeError::InvalidLength {
                    expected: 2,
                    actual
                }
            );
        }
    }

    #[test]
    fn shared_format_round_trips_prefixes_and_utf8() {
        for prefix in ["0x", "SHA:", "🔑:"] {
            let format = Format::new().with_case(HexCase::Upper).with_prefix(prefix);
            let view = hex(&[0xab, 0]).with_format(format);
            let text = format!("{prefix}AB00");
            assert_eq!(view.to_string(), text);
            assert_eq!(view.to_vec(), text.as_bytes());
            let mut appended = String::from("existing");
            view.append_to_string(&mut appended);
            assert_eq!(appended, format!("existing{text}"));
            assert_eq!(view.encoded_len(), text.len());
            assert_eq!(format.decode::<[u8; 2]>(&text).unwrap(), [0xab, 0]);
            assert_eq!(format.decode::<[u8; 0]>(prefix).unwrap(), [0u8; 0]);
            assert_eq!(
                format.decode::<Vec<u8>>("AB00").unwrap_err(),
                DecodeError::InvalidPrefix
            );
            let bad = format!("{prefix}0g");
            assert_eq!(
                format.decode::<Vec<u8>>(bad).unwrap_err(),
                DecodeError::InvalidDigit {
                    byte: b'g',
                    index: prefix.len() + 1
                }
            );
        }
    }

    #[test]
    fn errors_implement_display_and_error() {
        fn error(value: &dyn core::error::Error) -> String {
            value.to_string()
        }
        assert_eq!(
            error(&crate::hex::BufferTooSmall {
                required: 6,
                available: 2
            }),
            "hex output requires 6 bytes, but only 2 are available"
        );
        assert_eq!(
            error(&DecodeError::InvalidPrefix),
            "hex input does not start with the configured prefix"
        );
        assert_eq!(
            error(&DecodeError::OddLength),
            "hex input has an odd number of digits"
        );
        assert_eq!(
            error(&DecodeError::InvalidDigit {
                byte: 0xff,
                index: 5
            }),
            "invalid hex byte 0xFF at byte 5"
        );
        assert_eq!(
            error(&DecodeError::InvalidLength {
                expected: 32,
                actual: 1
            }),
            "hex input decodes to 1 bytes; expected 32"
        );
    }
}
