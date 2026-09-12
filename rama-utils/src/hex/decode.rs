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
    /// The existing destination cannot hold the decoded bytes.
    InsufficientCapacity { required: usize, available: usize },
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
            Self::InsufficientCapacity {
                required,
                available,
            } => write!(
                f,
                "decoded hex requires {required} bytes, but only {available} are available"
            ),
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

/// Decode into an existing slice-like buffer, returning its written portion.
///
/// Extra capacity is left untouched; this never grows a vector. Malformed input
/// or insufficient capacity leaves the entire destination unchanged.
pub fn decode_into<B: AsMut<[u8]> + ?Sized>(
    input: impl AsRef<[u8]>,
    output: &mut B,
) -> Result<&mut [u8], DecodeError> {
    Format::new().decode_into(input, output)
}

/// Append decoded bytes to a collection, returning the number appended.
///
/// Preserves existing contents and lets the collection allocate as needed.
/// Malformed input leaves the collection unchanged.
///
/// ```
/// use rama_utils::hex;
/// let mut bytes = vec![1];
/// assert_eq!(hex::decode_append("00ab", &mut bytes)?, 2);
/// assert_eq!(bytes, [1, 0, 0xab]);
/// # Ok::<(), hex::DecodeError>(())
/// ```
pub fn decode_append<B: Extend<u8> + ?Sized>(
    input: impl AsRef<[u8]>,
    output: &mut B,
) -> Result<usize, DecodeError> {
    Format::new().decode_append(input, output)
}

/// Decode into a byte writer without allocating an intermediate vector.
///
/// All input is validated before writing. On an I/O error, the writer may have
/// received a partial result. This function does not flush the writer.
#[cfg(feature = "std")]
pub fn decode_write<W: std::io::Write + ?Sized>(
    input: impl AsRef<[u8]>,
    output: &mut W,
) -> Result<usize, DecodeWriteError> {
    Format::new().decode_write(input, output)
}

/// Invalid input or an I/O failure while writing decoded bytes.
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum DecodeWriteError {
    /// Invalid input; nothing was written.
    Decode(DecodeError),
    /// The destination failed; a partial result may have been written.
    Write(std::io::Error),
}

#[cfg(feature = "std")]
impl fmt::Display for DecodeWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "invalid hex input: {error}"),
            Self::Write(error) => write!(f, "failed to write decoded hex: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl core::error::Error for DecodeWriteError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Write(error) => Some(error),
        }
    }
}

#[cfg(feature = "std")]
impl From<DecodeError> for DecodeWriteError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for DecodeWriteError {
    fn from(error: std::io::Error) -> Self {
        Self::Write(error)
    }
}

impl Format<'_> {
    /// Decode using this format, accepting either digit case and requiring the
    /// configured prefix. All input must be consumed.
    pub fn decode<T: FromHex>(&self, input: impl AsRef<[u8]>) -> Result<T, DecodeError> {
        T::from_hex(input.as_ref(), *self)
    }

    /// Decode with this format into the start of an existing buffer.
    /// See [`decode_into`] for destination and error behavior.
    pub fn decode_into<'out, B: AsMut<[u8]> + ?Sized>(
        &self,
        input: impl AsRef<[u8]>,
        output: &'out mut B,
    ) -> Result<&'out mut [u8], DecodeError> {
        let input = input.as_ref();
        let validated = Validated::new(input, *self)?;
        let bytes = validated.bytes();
        let output = output.as_mut();
        let available = output.len();
        let output = output
            .get_mut(..bytes.len())
            .ok_or(DecodeError::InsufficientCapacity {
                required: bytes.len(),
                available,
            })?;
        for (slot, byte) in output.iter_mut().zip(bytes) {
            *slot = byte;
        }
        Ok(output)
    }

    /// Append bytes decoded with this format to a growing collection.
    /// See [`decode_append`] for destination and error behavior.
    pub fn decode_append<B: Extend<u8> + ?Sized>(
        &self,
        input: impl AsRef<[u8]>,
        output: &mut B,
    ) -> Result<usize, DecodeError> {
        let input = input.as_ref();
        let validated = Validated::new(input, *self)?;
        let bytes = validated.bytes();
        let len = bytes.len();
        output.extend(bytes);
        Ok(len)
    }

    /// Write bytes decoded with this format to an I/O destination.
    /// See [`decode_write`] for validation and partial-write behavior.
    #[cfg(feature = "std")]
    pub fn decode_write<W: std::io::Write + ?Sized>(
        &self,
        input: impl AsRef<[u8]>,
        output: &mut W,
    ) -> Result<usize, DecodeWriteError> {
        let input = input.as_ref();
        let validated = Validated::new(input, *self)?;
        let mut bytes = validated.bytes();
        let len = bytes.len();
        let mut buffer = [0; 128];
        while bytes.len() != 0 {
            let chunk_len = bytes.len().min(buffer.len());
            let chunk = &mut buffer[..chunk_len];
            for (slot, byte) in chunk.iter_mut().zip(bytes.by_ref()) {
                *slot = byte;
            }
            output.write_all(chunk)?;
        }
        Ok(len)
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
    fn fixed_buffers_preserve_tail_and_reject_without_mutation() {
        let mut output = [0xcc; 5];
        let written = decode_into("00Abff", &mut output).unwrap();
        assert_eq!(written, [0, 0xab, 255]);
        written[0] = 1;
        assert_eq!(output, [1, 0xab, 255, 0xcc, 0xcc]);
        assert_eq!(decode_into("", &mut output[..]).unwrap(), [0u8; 0]);
        assert_eq!(output, [1, 0xab, 255, 0xcc, 0xcc]);

        for len in 0..3 {
            let mut output = crate::std::vec![0xcc; len];
            assert_eq!(
                decode_into("00abff", &mut output).unwrap_err(),
                DecodeError::InsufficientCapacity {
                    required: 3,
                    available: len
                }
            );
            assert_eq!(output, crate::std::vec![0xcc; len]);
        }
        let mut exact = [0; 3];
        assert_eq!(decode_into("00abff", &mut exact).unwrap(), [0, 0xab, 255]);
        for input in ["000", "00gg", "00 0"] {
            let mut output = [0xcc; 4];
            decode_into(input, &mut output).unwrap_err();
            assert_eq!(output, [0xcc; 4]);
        }
        let mut output = [0xcc; 4];
        let format = Format::new().with_prefix("hex:");
        assert_eq!(
            format.decode_into("hex:00aB", &mut output).unwrap(),
            [0, 0xab]
        );
        assert_eq!(output, [0, 0xab, 0xcc, 0xcc]);
        assert_eq!(
            format.decode_into("00ab", &mut output).unwrap_err(),
            DecodeError::InvalidPrefix
        );
        assert_eq!(output, [0, 0xab, 0xcc, 0xcc]);
    }

    #[test]
    fn growing_collections_preserve_contents_and_receive_exact_hint() {
        let mut output = Vec::with_capacity(32);
        output.push(42);
        let pointer = output.as_ptr();
        assert_eq!(decode_append("00Abff", &mut output).unwrap(), 3);
        assert_eq!(output, [42, 0, 0xab, 255]);
        assert_eq!(output.as_ptr(), pointer);
        assert_eq!(decode_append("", &mut output).unwrap(), 0);
        assert_eq!(output, [42, 0, 0xab, 255]);
        for input in ["000", "00gg", "0x00"] {
            decode_append(input, &mut output).unwrap_err();
            assert_eq!(output, [42, 0, 0xab, 255]);
        }
        let format = Format::new().with_prefix("hex:");
        assert_eq!(format.decode_append("hex:aB", &mut output).unwrap(), 1);
        assert_eq!(output, [42, 0, 0xab, 255, 0xab]);
        assert_eq!(
            format.decode_append("ab", &mut output).unwrap_err(),
            DecodeError::InvalidPrefix
        );
        assert_eq!(output, [42, 0, 0xab, 255, 0xab]);

        struct CheckHint;
        impl Extend<u8> for CheckHint {
            fn extend<T: IntoIterator<Item = u8>>(&mut self, bytes: T) {
                let bytes = bytes.into_iter();
                assert_eq!(bytes.size_hint(), (3, Some(3)));
                assert_eq!(bytes.collect::<Vec<_>>(), [0, 0xab, 255]);
            }
        }
        assert_eq!(decode_append("00abff", &mut CheckHint).unwrap(), 3);
        let mut deque = std::collections::VecDeque::from([42]);
        decode_append("00ab", &mut deque).unwrap();
        assert_eq!(deque, [42, 0, 0xab]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn byte_writers_handle_chunks_short_writes_and_errors() {
        use std::{
            error::Error as _,
            io::{self, Write},
        };
        struct Writer {
            bytes: Vec<u8>,
            remaining: usize,
            interrupt: bool,
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                assert!(!bytes.is_empty(), "empty input must not call write");
                if self.interrupt {
                    self.interrupt = false;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let n = bytes.len().min(self.remaining).min(7);
                self.bytes.extend_from_slice(&bytes[..n]);
                self.remaining -= n;
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("must not flush")
            }
        }
        let mut writer = Writer {
            bytes: Vec::from([42]),
            remaining: usize::MAX,
            interrupt: true,
        };
        let bytes: Vec<_> = (0..=255).chain([0, 0xab, 255]).collect();
        assert_eq!(
            decode_write(hex(&bytes).to_string(), &mut writer as &mut dyn Write).unwrap(),
            bytes.len()
        );
        assert_eq!(&writer.bytes[1..], bytes);
        assert_eq!(writer.bytes[0], 42);
        assert_eq!(decode_write("", &mut writer).unwrap(), 0);
        assert_eq!(&writer.bytes[1..], bytes);
        let format = Format::new().with_prefix("hex:");
        let mut output = Vec::from([42]);
        assert_eq!(format.decode_write("hex:00aB", &mut output).unwrap(), 2);
        assert_eq!(output, [42, 0, 0xab]);
        let error = format.decode_write("00ab", &mut output).unwrap_err();
        assert!(matches!(
            error,
            DecodeWriteError::Decode(DecodeError::InvalidPrefix)
        ));
        assert_eq!(output, [42, 0, 0xab]);
        for input in ["000", "00gg", "0x00"] {
            let error = decode_write(input, &mut output).unwrap_err();
            assert!(matches!(error, DecodeWriteError::Decode(_)));
            assert_eq!(output, [42, 0, 0xab]);
        }
        let mut invalid = hex(&bytes).to_string();
        invalid.push_str("gg");
        let error = decode_write(&invalid, &mut output).unwrap_err();
        assert!(matches!(
            error,
            DecodeWriteError::Decode(DecodeError::InvalidDigit { .. })
        ));
        assert_eq!(output, [42, 0, 0xab]);
        for capacity in [0, 1, 127, 128, 129, bytes.len() - 1] {
            let mut writer = Writer {
                bytes: Vec::new(),
                remaining: capacity,
                interrupt: false,
            };
            let error = decode_write(hex(&bytes).to_string(), &mut writer).unwrap_err();
            let DecodeWriteError::Write(source) = &error else {
                panic!("expected I/O error")
            };
            assert_eq!(source.kind(), io::ErrorKind::WriteZero);
            assert_eq!(writer.bytes, bytes[..capacity]);
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<io::Error>()
                    .unwrap()
                    .kind(),
                io::ErrorKind::WriteZero
            );
        }
        let error: DecodeWriteError = io::Error::other("broken").into();
        assert_eq!(error.to_string(), "failed to write decoded hex: broken");
        let error: DecodeWriteError = DecodeError::OddLength.into();
        assert_eq!(
            error.to_string(),
            "invalid hex input: hex input has an odd number of digits"
        );
        assert_eq!(
            error.source().unwrap().downcast_ref::<DecodeError>(),
            Some(&DecodeError::OddLength)
        );
    }

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
            error(&DecodeError::InsufficientCapacity {
                required: 3,
                available: 2
            }),
            "decoded hex requires 3 bytes, but only 2 are available"
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
