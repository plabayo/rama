//! Allocation-aware formatting helpers.

use core::fmt::{self, Write as _};

use crate::std::string::String;

/// Format `args` into a new string with the requested initial `capacity`.
///
/// This is useful when the caller can cheaply determine the rendered length
/// from its inputs. Formatting happens once and the string does not reallocate
/// as long as `capacity` is large enough.
///
/// # Panics
///
/// Panics if a formatting trait implementation supplied through `args` returns
/// [`fmt::Error`], matching [`format!`].
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "match format! semantics for caller-provided formatting implementations"
)]
pub fn format_with_capacity(capacity: usize, args: fmt::Arguments<'_>) -> String {
    let mut output = String::with_capacity(capacity);
    output
        .write_fmt(args)
        .expect("formatting into a String cannot fail");
    output
}

/// Clear `output`, try to format `args` into it, and return the resulting string.
///
/// The allocation owned by `output` is retained, making this suitable for a
/// scratch string reused across a loop or a sequence of writes.
///
/// If formatting fails, `output` contains the successfully formatted prefix.
pub fn try_format_into<'a>(
    output: &'a mut String,
    args: fmt::Arguments<'_>,
) -> Result<&'a str, fmt::Error> {
    output.clear();
    output.write_fmt(args)?;
    Ok(output.as_str())
}

/// Build a deferred [`Display`](fmt::Display) value from a formatting closure.
///
/// This is useful for passing composed output directly to another formatter
/// without first allocating an intermediate string.
pub fn display_fn<F>(formatter: F) -> DisplayFn<F> {
    DisplayFn(formatter)
}

/// Format bytes as contiguous hexadecimal without an intermediate allocation.
///
/// Display (`{}`) uses uppercase digits with a `0x` prefix. Lower hex (`{:x}`)
/// and upper hex (`{:X}`) omit the prefix unless alternate formatting (`#`)
/// is requested. Each input byte always produces two digits.
///
/// Use `write!` to append directly to a reusable `String` (`core::fmt::Write`)
/// or a byte buffer or I/O writer (`std::io::Write`). Only the destination may
/// allocate; the formatter uses a small stack buffer. A failed write can leave
/// a partially written prefix, following the destination's usual semantics.
///
/// Supported format options are the case (`{:x}` / `{:X}`) and the alternate
/// `0x` prefix (`#`). Width, fill, alignment, precision and zero padding are
/// accepted but not interpreted.
///
/// ```
/// use core::fmt::Write as _;
/// use rama_utils::fmt::hex;
///
/// let mut output = String::with_capacity(64);
/// output.push_str("key=");
/// write!(&mut output, "{:x}", hex(&[0xCA, 0xFE])).unwrap();
/// assert_eq!(output, "key=cafe");
/// assert_eq!(format!("{:#X}", hex(&[0xCA, 0xFE])), "0xCAFE");
/// ```
pub fn hex(bytes: &[u8]) -> impl fmt::Display + fmt::LowerHex + fmt::UpperHex + '_ {
    Hex(bytes)
}

struct Hex<'a>(&'a [u8]);

impl Hex<'_> {
    fn format(&self, formatter: &mut fmt::Formatter<'_>, upper: bool, prefix: bool) -> fmt::Result {
        if prefix {
            formatter.write_str("0x")?;
        }
        let mut buffer = [0u8; 128];
        for chunk in self.0.chunks(buffer.len() / 2) {
            let written = if upper {
                crate::hex::encode_upper_into(chunk, &mut buffer)
            } else {
                crate::hex::encode_into(chunk, &mut buffer)
            }
            .map_err(|_capacity| fmt::Error)?;
            // The encoders write only ASCII digits into the initialized prefix.
            let text = core::str::from_utf8(&buffer[..written]).map_err(|_ascii| fmt::Error)?;
            formatter.write_str(text)?;
        }
        Ok(())
    }
}

impl fmt::Display for Hex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(formatter, true, true)
    }
}

impl fmt::LowerHex for Hex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(formatter, false, formatter.alternate())
    }
}

impl fmt::UpperHex for Hex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(formatter, true, formatter.alternate())
    }
}

/// Display valid UTF-8 as a quoted debug string, or other bytes as [`hex`].
///
/// Formatting is deferred and does not allocate.
pub fn utf8_or_hex(bytes: &[u8]) -> impl fmt::Display + '_ {
    display_fn(
        move |formatter: &mut fmt::Formatter<'_>| match core::str::from_utf8(bytes) {
            Ok(text) => write!(formatter, "{text:?}"),
            Err(_) => fmt::Display::fmt(&hex(bytes), formatter),
        },
    )
}

/// Write values separated by `separator`, using `write_value` for each value.
///
/// Nothing is allocated, and the separator is written only between values.
pub fn write_joined_with<W, I, F>(
    writer: &mut W,
    values: I,
    separator: &str,
    mut write_value: F,
) -> fmt::Result
where
    W: fmt::Write + ?Sized,
    I: IntoIterator,
    F: FnMut(&mut W, I::Item) -> fmt::Result,
{
    let mut values = values.into_iter();
    let Some(first) = values.next() else {
        return Ok(());
    };
    write_value(writer, first)?;
    for value in values {
        writer.write_str(separator)?;
        write_value(writer, value)?;
    }
    Ok(())
}

/// Write [`fmt::Display`] values separated by `separator` without allocating.
pub fn write_joined<W, I>(writer: &mut W, values: I, separator: &str) -> fmt::Result
where
    W: fmt::Write + ?Sized,
    I: IntoIterator,
    I::Item: fmt::Display,
{
    write_joined_with(writer, values, separator, |writer, value| {
        write!(writer, "{value}")
    })
}

/// Deferred formatting value created by [`display_fn`].
#[derive(Clone, Copy)]
pub struct DisplayFn<F>(F);

impl<F> fmt::Display for DisplayFn<F>
where
    F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.0)(formatter)
    }
}

#[cfg(test)]
mod tests {
    use core::fmt;

    use super::*;

    #[test]
    fn hex_appends_to_reused_string_with_both_cases() {
        let bytes: crate::std::vec::Vec<_> = (0u8..=255).collect();
        let mut output = String::with_capacity(1100);
        output.push_str("key=");
        let allocation = output.as_ptr();
        write!(&mut output, "{:x}/{:X}", hex(&bytes), hex(&bytes)).unwrap();
        assert_eq!(output.as_ptr(), allocation);
        assert_eq!(
            output,
            format!(
                "key={}/{}",
                crate::hex::encode(&bytes),
                crate::hex::encode_upper(&bytes)
            )
        );
        assert_eq!(
            format!("{:#x}/{:#X}/{}", hex(&[0xAB]), hex(&[0xAB]), hex(&[0xAB])),
            "0xab/0xAB/0xAB"
        );
        assert_eq!(
            format!("{:x}/{:X}/{:#x}", hex(&[]), hex(&[]), hex(&[])),
            "//0x"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn hex_appends_to_reused_byte_buffer() {
        use std::io::Write as _;
        let mut output = Vec::with_capacity(32);
        output.extend_from_slice(b"key=");
        let allocation = output.as_ptr();
        write!(&mut output, "{:x}", hex(&[0xCA, 0xFE])).unwrap();
        assert_eq!(output, b"key=cafe");
        assert_eq!(output.as_ptr(), allocation);
    }

    #[cfg(feature = "std")]
    #[test]
    fn hex_preserves_writer_errors_after_partial_output() {
        use std::io::{self, Write as _};
        struct FailsAfterPrefix(Vec<u8>);
        impl io::Write for FailsAfterPrefix {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let remaining = 3 - self.0.len();
                if remaining == 0 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "writer closed"));
                }
                let written = remaining.min(bytes.len());
                self.0.extend_from_slice(&bytes[..written]);
                Ok(written)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut output = FailsAfterPrefix(Vec::new());
        let error = write!(&mut output, "{:x}", hex(&[0xCA, 0xFE])).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "writer closed");
        assert_eq!(output.0, b"caf");
    }

    #[test]
    fn formats_with_requested_capacity() {
        let output = format_with_capacity(32, format_args!("hello {value}", value = 42));

        assert_eq!(output, "hello 42");
        assert!(output.capacity() >= 32);
    }

    #[test]
    fn formats_into_reused_string() {
        let mut output = String::with_capacity(64);
        output.push_str("old contents");
        let allocation = output.as_ptr();

        let formatted =
            try_format_into(&mut output, format_args!("new {value}", value = "contents")).unwrap();

        assert_eq!(formatted, "new contents");
        assert_eq!(output.as_ptr(), allocation);
    }

    #[test]
    fn formatting_into_reused_string_propagates_display_errors() {
        struct Fails;

        impl fmt::Display for Fails {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                Err(fmt::Error)
            }
        }

        let mut output = String::from("old contents");
        let value = Fails;
        let error = try_format_into(&mut output, format_args!("prefix {value}")).unwrap_err();

        assert_eq!(error, fmt::Error);
        assert_eq!(output, "prefix ");
    }

    #[test]
    fn display_fn_defers_display_formatting() {
        let value =
            display_fn(|formatter: &mut fmt::Formatter<'_>| formatter.write_str("deferred"));

        assert_eq!(value.to_string(), "deferred");
    }

    #[test]
    fn displays_bytes_as_uppercase_hex_without_separators() {
        assert_eq!(hex(&[0x00, 0x4f, 0xa5, 0xff]).to_string(), "0x004FA5FF");
        assert_eq!(hex(&[]).to_string(), "0x");
    }

    #[test]
    fn displays_utf8_quoted_and_other_bytes_as_hex() {
        assert_eq!(
            utf8_or_hex(b"quote\" slash\\ line\n").to_string(),
            r#""quote\" slash\\ line\n""#
        );
        assert_eq!(utf8_or_hex(&[0xff, 0x00]).to_string(), "0xFF00");
        assert_eq!(utf8_or_hex(b"").to_string(), "\"\"");
    }

    #[test]
    fn writes_display_values_with_separators_without_edges() {
        let mut output = String::new();
        write_joined(&mut output, [1, 2, 3], ",").unwrap();
        assert_eq!(output, "1,2,3");

        output.clear();
        write_joined(&mut output, core::iter::empty::<u8>(), ",").unwrap();
        assert!(output.is_empty());

        output.clear();
        write_joined(&mut output, [42], ",").unwrap();
        assert_eq!(output, "42");
    }

    #[test]
    fn writes_joined_values_with_custom_formatting() {
        let mut output = String::new();
        write_joined_with(&mut output, [10, 11], "-", |writer, value| {
            write!(writer, "{value:x}")
        })
        .unwrap();
        assert_eq!(output, "a-b");
    }
}
