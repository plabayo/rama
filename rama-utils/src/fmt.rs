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
}
