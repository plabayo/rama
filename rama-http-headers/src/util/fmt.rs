use std::fmt::Display;

use rama_core::telemetry::tracing;
use rama_http_types::HeaderValue;

/// Format `fmt` as a [`HeaderValue`], or `None` if the output is not a valid one.
pub(crate) fn fmt<T: Display>(fmt: T) -> Option<HeaderValue> {
    match HeaderValue::try_from(fmt.to_string()) {
        Ok(val) => Some(val),
        Err(err) => {
            tracing::debug!("failed to format typed header as HeaderValue: {err}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_valid_and_invalid_without_panic() {
        assert_eq!(
            fmt(format_args!("bytes=-{}", u64::MAX)).unwrap(),
            "bytes=-18446744073709551615"
        );
        for invalid in ["a\nb", "a\rb", "\0", "\x7f"] {
            assert!(fmt(invalid).is_none());
        }
    }
}
