use core::{error::Error, fmt};

/// A runtime-independent timeout marker.
///
/// Return this error directly, wrap it with context, or expose it from a custom
/// error's [`Error::source`] to make that timeout recognizable without depending
/// on the service or runtime that imposed the deadline.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeoutError;

impl TimeoutError {
    /// Create a timeout without allocating or retaining runtime state.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operation timed out")
    }
}

impl Error for TimeoutError {}

/// Whether an error or its source chain represents a known timeout.
///
/// Recognizes [`TimeoutError`], `std::io::ErrorKind::TimedOut` with `std`, and
/// `tokio::time::error::Elapsed` with `std`. Custom errors
/// can expose [`TimeoutError`] as a source; messages are never inspected.
///
/// Uses [`crate::error_chain`], including wrapped I/O errors, with its 64-error
/// bound for cyclic or excessively deep sources. For [`crate::ErrorList`] only
/// the primary failure is followed: one secondary timeout does not classify a
/// collection of unrelated failures as a timeout.
#[must_use]
pub fn is_timeout_error(error: &(dyn Error + 'static)) -> bool {
    crate::error_chain(error).any(|cause| {
        if cause.is::<TimeoutError>() {
            return true;
        }
        #[cfg(feature = "std")]
        if cause
            .downcast_ref::<::std::io::Error>()
            .is_some_and(|error| error.kind() == ::std::io::ErrorKind::TimedOut)
        {
            return true;
        }
        #[cfg(feature = "std")]
        if cause.is::<tokio::time::error::Elapsed>() {
            return true;
        }
        false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BoxError, ErrorExt as _};

    #[derive(Debug)]
    struct CustomDeadline;
    impl fmt::Display for CustomDeadline {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("custom deadline")
        }
    }
    impl Error for CustomDeadline {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&TimeoutError)
        }
    }

    #[test]
    fn recognizes_custom_and_contextual_timeouts_without_text_matching() {
        assert!(is_timeout_error(&TimeoutError));
        assert!(is_timeout_error(&CustomDeadline));
        let wrapped = CustomDeadline
            .context("request")
            .context_field("attempt", 2u8);
        assert!(is_timeout_error(wrapped.as_ref()));
        assert!(!is_timeout_error(&fmt::Error));
        let text = <BoxError as crate::BoxErrorExt>::from_static_str("operation timed out");
        assert!(!is_timeout_error(text.as_ref()));
    }

    #[cfg(feature = "std")]
    #[test]
    fn recognizes_io_timeout_kinds_and_wrapped_markers() {
        use ::std::io;
        assert!(is_timeout_error(&io::Error::from(io::ErrorKind::TimedOut)));
        assert!(is_timeout_error(&io::Error::other(CustomDeadline)));
        assert!(is_timeout_error(&io::Error::other(io::Error::from(
            io::ErrorKind::TimedOut
        ))));
        assert!(!is_timeout_error(&io::Error::from(
            io::ErrorKind::WouldBlock
        )));
        assert!(!is_timeout_error(&io::Error::other("timed out")));
    }

    #[test]
    fn bounded_chain_handles_cycles_and_depth() {
        #[derive(Debug)]
        struct Cycle;
        impl fmt::Display for Cycle {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("cycle")
            }
        }
        impl Error for Cycle {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(self)
            }
        }
        assert!(!is_timeout_error(&Cycle));
        #[derive(Debug)]
        struct Wrapper(BoxError);
        impl fmt::Display for Wrapper {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("wrapper")
            }
        }
        impl Error for Wrapper {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(self.0.as_ref())
            }
        }
        let mut error: BoxError = TimeoutError.into();
        for _ in 0..63 {
            error = Wrapper(error).into();
        }
        assert!(is_timeout_error(error.as_ref()));
        assert!(!is_timeout_error(&Wrapper(error)));
    }

    #[test]
    fn only_primary_aggregate_failure_classifies_timeout() {
        let mut errors = crate::ErrorList::new();
        errors.push(fmt::Error);
        errors.push(TimeoutError);
        assert!(!is_timeout_error(&errors));
        errors.push_primary(TimeoutError);
        assert!(is_timeout_error(&errors));
    }

    #[cfg(feature = "std")]
    #[tokio::test(start_paused = true)]
    async fn recognizes_tokio_elapsed_with_context() {
        let error = tokio::time::timeout(
            core::time::Duration::from_secs(1),
            core::future::pending::<()>(),
        )
        .await
        .unwrap_err();
        assert!(is_timeout_error(&error));
        assert!(is_timeout_error(error.context("outer deadline").as_ref()));
    }
}
