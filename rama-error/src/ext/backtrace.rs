use super::BoxError;
use std::{backtrace::Backtrace, fmt};

#[derive(Debug)]
pub(super) struct ErrorWithBacktrace {
    source: BoxError,
    backtrace: Backtrace,
}

impl ErrorWithBacktrace {
    pub(super) fn new(source: BoxError) -> Self {
        Self {
            source,
            backtrace: Backtrace::capture(),
        }
    }
}

impl fmt::Display for ErrorWithBacktrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            return write!(f, "{}", self.source);
        }

        writeln!(f, "{}", self.source)?;

        writeln!(f, "Backtrace:")?;
        writeln!(f, "{}", self.backtrace)?;

        Ok(())
    }
}

impl std::error::Error for ErrorWithBacktrace {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{error::Error as _, io};

    #[test]
    fn display_non_alternate_prints_only_source() {
        let src = io::Error::other("boom");
        let err = ErrorWithBacktrace::new(Box::new(src));

        let s = format!("{err}");
        assert_eq!(s, "boom");
    }

    #[test]
    fn display_alternate_includes_source_and_backtrace_label() {
        let src = io::Error::other("boom");
        let err = ErrorWithBacktrace::new(Box::new(src));

        let s = format!("{err:#}");

        // First line should be the source message
        assert!(s.starts_with("boom\n"), "got: {s:?}");

        // Must include the backtrace section header
        assert!(
            s.contains("\nBacktrace:\n") || s.contains("\nBacktrace:\r\n"),
            "got: {s:?}"
        );

        // We do not assert backtrace contents because it can be disabled depending on env and build.
        // We only assert it printed something after the label.
        let parts: Vec<&str> = s.split("Backtrace:").collect();
        assert_eq!(parts.len(), 2, "got: {s:?}");
        assert!(
            !parts[1].trim().is_empty(),
            "expected something after Backtrace:, got: {s:?}"
        );
    }

    #[test]
    fn source_returns_inner_error() {
        let src = io::Error::other("boom");
        let err = ErrorWithBacktrace::new(Box::new(src));

        let src_ref = err.source().expect("source should exist");
        assert_eq!(src_ref.to_string(), "boom");
    }

    #[test]
    fn debug_includes_type_name() {
        let src = io::Error::other("boom");
        let err = ErrorWithBacktrace::new(Box::new(src));

        let s = format!("{err:?}");
        assert!(s.contains("ErrorWithBacktrace"), "got: {s:?}");
    }
}
