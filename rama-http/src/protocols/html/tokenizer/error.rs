//! Errors raised by the [`Tokenizer`](super::Tokenizer).

use std::error::Error;
use std::fmt;

use super::context::ParsingAmbiguityError;

/// Why the [`Tokenizer`](super::Tokenizer) stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenizerError {
    /// Strict mode met an ambiguous text-mode context.
    Ambiguity(ParsingAmbiguityError),
    /// One construct needs more memory than the configured limit.
    MemoryLimit(MemoryLimitExceededError),
}

impl fmt::Display for TokenizerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ambiguity(err) => err.fmt(f),
            Self::MemoryLimit(err) => err.fmt(f),
        }
    }
}

impl Error for TokenizerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Ambiguity(err) => Some(err),
            Self::MemoryLimit(err) => Some(err),
        }
    }
}

impl From<ParsingAmbiguityError> for TokenizerError {
    fn from(err: ParsingAmbiguityError) -> Self {
        Self::Ambiguity(err)
    }
}

impl From<MemoryLimitExceededError> for TokenizerError {
    fn from(err: MemoryLimitExceededError) -> Self {
        Self::MemoryLimit(err)
    }
}

/// Raised when one construct (a tag with its attributes, a comment, a
/// text-mode body, …) needs more than the tokenizer's
/// [`max_buffered_bytes`](super::Tokenizer::max_buffered_bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLimitExceededError {
    limit: usize,
}

impl MemoryLimitExceededError {
    pub(crate) const fn new(limit: usize) -> Self {
        Self { limit }
    }

    /// The limit, in bytes, that was exceeded.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

impl fmt::Display for MemoryLimitExceededError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HTML construct exceeds the tokenizer memory limit of {} bytes",
            self.limit
        )
    }
}

impl Error for MemoryLimitExceededError {}
