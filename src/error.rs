//! Error types for rama.

use std::{error::Error as StdError, fmt};

/// Alias for a type-erased error type.
pub type BoxError = Box<dyn StdError + Send + Sync>;

/// Errors that can happen when using rama.
#[derive(Debug)]
pub struct Error {
    inner: BoxError,
}

impl Error {
    /// Create a new `Error` from a boxable error.
    pub fn new(error: impl Into<BoxError>) -> Self {
        Self {
            inner: error.into(),
        }
    }

    /// Convert an `Error` back into the underlying boxed trait object.
    pub fn into_inner(self) -> BoxError {
        self.inner
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.inner)
    }
}

impl From<BoxError> for Error {
    fn from(error: BoxError) -> Self {
        Self { inner: error }
    }
}
