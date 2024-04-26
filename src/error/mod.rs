//! Error types for rama.
//!
//! The [`BoxError`] type is a type-erased error type that can be used to represent any error that
//! implements the `std::error::Error` trait and is used for cases where it is usually not
//! that important what specific error type is returned, but rather that an error occurred.
//!
//! That said, one can use downcasting or [`ErrorExt`] to try to get the cause of the error.

use std::{
    error::Error as StdError,
    fmt,
    ops::{Deref, DerefMut},
};

/// Alias for a type-erased error type.
pub type BoxError = Box<dyn StdError + Send + Sync>;

mod ext;
pub use ext::{BoxedError, ErrorContext, ErrorExt};

mod macros;
pub use crate::__error as error;

#[doc(hidden)]
pub mod __private {
    use super::*;
    use std::fmt::{Debug, Display};

    pub fn error<E>(error: E) -> BoxedError
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        BoxedError::from_std(error)
    }

    pub fn str_error<M>(message: M) -> BoxedError
    where
        M: Display + Debug + Send + Sync + 'static,
    {
        BoxedError::from_std(ext::MessageError(message))
    }
}

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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl AsRef<dyn StdError + Send + Sync> for Error {
    fn as_ref(&self) -> &(dyn StdError + Send + Sync + 'static) {
        &**self
    }
}

impl AsRef<dyn StdError> for Error {
    fn as_ref(&self) -> &(dyn StdError + 'static) {
        &**self
    }
}

impl Deref for Error {
    type Target = dyn StdError + Send + Sync + 'static;

    fn deref(&self) -> &Self::Target {
        &*self.inner
    }
}

impl DerefMut for Error {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.inner
    }
}

impl<E> From<E> for Error
where
    E: StdError + Send + Sync + 'static,
{
    fn from(error: E) -> Self {
        Self {
            inner: Box::new(error),
        }
    }
}

impl From<Error> for BoxError {
    fn from(error: Error) -> Self {
        error.inner
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_macro_error_string() {
        let error = error!("error").context("foo");
        assert_eq!(error.to_string(), "foo: error");
    }

    #[test]
    fn test_macro_error_format_string() {
        let error = error!("error {}", 404).context("foo");
        assert_eq!(error.to_string(), "foo: error 404");
    }

    #[derive(Debug)]
    struct CustomError;

    impl std::fmt::Display for CustomError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "entity not found")
        }
    }

    impl std::error::Error for CustomError {}

    #[test]
    fn test_macro_error_from_error() {
        let error = error!(CustomError).context("foo");
        assert_eq!(error.to_string(), "foo: entity not found");
    }
}
