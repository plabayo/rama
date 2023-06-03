use std::{error::Error, fmt::Display};

/// Alias for a type-erased error type.
#[derive(Debug)]
pub struct BoxError(Box<dyn Error>);

impl Display for BoxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<E> From<E> for BoxError
where
    E: Error + Send + Sync,
{
    fn from(err: E) -> Self {
        BoxError(Box::new(err))
    }
}

impl From<BoxError> for Box<dyn Error> {
    fn from(error: BoxError) -> Self {
        error.0
    }
}
