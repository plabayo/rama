use crate::error::BoxError;
use std::fmt::{self, Debug, Display};

#[repr(transparent)]
/// A type-erased error type that can be used as a trait object.
///
/// Note this type is not intended to be used directly,
/// it is used by `rama` to hide the concrete error type.
///
/// See the [module level documentation](crate::error) for more information.
pub struct OpaqueError(BoxError);

impl OpaqueError {
    /// create an [`OpaqueError`] from an std error
    pub fn from_std(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }

    /// create an [`OpaqueError`] from a display object
    pub fn from_display(msg: impl Display + Debug + Send + Sync + 'static) -> Self {
        Self::from_std(MessageError(msg))
    }

    /// create an [`OpaqueError`] from a boxed error
    pub fn from_boxed(inner: BoxError) -> Self {
        Self(inner)
    }
}

impl Debug for OpaqueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Display for OpaqueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl std::error::Error for OpaqueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

#[repr(transparent)]
/// An error type that wraps a message.
pub(crate) struct MessageError<M>(pub(crate) M);

impl<M> Debug for MessageError<M>
where
    M: Display + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<M> Display for MessageError<M>
where
    M: Display + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<M> std::error::Error for MessageError<M> where M: Display + Debug + 'static {}
