use crate::error::BoxError;
use std::fmt::{self, Debug, Display};

#[repr(transparent)]
/// A boxed error type that can be used as a trait object.
///
/// Note this type is not intended to be used directly,
/// it is used by `rama` to hide the concrete error type.
pub struct BoxedError(BoxError);

impl BoxedError {
    pub(crate) fn from_std(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }
}

impl Debug for BoxedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Display for BoxedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl std::error::Error for BoxedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

#[repr(transparent)]
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
