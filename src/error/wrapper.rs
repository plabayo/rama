use super::{BoxError, StdError};
use std::{
    fmt::{self, Debug, Display},
    ops::{Deref, DerefMut},
};

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

impl<M> StdError for MessageError<M> where M: Display + Debug + 'static {}

#[repr(transparent)]
pub(crate) struct DisplayError<M>(pub(crate) M);

impl<M> Debug for DisplayError<M>
where
    M: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<M> Display for DisplayError<M>
where
    M: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<M> StdError for DisplayError<M> where M: Display + 'static {}

#[repr(transparent)]
pub(crate) struct BoxedError(pub(crate) BoxError);

impl BoxedError {
    pub(crate) fn downcast<E: StdError + Send + Sync + 'static>(self) -> Result<E, Self> {
        match self.0.downcast::<E>() {
            Ok(err) => Ok(*err),
            Err(err) => Err(Self(err)),
        }
    }

    pub(crate) fn downcast_ref<E: StdError + Send + Sync + 'static>(&self) -> Option<&E> {
        self.0.downcast_ref::<E>()
    }

    pub(crate) fn downcast_mut<E: StdError + Send + Sync + 'static>(
        &mut self,
    ) -> Option<&mut E> {
        self.0.downcast_mut::<E>()
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

impl StdError for BoxedError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.0.source()
    }
}

impl AsRef<dyn StdError + Send + Sync> for BoxedError {
    fn as_ref(&self) -> &(dyn StdError + Send + Sync + 'static) {
        &*self.0
    }
}

impl Deref for BoxedError {
    type Target = dyn StdError + Send + Sync + 'static;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl DerefMut for BoxedError {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}
