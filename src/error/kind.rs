//! Tagged dispatch mechanism for resolving the behavior of `anyhow!($expr)`.
//!
//! When anyhow! is given a single expr argument to turn into anyhow::Error, we
//! want the resulting Error to pick up the input's implementation of source()
//! and backtrace() if it has a std::error::Error impl, otherwise require nothing
//! more than Display and Debug.

use super::{BoxError, Error, StdError};
use std::fmt::{Debug, Display};

#[derive(Debug)]
pub struct Adhoc;

#[doc(hidden)]
pub trait AdhocKind: Sized {
    #[inline]
    fn anyhow_kind(&self) -> Adhoc {
        Adhoc
    }
}

impl<T> AdhocKind for &T where T: ?Sized + Display + Debug + Send + Sync + 'static {}

impl Adhoc {
    #[cold]
    pub fn new<M>(self, message: M) -> Error
    where
        M: Display + Debug + Send + Sync + 'static,
    {
        Error::from_adhoc(message)
    }
}

#[derive(Debug)]
pub struct Trait;

#[doc(hidden)]
pub trait TraitKind: Sized {
    #[inline]
    fn anyhow_kind(&self) -> Trait {
        Trait
    }
}

impl<E> TraitKind for E where E: StdError {}

impl Trait {
    #[cold]
    pub fn new<E>(self, error: E) -> Error
    where
        E: StdError + Send + Sync + 'static,
    {
        Error::new(error)
    }
}

#[derive(Debug)]
pub struct Boxed;

#[doc(hidden)]
pub trait BoxedKind: Sized {
    #[inline]
    fn anyhow_kind(&self) -> Boxed {
        Boxed
    }
}

impl BoxedKind for BoxError {}

impl Boxed {
    #[cold]
    pub fn new(self, error: BoxError) -> Error {
        Error::from_boxed(error)
    }
}
