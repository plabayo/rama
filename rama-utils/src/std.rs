#[cfg(feature = "std")]
pub(crate) use ::std::alloc;

#[cfg(not(feature = "std"))]
pub(crate) use ::alloc::alloc;

#[cfg(feature = "std")]
pub(crate) use ::std::sync::Arc;

#[cfg(not(feature = "std"))]
pub(crate) use ::alloc::sync::Arc;

#[cfg(feature = "std")]
pub(crate) use ::std::{borrow, boxed, rc, string};

#[cfg(feature = "std")]
pub use ::std::vec;

#[cfg(not(feature = "std"))]
pub(crate) use ::alloc::{borrow, boxed, rc, string};

#[cfg(not(feature = "std"))]
pub use ::alloc::vec;
