#[cfg(feature = "std")]
#[expect(
    unused_imports,
    reason = "central std/alloc shim re-exports are used feature-dependently"
)]
pub(crate) use ::std::{borrow, boxed, collections, format, string, vec};

#[cfg(not(feature = "std"))]
#[expect(
    unused_imports,
    reason = "central std/alloc shim re-exports are used feature-dependently"
)]
pub(crate) use ::alloc::{borrow, boxed, collections, format, string, vec};

#[cfg(feature = "std")]
pub(crate) use ::std::sync;

#[cfg(not(feature = "std"))]
pub(crate) mod sync {
    #[expect(
        unused_imports,
        reason = "central std/alloc shim re-exports are used feature-dependently"
    )]
    pub(crate) use alloc::sync::{Arc, Weak};
    #[expect(
        unused_imports,
        reason = "central std/alloc shim re-exports are used feature-dependently"
    )]
    pub(crate) use core::sync::*;
}
