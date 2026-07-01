#[cfg(feature = "std")]
#[expect(
    unused_imports,
    reason = "central std/alloc shim re-exports are used feature-dependently"
)]
pub(crate) use ::std::{borrow, boxed, collections, format, string, sync, vec};

#[cfg(not(feature = "std"))]
#[expect(
    unused_imports,
    reason = "central std/alloc shim re-exports are used feature-dependently"
)]
pub(crate) use ::alloc::{borrow, boxed, collections, format, string, sync, vec};
