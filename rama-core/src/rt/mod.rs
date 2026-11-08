//! Runtime utilities used by Rama.
//!
//! Work that should be awaited on shutdown is spawned on a held
//! [`Scope`](crate::graceful::Scope), see [`Scope::spawn_task`](crate::graceful::Scope::spawn_task);
//! [`spawn`] is for tasks that intentionally live outside of any scope.

mod spawn;
#[doc(inline)]
pub use spawn::spawn;

mod owned;
#[doc(inline)]
pub use owned::{OwnedRuntime, OwnedRuntimeHandle};

pub mod blocking;

pub mod future;

#[cfg(test)]
#[cfg(feature = "dial9")]
pub(crate) mod dial9_test_util;
