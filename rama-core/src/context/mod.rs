//! Context passed to and between services as input.
//!
//! # State
//!
//! [`rama`] supports two kinds of states:
//!
//! 1. static state: this state can be a part of the service struct or captured by a closure
//! 2. dynamic state: these can be injected as [`Extensions`]s using methods such as [`Context::insert`]
//!
//! Any state that is optional, and especially optional state injected by middleware, can be inserted using extensions.
//! It is however important to try as much as possible to then also consume this state in an approach that deals
//! gracefully with its absence. Good examples of this are header-related inputs. Headers might be set or not,
//! and so absence of [`Extensions`]s that might be created as a result of these might reasonably not exist.
//! It might of course still mean the app returns an error response when it is absent, but it should not unwrap/panic.
//!
//! [`rama`]: crate
//!
//! # Examples
//!
//! ## Example: Extensions
//!
//! The [`Context`] can be extended with additional data using the [`Extensions`] type.
//!
//! [`Context`]: crate::Context
//! [`Extensions`]: crate::context::Extensions
//!
//! ```
//! use rama_core::Context;
//!
//! let mut ctx = Context::default();
//! ctx.insert(5i32);
//! assert_eq!(ctx.get::<i32>(), Some(&5i32));
//! ```

use crate::graceful::ShutdownGuard;
use crate::rt::Executor;
use std::ops::{Deref, DerefMut};
use tokio::task::JoinHandle;

#[doc(inline)]
pub use super::extensions::Extensions;

#[derive(Debug, Clone)]
/// Wrapper type that can be injected into the dynamic extensions of a "Response",
/// in order to preserve the [`Context`]'s extensions of the _Request_
/// which was used to produce the _Response_.
pub struct RequestContextExt(Extensions);

impl From<Extensions> for RequestContextExt {
    fn from(value: Extensions) -> Self {
        Self(value)
    }
}

impl From<RequestContextExt> for Extensions {
    fn from(value: RequestContextExt) -> Self {
        value.0
    }
}

impl AsRef<Extensions> for RequestContextExt {
    fn as_ref(&self) -> &Extensions {
        &self.0
    }
}

impl AsMut<Extensions> for RequestContextExt {
    fn as_mut(&mut self) -> &mut Extensions {
        &mut self.0
    }
}

impl Deref for RequestContextExt {
    type Target = Extensions;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for RequestContextExt {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug, Default, Clone)]
/// Context passed to and between services as input.
///
/// See [`crate::context`] for more information.
pub struct Context {
    executor: Executor,
}

#[derive(Debug)]
/// Component parts of [`Context`].
pub struct Parts {
    pub executor: Executor,
}

impl Context {
    #[must_use]
    /// Create a new [`Context`] with the given state.
    pub fn new(executor: Executor) -> Self {
        Self { executor }
    }

    #[must_use]
    pub fn from_parts(parts: Parts) -> Self {
        Self {
            executor: parts.executor,
        }
    }

    #[must_use]
    pub fn into_parts(self) -> Parts {
        Parts {
            executor: self.executor,
        }
    }

    #[must_use]
    /// Get a reference to the executor.
    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// Set a new [`Executor`] to the [`Context`].
    pub fn set_executor(&mut self, exec: Executor) -> &mut Self {
        self.executor = exec;
        self
    }

    /// Set a new [`Executor`] to the [`Context`].
    #[must_use]
    pub fn with_executor(mut self, exec: Executor) -> Self {
        self.executor = exec;
        self
    }

    /// Spawn a future on the current executor,
    /// this is spawned gracefully in case a shutdown guard has been registered.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        self.executor.spawn_task(future)
    }

    #[must_use]
    /// Get a reference to the shutdown guard,
    /// if and only if the context was created within a graceful environment.
    pub fn guard(&self) -> Option<&ShutdownGuard> {
        self.executor.guard()
    }
}
