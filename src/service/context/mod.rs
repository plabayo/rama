//! Context passed to and between services as input.

use std::{future::Future, sync::Arc};
use tokio::task::JoinHandle;

mod extensions;
pub use extensions::Extensions;
use tokio_graceful::ShutdownGuard;

use crate::rt::Executor;

/// Context passed to and between services as input.
#[derive(Debug)]
pub struct Context<S> {
    state: Arc<S>,
    executor: Executor,
    extensions: Extensions,
}

impl Default for Context<()> {
    fn default() -> Self {
        Self::new(Arc::new(()), Executor::default())
    }
}

impl<S> Clone for Context<S> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            executor: self.executor.clone(),
            extensions: self.extensions.clone(),
        }
    }
}

impl<S> Context<S> {
    /// Create a new [`Context`] with the given state.
    pub fn new(state: Arc<S>, executor: Executor) -> Self {
        Self {
            state,
            executor,
            extensions: Extensions::new(),
        }
    }

    /// Get a reference to the state.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Get a reference to the executor.
    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// Spawn a future on the current executor,
    /// this is spawned gracefully in case a shutdown guard has been registered.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.executor.spawn_task(future)
    }

    /// Get a reference to an extension.
    ///
    /// An extension is a type that implements `Send + Sync + 'static`,
    /// and can be used to inject dynamic data into the [`Context`].
    ///
    /// Extensions are specific to this [`Context`]. It will be cloned when the [`Context`] is cloned,
    /// but extensions inserted using [`Context::insert`] will not be visible the
    /// original [`Context`], or any other cloned [`Context`].
    ///
    /// Please use the statically typed state (see [`Context::state`]) for data that is shared between
    /// all context clones, parent or not.
    ///
    /// # Example
    ///
    /// ```
    /// # use rama::service::Context;
    /// # let mut ctx = Context::default();
    /// # ctx.insert(5i32);
    /// assert_eq!(ctx.get::<i32>(), Some(&5i32));
    /// ```
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions.get::<T>()
    }

    /// Insert an extension into the [`Context`].
    ///
    /// If a extension of this type already existed, it will
    /// be returned.
    ///
    /// See [`Context::get`] for more details regarding extensions.
    ///
    /// # Example
    ///
    /// ```
    /// # use rama::service::Context;
    /// let mut ctx = Context::default();
    ///
    /// assert_eq!(ctx.insert(5i32), None);
    /// assert_eq!(ctx.get::<i32>(), Some(&5i32));
    ///
    /// assert_eq!(ctx.insert(4i32), Some(5i32));
    /// assert_eq!(ctx.get::<i32>(), Some(&4i32));
    /// ```
    pub fn insert<T: Clone + Send + Sync + 'static>(&mut self, extension: T) -> Option<T> {
        self.extensions.insert(extension)
    }

    /// Extend The [`Context`] [`Extensions`] with another [`Extensions`].
    ///
    /// # Example
    ///
    /// ```
    /// # use rama::service::{context::Extensions, Context};
    /// let mut ctx = Context::default();
    /// let mut ext = Extensions::default();
    ///
    /// ctx.insert(true);
    /// ext.insert(5i32);
    /// ctx.extend(ext);
    ///
    /// assert_eq!(ctx.get::<bool>(), Some(&true));
    /// assert_eq!(ctx.get::<i32>(), Some(&5i32));
    /// ```
    pub fn extend(&mut self, extensions: Extensions) {
        self.extensions.extend(extensions);
    }

    /// Clear the [`Context`] of all inserted [`Extensions`].
    ///
    /// # Example
    ///
    /// ```
    /// # use rama::service::Context;
    /// let mut ctx = Context::default();
    ///
    /// ctx.insert(5i32);
    /// assert_eq!(ctx.get::<i32>(), Some(&5i32));
    ///
    /// ctx.clear();
    /// assert_eq!(ctx.get::<i32>(), None);
    /// ```
    pub fn clear(&mut self) {
        self.extensions.clear();
    }

    /// Get a reference to the shutdown guard,
    /// if and only if the context was created within a graceful environment.
    pub fn guard(&self) -> Option<&ShutdownGuard> {
        self.executor.guard()
    }

    /// Turn this Context into a parent [`Context`].
    ///
    /// Naming is hard. Essentially it is meant to optimise the [`Context`] for cloning,
    /// so that the extensions are not cloned upon [`Context`] cloning, but instead
    /// are shared between the original [`Context`] and the cloned [`Context`].
    ///
    /// This is used when branching the [`Context`] into multiple [`Context`]s,
    /// e.g. to go from a Transport Layer to a HTTP Layer, where the context is now
    /// branched for each HTTP request.
    pub fn into_parent(self) -> Self {
        Self {
            state: self.state,
            executor: self.executor,
            extensions: self.extensions.into_parent(),
        }
    }
}
