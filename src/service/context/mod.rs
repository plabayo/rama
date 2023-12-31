//! Context passed to and between services as input.

use futures::executor;
use std::future::Future;
use tokio::task::JoinHandle;

mod extensions;
pub use extensions::Extensions;
use tokio_graceful::ShutdownGuard;

use crate::rt::Executor;

/// Context passed to and between services as input.
#[derive(Debug, Clone)]
pub struct Context<S> {
    state: S,
    executor: Executor,
    extensions: Extensions,
}

impl Default for Context<()> {
    fn default() -> Self {
        Self::new((), Executor::default())
    }
}

impl<S> Context<S> {
    /// Create a new [`Context`] with the given state.
    pub fn new(state: S, executor: Executor) -> Self {
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

    /// Get a mutable reference to the state.
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
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

    /// Get a reference to the extensions.
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Get a mutable reference to the extensions.
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}
