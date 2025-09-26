//! Context passed to and between services as input.
use crate::graceful::ShutdownGuard;
use crate::rt::Executor;
use tokio::task::JoinHandle;

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
