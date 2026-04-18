use crate::futures::FutureExt as _;
use crate::graceful::ShutdownGuard;

/// Future executor that utilises `tokio` threads.
#[derive(Default, Debug, Clone)]
pub struct Executor {
    guard: Option<ShutdownGuard>,
}

impl Executor {
    /// Create a new [`Executor`].
    #[must_use]
    pub const fn new() -> Self {
        Self { guard: None }
    }

    /// Create a new [`Executor`] with the given shutdown guard,
    ///
    /// This will spawn tasks that are awaited gracefully
    /// in case the shutdown guard is triggered.
    #[must_use]
    pub fn graceful(guard: ShutdownGuard) -> Self {
        Self { guard: Some(guard) }
    }

    /// Spawn a future on the current executor,
    /// this is spawned gracefully in case a shutdown guard has been registered.
    pub fn spawn_task<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        match &self.guard {
            Some(guard) => guard.spawn_task(future),
            None => tokio::spawn(future),
        }
    }

    /// Spawn a future on the current executor,
    /// this is aborted early in case the executor is graceful.
    ///
    /// In case this executor is not graceful,
    /// this function operates the same as [`Self::spawn_task`].
    ///
    /// # Note
    ///
    /// Ensure that your future is cancellable!
    pub fn spawn_cancellable_task<F>(&self, future: F) -> tokio::task::JoinHandle<Option<F::Output>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        match &self.guard {
            Some(guard) => guard.spawn_task_fn(async |guard| {
                tokio::select! {
                    _ = guard.cancelled() => {
                        tracing::trace!("cancellable task is cancelled due to guard");
                        None
                    }
                    output = future => {
                        Some(output)
                    }
                }
            }),
            None => tokio::spawn(future.map(Some)),
        }
    }

    /// Spawn a future on the current executor,
    /// this is spawned gracefully in case a shutdown guard has been registered.
    pub fn into_spawn_task<F>(self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        match self.guard {
            Some(guard) => guard.into_spawn_task(future),
            None => tokio::spawn(future),
        }
    }

    /// Get a reference to the shutdown guard,
    /// if and only if the executor was created with [`Self::graceful`].
    #[must_use]
    pub fn guard(&self) -> Option<&ShutdownGuard> {
        self.guard.as_ref()
    }

    /// Consume itself as the internal shutdown guard, if any
    #[must_use]
    pub fn into_guard(self) -> Option<ShutdownGuard> {
        self.guard
    }
}
