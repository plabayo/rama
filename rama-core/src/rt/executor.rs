use crate::graceful::ShutdownGuard;

/// Future executor that utilises `tokio` threads.
#[derive(Default, Debug, Clone)]
pub struct Executor {
    guard: Option<ShutdownGuard>,
}

impl Executor {
    /// Create a new [`Executor`].
    pub const fn new() -> Self {
        Self { guard: None }
    }

    /// Create a new [`Executor`] with the given shutdown guard,
    ///
    /// This will spawn tasks that are awaited gracefully
    /// in case the shutdown guard is triggered.
    pub fn graceful(guard: ShutdownGuard) -> Self {
        Self { guard: Some(guard) }
    }

    /// Spawn a future on the current executor,
    /// this is spawned gracefully in case a shutdown guard has been registered.
    pub fn spawn_task<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match &self.guard {
            Some(guard) => guard.spawn_task(future),
            None => tokio::spawn(future),
        }
    }
}

impl Executor {
    /// Get a reference to the shutdown guard,
    /// if and only if the executor was created with [`Self::graceful`].
    pub(crate) fn guard(&self) -> Option<&ShutdownGuard> {
        self.guard.as_ref()
    }
}
