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
            Some(guard) => {
                // Replicate `tokio_graceful::ShutdownGuard::spawn_task`
                // inline (see `tokio-graceful/src/guard.rs`) so the
                // underlying `tokio::spawn` can be routed through dial9
                // when the feature is on. The cloned guard pins shutdown
                // until the future ends, matching tokio-graceful's
                // semantics exactly. If a future tokio-graceful release
                // adds tracking inside `spawn_task`/`spawn_task_fn`, we
                // would silently diverge — keep this in sync if you
                // bump tokio-graceful past 0.2.x.
                let guard = guard.clone();
                spawn(async move {
                    let output = future.await;
                    drop(guard);
                    output
                })
            }
            None => spawn(future),
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
            Some(guard) => {
                let guard = guard.clone();
                spawn(async move {
                    let output = tokio::select! {
                        _ = guard.cancelled() => {
                            tracing::trace!("cancellable task is cancelled due to guard");
                            None
                        }
                        output = future => {
                            Some(output)
                        }
                    };
                    drop(guard);
                    output
                })
            }
            None => spawn(future.map(Some)),
        }
    }

    /// Spawn a future on the current executor,
    /// this is spawned gracefully in case a shutdown guard has been registered.
    pub fn into_spawn_task<F>(self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        match self.guard {
            Some(guard) => spawn(async move {
                let output = future.await;
                drop(guard);
                output
            }),
            None => spawn(future),
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

/// Spawn a future on the current tokio runtime.
///
/// When the `dial9` feature is enabled this routes through
/// `dial9_tokio_telemetry::spawn`, which wraps the future with
/// wake-event tracking on a traced runtime and falls through to
/// plain `tokio::spawn` otherwise. With the feature disabled this
/// is a direct call to `tokio::spawn`.
#[inline]
fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future<Output: Send + 'static> + Send + 'static,
{
    #[cfg(feature = "dial9")]
    {
        ::dial9_tokio_telemetry::spawn(future)
    }
    #[cfg(not(feature = "dial9"))]
    {
        tokio::spawn(future)
    }
}
