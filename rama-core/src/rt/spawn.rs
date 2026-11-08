/// Spawn a future on the current tokio runtime.
///
/// Drop-in replacement for `tokio::spawn` for tasks that intentionally
/// live outside graceful shutdown (background workers, detached drivers).
/// Prefer [`Scope::spawn_task`](crate::graceful::Scope::spawn_task) for work that
/// should be awaited on shutdown.
///
/// When the `dial9` feature is enabled this routes through
/// `dial9::spawn`, which wraps the future with
/// wake-event tracking on a traced runtime and falls through to
/// plain `tokio::spawn` otherwise. With the feature disabled this
/// is a direct call to `tokio::spawn`.
///
/// # Panics
///
/// Panics if called from outside a tokio runtime context,
/// same as `tokio::spawn`.
#[inline]
#[track_caller]
pub fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future<Output: Send + 'static> + Send + 'static,
{
    #[cfg(feature = "dial9")]
    {
        ::dial9::spawn(crate::telemetry::dial9::inherit(future))
    }
    #[cfg(not(feature = "dial9"))]
    {
        tokio::spawn(future)
    }
}
