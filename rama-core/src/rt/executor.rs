use crate::graceful::Scope;

/// Future executor that utilises `tokio` threads.
///
/// Spawned tasks hold the executor's [`Scope`], so its [`Scope::join`] waits for them.
#[derive(Default, Debug, Clone)]
pub struct Executor {
    scope: Scope,
}

impl Executor {
    /// Create a new [`Executor`] without a scope: its tasks are never cancelled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scope: Scope::never(),
        }
    }

    /// The scope held by every task this executor spawns.
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// An executor for a child of this executor's scope.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            scope: self.scope.child(),
        }
    }

    /// Spawn a future on the current executor; it holds the executor's scope until it ends.
    pub fn spawn_task<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        self.clone().into_spawn_task(future)
    }

    /// Spawn a future on the current executor that is dropped once the executor's scope is
    /// cancelled.
    ///
    /// # Note
    ///
    /// Ensure that your future is cancellable!
    pub fn spawn_cancellable_task<F>(&self, future: F) -> tokio::task::JoinHandle<Option<F::Output>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        let scope = self.scope.clone();
        spawn(async move {
            let output = scope.run_until_cancelled(future).await;
            drop(scope);
            output
        })
    }

    /// Spawn a future on the current executor that runs through the graceful phase of the
    /// executor's scope and is dropped once that scope is aborted.
    pub fn spawn_abortable_task<F>(&self, future: F) -> tokio::task::JoinHandle<Option<F::Output>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        let scope = self.scope.clone();
        spawn(async move {
            let output = scope.run_until_aborted(future).await;
            drop(scope);
            output
        })
    }

    /// Spawn a future on the current executor, as [`Self::spawn_task`].
    pub fn into_spawn_task<F>(self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        let Self { scope } = self;
        spawn(async move {
            let output = future.await;
            drop(scope);
            output
        })
    }

    /// Completes once the executor's scope is cancelled.
    ///
    /// The future does not hold the scope, so waiting on it never keeps a drain open.
    pub fn cancelled(&self) -> impl Future<Output = ()> + Send + 'static {
        self.scope.clone_weak().cancelled()
    }

    /// Completes once the executor's scope is aborted: the moment work that cannot drain,
    /// such as a byte relay, has to stop.
    ///
    /// The future does not hold the scope, so waiting on it never keeps a drain open.
    pub fn aborted(&self) -> impl Future<Output = ()> + Send + 'static {
        self.scope.clone_weak().aborted()
    }
}

impl From<Scope> for Executor {
    /// An executor whose tasks hold `scope`.
    fn from(scope: Scope) -> Self {
        Self { scope }
    }
}

/// Spawn a future on the current tokio runtime.
///
/// Drop-in replacement for `tokio::spawn` for tasks that intentionally
/// live outside graceful shutdown (background workers, detached drivers).
/// Prefer [`Executor::spawn_task`] for work that should be awaited on
/// shutdown.
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::graceful::Cause;

    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    #[tokio::test(start_paused = true)]
    async fn join_waits_for_spawned_tasks() {
        let root = Scope::new();
        let exec = Executor::from(root.clone());
        let task = exec.spawn_task(async {
            tokio::time::sleep(2 * SEC).await;
            7
        });
        drop(exec);
        let start = tokio::time::Instant::now();
        assert_eq!(root.join().await.unwrap().elapsed(), 2 * SEC);
        assert_eq!(start.elapsed(), 2 * SEC);
        assert_eq!(task.await.unwrap(), 7);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellable_task_stops_at_the_graceful_phase() {
        let root = Scope::new().with_grace(10 * SEC);
        let exec = Executor::from(root.clone());
        let cancellable = exec.spawn_cancellable_task(std::future::pending::<()>());
        let abortable = exec.spawn_abortable_task(async {
            tokio::time::sleep(3 * SEC).await;
            "done"
        });
        root.cancel(Cause::Owner);
        assert!(cancellable.await.unwrap().is_none());
        assert_eq!(abortable.await.unwrap(), Some("done"));
    }

    #[tokio::test]
    async fn abortable_task_stops_at_the_hard_phase() {
        let root = Scope::new();
        let exec = Executor::from(root.clone());
        let abortable = exec.spawn_abortable_task(std::future::pending::<()>());
        root.cancel(Cause::Owner);
        tokio::task::yield_now().await;
        assert!(!abortable.is_finished());
        root.abort(Cause::Owner);
        assert!(abortable.await.unwrap().is_none());
    }

    #[tokio::test]
    async fn child_executor_follows_its_parent_only() {
        let root = Scope::new();
        let exec = Executor::from(root.clone());
        let child = exec.child();
        child.scope().cancel(Cause::Owner);
        assert!(!exec.scope().is_cancelled());
        let other = exec.child();
        root.cancel(Cause::Owner);
        assert!(other.scope().is_cancelled());
    }

    #[tokio::test]
    async fn executor_without_scope_never_cancels() {
        let exec = Executor::new();
        assert!(exec.scope().is_never());
        let task = exec.spawn_cancellable_task(async { 1 });
        assert_eq!(task.await.unwrap(), Some(1));
        // As for scopes, the child of a scopeless executor is a new root.
        assert!(!exec.child().scope().is_never());
    }
}
