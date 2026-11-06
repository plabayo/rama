use std::fmt;

use crate::graceful::{Cause, Scope, ScopeClosed, WeakScope};

/// Future executor that utilises `tokio` threads.
///
/// An executor holds nothing itself: every task it spawns holds the executor's [`Scope`] until
/// it ends, so [`Scope::join`] waits for running tasks, never for an executor kept around.
/// Once that scope is closed (cancelled with no holder left) it admits no new task, so its
/// spawn functions can be refused, see [`SpawnRefused`]. Holding a [`Scope`] guarantees
/// admission: spawn through [`Scope::spawn_task`] where one is at hand.
#[derive(Default, Debug, Clone)]
pub struct Executor {
    scope: WeakScope,
}

impl Executor {
    /// Create a new [`Executor`] without a scope: its tasks are never cancelled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scope: WeakScope::never(),
        }
    }

    /// The scope held by every task this executor spawns.
    #[must_use]
    pub fn scope(&self) -> &WeakScope {
        &self.scope
    }

    /// An executor for a new child of this executor's scope.
    ///
    /// # Errors
    ///
    /// [`ScopeClosed`] once this executor's scope is closed.
    pub fn try_child(&self) -> Result<Self, ScopeClosed> {
        let scope = self.scope.to_scope().ok_or(ScopeClosed)?;
        Ok(Self::from(scope.child()))
    }

    /// Spawn a future on the current executor; it holds the executor's scope until it ends.
    ///
    /// # Errors
    ///
    /// [`SpawnRefused`], with the future, once the executor's scope is closed.
    pub fn try_spawn_task<F>(
        &self,
        future: F,
    ) -> Result<tokio::task::JoinHandle<F::Output>, SpawnRefused<F>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        match self.scope.to_scope() {
            Some(scope) => Ok(scope.into_spawn_task(future)),
            None => Err(self.refused(future)),
        }
    }

    /// Spawn the future `make` returns for an executor of its own, see
    /// [`Executor::try_spawn_task`].
    ///
    /// # Errors
    ///
    /// [`SpawnRefused`], with `make`, once the executor's scope is closed.
    pub fn try_spawn_task_fn<M, F>(
        &self,
        make: M,
    ) -> Result<tokio::task::JoinHandle<F::Output>, SpawnRefused<M>>
    where
        M: FnOnce(Self) -> F,
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        match self.scope.to_scope() {
            Some(scope) => Ok(scope.into_spawn_task(make(self.clone()))),
            None => Err(self.refused(make)),
        }
    }

    /// Spawn a future on the current executor that is dropped once the executor's scope is
    /// cancelled, see [`Scope::spawn_cancellable_task`].
    ///
    /// # Errors
    ///
    /// [`SpawnRefused`], with the future, once the executor's scope is closed.
    pub fn try_spawn_cancellable_task<F>(
        &self,
        future: F,
    ) -> Result<tokio::task::JoinHandle<Option<F::Output>>, SpawnRefused<F>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        match self.scope.to_scope() {
            Some(scope) => Ok(scope.spawn_cancellable_task(future)),
            None => Err(self.refused(future)),
        }
    }

    /// Spawn a future on the current executor that runs through the graceful phase of the
    /// executor's scope and is dropped once that scope is aborted, see
    /// [`Scope::spawn_abortable_task`].
    ///
    /// # Errors
    ///
    /// [`SpawnRefused`], with the future, once the executor's scope is closed.
    pub fn try_spawn_abortable_task<F>(
        &self,
        future: F,
    ) -> Result<tokio::task::JoinHandle<Option<F::Output>>, SpawnRefused<F>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        match self.scope.to_scope() {
            Some(scope) => Ok(scope.spawn_abortable_task(future)),
            None => Err(self.refused(future)),
        }
    }

    /// Completes once the executor's scope is cancelled.
    ///
    /// The future does not hold the scope, so waiting on it never keeps a drain open.
    pub fn cancelled(&self) -> impl Future<Output = ()> + Send + 'static {
        self.scope.cancelled()
    }

    /// Completes once the executor's scope is aborted: the moment work that cannot drain,
    /// such as a byte relay, has to stop.
    ///
    /// The future does not hold the scope, so waiting on it never keeps a drain open.
    pub fn aborted(&self) -> impl Future<Output = ()> + Send + 'static {
        self.scope.aborted()
    }

    fn refused<T>(&self, task: T) -> SpawnRefused<T> {
        SpawnRefused {
            task,
            cause: self.scope.cause(),
        }
    }
}

impl From<Scope> for Executor {
    /// An executor whose tasks hold `scope`.
    fn from(scope: Scope) -> Self {
        Self {
            scope: scope.into_weak_scope(),
        }
    }
}

impl From<WeakScope> for Executor {
    /// An executor whose tasks hold `scope`.
    fn from(scope: WeakScope) -> Self {
        Self { scope }
    }
}

impl From<Executor> for WeakScope {
    /// The scope the tasks of `executor` hold.
    fn from(executor: Executor) -> Self {
        executor.scope
    }
}

/// The scope of an [`Executor`] is closed: cancelled with no holder left, so it admits no
/// new task. Carries the task that was refused.
///
/// It is an [`Error`](std::error::Error) only once the task is gone, see
/// [`SpawnRefused::discard_task`]: an error that is kept around never keeps a task, and what
/// it holds, alive.
pub struct SpawnRefused<T> {
    task: T,
    cause: Option<Cause>,
}

impl<T> SpawnRefused<T> {
    /// Why the scope was cancelled.
    #[must_use]
    pub fn cause(&self) -> Option<&Cause> {
        self.cause.as_ref()
    }

    /// The task that was refused.
    pub fn into_task(self) -> T {
        self.task
    }

    /// Drop the task now, keeping the error: what it holds, such as IO, is released at once.
    #[must_use]
    pub fn discard_task(self) -> SpawnRefused<()> {
        SpawnRefused {
            task: (),
            cause: self.cause,
        }
    }
}

impl<T> fmt::Debug for SpawnRefused<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnRefused")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

impl<T> fmt::Display for SpawnRefused<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            Some(cause) => write!(f, "spawn refused: executor scope closed ({cause})"),
            None => f.write_str("spawn refused: executor scope closed"),
        }
    }
}

impl std::error::Error for SpawnRefused<()> {}

impl Scope {
    /// Spawn a future that holds this scope until it ends. Never refused: this handle holds
    /// the scope, so it cannot be closed.
    pub fn spawn_task<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        self.clone().into_spawn_task(future)
    }

    /// Spawn a future that holds this scope until it ends, as [`Scope::spawn_task`], giving
    /// up this handle's hold to the task.
    pub fn into_spawn_task<F>(self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        spawn(async move {
            let output = future.await;
            drop(self);
            output
        })
    }

    /// Spawn a future that holds this scope and is dropped once the scope is cancelled.
    ///
    /// # Note
    ///
    /// Ensure that your future is cancellable!
    pub fn spawn_cancellable_task<F>(&self, future: F) -> tokio::task::JoinHandle<Option<F::Output>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        let scope = self.clone();
        spawn(async move {
            let output = scope.run_until_cancelled(future).await;
            drop(scope);
            output
        })
    }

    /// Spawn a future that holds this scope, runs through its graceful phase and is dropped
    /// once the scope is aborted.
    pub fn spawn_abortable_task<F>(&self, future: F) -> tokio::task::JoinHandle<Option<F::Output>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        let scope = self.clone();
        spawn(async move {
            let output = scope.run_until_aborted(future).await;
            drop(scope);
            output
        })
    }
}

/// Spawn a future on the current tokio runtime.
///
/// Drop-in replacement for `tokio::spawn` for tasks that intentionally
/// live outside graceful shutdown (background workers, detached drivers).
/// Prefer [`Scope::spawn_task`] or [`Executor::try_spawn_task`] for work
/// that should be awaited on shutdown.
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
    use std::{cell::Cell, time::Duration};

    use rama_error::BoxError;

    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    #[tokio::test(start_paused = true)]
    async fn join_waits_for_spawned_tasks_not_for_the_executor() {
        let root = Scope::new();
        let exec = Executor::from(root.clone());
        let task = exec
            .try_spawn_task(async {
                tokio::time::sleep(2 * SEC).await;
                7
            })
            .unwrap();
        let start = tokio::time::Instant::now();
        assert_eq!(root.join().await.unwrap().elapsed(), 2 * SEC);
        assert_eq!(start.elapsed(), 2 * SEC);
        assert_eq!(task.await.unwrap(), 7);
        drop(exec);
    }

    #[tokio::test]
    async fn an_idle_executor_does_not_hold_the_join() {
        let root = Scope::new();
        let exec = Executor::from(root.clone());
        let child = exec.try_child().unwrap();
        root.cancel(Cause::Owner);
        let joined = tokio::time::timeout(SEC, root.join()).await;
        joined.expect("nothing holds the scope").unwrap();
        drop((exec, child));
    }

    #[tokio::test]
    async fn a_closed_scope_refuses_and_returns_the_task() {
        let root = Scope::new();
        let exec = Executor::from(root.clone());
        root.cancel(Cause::Reason("closing"));
        root.join().await.unwrap();

        let refused = exec.try_spawn_task(async { 3 }).unwrap_err();
        assert!(matches!(refused.cause(), Some(Cause::Reason("closing"))));
        assert_eq!(refused.into_task().await, 3);
        exec.try_spawn_cancellable_task(async {}).unwrap_err();
        exec.try_spawn_abortable_task(async {}).unwrap_err();
        let made = Cell::new(false);
        let refused = exec.try_spawn_task_fn(|_| {
            made.set(true);
            async {}
        });
        refused.unwrap_err();
        assert!(!made.get());
        exec.try_child().unwrap_err();
    }

    #[tokio::test]
    async fn a_draining_scope_admits_tasks_and_waits_for_them() {
        let root = Scope::new();
        let exec = Executor::from(root.clone());
        let (release_tx, release) = tokio::sync::oneshot::channel::<()>();
        let holder = exec.try_spawn_task(release).unwrap();
        root.cancel(Cause::Owner);

        let (late_tx, late) = tokio::sync::oneshot::channel::<()>();
        let late_task = exec.try_spawn_task(late).unwrap();
        release_tx.send(()).unwrap();
        holder.await.unwrap().unwrap();

        let mut join = Box::pin(root.join());
        assert!(
            tokio::time::timeout(SEC / 10, join.as_mut()).await.is_err(),
            "the task admitted during the drain holds it"
        );
        late_tx.send(()).unwrap();
        late_task.await.unwrap().unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn a_held_scope_spawns_without_refusal() {
        let root = Scope::new();
        root.cancel(Cause::Owner);
        let task = root.spawn_task(async { 5 });
        assert_eq!(task.await.unwrap(), 5);
        let exec = Executor::from(root.clone());
        let task = exec.try_spawn_task_fn(move |exec| async move { exec.scope().is_cancelled() });
        assert!(task.unwrap().await.unwrap());
        root.join().await.unwrap();
    }

    #[tokio::test]
    async fn a_refusal_converts_into_a_box_error_without_its_task() {
        fn spawn_not_sync(exec: &Executor) -> Result<(), BoxError> {
            let not_sync = Cell::new(1);
            exec.try_spawn_task(async move { not_sync.get() })
                .map_err(SpawnRefused::discard_task)?;
            Ok(())
        }
        let root = Scope::new();
        let exec = Executor::from(root.clone());
        root.cancel(Cause::Owner);
        root.join().await.unwrap();
        let err = spawn_not_sync(&exec).unwrap_err();
        assert!(err.to_string().contains("spawn refused"));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellable_task_stops_at_the_graceful_phase() {
        let root = Scope::new().with_grace(10 * SEC);
        let cancellable = root.spawn_cancellable_task(std::future::pending::<()>());
        let abortable = root.spawn_abortable_task(async {
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
        let abortable = exec
            .try_spawn_abortable_task(std::future::pending::<()>())
            .unwrap();
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
        let child = exec.try_child().unwrap();
        child.scope().cancel(Cause::Owner);
        assert!(!exec.scope().is_cancelled());
        let other = exec.try_child().unwrap();
        root.cancel(Cause::Owner);
        assert!(other.scope().is_cancelled());
    }

    #[tokio::test]
    async fn executor_without_scope_never_cancels() {
        let exec = Executor::new();
        assert!(exec.scope().is_never());
        let task = exec.try_spawn_cancellable_task(async { 1 }).unwrap();
        assert_eq!(task.await.unwrap(), Some(1));
        // As for scopes, the child of a scopeless executor is a new root.
        assert!(!exec.try_child().unwrap().scope().is_never());
    }
}
