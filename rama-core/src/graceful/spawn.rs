//! Spawning work that holds a scope.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use tokio::task::JoinHandle;

use super::Scope;
use crate::rt::spawn;

pin_project! {
    /// A task's future and the hold it runs under. Fields drop in order, so the future and its
    /// destructor finish inside the scope on every path, a task aborted before its first poll
    /// included.
    struct Held<F> {
        #[pin]
        future: F,
        scope: Scope,
    }
}

impl<F: Future> Future for Held<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().future.poll(cx)
    }
}

impl Scope {
    /// Spawn a future that holds this scope until it ends: it runs through the graceful phase,
    /// so it can drain, and is dropped at the hard phase.
    ///
    /// Never refused: this handle holds the scope, so it cannot be closed. Take a hold from a
    /// [`WeakScope`](super::WeakScope) with [`WeakScope::try_hold`](super::WeakScope::try_hold).
    pub fn spawn_task<F>(&self, future: F) -> JoinHandle<Option<F::Output>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        self.clone().into_spawn_task(future)
    }

    /// As [`Scope::spawn_task`], giving this handle's hold to the task.
    pub fn into_spawn_task<F>(self, future: F) -> JoinHandle<Option<F::Output>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        let future = self.run_until_aborted(future);
        spawn(Held {
            future,
            scope: self,
        })
    }

    /// Spawn a future that holds this scope and is dropped once the scope is cancelled: work
    /// with nothing to drain.
    pub fn spawn_cancellable_task<F>(&self, future: F) -> JoinHandle<Option<F::Output>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        self.clone().into_spawn_cancellable_task(future)
    }

    /// As [`Scope::spawn_cancellable_task`], giving this handle's hold to the task.
    pub fn into_spawn_cancellable_task<F>(self, future: F) -> JoinHandle<Option<F::Output>>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        let future = self.run_until_cancelled(future);
        spawn(Held {
            future,
            scope: self,
        })
    }

    /// Spawn a future that holds this scope and is never stopped by it, not at the hard phase
    /// either: it ends on its own, typically by observing [`Scope::aborted`].
    ///
    /// For work that has to act at the hard phase itself, such as closing a connection or
    /// flushing output. A [`Scope::join`] that returns at the hard phase does not wait for it;
    /// await its handle when its end matters.
    pub fn spawn_task_to_completion<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        self.clone().into_spawn_task_to_completion(future)
    }

    /// As [`Scope::spawn_task_to_completion`], giving this handle's hold to the task.
    pub fn into_spawn_task_to_completion<F>(self, future: F) -> JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        spawn(Held {
            future,
            scope: self,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::{Cause, WeakScope};
    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
    }

    #[test]
    fn join_waits_for_spawned_tasks() {
        rt().block_on(async {
            let root = Scope::new();
            let task = root.spawn_task(async {
                tokio::time::sleep(2 * SEC).await;
                7
            });
            let start = tokio::time::Instant::now();
            assert_eq!(root.join().await.unwrap().elapsed(), 2 * SEC);
            assert_eq!(start.elapsed(), 2 * SEC);
            assert_eq!(task.await.unwrap(), Some(7));
        });
    }

    #[test]
    fn a_weak_scope_kept_around_does_not_hold_the_join() {
        rt().block_on(async {
            let root = Scope::new();
            let weak = root.clone_weak();
            root.cancel(Cause::Owner);
            let joined = tokio::time::timeout(SEC, root.join()).await;
            joined.expect("nothing holds the scope").unwrap();
            drop(weak);
        });
    }

    #[test]
    fn a_closed_scope_refuses_a_hold() {
        rt().block_on(async {
            let root = Scope::new();
            let weak = root.clone_weak();
            root.cancel(Cause::Reason("closing"));
            root.join().await.unwrap();
            weak.try_hold().unwrap_err();
            assert!(matches!(weak.cause(), Some(Cause::Reason("closing"))));
        });
    }

    #[test]
    fn a_draining_scope_admits_a_hold_and_waits_for_its_task() {
        rt().block_on(async {
            let root = Scope::new();
            let weak = root.clone_weak();
            let (release_tx, release) = tokio::sync::oneshot::channel::<()>();
            let holder = root.spawn_task(release);
            root.cancel(Cause::Owner);

            let (late_tx, late) = tokio::sync::oneshot::channel::<()>();
            let late_task = weak.try_hold().unwrap().into_spawn_task(late);
            release_tx.send(()).unwrap();
            holder.await.unwrap().unwrap().unwrap();

            let mut join = Box::pin(root.join());
            assert!(
                tokio::time::timeout(SEC / 10, join.as_mut()).await.is_err(),
                "the task admitted during the drain holds it"
            );
            late_tx.send(()).unwrap();
            late_task.await.unwrap().unwrap().unwrap();
            join.await.unwrap();
        });
    }

    #[test]
    fn a_cancellable_task_stops_at_the_graceful_phase() {
        rt().block_on(async {
            let root = Scope::new().with_grace(10 * SEC);
            let cancellable = root.spawn_cancellable_task(std::future::pending::<()>());
            let draining = root.spawn_task(async {
                tokio::time::sleep(3 * SEC).await;
                "done"
            });
            root.cancel(Cause::Owner);
            assert!(cancellable.await.unwrap().is_none());
            assert_eq!(draining.await.unwrap(), Some("done"));
        });
    }

    #[test]
    fn a_task_stops_at_the_hard_phase() {
        rt().block_on(async {
            let root = Scope::new();
            let task = root.spawn_task(std::future::pending::<()>());
            root.cancel(Cause::Owner);
            tokio::task::yield_now().await;
            assert!(!task.is_finished());
            root.abort(Cause::Owner);
            assert!(task.await.unwrap().is_none());
        });
    }

    #[test]
    fn a_task_to_completion_outlives_the_hard_phase() {
        rt().block_on(async {
            let root = Scope::new();
            let (done_tx, done) = tokio::sync::oneshot::channel::<()>();
            let task = root.spawn_task_to_completion(async move {
                done.await.unwrap();
                3
            });
            root.abort(Cause::Owner);
            tokio::task::yield_now().await;
            assert!(!task.is_finished(), "the hard phase does not stop it");
            done_tx.send(()).unwrap();
            assert_eq!(task.await.unwrap(), 3);
            let weak = root.into_weak_scope();
            tokio::time::timeout(SEC, weak.drained())
                .await
                .expect("its hold ended with it");
        });
    }

    /// Records, when dropped, whether its scope was still held at that moment.
    struct DropProbe {
        weak: WeakScope,
        held_at_drop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Future for DropProbe {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            // A cancelled scope admits a new hold only while another one is still alive.
            self.held_at_drop.store(
                self.weak.try_hold().is_ok(),
                std::sync::atomic::Ordering::SeqCst,
            );
        }
    }

    #[test]
    fn a_task_aborted_before_its_first_poll_drops_its_future_inside_the_scope() {
        rt().block_on(async {
            for variant in 0..3 {
                let root = Scope::new();
                let held_at_drop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let probe = DropProbe {
                    weak: root.clone_weak(),
                    held_at_drop: held_at_drop.clone(),
                };
                let task = root.clone();
                let handle = match variant {
                    0 => task.into_spawn_task(probe).abort_handle(),
                    1 => task.into_spawn_cancellable_task(probe).abort_handle(),
                    _ => task.into_spawn_task_to_completion(probe).abort_handle(),
                };
                root.cancel(Cause::Owner);
                let weak = root.into_weak_scope();
                // Aborted before the runtime polled it once.
                handle.abort();
                tokio::time::timeout(SEC, weak.drained())
                    .await
                    .expect("the aborted task lets go of the scope");
                assert!(
                    held_at_drop.load(std::sync::atomic::Ordering::SeqCst),
                    "variant {variant}: the future dropped after its hold"
                );
            }
        });
    }

    #[test]
    fn a_never_scope_spawns_without_holding() {
        rt().block_on(async {
            let weak = WeakScope::never();
            let task = weak
                .try_hold()
                .unwrap()
                .into_spawn_cancellable_task(async { 1 });
            assert_eq!(task.await.unwrap(), Some(1));
        });
    }
}
