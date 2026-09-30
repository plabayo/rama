use std::{fmt, hash::Hash, sync::Arc};

use ahash::HashMap;
use parking_lot::Mutex;
use rama_core::futures::future::{BoxFuture, FutureExt as _, WeakShared};

/// Coalesces concurrent operations for the same key into a single one.
///
/// The first caller for a key (the leader) starts the operation, every caller
/// that arrives while it is still running awaits that same operation and gets
/// a clone of its output. Nothing is retained once the operation is done, so
/// the next caller for that key starts a fresh one: this is not a cache.
///
/// The operation is driven by whichever callers are still waiting for it. If
/// the leader is dropped, the remaining callers keep it running; if all of
/// them are dropped, it is cancelled and the key is released.
pub(super) struct SingleFlight<K, V: Clone> {
    state: Arc<Mutex<State<K, V>>>,
}

struct State<K, V: Clone> {
    next_id: u64,
    flights: HashMap<K, (u64, WeakShared<BoxFuture<'static, V>>)>,
}

impl<K, V: Clone> Default for SingleFlight<K, V> {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                next_id: 0,
                flights: HashMap::default(),
            })),
        }
    }
}

impl<K, V: Clone> Clone for SingleFlight<K, V> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<K, V: Clone> fmt::Debug for SingleFlight<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleFlight")
            .field("in_flight", &self.state.lock().flights.len())
            .finish()
    }
}

impl<K, V> SingleFlight<K, V>
where
    K: Hash + Eq + Clone + Send + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Run the operation created by `init` for `key`, or join the one that is
    /// already running for it, in which case `init` is not called.
    pub(super) async fn run<F>(&self, key: K, init: impl FnOnce() -> F) -> V
    where
        F: Future<Output = V> + Send + 'static,
    {
        let flight = {
            let mut state = self.state.lock();
            let running = state
                .flights
                .get(&key)
                .and_then(|(_, flight)| flight.upgrade());
            if let Some(flight) = running {
                flight
            } else {
                state.next_id += 1;
                let id = state.next_id;
                let release = Release {
                    state: self.state.clone(),
                    key: key.clone(),
                    id,
                };
                let operation = init();
                let flight = async move {
                    let output = operation.await;
                    drop(release);
                    output
                }
                .boxed()
                .shared();
                if let Some(weak) = flight.downgrade() {
                    state.flights.insert(key, (id, weak));
                }
                flight
            }
        };
        flight.await
    }
}

/// Releases the key when the operation completes or is cancelled.
struct Release<K: Hash + Eq, V: Clone> {
    state: Arc<Mutex<State<K, V>>>,
    key: K,
    id: u64,
}

impl<K: Hash + Eq, V: Clone> Drop for Release<K, V> {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        // a newer operation may already have replaced ours: leave it alone
        if state
            .flights
            .get(&self.key)
            .is_some_and(|(id, _)| *id == self.id)
        {
            state.flights.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use rama_core::futures::future::join_all;
    use tokio::sync::Notify;

    use super::*;

    fn in_flight<K, V: Clone>(flights: &SingleFlight<K, V>) -> usize {
        flights.state.lock().flights.len()
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_operation() {
        let flights = SingleFlight::<&'static str, usize>::default();
        let started = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());

        let callers = (0..100).map(|_| {
            let started = started.clone();
            let gate = gate.clone();
            flights.run("key", move || async move {
                started.fetch_add(1, Ordering::SeqCst);
                gate.notified().await;
                42
            })
        });
        let release = async {
            // let every caller reach the shared operation first
            tokio::time::sleep(Duration::from_millis(50)).await;
            gate.notify_one();
        };

        let (outputs, ()) = tokio::join!(join_all(callers), release);

        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(outputs, vec![42; 100]);
        assert_eq!(in_flight(&flights), 0, "finished operations are released");
    }

    #[tokio::test]
    async fn different_keys_do_not_share() {
        let flights = SingleFlight::<u8, u8>::default();
        let started = Arc::new(AtomicUsize::new(0));

        let outputs = join_all((0..4u8).map(|key| {
            let started = started.clone();
            flights.run(key, move || async move {
                started.fetch_add(1, Ordering::SeqCst);
                key
            })
        }))
        .await;

        assert_eq!(started.load(Ordering::SeqCst), 4);
        assert_eq!(outputs, [0, 1, 2, 3]);
    }

    #[tokio::test]
    async fn sequential_callers_each_start_an_operation() {
        let flights = SingleFlight::<&'static str, usize>::default();
        let started = Arc::new(AtomicUsize::new(0));

        for expected in 1..=3 {
            let started = started.clone();
            let output = flights
                .run("key", move || async move {
                    started.fetch_add(1, Ordering::SeqCst) + 1
                })
                .await;
            assert_eq!(output, expected);
        }
    }

    #[tokio::test]
    async fn dropped_leader_does_not_strand_followers() {
        let flights = SingleFlight::<&'static str, usize>::default();
        let started = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());

        let operation = |started: Arc<AtomicUsize>, gate: Arc<Notify>| async move {
            started.fetch_add(1, Ordering::SeqCst);
            gate.notified().await;
            7
        };

        let leader = flights.run("key", {
            let (started, gate) = (started.clone(), gate.clone());
            move || operation(started, gate)
        });
        let mut leader = Box::pin(leader);
        // poll the leader once so it starts the operation, then abandon it
        assert!(rama_core::futures::poll!(leader.as_mut()).is_pending());

        let follower = flights.run("key", || async { unreachable_operation() });
        let release = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(leader);
            tokio::time::sleep(Duration::from_millis(20)).await;
            gate.notify_one();
        };

        let (output, ()) = tokio::join!(follower, release);
        assert_eq!(output, 7);
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(in_flight(&flights), 0);
    }

    #[tokio::test]
    async fn cancelling_every_caller_releases_the_key() {
        let flights = SingleFlight::<&'static str, usize>::default();
        let started = Arc::new(AtomicUsize::new(0));

        let abandoned = flights.run("key", {
            let started = started.clone();
            move || async move {
                started.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<usize>().await
            }
        });
        let mut abandoned = Box::pin(abandoned);
        assert!(rama_core::futures::poll!(abandoned.as_mut()).is_pending());
        assert_eq!(in_flight(&flights), 1);
        drop(abandoned);
        assert_eq!(in_flight(&flights), 0);

        let output = flights
            .run("key", {
                let started = started.clone();
                move || async move { started.fetch_add(1, Ordering::SeqCst) + 100 }
            })
            .await;
        assert_eq!(output, 101, "a released key starts a fresh operation");
    }

    fn unreachable_operation() -> usize {
        panic!("a follower must join the running operation instead of starting one")
    }
}
