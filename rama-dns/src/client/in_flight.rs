use std::{
    any::{Any, TypeId},
    fmt,
    hash::Hash,
    sync::Arc,
    time::Duration,
};

use ahash::HashMap;
use parking_lot::Mutex;
use rama_core::{
    error::{ArcError, BoxError},
    futures::{
        FutureExt as _, Stream, StreamExt as _,
        async_stream::stream_fn,
        future::{BoxFuture, Shared},
        stream,
    },
    rt,
    telemetry::tracing::{self, Instrument as _},
};
use tokio::sync::oneshot;

/// `None`: the run ended without an answer (its runtime shut down, or it panicked).
type Flight<V> = Shared<BoxFuture<'static, Option<Result<Arc<V>, ArcError>>>>;
type Flights<K> = Arc<Mutex<HashMap<(K, TypeId), Box<dyn Any + Send + Sync>>>>;
type Reply<V> = oneshot::Sender<Result<Arc<V>, ArcError>>;

/// Concurrent lookups for the same key share one run of the lookup.
///
/// The run is its own task, so it completes (and can fill a cache) even when
/// every caller stops waiting. Nothing is kept once it is done.
pub(crate) struct InFlight<K> {
    flights: Flights<K>,
}

impl<K> Default for InFlight<K> {
    fn default() -> Self {
        Self {
            flights: Arc::default(),
        }
    }
}

impl<K> Clone for InFlight<K> {
    fn clone(&self) -> Self {
        Self {
            flights: self.flights.clone(),
        }
    }
}

impl<K> fmt::Debug for InFlight<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InFlight")
            .field("running", &self.flights.lock().len())
            .finish()
    }
}

#[cfg(test)]
impl<K> InFlight<K> {
    /// Keys with a run in progress.
    pub(crate) fn running(&self) -> usize {
        self.flights.lock().len()
    }
}

enum Joined<V> {
    Running(Flight<V>),
    Started(Flight<V>, Reply<V>),
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> InFlight<K> {
    /// Join the run for `key`, or start one with `lookup`.
    ///
    /// `max_duration` is the longest the lookup may legitimately take: a
    /// caller waits at most a quarter longer, and a run is abandoned after
    /// three times it, a safety net for a backend ignoring its own deadline.
    pub(crate) async fn run<V, F>(
        &self,
        key: K,
        max_duration: Duration,
        lookup: impl FnOnce() -> F,
    ) -> Result<Arc<V>, ArcError>
    where
        V: Send + Sync + 'static,
        F: Future<Output = V> + Send + 'static,
    {
        let slot = (key, TypeId::of::<V>());
        let wait = max_duration.saturating_add(max_duration / 4);
        let shared = async {
            let flight = match self.join(&slot) {
                Joined::Running(flight) => match flight.await {
                    Some(answer) => return answer,
                    // it died with another runtime: take over, once
                    None => match self.join(&slot) {
                        Joined::Running(flight) => flight,
                        Joined::Started(flight, reply) => {
                            self.start(slot, max_duration, reply, lookup);
                            flight
                        }
                    },
                },
                Joined::Started(flight, reply) => {
                    self.start(slot, max_duration, reply, lookup);
                    flight
                }
            };
            flight.await.unwrap_or_else(|| {
                Err(ArcError::from_static_str(
                    "dns lookup ended without an answer",
                ))
            })
        };
        tokio::time::timeout(wait, shared)
            .await
            .unwrap_or_else(|_elapsed| {
                Err(ArcError::from_static_str("dns lookup timed out")
                    .context_debug_field("timeout", wait))
            })
    }

    fn join<V: Send + Sync + 'static>(&self, slot: &(K, TypeId)) -> Joined<V> {
        let mut flights = self.flights.lock();
        if let Some(flight) = flights
            .get(slot)
            .and_then(|flight| flight.downcast_ref::<Flight<V>>())
        {
            return Joined::Running(flight.clone());
        }
        let (reply, answer) = oneshot::channel();
        let flight: Flight<V> = answer.map(Result::ok).boxed().shared();
        flights.insert(slot.clone(), Box::new(flight.clone()));
        Joined::Started(flight, reply)
    }

    fn start<V, F>(
        &self,
        slot: (K, TypeId),
        max_duration: Duration,
        reply: Reply<V>,
        lookup: impl FnOnce() -> F,
    ) where
        V: Send + Sync + 'static,
        F: Future<Output = V> + Send + 'static,
    {
        // outside the map lock: dropping it (a panic, a closed runtime) re-locks
        let release = Release {
            flights: self.flights.clone(),
            slot,
            reply: Some(reply),
        };
        let lookup = lookup();
        let span = tracing::debug_span!("dns lookup");
        span.follows_from(tracing::Span::current());
        rt::spawn(
            async move {
                let answer = tokio::time::timeout(max_duration.saturating_mul(3), lookup)
                    .await
                    .map(Arc::new)
                    .map_err(|_elapsed| {
                        ArcError::from_static_str(
                            "dns lookup abandoned: backend ignored its deadline",
                        )
                    });
                release.finish(answer);
            }
            .instrument(span),
        );
    }
}

/// Frees the key when its run ends, however it ends, before its callers
/// learn the outcome.
struct Release<K: Hash + Eq, V> {
    flights: Flights<K>,
    slot: (K, TypeId),
    reply: Option<Reply<V>>,
}

impl<K: Hash + Eq, V> Release<K, V> {
    fn finish(mut self, answer: Result<Arc<V>, ArcError>) {
        let reply = self.reply.take();
        drop(self);
        if let Some(reply) = reply {
            _ = reply.send(answer);
        }
    }
}

impl<K: Hash + Eq, V> Drop for Release<K, V> {
    fn drop(&mut self) {
        self.flights.lock().remove(&self.slot);
    }
}

/// What a shared lookup produced: its records, then the error that ended it.
pub(crate) struct Outcome<T> {
    records: Vec<T>,
    error: Option<ArcError>,
}

impl<T> Outcome<T> {
    pub(crate) fn new(records: Vec<T>, error: Option<BoxError>) -> Self {
        Self {
            records,
            error: error.map(ArcError::from_box_error),
        }
    }

    /// Drain `stream` up to and including its first error.
    pub(crate) async fn collect<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<T, BoxError>>,
    {
        let mut stream = std::pin::pin!(stream);
        let mut records = Vec::new();
        while let Some(item) = stream.next().await {
            match item {
                Ok(record) => records.push(record),
                Err(err) => return Self::new(records, Some(err)),
            }
        }
        Self::new(records, None)
    }
}

/// Replay a shared outcome to one caller.
pub(crate) fn outcome_stream<T>(
    outcome: Result<Arc<Outcome<T>>, ArcError>,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: Clone + Send + Sync + 'static,
{
    stream_fn(async move |mut yielder| match outcome {
        Ok(outcome) => {
            for record in &outcome.records {
                yielder.yield_item(Ok(record.clone())).await;
            }
            if let Some(err) = &outcome.error {
                yielder.yield_item(Err(err.clone().into())).await;
            }
        }
        Err(err) => yielder.yield_item(Err(err.into())).await,
    })
}

/// Run a streaming `lookup` once for all concurrent callers of `key`.
pub(crate) fn coalesced_stream<K, T, S>(
    in_flight: InFlight<K>,
    key: K,
    timeout: Duration,
    lookup: impl FnOnce() -> S + Send + 'static,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
    S: Stream<Item = Result<T, BoxError>> + Send + 'static,
{
    stream::once(async move {
        in_flight
            .run(key, timeout, move || Outcome::collect(lookup()))
            .await
    })
    .flat_map(outcome_stream)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rama_core::{error::BoxErrorExt as _, futures::future::join_all};
    use tokio::sync::Notify;

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// A lookup that counts its starts and resolves once `gate` opens.
    fn gated(
        starts: &Arc<AtomicUsize>,
        gate: &Arc<Notify>,
        value: usize,
    ) -> impl Future<Output = usize> + Send + 'static {
        starts.fetch_add(1, Ordering::SeqCst);
        let gate = gate.clone();
        async move {
            gate.notified().await;
            value
        }
    }

    async fn open(gate: &Notify) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        gate.notify_waiters();
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_run() {
        let in_flight = InFlight::default();
        let starts = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());

        let callers = join_all(
            (0..1000).map(|_| in_flight.run("key", TIMEOUT, || gated(&starts, &gate, 42))),
        );
        let (results, ()) = tokio::join!(callers, open(&gate));

        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert!(
            results
                .iter()
                .all(|value| matches!(value, Ok(v) if **v == 42))
        );
        assert_eq!(in_flight.running(), 0, "a finished run frees its key");
    }

    #[tokio::test]
    async fn keys_and_value_types_do_not_share() {
        let in_flight = InFlight::default();
        let starts = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());

        let callers = async {
            tokio::join!(
                in_flight.run("a", TIMEOUT, || gated(&starts, &gate, 1)),
                in_flight.run("b", TIMEOUT, || gated(&starts, &gate, 2)),
                in_flight.run("a", TIMEOUT, || {
                    starts.fetch_add(1, Ordering::SeqCst);
                    async { "other type" }
                }),
            )
        };
        let ((a, b, typed), ()) = tokio::join!(callers, open(&gate));

        assert_eq!(starts.load(Ordering::SeqCst), 3);
        assert_eq!(*a.unwrap(), 1);
        assert_eq!(*b.unwrap(), 2);
        assert_eq!(*typed.unwrap(), "other type");
    }

    #[tokio::test]
    async fn run_completes_after_every_caller_left() {
        let in_flight = InFlight::default();
        let starts = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());

        let abandoned = in_flight.run("key", TIMEOUT, || gated(&starts, &gate, 7));
        tokio::time::timeout(Duration::from_millis(20), abandoned)
            .await
            .expect_err("the caller gives up before the run ends");
        assert_eq!(in_flight.running(), 1, "an abandoned run keeps its key");

        let joined = in_flight.run("key", TIMEOUT, || gated(&starts, &gate, 0));
        let (value, ()) = tokio::join!(joined, open(&gate));

        assert_eq!(*value.unwrap(), 7, "a late caller gets the abandoned run");
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(in_flight.running(), 0);
    }

    #[tokio::test]
    async fn a_new_run_starts_after_the_previous_one() {
        let in_flight = InFlight::default();
        let starts = Arc::new(AtomicUsize::new(0));

        for value in 0..3 {
            let got = in_flight
                .run("key", TIMEOUT, || {
                    starts.fetch_add(1, Ordering::SeqCst);
                    async move { value }
                })
                .await;
            assert_eq!(*got.unwrap(), value);
        }
        assert_eq!(starts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn panicking_run_fails_its_callers_and_frees_the_key() {
        let in_flight = InFlight::<&str>::default();

        let result = in_flight
            .run("key", TIMEOUT, || async { panic!("backend bug") })
            .await;

        result.expect_err("a panicking run fails its callers");
        assert_eq!(in_flight.running(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn stuck_run_is_abandoned_after_its_bound() {
        let in_flight = InFlight::<&str>::default();

        let result = in_flight
            .run("key", Duration::from_secs(1), std::future::pending::<usize>)
            .await;
        result.expect_err("the caller gives up on a stuck run");
        assert_eq!(
            in_flight.running(),
            1,
            "the run itself lingers a bit longer"
        );

        tokio::time::sleep(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        assert_eq!(in_flight.running(), 0, "a stuck run is abandoned");
    }

    #[tokio::test(start_paused = true)]
    async fn joiner_waits_no_longer_than_its_own_bound() {
        let in_flight = InFlight::<&str>::default();
        let starts = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());

        let patient = in_flight.run("key", Duration::from_secs(5), || gated(&starts, &gate, 1));
        let hasty = async {
            tokio::task::yield_now().await;
            let started = tokio::time::Instant::now();
            let result = in_flight
                .run("key", Duration::from_millis(100), || {
                    gated(&starts, &gate, 2)
                })
                .await;
            (result, started.elapsed())
        };
        let release = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            gate.notify_waiters();
        };
        let (patient, (hasty, waited), ()) = tokio::join!(patient, hasty, release);

        assert_eq!(*patient.unwrap(), 1);
        hasty.expect_err("the hasty caller times out on its own");
        assert!(waited <= Duration::from_millis(125), "waited {waited:?}");
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn panicking_lookup_constructor_frees_the_key() {
        let in_flight = InFlight::<&str>::default();

        let result = std::panic::AssertUnwindSafe(in_flight.run(
            "key",
            TIMEOUT,
            || -> std::future::Ready<usize> { panic!("constructor bug") },
        ))
        .catch_unwind()
        .await;
        result.expect_err("the caller's own panic propagates");
        assert_eq!(in_flight.running(), 0);

        let value = in_flight
            .run("key", TIMEOUT, || std::future::ready(3_usize))
            .await;
        assert_eq!(*value.unwrap(), 3);
    }

    #[test]
    fn closed_runtime_does_not_deadlock() {
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let handle = runtime.handle().clone();
            drop(runtime);

            let in_flight = InFlight::<&str>::default();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle.block_on(in_flight.run("key", TIMEOUT, || std::future::ready(1_usize)))
            }));
            done.send((result.is_ok(), in_flight.running())).unwrap();
        });

        let (_returned, left) = finished
            .recv_timeout(Duration::from_secs(10))
            .expect("run must not deadlock on a closed runtime");
        assert_eq!(left, 0, "a run that never started frees its key");
    }

    #[tokio::test]
    async fn joiner_takes_over_a_run_that_died_with_its_runtime() {
        let in_flight = InFlight::<&str>::default();
        let other = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        let starter = in_flight.clone();
        other.spawn(async move {
            starter
                .run("key", TIMEOUT, std::future::pending::<usize>)
                .await
        });
        while in_flight.running() == 0 {
            tokio::task::yield_now().await;
        }

        let mut joiner =
            std::pin::pin!(in_flight.run("key", TIMEOUT, || std::future::ready(9_usize)));
        assert!(
            joiner.as_mut().now_or_never().is_none(),
            "joined, still pending"
        );
        other.shutdown_background();

        assert_eq!(
            *joiner.await.unwrap(),
            9,
            "the joiner took over with its own lookup"
        );
        assert_eq!(in_flight.running(), 0);
    }

    #[tokio::test]
    async fn coalesced_stream_replays_records_then_error() {
        let in_flight = InFlight::default();
        let starts = Arc::new(AtomicUsize::new(0));

        let lookup = || {
            let starts = starts.clone();
            move || {
                starts.fetch_add(1, Ordering::SeqCst);
                stream::iter([Ok(1), Ok(2), Err(BoxError::from_static_str("boom")), Ok(3)])
            }
        };
        let callers = (0..10).map(|_| {
            coalesced_stream(in_flight.clone(), "key", TIMEOUT, lookup()).collect::<Vec<_>>()
        });
        let results = join_all(callers).await;

        for items in results {
            assert!(matches!(
                items.as_slice(),
                [Ok(1), Ok(2), Err(err)] if err.to_string() == "boom"
            ));
        }
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }
}
