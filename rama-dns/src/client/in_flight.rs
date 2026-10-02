use std::{
    any::{Any, TypeId},
    fmt,
    hash::Hash,
    mem::take,
    num::NonZero,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::{Pin, pin},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker, ready},
    time::Duration,
};

use ahash::HashMap;
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use rama_core::{
    error::{ArcError, BoxError, BoxErrorExt as _},
    futures::{Stream, StreamExt as _, async_stream::stream_fn},
    rt,
    telemetry::tracing::{self, Instrument as _},
};
use rama_net::address::Domain;
use rama_utils::collections::smallvec::SmallVec;
use tokio::{
    runtime::{self, Handle},
    task::AbortHandle,
    time::error::Elapsed,
};

use super::limit::DnsTimeoutError;

/// A run lives on the runtime that started it, which only that runtime's
/// callers can count on to drive it.
type Slot<K> = (K, TypeId, Option<runtime::Id>);
type Map<K> = HashMap<Slot<K>, Arc<dyn Any + Send + Sync>>;
type Flights<K> = Arc<Shards<K>>;

/// The runs by key, spread over locks so unrelated keys rarely contend.
struct Shards<K> {
    hasher: ahash::RandomState,
    /// A power of two: contention comes from threads, not from keys.
    maps: Box<[Mutex<Map<K>>]>,
}

impl<K> Shards<K> {
    fn new() -> Self {
        let threads = std::thread::available_parallelism().map_or(4, NonZero::get);
        let shards = (threads * 4).next_power_of_two().clamp(8, 1024);
        Self {
            hasher: ahash::RandomState::new(),
            maps: (0..shards).map(|_| Mutex::default()).collect(),
        }
    }

    fn len(&self) -> usize {
        self.maps.iter().map(|map| map.lock().len()).sum()
    }
}

impl<K: Hash> Shards<K> {
    fn shard(&self, slot: &Slot<K>) -> usize {
        // the mask keeps it below the shard count, so the cast cannot truncate
        (self.hasher.hash_one(slot) & (self.maps.len() as u64 - 1)) as usize
    }
}

/// What happens to a run once every caller stopped waiting for it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Abandoned {
    /// Complete it anyway, e.g. to fill a cache or because it cannot be
    /// cancelled (a blocking libc call).
    #[default]
    Finish,
    /// Cancel it, releasing whatever it holds.
    Cancel,
}

/// Concurrent lookups for the same key share one run of the lookup.
///
/// The run is its own task, so no single caller's cancellation cancels it.
/// Nothing is kept once it is done.
pub(crate) struct InFlight<K> {
    flights: Flights<K>,
    abandoned: Abandoned,
}

impl<K> Default for InFlight<K> {
    fn default() -> Self {
        Self::new(Abandoned::default())
    }
}

impl<K> Clone for InFlight<K> {
    fn clone(&self) -> Self {
        Self {
            flights: self.flights.clone(),
            abandoned: self.abandoned,
        }
    }
}

impl<K> fmt::Debug for InFlight<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InFlight")
            .field("running", &self.flights.len())
            .finish()
    }
}

#[cfg(test)]
impl<K> InFlight<K> {
    /// Keys with a run in progress.
    pub(crate) fn running(&self) -> usize {
        self.flights.len()
    }

    fn capacity(&self) -> usize {
        self.flights
            .maps
            .iter()
            .map(|map| map.lock().capacity())
            .sum()
    }

    pub(crate) fn shares_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.flights, &other.flights)
    }

    pub(crate) fn abandoned(&self) -> Abandoned {
        self.abandoned
    }
}

/// One run and everyone waiting on it, in a single allocation.
struct Flight<V> {
    answer: OnceLock<Result<Arc<V>, ArcError>>,
    /// Callers waiting for the answer; `None` once the run ended, with or
    /// without one.
    wakers: Mutex<Option<Wakers>>,
    waiters: AtomicUsize,
    abort: OnceLock<AbortHandle>,
}

impl<V> Flight<V> {
    fn new() -> Self {
        Self {
            answer: OnceLock::new(),
            wakers: Mutex::new(Some(Wakers::default())),
            waiters: AtomicUsize::new(1),
            abort: OnceLock::new(),
        }
    }

    /// The run's answer; `None` when it ended without one (its runtime shut
    /// down, or it panicked).
    fn answer(&self) -> Answer<'_, V> {
        Answer {
            flight: self,
            waker: None,
        }
    }

    fn end(&self, answer: Option<Result<Arc<V>, ArcError>>) {
        if let Some(answer) = answer {
            _ = self.answer.set(answer);
        }
        // wake outside the lock, all at once
        let wakers = self.wakers.lock().take();
        for waker in wakers.into_iter().flat_map(|wakers| wakers.slots).flatten() {
            waker.wake();
        }
    }
}

/// The wakers of a run's callers; a caller that leaves frees its slot for
/// the next one, so they take as much room as callers wait at once.
#[derive(Default)]
struct Wakers {
    slots: SmallVec<[Option<Waker>; 4]>,
    free: SmallVec<[usize; 4]>,
}

impl Wakers {
    fn insert(&mut self, waker: Waker) -> usize {
        if let Some(index) = self.free.pop() {
            self.slots[index] = Some(waker);
            index
        } else {
            self.slots.push(Some(waker));
            self.slots.len() - 1
        }
    }

    fn remove(&mut self, index: usize) {
        if self.slots[index].take().is_some() {
            self.free.push(index);
        }
    }
}

/// The future of [`Flight::answer`].
struct Answer<'a, V> {
    flight: &'a Flight<V>,
    /// This caller's place among the flight's wakers.
    waker: Option<usize>,
}

impl<V> Future for Answer<'_, V> {
    type Output = Option<Result<Arc<V>, ArcError>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let flight = self.flight;
        let mut wakers = flight.wakers.lock();
        let Some(wakers) = wakers.as_mut() else {
            return Poll::Ready(flight.answer.get().cloned());
        };
        if let Some(index) = self.waker {
            let waker = &mut wakers.slots[index];
            if !waker
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                *waker = Some(cx.waker().clone());
            }
        } else {
            self.waker = Some(wakers.insert(cx.waker().clone()));
        }
        Poll::Pending
    }
}

impl<V> Drop for Answer<'_, V> {
    fn drop(&mut self) {
        if let Some(index) = self.waker
            && let Some(wakers) = self.flight.wakers.lock().as_mut()
        {
            wakers.remove(index);
        }
    }
}

/// One caller waiting on a run; the last one to leave may cancel it.
struct Waiting<V> {
    flight: Arc<Flight<V>>,
    abandoned: Abandoned,
}

impl<V> Drop for Waiting<V> {
    fn drop(&mut self) {
        if self.flight.waiters.fetch_sub(1, Ordering::AcqRel) == 1
            && self.abandoned == Abandoned::Cancel
            && let Some(abort) = self.flight.abort.get()
        {
            abort.abort();
        }
    }
}

enum Joined<V> {
    Running(Waiting<V>),
    Started(Waiting<V>),
}

impl<K> InFlight<K> {
    pub(crate) fn new(abandoned: Abandoned) -> Self {
        Self {
            flights: Arc::new(Shards::new()),
            abandoned,
        }
    }
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
        let runtime = Handle::try_current().ok().map(|runtime| runtime.id());
        let slot = (key, TypeId::of::<V>(), runtime);
        let shard = self.flights.shard(&slot);
        let wait = max_duration.saturating_add(max_duration / 4);
        let shared = async {
            let mut lookup = Some(lookup);
            loop {
                match self.join::<V>(&slot, shard) {
                    Joined::Running(waiting) => {
                        if let Some(answer) = waiting.flight.answer().await {
                            return answer;
                        }
                        // it died with another runtime, or was cancelled as we
                        // joined: join or start the next run, within our deadline
                    }
                    Joined::Started(waiting) => {
                        let Some(lookup) = lookup.take() else {
                            return Err(ArcError::from_static_str(
                                "dns lookup ended without an answer",
                            ));
                        };
                        self.start(slot, shard, max_duration, &waiting.flight, lookup);
                        return waiting.flight.answer().await.unwrap_or_else(|| {
                            Err(ArcError::from_static_str(
                                "dns lookup ended without an answer",
                            ))
                        });
                    }
                }
            }
        };
        tokio::time::timeout(wait, shared)
            .await
            .unwrap_or_else(|_elapsed| Err(ArcError::new(DnsTimeoutError::new(max_duration))))
    }

    fn join<V: Send + Sync + 'static>(&self, slot: &Slot<K>, shard: usize) -> Joined<V> {
        let map = &self.flights.maps[shard];
        if let Some(waiting) = self.join_running(&map.lock(), slot) {
            return Joined::Running(waiting);
        }
        // allocated outside the lock; a racing starter may still win the slot
        let flight = Arc::new(Flight::new());
        let mut flights = map.lock();
        if let Some(waiting) = self.join_running(&flights, slot) {
            return Joined::Running(waiting);
        }
        flights.insert(slot.clone(), flight.clone());
        Joined::Started(self.waiting(flight))
    }

    fn join_running<V: Send + Sync + 'static>(
        &self,
        flights: &Map<K>,
        slot: &Slot<K>,
    ) -> Option<Waiting<V>> {
        let flight = flights.get(slot)?.clone().downcast::<Flight<V>>().ok()?;
        // counted under the lock, so a leaving waiter never misses us
        flight.waiters.fetch_add(1, Ordering::AcqRel);
        Some(self.waiting(flight))
    }

    fn waiting<V>(&self, flight: Arc<Flight<V>>) -> Waiting<V> {
        Waiting {
            flight,
            abandoned: self.abandoned,
        }
    }

    fn start<V, F>(
        &self,
        slot: Slot<K>,
        shard: usize,
        max_duration: Duration,
        flight: &Arc<Flight<V>>,
        lookup: impl FnOnce() -> F,
    ) where
        V: Send + Sync + 'static,
        F: Future<Output = V> + Send + 'static,
    {
        // outside the map lock: dropping it (a panic, a closed runtime) re-locks
        let release = Release {
            flights: self.flights.clone(),
            slot,
            shard,
            flight: Some(flight.clone()),
        };
        let span = tracing::debug_span!("dns lookup");
        span.follows_from(tracing::Span::current());
        let mut run = Box::pin(
            tokio::time::timeout(max_duration.saturating_mul(3), lookup()).instrument(span),
        );

        // first poll in the caller's own turn, so queries go out in the order
        // callers ask; the task's own first poll registers its waker
        let mut cx = Context::from_waker(Waker::noop());
        match catch_unwind(AssertUnwindSafe(|| run.as_mut().poll(&mut cx))) {
            Ok(Poll::Ready(answer)) => release.finish(answer_of(answer, max_duration)),
            Ok(Poll::Pending) => {
                let task =
                    rt::spawn(async move { release.finish(answer_of(run.await, max_duration)) });
                _ = flight.abort.set(task.abort_handle());
            }
            // the run died: its waiters see it end without an answer
            Err(_panic) => drop(release),
        }
    }
}

fn answer_of<V>(answer: Result<V, Elapsed>, max_duration: Duration) -> Result<Arc<V>, ArcError> {
    answer.map(Arc::new).map_err(|_elapsed| {
        tracing::debug!(
            ?max_duration,
            "dns lookup abandoned: backend ignored its deadline"
        );
        ArcError::new(DnsTimeoutError::new(max_duration))
    })
}

/// Frees the key when its run ends, however it ends, before its callers
/// learn the outcome.
struct Release<K: Hash + Eq, V> {
    flights: Flights<K>,
    slot: Slot<K>,
    shard: usize,
    flight: Option<Arc<Flight<V>>>,
}

impl<K: Hash + Eq, V> Release<K, V> {
    fn finish(mut self, answer: Result<Arc<V>, ArcError>) {
        let flight = self.flight.take();
        drop(self);
        if let Some(flight) = flight {
            flight.end(Some(answer));
        }
    }
}

impl<K: Hash + Eq, V> Drop for Release<K, V> {
    fn drop(&mut self) {
        {
            let mut flights = self.flights.maps[self.shard].lock();
            flights.remove(&self.slot);
            // a burst spreads over every shard: free what it grew once drained
            if flights.is_empty() && flights.capacity() > RETAINED_CAPACITY {
                flights.shrink_to(0);
            }
        }
        // ended without an answer
        if let Some(flight) = self.flight.take() {
            flight.end(None);
        }
    }
}

/// Per shard: the smallest table, kept for steady light traffic.
const RETAINED_CAPACITY: usize = 3;

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
    pub(crate) fn collect<S>(stream: S) -> Collect<S, T>
    where
        S: Stream<Item = Result<T, BoxError>>,
    {
        Collect {
            stream,
            records: Vec::new(),
        }
    }
}

pin_project! {
    /// The future of [`Outcome::collect`]; holds its stream once, unlike an `async fn`.
    pub(crate) struct Collect<S, T> {
        #[pin]
        stream: S,
        records: Vec<T>,
    }
}

impl<S, T> Future for Collect<S, T>
where
    S: Stream<Item = Result<T, BoxError>>,
{
    type Output = Outcome<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        loop {
            match ready!(this.stream.as_mut().poll_next(cx)) {
                Some(Ok(record)) => this.records.push(record),
                Some(Err(err)) => return Poll::Ready(Outcome::new(take(this.records), Some(err))),
                None => return Poll::Ready(Outcome::new(take(this.records), None)),
            }
        }
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
                yielder.yield_item(Err(replay(err))).await;
            }
        }
        Err(err) => yielder.yield_item(Err(replay(&err))).await,
    })
}

/// One caller's copy of a shared error: a timeout as itself, so a plain
/// downcast finds it.
fn replay(err: &ArcError) -> BoxError {
    match err.downcast_ref::<DnsTimeoutError>() {
        Some(timeout) => (*timeout).into(),
        None => err.clone().into(),
    }
}

/// `Domain` equality ignores a leading dot, yet no backend accepts one in a
/// query name: refuse it before it can share the bare name's lookup.
pub(crate) fn leading_dot_refusal(domain: &Domain) -> Option<BoxError> {
    domain
        .strip_leading_dot()
        .is_some()
        .then(|| BoxError::from_static_str("dns query name starts with a dot"))
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
    // one stream, so waiting for the run and replaying it share their state
    stream_fn(async move |mut yielder| {
        let outcome = in_flight
            .run(key, timeout, move || Outcome::collect(lookup()))
            .await;
        let mut items = pin!(outcome_stream(outcome));
        while let Some(item) = items.next().await {
            yielder.yield_item(item).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use rama_core::futures::{FutureExt as _, future::join_all, stream};
    use tokio::sync::Notify;

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn lookups_go_out_in_the_order_callers_ask() {
        let issued = Arc::new(Mutex::new(Vec::new()));
        let log = issued.clone();
        let lookup = move |name: &'static str| {
            let issued = log.clone();
            move || async move {
                issued.lock().push(name);
                tokio::task::yield_now().await;
            }
        };

        // on a worker, so spawned runs pass through tokio's LIFO slot
        tokio::spawn(async move {
            let in_flight = InFlight::default();
            _ = tokio::join!(
                in_flight.run("aaaa", TIMEOUT, lookup("aaaa")),
                in_flight.run("a", TIMEOUT, lookup("a")),
            );
        })
        .await
        .unwrap();

        assert_eq!(*issued.lock(), ["aaaa", "a"]);
    }

    #[tokio::test]
    async fn drained_burst_frees_its_capacity() {
        let in_flight = InFlight::default();
        let starts = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());

        let (starts_ref, gate_ref) = (&starts, &gate);
        // enough keys for every shard to outgrow what it keeps
        let callers = join_all(
            (0..10_000)
                .map(|key| in_flight.run(key, TIMEOUT, move || gated(starts_ref, gate_ref, key))),
        );
        let (results, ()) = tokio::join!(callers, open(&gate));

        assert!(results.iter().all(Result::is_ok));
        assert_eq!(in_flight.running(), 0);
        // a shard keeps a table only if it never outgrew it, and 10k keys
        // leave few of them that small
        assert!(
            in_flight.capacity() <= in_flight.flights.maps.len() * RETAINED_CAPACITY / 2,
            "{}",
            in_flight.capacity()
        );
    }

    #[tokio::test]
    async fn steady_lookups_keep_their_small_table() {
        let in_flight = InFlight::default();
        for key in 0..100 {
            let value = in_flight.run(key, TIMEOUT, move || async move { key });
            assert!(matches!(value.await, Ok(v) if *v == key));
        }
        // one lookup at a time never outgrows a shard's smallest table
        let tables = in_flight.capacity() / RETAINED_CAPACITY;
        assert!(tables > 0 && tables <= in_flight.flights.maps.len());
        assert_eq!(in_flight.capacity() % RETAINED_CAPACITY, 0);
    }

    #[tokio::test]
    async fn callers_that_leave_free_their_waker_slots() {
        let in_flight = InFlight::<&str>::default();
        let mut staying = pin!(in_flight.run("key", TIMEOUT, std::future::pending::<usize>));
        assert!(staying.as_mut().now_or_never().is_none());

        // many callers join the same pending run and give up again
        for _ in 0..10_000 {
            let mut leaving = pin!(in_flight.run("key", TIMEOUT, std::future::pending::<usize>));
            assert!(leaving.as_mut().now_or_never().is_none());
        }

        let flights = in_flight.flights.maps.iter().find_map(|map| {
            map.lock()
                .get(&("key", TypeId::of::<usize>(), Some(Handle::current().id())))
                .cloned()
                .and_then(|flight| flight.downcast::<Flight<usize>>().ok())
        });
        let flight = flights.expect("the pending run");
        let slots = flight
            .wakers
            .lock()
            .as_ref()
            .map(|wakers| wakers.slots.len());
        assert!(slots.is_some_and(|slots| slots <= 2), "{slots:?}");
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

    /// Flags when the lookup it is part of gets dropped.
    struct DropFlag(Arc<AtomicUsize>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn until(condition: impl Fn() -> bool) {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn abandoned_run_is_cancelled_when_asked_to() {
        let in_flight = InFlight::new(Abandoned::Cancel);
        let dropped = Arc::new(AtomicUsize::new(0));

        let flag = DropFlag(dropped.clone());
        let caller = in_flight.run("key", TIMEOUT, move || async move {
            let _flag = flag;
            std::future::pending::<usize>().await
        });
        tokio::time::timeout(Duration::from_millis(20), caller)
            .await
            .expect_err("nobody answers");

        tokio::time::timeout(TIMEOUT, until(|| dropped.load(Ordering::SeqCst) == 1))
            .await
            .expect("the abandoned lookup is cancelled");
        tokio::time::timeout(TIMEOUT, until(|| in_flight.running() == 0))
            .await
            .expect("and its key freed");
    }

    #[tokio::test]
    async fn cancelling_run_lives_while_anyone_waits() {
        let in_flight = InFlight::new(Abandoned::Cancel);
        let starts = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());

        let leaving = in_flight.run("key", TIMEOUT, || gated(&starts, &gate, 5));
        tokio::time::timeout(Duration::from_millis(20), leaving)
            .await
            .expect_err("the first caller leaves early");

        let staying = in_flight.run("key", TIMEOUT, || gated(&starts, &gate, 6));
        let (value, ()) = tokio::join!(staying, open(&gate));
        assert_eq!(
            starts.load(Ordering::SeqCst),
            2,
            "the lone waiter left, so it restarted"
        );
        assert_eq!(*value.unwrap(), 6);

        let starts = Arc::new(AtomicUsize::new(0));
        let mut first = Box::pin(in_flight.run("other", TIMEOUT, || gated(&starts, &gate, 7)));
        let mut second = Box::pin(in_flight.run("other", TIMEOUT, || gated(&starts, &gate, 8)));
        assert!(
            first.as_mut().now_or_never().is_none(),
            "first started the run"
        );
        assert!(second.as_mut().now_or_never().is_none(), "second joined it");
        drop(first);
        let (value, ()) = tokio::join!(second, open(&gate));
        assert_eq!(
            *value.unwrap(),
            7,
            "one caller left, the other still got the run"
        );
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn waiter_survives_repeated_cancellation() {
        let in_flight = InFlight::new(Abandoned::Cancel);

        // A starts a run and leaves; B joins it before it is cleaned up
        let mut a = Box::pin(in_flight.run("key", TIMEOUT, std::future::pending::<usize>));
        assert!(a.as_mut().now_or_never().is_none());
        drop(a);
        let mut b = Box::pin(in_flight.run("key", TIMEOUT, || async { 42_usize }));
        assert!(b.as_mut().now_or_never().is_none());
        tokio::task::yield_now().await;

        // C starts the replacement and leaves too, before B takes over
        let mut c = Box::pin(in_flight.run("key", TIMEOUT, std::future::pending::<usize>));
        assert!(c.as_mut().now_or_never().is_none());
        drop(c);
        assert!(b.as_mut().now_or_never().is_none());
        tokio::task::yield_now().await;

        assert_eq!(*b.await.unwrap(), 42, "B falls back to its own lookup");
    }

    #[tokio::test]
    async fn default_policy_finishes_abandoned_runs() {
        let in_flight = InFlight::default();
        let dropped = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(Notify::new());

        let (flag, done) = (DropFlag(dropped.clone()), finished.clone());
        let caller = in_flight.run("key", TIMEOUT, move || async move {
            let _flag = flag;
            tokio::time::sleep(Duration::from_millis(50)).await;
            done.notify_one();
        });
        tokio::time::timeout(Duration::from_millis(10), caller)
            .await
            .expect_err("the caller leaves early");

        finished.notified().await;
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "dropped only after finishing"
        );
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

    #[tokio::test]
    async fn run_panicking_after_its_first_poll_fails_its_callers() {
        let in_flight = InFlight::<&str>::default();

        let result = in_flight
            .run("key", TIMEOUT, || async {
                tokio::task::yield_now().await;
                panic!("backend bug")
            })
            .await;

        result.expect_err("a panicking run fails its callers");
        assert_eq!(in_flight.running(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn late_joiner_of_an_abandoned_run_sees_a_timeout() {
        let in_flight = InFlight::<&str>::default();
        let budget = Duration::from_secs(1);

        let first = in_flight.run("key", budget, std::future::pending::<usize>);
        // joins the lingering run, which is abandoned before this caller's own bound
        let late = async {
            tokio::time::sleep(Duration::from_millis(2500)).await;
            in_flight
                .run("key", budget, std::future::pending::<usize>)
                .await
        };
        let (first, late) = tokio::join!(first, late);

        for result in [first, late] {
            let err = result.expect_err("a stuck run fails its callers");
            let timeout = err
                .downcast_ref::<DnsTimeoutError>()
                .map(DnsTimeoutError::timeout);
            assert_eq!(timeout, Some(budget), "{err}");
        }
    }

    #[tokio::test]
    async fn shared_timeout_reaches_every_caller_as_itself() {
        let in_flight = InFlight::default();
        let callers = (0..3).map(|_| {
            coalesced_stream(in_flight.clone(), "key", TIMEOUT, || {
                stream::once(async {
                    tokio::task::yield_now().await;
                    Err::<usize, _>(BoxError::from(DnsTimeoutError::new(TIMEOUT)))
                })
            })
            .collect::<Vec<_>>()
        });

        for items in join_all(callers).await {
            assert!(
                matches!(items.as_slice(), [Err(err)] if err.downcast_ref::<DnsTimeoutError>().is_some()),
                "{items:?}"
            );
        }
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
        let err = hasty.expect_err("the hasty caller times out on its own");
        let timeout = err
            .downcast_ref::<DnsTimeoutError>()
            .expect("a typed timeout");
        assert_eq!(
            timeout.timeout(),
            Duration::from_millis(100),
            "its own budget"
        );
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

    #[test]
    fn runs_are_shared_only_within_their_runtime() {
        let in_flight = InFlight::<&str>::new(Abandoned::Finish);
        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        };
        let (idle, busy) = (runtime(), runtime());

        // its caller gives up, leaving the run on a runtime nothing drives
        idle.block_on(async {
            let pending = in_flight.run("key", TIMEOUT, std::future::pending::<usize>);
            tokio::time::timeout(Duration::from_millis(10), pending)
                .await
                .expect_err("the run stays pending");
        });
        assert_eq!(in_flight.running(), 1);

        let answer = busy.block_on(async {
            let lookup = in_flight.run("key", TIMEOUT, || std::future::ready(9_usize));
            tokio::time::timeout(Duration::from_secs(1), lookup).await
        });
        assert_eq!(*answer.expect("not stuck behind the idle run").unwrap(), 9);

        // the idle run goes with its runtime
        drop(idle);
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
                // pending at first, as a real query: an instant answer has nothing to share
                stream::once(tokio::task::yield_now()).flat_map(|()| {
                    stream::iter([Ok(1), Ok(2), Err(BoxError::from_static_str("boom")), Ok(3)])
                })
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
