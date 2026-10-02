use std::{
    collections::VecDeque,
    fmt,
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use parking_lot::Mutex;
#[cfg(any(target_vendor = "apple", target_os = "windows", test))]
use rama_core::error::BoxError;
use rama_core::telemetry::tracing;
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    task::{JoinError, JoinHandle},
    time::Instant,
};

/// Bounds on one resolver's lookups; `None` leaves that bound off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Lookups running at once: each blocking call holds a thread.
    pub(crate) max_concurrency: Option<usize>,
    /// Queries sent within the last `burst_window` and still unanswered: a
    /// local stub such as systemd-resolved drops what arrives faster than it
    /// reads, whereas a query waiting on a slow upstream has long been read.
    pub(crate) burst_limit: Option<usize>,
    pub(crate) burst_window: Duration,
}

impl Limits {
    /// For lookups that send one query each. 384 calls leave a quarter of
    /// tokio's 512 blocking threads to the rest; 128 queries are half of the
    /// ~256 datagrams a stub's default receive buffer holds, and a busy stub
    /// reads a full buffer well within 20ms.
    pub(crate) const ONE_QUERY: Self = Self {
        max_concurrency: Some(384),
        burst_limit: Some(128),
        burst_window: Duration::from_millis(20),
    };

    /// For `getaddrinfo` calls that ask for A and AAAA at once.
    pub(crate) const TWO_QUERIES: Self = Self {
        burst_limit: Some(64),
        ..Self::ONE_QUERY
    };

    /// For lookups a system service queues itself.
    #[cfg(any(windows, test))]
    pub(crate) const UNBOUNDED: Self = Self {
        max_concurrency: None,
        burst_limit: None,
        ..Self::ONE_QUERY
    };

    /// Each lookup holds an mDNSResponder connection and its descriptor, of
    /// launchd's default soft limit of 256.
    #[cfg(target_vendor = "apple")]
    pub(crate) const fn with_apple_descriptors(self) -> Self {
        Self {
            max_concurrency: Some(64),
            ..self
        }
    }
}

/// Bounds one resolver's lookups by [`Limits`].
#[derive(Debug, Clone)]
pub(crate) struct LookupLimit {
    calls: Option<Arc<Semaphore>>,
    burst: Option<Arc<Burst>>,
    limits: Limits,
}

impl LookupLimit {
    pub(crate) fn new(limits: Limits) -> Self {
        let limits = Limits {
            max_concurrency: limits
                .max_concurrency
                .map(|max| max.clamp(1, Semaphore::MAX_PERMITS)),
            burst_limit: limits.burst_limit.map(|max| max.max(1)),
            burst_window: limits.burst_window,
        };
        Self {
            calls: limits
                .max_concurrency
                .map(|max| Arc::new(Semaphore::new(max))),
            burst: limits
                .burst_limit
                .map(|max| Arc::new(Burst::new(max, limits.burst_window))),
            limits,
        }
    }

    pub(crate) fn limits(&self) -> Limits {
        self.limits
    }

    /// A limit with fresh slots, `change`d from this one's.
    pub(crate) fn with(&self, change: impl FnOnce(&mut Limits)) -> Self {
        let mut limits = self.limits;
        change(&mut limits);
        Self::new(limits)
    }

    /// A slot for one lookup, or `None` when none frees up before `deadline`.
    pub(crate) async fn acquire(&self, deadline: Instant) -> Option<Slot> {
        let call = match &self.calls {
            Some(calls) => Some(self.call(calls, deadline).await?),
            None => None,
        };
        let burst = match &self.burst {
            Some(burst) => Some(burst.acquire(deadline).await?),
            None => None,
        };
        Some(Slot { _call: call, burst })
    }

    async fn call(
        &self,
        calls: &Arc<Semaphore>,
        deadline: Instant,
    ) -> Option<OwnedSemaphorePermit> {
        if let Ok(call) = calls.clone().try_acquire_owned() {
            return Some(call);
        }
        tracing::debug!(
            max = self.limits.max_concurrency,
            "dns: all lookup slots taken; waiting"
        );
        tokio::time::timeout_at(deadline, calls.clone().acquire_owned())
            .await
            .ok()?
            .ok()
    }

    /// Run a blocking `lookup` once a slot is free, or `None` when none frees
    /// up before `deadline`.
    ///
    /// A timeout cannot cancel a blocking call, so its slot stays taken until
    /// the call itself returns. `lookup` gets the budget left when it starts:
    /// zero means its caller already gave up.
    pub(crate) async fn spawn_blocking<T, F>(
        &self,
        deadline: Instant,
        lookup: F,
    ) -> Option<Blocking<T>>
    where
        F: FnOnce(Duration) -> T + Send + 'static,
        T: Send + 'static,
    {
        let slot = self.acquire(deadline).await?;
        // budget in tokio time (which tests may pause), queueing in wall time
        let budget = deadline.saturating_duration_since(Instant::now());
        let queued = std::time::Instant::now();
        let held = Arc::new(Mutex::new(Held {
            slot: Some(slot),
            returned: false,
            left: false,
        }));
        let returned = Returned(held.clone());
        let call = tokio::task::spawn_blocking(move || {
            let _returned = returned;
            lookup(budget.saturating_sub(queued.elapsed()))
        });
        Some(Blocking {
            call: Some(call),
            held,
        })
    }
}

/// A blocking lookup in flight; its slot frees once its thread is done with
/// it, so the next lookup reuses that thread rather than spawning another.
#[derive(Debug)]
pub(crate) struct Blocking<T: Send + 'static> {
    call: Option<JoinHandle<T>>,
    held: Arc<Mutex<Held>>,
}

/// A blocking call's slot, until the call returned and its caller saw that
/// or left: neither a runtime nor the caller has to outlive the call.
#[derive(Debug)]
struct Held {
    slot: Option<Slot>,
    returned: bool,
    left: bool,
}

/// Marks its blocking call returned, also when the call unwinds or never ran.
struct Returned(Arc<Mutex<Held>>);

impl Drop for Returned {
    fn drop(&mut self) {
        let slot = {
            let mut held = self.0.lock();
            held.returned = true;
            held.left.then(|| held.slot.take()).flatten()
        };
        free(slot);
    }
}

/// The call returned: libc is done with its query either way.
fn free(slot: Option<Slot>) {
    if let Some(mut slot) = slot {
        slot.answered();
    }
}

impl<T: Send + 'static> Future for Blocking<T> {
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(call) = self.call.as_mut() else {
            return Poll::Pending;
        };
        let answer = ready!(Pin::new(call).poll(cx));
        self.call = None;
        let slot = self.held.lock().slot.take();
        free(slot);
        Poll::Ready(answer)
    }
}

impl<T: Send + 'static> Drop for Blocking<T> {
    fn drop(&mut self) {
        if self.call.is_none() {
            return;
        }
        // its caller gave up, the call itself cannot: the call frees the slot
        let slot = {
            let mut held = self.held.lock();
            held.left = true;
            held.returned.then(|| held.slot.take()).flatten()
        };
        free(slot);
    }
}

/// A running lookup's place: its call slot until it ends, its burst slot
/// until it is answered or a burst window old.
#[derive(Debug)]
pub(crate) struct Slot {
    _call: Option<OwnedSemaphorePermit>,
    burst: Option<BurstSlot>,
}

impl Slot {
    /// The lookup's query is done, so its burst place frees up now; a
    /// lookup dropped before this keeps it until the window has passed.
    pub(crate) fn answered(&mut self) {
        if let Some(burst) = &mut self.burst {
            burst.answered = true;
        }
    }

    /// The lookup yielded `item`: anything but a timeout is an answer.
    #[cfg(any(target_vendor = "apple", target_os = "windows", test))]
    pub(crate) fn saw<T>(&mut self, item: &Result<T, BoxError>) {
        let timeout = item
            .as_ref()
            .is_err_and(|err| err.downcast_ref::<DnsTimeoutError>().is_some());
        if !timeout {
            self.answered();
        }
    }
}

/// At most `max` queries started within the last `window` and unanswered.
///
/// An answer frees its place at once; age frees it lazily, when the next
/// caller looks, so a running query needs no timer of its own. Callers that
/// have to wait for a place get one in the order they came.
#[derive(Debug)]
struct Burst {
    max: usize,
    window: Duration,
    state: Mutex<BurstState>,
    freed: Notify,
    /// Callers queued for a place; newcomers line up behind them.
    queued: AtomicUsize,
    turn: tokio::sync::Mutex<()>,
}

#[derive(Debug, Default)]
struct BurstState {
    next: u64,
    /// Unanswered queries still young, oldest first, by id.
    young: VecDeque<(u64, Instant)>,
}

impl BurstState {
    /// Forget aged queries, returning when the oldest one left ages, if ever.
    fn expire(&mut self, now: Instant, window: Duration) -> Option<Instant> {
        while let Some(&(_, started)) = self.young.front() {
            if now.saturating_duration_since(started) < window {
                return started.checked_add(window);
            }
            self.young.pop_front();
        }
        None
    }
}

impl Burst {
    fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            state: Mutex::default(),
            freed: Notify::new(),
            queued: AtomicUsize::new(0),
            turn: tokio::sync::Mutex::new(()),
        }
    }

    async fn acquire(self: &Arc<Self>, deadline: Instant) -> Option<BurstSlot> {
        if self.queued.load(Ordering::Acquire) == 0
            && let Ok(slot) = self.take()
        {
            return Some(slot);
        }
        self.queued.fetch_add(1, Ordering::AcqRel);
        let _queued = Queued(&self.queued);
        let _turn = tokio::time::timeout_at(deadline, self.turn.lock())
            .await
            .ok()?;
        loop {
            let mut freed = pin!(self.freed.notified());
            freed.as_mut().enable();
            let ages_at = match self.take() {
                Ok(slot) => return Some(slot),
                Err(ages_at) => ages_at,
            };
            if Instant::now() >= deadline {
                return None;
            }
            let wake = ages_at.map_or(deadline, |at| at.min(deadline));
            tokio::select! {
                () = freed => {}
                () = tokio::time::sleep_until(wake) => {}
            }
        }
    }

    /// A place now, or when the oldest young query ages.
    fn take(self: &Arc<Self>) -> Result<BurstSlot, Option<Instant>> {
        let mut state = self.state.lock();
        let now = Instant::now();
        let ages_at = state.expire(now, self.window);
        if state.young.len() >= self.max {
            return Err(ages_at);
        }
        let id = state.next;
        state.next += 1;
        state.young.push_back((id, now));
        Ok(BurstSlot {
            burst: self.clone(),
            id,
            answered: false,
        })
    }
}

/// Leaves the queue however its caller stops waiting.
struct Queued<'a>(&'a AtomicUsize);

impl Drop for Queued<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct BurstSlot {
    burst: Arc<Burst>,
    id: u64,
    answered: bool,
}

impl Drop for BurstSlot {
    fn drop(&mut self) {
        // its query may still be in the stub's queue
        if !self.answered {
            return;
        }
        let mut state = self.burst.state.lock();
        // an aged query already gave its place up
        if let Ok(index) = state.young.binary_search_by_key(&self.id, |&(id, _)| id) {
            state.young.remove(index);
            drop(state);
            self.burst.freed.notify_one();
        }
    }
}

/// A DNS lookup that ran out of time.
///
/// The Apple, Windows, Linux and Tokio resolvers yield it as the error
/// itself, also to callers that shared a lookup, so a plain `downcast_ref`
/// finds it.
#[derive(Debug, Clone, Copy)]
pub struct DnsTimeoutError {
    timeout: Duration,
}

impl DnsTimeoutError {
    pub(crate) const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// The resolver's configured timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl fmt::Display for DnsTimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dns lookup timed out after {:?}", self.timeout)
    }
}

impl std::error::Error for DnsTimeoutError {}

/// `timeout` from now, saturating instead of overflowing.
pub(crate) fn deadline_after(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout)
        .unwrap_or_else(|| now + Duration::from_hours(24 * 365 * 30))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    use rama_core::{
        error::BoxErrorExt as _,
        futures::{FutureExt as _, future::join_all},
    };

    use super::*;

    fn deadline_in(secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(secs)
    }

    /// The lookup holding `slot` got its answer.
    fn answer(mut slot: Slot) {
        slot.answered();
    }

    /// At most `max` calls, with no burst limit.
    fn calls(max: usize) -> LookupLimit {
        LookupLimit::new(Limits {
            max_concurrency: Some(max),
            ..Limits::UNBOUNDED
        })
    }

    /// Any number of calls, at most `max` unanswered per `window`.
    fn burst(max: usize, window: Duration) -> LookupLimit {
        LookupLimit::new(Limits {
            max_concurrency: None,
            burst_limit: Some(max),
            burst_window: window,
        })
    }

    /// The unanswered queries `lookups` still counts.
    fn young(lookups: &LookupLimit) -> usize {
        lookups
            .burst
            .as_ref()
            .expect("a burst limit")
            .state
            .lock()
            .young
            .len()
    }

    #[tokio::test(start_paused = true)]
    async fn unanswered_queries_are_bounded_per_window() {
        let lookups = burst(2, Duration::from_millis(10));
        let started = Instant::now();
        let _first = lookups.acquire(deadline_in(5)).await.expect("slot");
        let _second = lookups.acquire(deadline_in(5)).await.expect("slot");

        // neither answered: the third starts once the first is a window old
        let _third = lookups.acquire(deadline_in(5)).await.expect("slot");
        assert_eq!(started.elapsed(), Duration::from_millis(10));
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_frees_its_place_at_once() {
        let lookups = burst(1, Duration::from_mins(1));
        let started = Instant::now();
        let answered = lookups.acquire(deadline_in(5)).await.expect("slot");
        let next = lookups.acquire(deadline_in(5));
        let answer = async {
            tokio::time::sleep(Duration::from_millis(3)).await;
            answer(answered);
        };
        let (next, ()) = tokio::join!(next, answer);

        assert!(next.is_some());
        assert_eq!(started.elapsed(), Duration::from_millis(3));
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_query_keeps_its_place_for_the_window() {
        let lookups = burst(1, Duration::from_millis(10));
        let started = Instant::now();
        // dropped unanswered: its query may still be in the stub's queue
        drop(lookups.acquire(deadline_in(5)).await.expect("slot"));
        let _next = lookups.acquire(deadline_in(5)).await.expect("slot");
        assert_eq!(started.elapsed(), Duration::from_millis(10));
    }

    #[tokio::test(start_paused = true)]
    async fn a_window_past_any_deadline_never_ages() {
        let lookups = burst(1, Duration::MAX);
        let held = lookups.acquire(deadline_in(5)).await.expect("slot");
        // only an answer frees the place
        let starved = lookups
            .acquire(Instant::now() + Duration::from_millis(50))
            .await;
        assert!(starved.is_none());
        answer(held);
        assert!(lookups.acquire(deadline_in(5)).await.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn an_aged_query_keeps_its_call_slot() {
        let lookups = LookupLimit::new(Limits {
            max_concurrency: Some(2),
            burst_limit: Some(1),
            burst_window: Duration::from_millis(10),
        });
        let _slow = lookups.acquire(deadline_in(5)).await.expect("slot");
        // a slow query frees its burst place by age, not its call slot
        let _second = lookups.acquire(deadline_in(5)).await.expect("slot");
        let third = lookups
            .acquire(Instant::now() + Duration::from_millis(100))
            .await;
        assert!(third.is_none(), "both calls still run");
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_for_a_burst_place_counts_against_the_deadline() {
        let lookups = burst(1, Duration::from_mins(1));
        let _held = lookups.acquire(deadline_in(5)).await.expect("slot");
        let started = Instant::now();
        let starved = lookups
            .acquire(Instant::now() + Duration::from_millis(50))
            .await;
        assert!(starved.is_none());
        assert_eq!(started.elapsed(), Duration::from_millis(50));
    }

    #[tokio::test(start_paused = true)]
    async fn only_unanswered_queries_are_kept() {
        let lookups = LookupLimit::new(Limits {
            max_concurrency: Some(2),
            burst_limit: Some(2),
            burst_window: Duration::from_hours(1),
        });
        // one query stays unanswered while many others come and go
        let held = lookups.acquire(deadline_in(5)).await.expect("slot");
        for _ in 0..10_000 {
            answer(lookups.acquire(deadline_in(5)).await.expect("slot"));
        }
        assert_eq!(young(&lookups), 1);
        answer(held);
        assert_eq!(young(&lookups), 0);

        // an unanswered query is forgotten once it ages
        let aging = lookups.acquire(deadline_in(5)).await.expect("slot");
        tokio::time::sleep(Duration::from_hours(1)).await;
        answer(lookups.acquire(deadline_in(5)).await.expect("slot"));
        assert_eq!(young(&lookups), 0);
        drop(aging);
    }

    #[tokio::test(start_paused = true)]
    async fn queued_callers_get_places_in_order() {
        let lookups = LookupLimit::new(Limits {
            max_concurrency: Some(8),
            burst_limit: Some(1),
            burst_window: Duration::from_mins(1),
        });
        let held = lookups.acquire(deadline_in(5)).await.expect("slot");
        let mut first = pin!(lookups.acquire(deadline_in(5)));
        assert!(first.as_mut().now_or_never().is_none(), "first queues");

        answer(held);
        // a newcomer polled before the queued caller does not get its place
        let mut newcomer = pin!(lookups.acquire(deadline_in(5)));
        assert!(
            newcomer.as_mut().now_or_never().is_none(),
            "newcomer queues"
        );
        let first = first.await.expect("the first in line gets the place");
        assert!(newcomer.as_mut().now_or_never().is_none());
        answer(first);
        assert!(newcomer.await.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_lookups_stay_within_the_bound() {
        let lookups = calls(3);
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let calls = (0..24).map(|_| {
            let (running, peak) = (running.clone(), peak.clone());
            let lookups = lookups.clone();
            async move {
                let task = lookups
                    .spawn_blocking(deadline_in(10), move |_budget| {
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(5));
                        running.fetch_sub(1, Ordering::SeqCst);
                    })
                    .await
                    .expect("slot within deadline");
                task.await.expect("lookup ran");
            }
        });
        join_all(calls).await;

        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn waiting_for_a_slot_counts_against_the_deadline() {
        let lookups = calls(1);
        let (release, held) = mpsc::channel::<()>();
        let busy = lookups
            .spawn_blocking(deadline_in(10), move |_budget| held.recv().ok())
            .await
            .expect("first slot");

        let starved = lookups
            .spawn_blocking(Instant::now() + Duration::from_millis(50), |_budget| ())
            .await;
        assert!(starved.is_none(), "no slot frees up in time");

        drop(release);
        busy.await.expect("busy lookup ends");
        assert!(
            lookups
                .spawn_blocking(deadline_in(10), |_budget| ())
                .await
                .is_some(),
            "slot is free again once the call returns",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slot_stays_taken_after_the_caller_gave_up() {
        let lookups = calls(1);
        let (release, held) = mpsc::channel::<()>();
        let abandoned = lookups
            .spawn_blocking(deadline_in(10), move |_budget| held.recv().ok())
            .await
            .expect("first slot");
        drop(abandoned);

        let starved = lookups
            .spawn_blocking(Instant::now() + Duration::from_millis(50), |_budget| ())
            .await;
        assert!(
            starved.is_none(),
            "the uncancellable call still holds its slot"
        );

        // once the call returns, its slot is free again
        drop(release);
        let freed = lookups
            .spawn_blocking(deadline_in(5), |_budget| ())
            .await
            .expect("the slot frees when the call returns");
        freed.await.expect("lookup ran");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_blocking_slot_frees_once_its_caller_saw_the_call_return() {
        let lookups = calls(1);
        let done = lookups
            .spawn_blocking(deadline_in(5), |_budget| ())
            .await
            .expect("slot");
        // the call returns at once, but its caller has not looked yet
        tokio::time::sleep(Duration::from_millis(20)).await;
        let early = lookups
            .acquire(Instant::now() + Duration::from_millis(10))
            .await;
        assert!(early.is_none(), "its thread may still be on its way back");
        done.await.expect("lookup ran");
        assert!(lookups.acquire(deadline_in(5)).await.is_some());
    }

    #[test]
    fn a_blocking_slot_outlives_a_caller_dropped_off_runtime() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let lookups = calls(1);
        let (release, held) = mpsc::channel::<()>();
        let blocking = runtime
            .block_on(lookups.spawn_blocking(deadline_in(10), move |_budget| held.recv().ok()))
            .expect("slot");
        // no runtime here, while the call still blocks
        drop(blocking);

        let starved = runtime.block_on(lookups.acquire(Instant::now() + Duration::from_millis(50)));
        assert!(starved.is_none(), "the running call keeps its slot");
        drop(release);
        assert!(
            runtime.block_on(lookups.acquire(deadline_in(5))).is_some(),
            "the call frees its slot once it returns"
        );
    }

    #[test]
    fn a_blocking_slot_outlives_its_runtime_shutting_down() {
        let lookups = calls(1);
        let (release, held) = mpsc::channel::<()>();
        let (started_tx, started) = mpsc::channel::<()>();
        let shutting = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let caller = lookups.clone();
        shutting.spawn(async move {
            let call = caller
                .spawn_blocking(deadline_in(10), move |_budget| {
                    _ = started_tx.send(());
                    held.recv().ok()
                })
                .await
                .expect("slot");
            _ = call.await;
        });
        started.recv().expect("the call runs");
        // drops the waiting caller inside the runtime
        shutting.shutdown_timeout(Duration::from_millis(10));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let starved = runtime.block_on(lookups.acquire(Instant::now() + Duration::from_millis(50)));
        assert!(starved.is_none(), "the running call keeps its slot");
        drop(release);
        assert!(runtime.block_on(lookups.acquire(deadline_in(5))).is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_answered_blocking_lookup_frees_its_burst_place_at_once() {
        let lookups = burst(1, Duration::from_mins(1));
        lookups
            .spawn_blocking(deadline_in(5), |_budget| ())
            .await
            .expect("slot")
            .await
            .expect("lookup ran");
        let next = lookups
            .spawn_blocking(Instant::now() + Duration::from_millis(50), |_budget| ())
            .await;
        assert!(next.is_some(), "the answered lookup left its place");
    }

    #[tokio::test(start_paused = true)]
    async fn an_error_answer_frees_its_burst_place_a_timeout_does_not() {
        let lookups = burst(1, Duration::from_mins(1));
        let soon = || Instant::now() + Duration::from_millis(50);
        let mut slot = lookups.acquire(deadline_in(5)).await.expect("slot");
        slot.saw(&Err::<(), _>(BoxError::from_static_str("SERVFAIL")));
        drop(slot);

        let mut slot = lookups
            .acquire(soon())
            .await
            .expect("the error answer left its place");
        slot.saw(&Err::<(), _>(
            DnsTimeoutError::new(Duration::from_secs(5)).into(),
        ));
        drop(slot);
        assert!(
            lookups.acquire(soon()).await.is_none(),
            "a timeout is no answer"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_gets_the_remaining_budget() {
        let lookups = LookupLimit::new(Limits::ONE_QUERY);

        let budget = lookups
            .spawn_blocking(deadline_in(5), |budget| budget)
            .await
            .expect("slot")
            .await
            .expect("lookup ran");
        assert!(budget > Duration::from_secs(4) && budget <= Duration::from_secs(5));

        // a free slot is still handed out at the deadline, with nothing left
        let expired = lookups
            .spawn_blocking(Instant::now(), |budget| budget)
            .await
            .expect("a free slot is taken even at the deadline");
        assert!(expired.await.expect("lookup ran").is_zero());
    }

    #[tokio::test]
    async fn huge_timeouts_saturate() {
        assert!(deadline_after(Duration::MAX) > Instant::now() + Duration::from_hours(24 * 365));
    }

    #[tokio::test(start_paused = true)]
    async fn budget_follows_a_paused_clock() {
        let lookups = calls(1);
        // the paused clock runs ahead of wall time from here on
        tokio::time::sleep(Duration::from_mins(1)).await;

        let budget = lookups
            .spawn_blocking(deadline_in(5), |budget| budget)
            .await
            .expect("slot")
            .await
            .expect("lookup ran");
        assert!(
            budget > Duration::from_secs(4) && budget <= Duration::from_secs(5),
            "budget {budget:?}",
        );
    }

    #[test]
    fn timeout_error_reads_the_same_for_every_backend() {
        let err = DnsTimeoutError::new(Duration::from_millis(50));
        assert_eq!(err.to_string(), "dns lookup timed out after 50ms");
        assert_eq!(err.timeout(), Duration::from_millis(50));
    }

    #[test]
    fn bounds_are_clamped() {
        let none = LookupLimit::new(Limits {
            max_concurrency: Some(0),
            burst_limit: Some(0),
            ..Limits::ONE_QUERY
        });
        assert_eq!(none.limits().max_concurrency, Some(1));
        assert_eq!(none.limits().burst_limit, Some(1));
        let all = none.with(|limits| limits.max_concurrency = Some(usize::MAX));
        assert_eq!(all.limits().max_concurrency, Some(Semaphore::MAX_PERMITS));
        assert_eq!(all.limits().burst_limit, Some(1));
        let unbounded = all.with(|limits| limits.max_concurrency = None);
        assert_eq!(unbounded.limits().max_concurrency, None);
        assert_eq!(unbounded.limits().burst_limit, Some(1));
    }

    #[tokio::test(start_paused = true)]
    async fn unbounded_lookups_never_wait() {
        let lookups = LookupLimit::new(Limits::UNBOUNDED);
        let started = Instant::now();
        let mut held = Vec::new();
        for _ in 0..10_000 {
            let slot = lookups.acquire(Instant::now()).now_or_never();
            held.push(slot.flatten().expect("a slot at once"));
        }
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert!(lookups.calls.is_none() && lookups.burst.is_none());
    }
}
