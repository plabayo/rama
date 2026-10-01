use std::{
    collections::VecDeque,
    fmt,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use rama_core::telemetry::tracing;
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::Instant,
};

/// Bounds on one resolver's lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Lookups running at once: each blocking call holds a thread.
    pub(crate) max_concurrency: usize,
    /// Queries sent within the last `burst_window` and still unanswered: a
    /// local stub such as systemd-resolved drops what arrives faster than it
    /// reads, whereas a query waiting on a slow upstream has long been read.
    pub(crate) burst_limit: usize,
    pub(crate) burst_window: Duration,
}

impl Limits {
    /// For lookups that send one query each. 384 calls leave a quarter of
    /// tokio's 512 blocking threads to the rest; 128 queries are half of the
    /// ~256 datagrams a stub's default receive buffer holds, and a busy stub
    /// reads a full buffer well within 50ms.
    pub(crate) const ONE_QUERY: Self = Self {
        max_concurrency: 384,
        burst_limit: 128,
        burst_window: Duration::from_millis(50),
    };

    /// For `getaddrinfo` calls that ask for A and AAAA at once.
    pub(crate) const TWO_QUERIES: Self = Self {
        burst_limit: 64,
        ..Self::ONE_QUERY
    };
}

/// Bounds one resolver's lookups by [`Limits`].
#[derive(Debug, Clone)]
pub(crate) struct LookupLimit {
    calls: Arc<Semaphore>,
    burst: Arc<Burst>,
    limits: Limits,
}

impl LookupLimit {
    pub(crate) fn new(limits: Limits) -> Self {
        let limits = Limits {
            max_concurrency: limits.max_concurrency.clamp(1, Semaphore::MAX_PERMITS),
            burst_limit: limits.burst_limit.max(1),
            burst_window: limits.burst_window,
        };
        Self {
            calls: Arc::new(Semaphore::new(limits.max_concurrency)),
            burst: Arc::new(Burst::new(limits.burst_limit, limits.burst_window)),
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
        let call = if let Ok(call) = self.calls.clone().try_acquire_owned() {
            call
        } else {
            tracing::debug!(
                max = self.limits.max_concurrency,
                "dns: all lookup slots taken; waiting"
            );
            tokio::time::timeout_at(deadline, self.calls.clone().acquire_owned())
                .await
                .ok()?
                .ok()?
        };
        let burst = self.burst.acquire(deadline).await?;
        Some(Slot {
            _call: call,
            _burst: burst,
        })
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
    ) -> Option<JoinHandle<T>>
    where
        F: FnOnce(Duration) -> T + Send + 'static,
        T: Send + 'static,
    {
        let slot = self.acquire(deadline).await?;
        // budget in tokio time (which tests may pause), queueing in wall time
        let budget = deadline.saturating_duration_since(Instant::now());
        let queued = std::time::Instant::now();
        Some(tokio::task::spawn_blocking(move || {
            let _slot = slot;
            lookup(budget.saturating_sub(queued.elapsed()))
        }))
    }
}

/// A running lookup's place: its call slot until it ends, its burst slot
/// until it is answered or a burst window old.
#[derive(Debug)]
pub(crate) struct Slot {
    _call: OwnedSemaphorePermit,
    _burst: BurstSlot,
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
    /// Forget aged queries, returning when the oldest one left ages.
    fn expire(&mut self, now: Instant, window: Duration) -> Option<Instant> {
        while let Some(&(_, started)) = self.young.front() {
            if now.saturating_duration_since(started) < window {
                return Some(started + window);
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
}

impl Drop for BurstSlot {
    fn drop(&mut self) {
        let mut state = self.burst.state.lock();
        // an aged query already gave its place up
        if let Ok(index) = state.young.binary_search_by_key(&self.id, |&(id, _)| id) {
            state.young.remove(index);
            drop(state);
            self.burst.freed.notify_one();
        }
    }
}

/// A DNS lookup that ran out of time, whichever resolver served it.
///
/// Every native resolver yields it as the error itself, also to callers that
/// shared a lookup, so a plain `downcast_ref` finds it.
#[derive(Debug, Clone, Copy)]
pub struct DnsTimeoutError {
    timeout: Duration,
}

impl DnsTimeoutError {
    pub(crate) const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// The budget the lookup ran out of.
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

    use rama_core::futures::{FutureExt as _, future::join_all};

    use super::*;

    fn deadline_in(secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(secs)
    }

    /// At most `max` calls, with a burst limit that never gets in the way.
    fn calls(max: usize) -> LookupLimit {
        LookupLimit::new(Limits {
            max_concurrency: max,
            burst_limit: usize::MAX,
            ..Limits::ONE_QUERY
        })
    }

    /// Plenty of calls, at most `max` unanswered per `window`.
    fn burst(max: usize, window: Duration) -> LookupLimit {
        LookupLimit::new(Limits {
            max_concurrency: 1024,
            burst_limit: max,
            burst_window: window,
        })
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
        let lookups = burst(1, Duration::from_secs(60));
        let started = Instant::now();
        let answered = lookups.acquire(deadline_in(5)).await.expect("slot");
        let next = lookups.acquire(deadline_in(5));
        let answer = async {
            tokio::time::sleep(Duration::from_millis(3)).await;
            drop(answered);
        };
        let (next, ()) = tokio::join!(next, answer);

        assert!(next.is_some());
        assert_eq!(started.elapsed(), Duration::from_millis(3));
    }

    #[tokio::test(start_paused = true)]
    async fn an_aged_query_keeps_its_call_slot() {
        let lookups = LookupLimit::new(Limits {
            max_concurrency: 2,
            burst_limit: 1,
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
        let lookups = burst(1, Duration::from_secs(60));
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
            max_concurrency: 2,
            burst_limit: 2,
            burst_window: Duration::from_hours(1),
        });
        // one query stays unanswered while many others come and go
        let held = lookups.acquire(deadline_in(5)).await.expect("slot");
        for _ in 0..10_000 {
            drop(lookups.acquire(deadline_in(5)).await.expect("slot"));
        }
        assert_eq!(lookups.burst.state.lock().young.len(), 1);
        drop(held);
        assert!(lookups.burst.state.lock().young.is_empty());

        // an unanswered query is forgotten once it ages
        let aging = lookups.acquire(deadline_in(5)).await.expect("slot");
        tokio::time::sleep(Duration::from_hours(1)).await;
        drop(lookups.acquire(deadline_in(5)).await.expect("slot"));
        assert!(lookups.burst.state.lock().young.is_empty());
        drop(aging);
    }

    #[tokio::test(start_paused = true)]
    async fn queued_callers_get_places_in_order() {
        let lookups = LookupLimit::new(Limits {
            max_concurrency: 8,
            burst_limit: 1,
            burst_window: Duration::from_secs(60),
        });
        let held = lookups.acquire(deadline_in(5)).await.expect("slot");
        let mut first = pin!(lookups.acquire(deadline_in(5)));
        assert!(first.as_mut().now_or_never().is_none(), "first queues");

        drop(held);
        // a newcomer polled before the queued caller does not get its place
        let mut newcomer = pin!(lookups.acquire(deadline_in(5)));
        assert!(
            newcomer.as_mut().now_or_never().is_none(),
            "newcomer queues"
        );
        let first = first.await.expect("the first in line gets the place");
        assert!(newcomer.as_mut().now_or_never().is_none());
        drop(first);
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
        drop(release);
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
        tokio::time::sleep(Duration::from_secs(60)).await;

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
            max_concurrency: 0,
            burst_limit: 0,
            ..Limits::ONE_QUERY
        });
        assert_eq!(none.limits().max_concurrency, 1);
        assert_eq!(none.limits().burst_limit, 1);
        let all = none.with(|limits| limits.max_concurrency = usize::MAX);
        assert_eq!(all.limits().max_concurrency, Semaphore::MAX_PERMITS);
        assert_eq!(all.limits().burst_limit, 1);
    }
}
