//! [`IdleGuard`]: an idle deadline whose timer is re-armed only when it fires.

use core::{
    fmt::{Debug, Formatter},
    future::poll_fn,
};
use std::{
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, ready},
    time::Duration,
};

use parking_lot::Mutex;
use rama_utils::time::deadline_after;
use tokio::time::{Instant, Sleep, sleep_until};

/// The far future of a tokio sleep: a bound below it keeps every deadline an unchecked add.
const MAX_TIMEOUT: Duration = Duration::from_hours(24 * 365 * 30);

/// An idle deadline: `timeout` after the last recorded activity.
///
/// Activity is recorded by the guard's owner with [`IdleGuard::reset`], from any task as a
/// timestamp on an [`IdleActivity`] polled with [`IdleGuard::expired`], or from any task as
/// a count on an [`IdleProgress`] polled with [`IdleGuard::stalled`]. The timer itself is
/// only re-armed when it fires and activity moved the deadline since, so recording costs no
/// timer work per event.
///
/// Every wait is cancel safe: dropping it keeps the deadline, so it can be polled again
/// from every iteration of a `tokio::select!` loop. Once a wait completed it completes
/// again at once, until activity is recorded.
///
/// A guard can be created outside a Tokio runtime: its timer is armed on the first wait,
/// still at the deadline counted from its creation or the activity it follows.
pub struct IdleGuard {
    timeout: Duration,
    last: Instant,
    seen: u64,
    progress_deadline: Instant,
    wait: Option<Wait>,
    sleep: Option<Pin<Box<Sleep>>>,
}

/// What an [`IdleGuard`] last waited on: each sets its timer by its own deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wait {
    Reset,
    Activity,
    Progress,
}

impl Debug for IdleGuard {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdleGuard")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl IdleGuard {
    /// Create a new [`IdleGuard`] that fires after `timeout` of inactivity, counted from now.
    ///
    /// Timeouts beyond thirty years are capped there, tokio's own far future.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self::since(Instant::now(), timeout)
    }

    /// Create an [`IdleGuard`] that fires `timeout` after the last activity recorded on
    /// `activity`, for use with [`IdleGuard::expired`].
    ///
    /// Timeouts beyond thirty years are capped there, tokio's own far future.
    #[must_use]
    pub fn for_activity(timeout: Duration, activity: &IdleActivity) -> Self {
        Self::since(activity.last(), timeout)
    }

    /// Initialize the monitor from the supplied activity timestamp.
    fn since(last: Instant, timeout: Duration) -> Self {
        let timeout = timeout.min(MAX_TIMEOUT);
        Self {
            timeout,
            last,
            seen: 0,
            progress_deadline: deadline_after(last, timeout),
            wait: None,
            sleep: None,
        }
    }

    /// Start waiting as `wait`; another kind of wait before it may have set the timer later.
    fn begin(&mut self, wait: Wait) {
        if self.wait == Some(wait) {
            return;
        }
        self.wait = Some(wait);
        let reset = deadline_after(self.last, self.timeout);
        let earliest = if wait == Wait::Progress {
            self.progress_deadline.max(reset)
        } else {
            reset
        };
        if let Some(sleep) = self.sleep.as_mut() {
            sleep.as_mut().reset(earliest);
        }
    }

    /// Return the timer for the current wait kind.
    fn timer(&mut self) -> Pin<&mut Sleep> {
        let deadline = deadline_after(self.last, self.timeout);
        self.sleep
            .get_or_insert_with(|| Box::pin(sleep_until(deadline)))
            .as_mut()
    }

    /// The configured idle timeout, capped at thirty years.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Record activity now, moving the idle deadline to `now + timeout`.
    #[inline]
    pub fn reset(&mut self) {
        self.last = Instant::now();
    }

    /// Completes once `timeout` passed since the last [`IdleGuard::reset`].
    pub fn tick(&mut self) -> impl Future<Output = ()> + '_ {
        poll_fn(|cx| self.poll_tick(cx))
    }

    /// Poll form of [`IdleGuard::tick`], for use within a `poll_*` method.
    pub fn poll_tick(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.begin(Wait::Reset);
        self.poll_idle(cx, Instant::now, || None)
    }

    /// Completes once `timeout` passed since the last activity, recorded on `activity` or
    /// with [`IdleGuard::reset`].
    pub fn expired<'a>(&'a mut self, activity: &'a IdleActivity) -> impl Future<Output = ()> + 'a {
        poll_fn(|cx| self.poll_expired(cx, activity))
    }

    /// Poll form of [`IdleGuard::expired`], for use within a `poll_*` method.
    pub fn poll_expired(&mut self, cx: &mut Context<'_>, activity: &IdleActivity) -> Poll<()> {
        self.begin(Wait::Activity);
        let deadline = activity
            .deadline(self.timeout)
            .max(deadline_after(self.last, self.timeout));
        if let Some(sleep) = self.sleep.as_mut()
            && sleep.deadline() > deadline
        {
            sleep.as_mut().reset(deadline);
        }
        self.poll_idle(cx, Instant::now, || Some(activity.last()))
    }

    /// Completes once a timer of `timeout` fired without `progress` counting anything since
    /// it was armed, nor a [`IdleGuard::reset`] within `timeout`: between `timeout` and twice
    /// it after the last progress.
    pub fn stalled<'a>(&'a mut self, progress: &'a IdleProgress) -> impl Future<Output = ()> + 'a {
        poll_fn(|cx| self.poll_stalled(cx, progress))
    }

    /// Poll form of [`IdleGuard::stalled`], for use within a `poll_*` method.
    pub fn poll_stalled(&mut self, cx: &mut Context<'_>, progress: &IdleProgress) -> Poll<()> {
        self.poll_stalled_by(cx, || progress.count())
    }

    /// As [`IdleGuard::stalled`], with progress read from `count`: a total that starts at
    /// zero and grows with every step of progress, such as bytes moved by its owner.
    pub fn stalled_by<'a>(
        &'a mut self,
        count: impl Fn() -> u64 + 'a,
    ) -> impl Future<Output = ()> + 'a {
        poll_fn(move |cx| self.poll_stalled_by(cx, &count))
    }

    /// Poll form of [`IdleGuard::stalled_by`], for use within a `poll_*` method.
    pub fn poll_stalled_by(&mut self, cx: &mut Context<'_>, count: impl Fn() -> u64) -> Poll<()> {
        self.begin(Wait::Progress);
        self.poll_progress(cx, Instant::now, count)
    }

    /// Poll the progress deadline against the current counter.
    fn poll_progress(
        &mut self,
        cx: &mut Context<'_>,
        now: impl Fn() -> Instant,
        count: impl Fn() -> u64,
    ) -> Poll<()> {
        loop {
            ready!(self.timer().poll(cx));
            // Progress first: a window it opens then starts no earlier than the progress.
            let count = count();
            let now = now();
            if count != self.seen {
                self.seen = count;
                self.progress_deadline = deadline_after(now, self.timeout);
            }
            let deadline = self
                .progress_deadline
                .max(deadline_after(self.last, self.timeout));
            if deadline <= now {
                return Poll::Ready(());
            }
            self.timer().reset(deadline);
        }
    }

    /// Poll an idle deadline against its activity source.
    fn poll_idle(
        &mut self,
        cx: &mut Context<'_>,
        now: impl Fn() -> Instant,
        activity: impl Fn() -> Option<Instant>,
    ) -> Poll<()> {
        loop {
            ready!(self.timer().poll(cx));
            // The clock first: activity recorded after it can only defer expiry.
            let now = now();
            let last = activity().map_or(self.last, |activity| activity.max(self.last));
            let deadline = deadline_after(last, self.timeout);
            if deadline <= now {
                return Poll::Ready(());
            }
            self.timer().reset(deadline);
        }
    }
}

/// When a flow was last active, recorded from any task and read by an [`IdleGuard`]
/// when its deadline fires.
#[derive(Debug)]
pub struct IdleActivity {
    // An uncontended lock costs less per record than an atomic offset from an epoch.
    last: Mutex<Instant>,
}

impl IdleActivity {
    /// Create an [`IdleActivity`] whose last activity is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last: Mutex::new(Instant::now()),
        }
    }

    /// Record activity now.
    #[inline]
    pub fn record(&self) {
        self.record_at(Instant::now());
    }

    /// Record activity at the supplied timestamp.
    fn record_at(&self, now: Instant) {
        let mut last = self.last.lock();
        *last = (*last).max(now);
    }

    /// Read the most recent activity timestamp.
    fn last(&self) -> Instant {
        *self.last.lock()
    }

    /// `timeout` after the last recorded activity, saturating far in the future.
    #[must_use]
    pub fn deadline(&self, timeout: Duration) -> Instant {
        deadline_after(self.last(), timeout)
    }
}

impl Default for IdleActivity {
    fn default() -> Self {
        Self::new()
    }
}

/// Progress counted from any task and read by an [`IdleGuard`] when its timer fires.
///
/// Cheaper to record than an [`IdleActivity`], as it reads no clock, at the cost of
/// precision: see [`IdleGuard::stalled`].
#[derive(Debug, Default)]
pub struct IdleProgress {
    count: AtomicU64,
}

impl IdleProgress {
    /// Create an [`IdleProgress`] that counted nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one step of progress.
    #[inline]
    pub fn record(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Read the recorded progress count.
    fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, task::Waker, time::Duration};

    use tokio::time::{advance, sleep};

    use super::*;
    use crate::rt::future::now_or_never;

    #[test]
    fn guards_are_created_outside_a_runtime() {
        let activity = IdleActivity::new();
        let progress = IdleProgress::new();
        let mut guards = [
            IdleGuard::new(Duration::from_secs(1)),
            IdleGuard::for_activity(Duration::from_secs(1), &activity),
            IdleGuard::new(Duration::MAX),
        ];
        activity.record();
        progress.record();
        for guard in &mut guards {
            guard.reset();
        }
        assert_eq!(guards[2].timeout(), MAX_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_guard_first_polled_late_expires_from_its_creation() {
        let timeout = Duration::from_secs(10);
        let activity = IdleActivity::new();
        let progress = IdleProgress::new();
        let start = Instant::now();
        let mut fresh = IdleGuard::new(timeout);
        let mut following = IdleGuard::for_activity(timeout, &activity);
        let mut counting = IdleGuard::new(timeout);
        advance(Duration::from_secs(6)).await;
        tokio::join!(
            fresh.tick(),
            following.expired(&activity),
            counting.stalled(&progress)
        );
        assert_eq!(start.elapsed(), timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_guard_fires_after_timeout() {
        let mut guard = IdleGuard::new(Duration::from_millis(100));
        advance(Duration::from_millis(101)).await;
        assert!(now_or_never(guard.tick()).is_some());
    }

    /// Reads that see the clock first at `early` and later at `late`, or the reverse order.
    fn interleaved<T: Copy>(first: &Cell<bool>, early: T, late: T) -> T {
        if first.replace(false) { early } else { late }
    }

    #[tokio::test(start_paused = true)]
    async fn activity_recorded_while_the_clock_is_read_defers_expiry() {
        let start = Instant::now();
        let at = |millis| start + Duration::from_millis(millis);
        let mut guard = IdleGuard::new(Duration::from_secs(1));
        advance(Duration::from_millis(1_900)).await;
        // The first read runs at 1.0s, the second at 1.9s, with activity at 1.5s between.
        let first = Cell::new(true);
        let mut cx = Context::from_waker(Waker::noop());
        let polled = guard.poll_idle(
            &mut cx,
            || interleaved(&first, at(1_000), at(1_900)),
            || Some(interleaved(&first, at(800), at(1_500))),
        );
        assert!(polled.is_pending());
    }

    #[tokio::test(start_paused = true)]
    async fn progress_seen_by_a_late_read_is_given_a_full_window() {
        let start = Instant::now();
        let mut guard = IdleGuard::new(Duration::from_secs(1));
        advance(Duration::from_millis(2_100)).await;
        // The first read runs at 1.0s, the second at 2.1s, with progress at 2.0s between.
        let first = Cell::new(true);
        let observed = Cell::new(false);
        let mut cx = Context::from_waker(Waker::noop());
        let polled = guard.poll_progress(
            &mut cx,
            || interleaved(&first, start + Duration::from_secs(1), Instant::now()),
            || {
                let count = interleaved(&first, 0, 1);
                observed.set(observed.get() || count == 1);
                count
            },
        );
        assert!(polled.is_pending() || !observed.get());
    }

    #[tokio::test(start_paused = true)]
    async fn switching_waits_keeps_each_waits_deadline() {
        let timeout = Duration::from_secs(10);
        let progress = IdleProgress::new();
        let mut guard = IdleGuard::new(timeout);
        advance(Duration::from_secs(9)).await;
        progress.record();
        advance(Duration::from_secs(1)).await;
        // Seen at 10s, the progress moves the stall deadline to 20s.
        assert!(now_or_never(guard.stalled(&progress)).is_none());
        advance(Duration::from_secs(1)).await;
        // No reset since creation: a tick is due since 10s.
        assert!(now_or_never(guard.tick()).is_some());
        assert!(now_or_never(guard.stalled(&progress)).is_none());
        guard.stalled(&progress).await;
        assert_eq!(Instant::now(), guard.last + 2 * timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn switching_activity_sources_rechecks_the_deadline() {
        let timeout = Duration::from_secs(10);
        let a = IdleActivity::new();
        let b = IdleActivity::new();
        let mut guard = IdleGuard::new(timeout);
        advance(Duration::from_secs(9)).await;
        a.record();
        advance(Duration::from_secs(1)).await;
        assert!(now_or_never(guard.expired(&a)).is_none());
        advance(Duration::from_secs(1)).await;
        assert!(now_or_never(guard.expired(&b)).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_guard_reset_extends_window() {
        let mut guard = IdleGuard::new(Duration::from_millis(100));

        // Advance most of the way, then reset.
        advance(Duration::from_millis(80)).await;
        guard.reset();

        // Advance another 80ms — would have fired without reset.
        advance(Duration::from_millis(80)).await;

        // Race a short timeout against the guard; the guard should NOT have
        // fired yet (we've only spent 80ms since reset out of 100ms window).
        tokio::select! {
            biased;
            () = guard.tick() => panic!("idle guard fired prematurely"),
            () = sleep(Duration::from_millis(0)) => {}
        }

        // Advance past the reset deadline.
        advance(Duration::from_millis(30)).await;
        assert!(now_or_never(guard.tick()).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn tick_fires_exactly_timeout_after_the_last_reset() {
        let timeout = Duration::from_secs(10);
        let mut guard = IdleGuard::new(timeout);
        for _ in 0..3 {
            sleep(Duration::from_secs(4)).await;
            guard.reset();
        }
        let last = Instant::now();
        guard.tick().await;
        assert_eq!(last.elapsed(), timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn a_fired_tick_stays_ready_until_reset() {
        let timeout = Duration::from_secs(1);
        let mut guard = IdleGuard::new(timeout);
        guard.tick().await;
        let fired = Instant::now();
        guard.tick().await;
        assert_eq!(fired.elapsed(), Duration::ZERO);
        guard.reset();
        guard.tick().await;
        assert_eq!(fired.elapsed(), timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn a_guard_made_later_keeps_the_deadline_of_earlier_activity() {
        let timeout = Duration::from_secs(10);
        let activity = IdleActivity::new();
        let start = Instant::now();
        advance(Duration::from_secs(6)).await;
        let mut guard = IdleGuard::for_activity(timeout, &activity);
        guard.expired(&activity).await;
        assert_eq!(start.elapsed(), timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn a_reset_also_defers_expiry_on_shared_activity() {
        let timeout = Duration::from_secs(10);
        let activity = IdleActivity::new();
        let mut guard = IdleGuard::for_activity(timeout, &activity);
        advance(Duration::from_secs(6)).await;
        guard.reset();
        let last = Instant::now();
        guard.expired(&activity).await;
        assert_eq!(last.elapsed(), timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_fires_one_timer_after_the_last_progress_was_seen() {
        let timeout = Duration::from_secs(10);
        let progress = IdleProgress::new();
        let mut guard = IdleGuard::new(timeout);
        let start = Instant::now();
        sleep(Duration::from_secs(4)).await;
        progress.record();
        // The first timer sees the progress and arms another one from there.
        guard.stalled(&progress).await;
        assert_eq!(start.elapsed(), 2 * timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_without_progress_fires_after_one_timeout() {
        let timeout = Duration::from_secs(10);
        let progress = IdleProgress::new();
        let mut guard = IdleGuard::new(timeout);
        let start = Instant::now();
        guard.stalled(&progress).await;
        assert_eq!(start.elapsed(), timeout);
        // Fired, it stays so until progress or a reset.
        guard.stalled(&progress).await;
        assert_eq!(start.elapsed(), timeout);
        progress.record();
        guard.stalled(&progress).await;
        assert_eq!(start.elapsed(), 2 * timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_by_follows_its_own_total() {
        let timeout = Duration::from_secs(10);
        let total = AtomicU64::new(0);
        let mut guard = IdleGuard::new(timeout);
        let start = Instant::now();
        sleep(Duration::from_secs(4)).await;
        total.fetch_add(512, Ordering::Relaxed);
        guard.stalled_by(|| total.load(Ordering::Relaxed)).await;
        assert_eq!(start.elapsed(), 2 * timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn a_reset_also_defers_a_stall() {
        let timeout = Duration::from_secs(10);
        let progress = IdleProgress::new();
        let mut guard = IdleGuard::new(timeout);
        advance(Duration::from_secs(6)).await;
        guard.reset();
        let last = Instant::now();
        guard.stalled(&progress).await;
        assert_eq!(last.elapsed(), timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_record_keeps_the_most_recent_activity() {
        let timeout = Duration::from_secs(10);
        let activity = IdleActivity::new();
        let mut guard = IdleGuard::for_activity(timeout, &activity);
        let earlier = Instant::now();
        advance(Duration::from_secs(5)).await;
        activity.record();
        let latest = Instant::now();
        // The first recorder resumes after the second one released the lock.
        activity.record_at(earlier);
        guard.expired(&activity).await;
        assert_eq!(latest.elapsed(), timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn activity_just_before_the_deadline_postpones_expiry() {
        let timeout = Duration::from_secs(10);
        let activity = IdleActivity::new();
        let mut guard = IdleGuard::for_activity(timeout, &activity);
        let before_deadline = Duration::from_millis(9_999);
        let start = Instant::now();
        sleep(before_deadline).await;
        activity.record();
        guard.expired(&activity).await;
        assert_eq!(start.elapsed(), before_deadline + timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_fires_shortly_after_the_last_activity() {
        let timeout = Duration::from_millis(50);
        let activity = IdleActivity::new();
        let mut guard = IdleGuard::for_activity(timeout, &activity);
        for _ in 0..3 {
            sleep(Duration::from_millis(20)).await;
            activity.record();
        }
        let last = Instant::now();
        guard.expired(&activity).await;
        let idle = last.elapsed();
        assert!(idle >= timeout, "expired early: {idle:?}");
        assert!(
            idle < timeout + Duration::from_millis(40),
            "expired late: {idle:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_huge_timeout_neither_panics_nor_expires() {
        let activity = IdleActivity::new();
        let mut guard = IdleGuard::for_activity(Duration::MAX, &activity);
        activity.record();
        guard.reset();
        let mut fresh = IdleGuard::new(Duration::MAX);
        tokio::select! {
            biased;
            () = guard.expired(&activity) => panic!("a huge timeout expired"),
            () = fresh.tick() => panic!("a huge timeout elapsed"),
            () = sleep(Duration::from_hours(24 * 365)) => {}
        }
    }
}
