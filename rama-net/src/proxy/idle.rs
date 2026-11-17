//! [`IdleGuard`] — a small helper for detecting idleness in a `tokio::select!` loop.

use std::pin::Pin;
use std::time::Duration;

use parking_lot::Mutex;
use rama_utils::time::deadline_after;
use tokio::time::{Instant, Sleep};

/// The far future of a tokio sleep: a bound below it keeps every reset an unchecked add.
const MAX_TIMEOUT: Duration = Duration::from_hours(24 * 365 * 30);

/// A resettable idle deadline.
///
/// Designed to be used as one arm of a `tokio::select!`: poll [`IdleGuard::tick`]
/// in the select; when another arm fires (i.e. progress was observed) call
/// [`IdleGuard::reset`] before re-entering the select to extend the idle window.
///
/// If the inner [`Sleep`] elapses before [`reset`](IdleGuard::reset) is called,
/// the idle window has lapsed.
///
/// When activity is observed elsewhere, at a rate where resetting a timer per event
/// costs too much, record it on an [`IdleActivity`] and poll [`IdleGuard::expired`]
/// instead: the timer is only re-armed when it fires.
///
/// `IdleGuard` is intended for cases where the watched activity does not itself
/// produce values that can be selected on (e.g. byte progress observed inside
/// another future). For values that can be selected on, prefer racing the
/// activity directly.
pub struct IdleGuard {
    timeout: Duration,
    sleep: Pin<Box<Sleep>>,
}

impl core::fmt::Debug for IdleGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdleGuard")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl IdleGuard {
    /// Create a new [`IdleGuard`] that fires after `timeout` of inactivity.
    ///
    /// Timeouts beyond thirty years are capped there, tokio's own far future.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        let timeout = timeout.min(MAX_TIMEOUT);
        Self::until(deadline_after(Instant::now(), timeout), timeout)
    }

    /// Create an [`IdleGuard`] that fires `timeout` after the last activity recorded on
    /// `activity`, for use with [`IdleGuard::expired`].
    ///
    /// Timeouts beyond thirty years are capped there, tokio's own far future.
    #[must_use]
    pub fn for_activity(timeout: Duration, activity: &IdleActivity) -> Self {
        let timeout = timeout.min(MAX_TIMEOUT);
        Self::until(activity.deadline(timeout), timeout)
    }

    fn until(deadline: Instant, timeout: Duration) -> Self {
        Self {
            timeout,
            sleep: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }

    /// The configured idle timeout, capped at thirty years.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Reset the idle deadline to `now + timeout`. Call this whenever progress
    /// has been observed, before re-entering the select that polls
    /// [`IdleGuard::tick`].
    pub fn reset(&mut self) {
        // Capped like a tokio sleep, which adds its far future to now the same way.
        let deadline = Instant::now() + self.timeout;
        self.sleep.as_mut().reset(deadline);
    }

    /// Poll-able future that completes when the idle window has elapsed.
    ///
    /// Borrow-and-poll inside `tokio::select!`. Once it completes, the guard
    /// is considered tripped — call [`IdleGuard::reset`] before re-arming if
    /// you want to keep waiting.
    pub fn tick(&mut self) -> &mut Pin<Box<Sleep>> {
        &mut self.sleep
    }

    /// Completes once `timeout` passed since the last activity recorded on `activity`.
    ///
    /// Cancel safe: dropping the future keeps the deadline, so it can be polled again
    /// from every iteration of a `tokio::select!` loop.
    pub async fn expired(&mut self, activity: &IdleActivity) {
        loop {
            self.sleep.as_mut().await;
            let deadline = activity.deadline(self.timeout);
            if deadline <= Instant::now() {
                return;
            }
            self.sleep.as_mut().reset(deadline);
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
        let now = Instant::now();
        *self.last.lock() = now;
    }

    /// `timeout` after the last recorded activity, saturating far in the future.
    #[must_use]
    pub fn deadline(&self, timeout: Duration) -> Instant {
        deadline_after(*self.last.lock(), timeout)
    }
}

impl Default for IdleActivity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn idle_guard_fires_after_timeout() {
        let mut guard = IdleGuard::new(Duration::from_millis(100));
        tokio::time::advance(Duration::from_millis(101)).await;
        // Should be ready immediately after enough virtual time has passed.
        guard.tick().await;
    }

    #[tokio::test(start_paused = true)]
    async fn idle_guard_reset_extends_window() {
        let mut guard = IdleGuard::new(Duration::from_millis(100));

        // Advance most of the way, then reset.
        tokio::time::advance(Duration::from_millis(80)).await;
        guard.reset();

        // Advance another 80ms — would have fired without reset.
        tokio::time::advance(Duration::from_millis(80)).await;

        // Race a short timeout against the guard; the guard should NOT have
        // fired yet (we've only spent 80ms since reset out of 100ms window).
        tokio::select! {
            biased;
            _ = guard.tick() => panic!("idle guard fired prematurely"),
            _ = tokio::time::sleep(Duration::from_millis(0)) => {}
        }

        // Advance past the reset deadline.
        tokio::time::advance(Duration::from_millis(30)).await;
        guard.tick().await;
    }

    #[tokio::test(start_paused = true)]
    async fn activity_just_before_the_deadline_postpones_expiry() {
        let timeout = Duration::from_secs(10);
        let activity = IdleActivity::new();
        let mut guard = IdleGuard::for_activity(timeout, &activity);
        let before_deadline = Duration::from_millis(9_999);
        let start = Instant::now();
        tokio::time::sleep(before_deadline).await;
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
            tokio::time::sleep(Duration::from_millis(20)).await;
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
            () = tokio::time::sleep(Duration::from_hours(24 * 365)) => {}
        }
    }
}
