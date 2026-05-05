//! [`IdleGuard`] — a small helper for detecting idleness in a `tokio::select!` loop.

use std::pin::Pin;
use std::time::Duration;
use tokio::time::{Instant, Sleep};

/// A resettable idle deadline.
///
/// Designed to be used as one arm of a `tokio::select!`: poll [`IdleGuard::tick`]
/// in the select; when another arm fires (i.e. progress was observed) call
/// [`IdleGuard::reset`] before re-entering the select to extend the idle window.
///
/// If the inner [`Sleep`] elapses before [`reset`](IdleGuard::reset) is called,
/// the idle window has lapsed.
///
/// `IdleGuard` is intended for cases where the watched activity does not itself
/// produce values that can be selected on (e.g. byte progress observed inside
/// another future). For values that can be selected on, prefer racing the
/// activity directly.
pub struct IdleGuard {
    timeout: Duration,
    sleep: Pin<Box<Sleep>>,
}

impl std::fmt::Debug for IdleGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdleGuard")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl IdleGuard {
    /// Create a new [`IdleGuard`] that fires after `timeout` of inactivity.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            sleep: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    /// The configured idle timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Reset the idle deadline to `now + timeout`. Call this whenever progress
    /// has been observed, before re-entering the select that polls
    /// [`IdleGuard::tick`].
    pub fn reset(&mut self) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
}
