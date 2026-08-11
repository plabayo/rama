use super::{Acquire, Rate, TokenBucket};

use parking_lot::Mutex;
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;

/// A cheap-to-clone async handle around a shared [`TokenBucket`]:
/// clones share the same budget.
///
/// Two ways to consume it:
///
/// - [`RateLimiter::acquire`] waits until the budget allows (pacing);
/// - [`RateLimiter::try_acquire`] never waits and reports when to retry
///   (rejecting, e.g. a 429 path).
///
/// Time is tracked against a per-limiter epoch taken at construction,
/// using tokio's clock (so paused-time tests work as expected).
///
/// There is no FIFO fairness guarantee between concurrent waiters. Under a
/// sustained stream of smaller acquisitions, a larger acquisition can be
/// repeatedly beaten to newly refilled tokens and starve; callers that need
/// strict waiter fairness must serialize acquisitions above this primitive.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    bucket: Mutex<TokenBucket>,
    epoch: Instant,
    rate: Rate,
    burst: u64,
}

impl RateLimiter {
    /// Create a new [`RateLimiter`] with the given [`Rate`] and
    /// burst capacity, starting full.
    ///
    /// # Panics
    ///
    /// Panics if `burst` is zero.
    #[must_use]
    pub fn new(rate: Rate, burst: u64) -> Self {
        Self::from_bucket(TokenBucket::new(rate, burst))
    }

    /// Create a new [`RateLimiter`] with a burst capacity of one period
    /// worth of units (`rate.units()`): a plain smooth rate.
    #[must_use]
    pub fn from_rate(rate: Rate) -> Self {
        Self::from_bucket(TokenBucket::from_rate(rate))
    }

    fn from_bucket(bucket: TokenBucket) -> Self {
        Self {
            inner: Arc::new(Inner {
                rate: bucket.rate(),
                burst: bucket.burst(),
                bucket: Mutex::new(bucket),
                epoch: Instant::now(),
            }),
        }
    }

    /// The configured [`Rate`].
    #[must_use]
    pub fn rate(&self) -> Rate {
        self.inner.rate
    }

    /// The configured burst capacity.
    #[must_use]
    pub fn burst(&self) -> u64 {
        self.inner.burst
    }

    fn now_nanos(&self) -> u64 {
        Instant::now()
            .saturating_duration_since(self.inner.epoch)
            .as_nanos() as u64
    }

    /// Try to spend `n` units without waiting.
    ///
    /// See [`TokenBucket::try_acquire`]; the [`Acquire::RetryAt`] instant
    /// is in this limiter's clock and can be turned into a deadline
    /// with [`RateLimiter::deadline`].
    pub fn try_acquire(&self, n: u64) -> Acquire {
        self.inner.bucket.lock().try_acquire(self.now_nanos(), n)
    }

    /// Spend `n` units, waiting until the budget allows it.
    ///
    /// Requests larger than the burst capacity are acquired in
    /// burst-sized chunks, so this never fails: it paces.
    /// Concurrent acquisitions are not queued fairly; see the type docs.
    ///
    /// Dropping the future while it waits for a chunk spends nothing for that
    /// chunk. For a request larger than the burst, chunks already acquired
    /// before cancellation stay spent. Refunding them could mint capacity when
    /// concurrent users spent refill produced while those chunks were held.
    pub async fn acquire(&self, n: u64) {
        let mut remaining = n;
        while remaining > 0 {
            let want = remaining.min(self.inner.burst);
            match self.try_acquire(want) {
                Acquire::Granted => {
                    remaining -= want;
                }
                Acquire::RetryAt(at) => tokio::time::sleep_until(self.deadline(at)).await,
                Acquire::Never => {
                    // defence-in-depth: chunks are clamped to the burst
                    // capacity, so this cannot fire; bail rather than spin
                    debug_assert!(false, "burst-clamped chunk reported Acquire::Never");
                    break;
                }
            }
        }
    }

    /// Give back up to `n` previously spent units, saturating at the
    /// burst capacity.
    pub fn refund(&self, n: u64) {
        self.inner.bucket.lock().refund(n);
    }

    /// Turn an [`Acquire::RetryAt`] instant into a timer deadline,
    /// for poll-based callers.
    #[must_use]
    pub fn deadline(&self, retry_at_nanos: u64) -> Instant {
        self.inner
            .epoch
            .checked_add(Duration::from_nanos(retry_at_nanos))
            // saturated retry-at with an extreme rate config: far enough
            .unwrap_or_else(|| Instant::now() + Duration::from_hours(24 * 365))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn acquire_paces_exactly() {
        let limiter = RateLimiter::from_rate(Rate::per_sec(10));
        limiter.acquire(10).await; // drain the initial burst

        let start = Instant::now();
        for i in 1..=5u64 {
            limiter.acquire(1).await;
            assert_eq!(start.elapsed(), Duration::from_millis(i * 100));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_chunks_oversized_requests() {
        let limiter = RateLimiter::new(Rate::per_sec(10), 10);

        let start = Instant::now();
        // 25 units at 10/s with a full 10-unit start:
        // 10 now, 10 at +1s, 5 at +1.5s
        limiter.acquire(25).await;
        assert_eq!(start.elapsed(), Duration::from_millis(1_500));
    }

    #[tokio::test(start_paused = true)]
    async fn try_acquire_never_waits() {
        let limiter = RateLimiter::new(Rate::per_sec(2), 2);
        assert_eq!(limiter.try_acquire(2), Acquire::Granted);

        let retry_at = match limiter.try_acquire(1) {
            Acquire::RetryAt(at) => at,
            other => panic!("expected retry-at, got {other:?}"),
        };
        assert_eq!(
            limiter.deadline(retry_at),
            Instant::now() + Duration::from_millis(500)
        );
        assert_eq!(limiter.try_acquire(3), Acquire::Never);
    }

    #[tokio::test(start_paused = true)]
    async fn clones_share_the_budget() {
        let limiter = RateLimiter::new(Rate::per_sec(10), 2);
        let clone = limiter.clone();

        assert_eq!(limiter.try_acquire(1), Acquire::Granted);
        assert_eq!(clone.try_acquire(1), Acquire::Granted);
        assert!(matches!(clone.try_acquire(1), Acquire::RetryAt(_)));

        limiter.refund(1);
        assert_eq!(clone.try_acquire(1), Acquire::Granted);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_oversized_acquire_does_not_mint_shared_budget() {
        let limiter = RateLimiter::new(Rate::per_sec(10), 10);
        limiter.acquire(10).await; // drain the initial burst

        let acquire_limiter = limiter.clone();
        let task = tokio::spawn(async move { acquire_limiter.acquire(20).await });
        tokio::task::yield_now().await;

        // The oversized acquire takes its first 10-unit chunk at +1s and is
        // then waiting for the second. A concurrent user spends the five
        // units that refill before +1.5s.
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(500)).await;
        tokio::task::yield_now().await;
        assert_eq!(limiter.try_acquire(5), Acquire::Granted);

        task.abort();
        let _cancelled = task.await;

        // Refunding the first chunk here would restore a full burst even
        // though the concurrent user already spent the intervening refill.
        assert!(matches!(limiter.try_acquire(1), Acquire::RetryAt(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_within_burst_is_cancel_safe() {
        let limiter = RateLimiter::new(Rate::per_sec(10), 10);
        limiter.acquire(10).await; // drain the initial burst

        // a single-chunk acquire only ever grants at the very end, so a
        // cancel mid-wait spends nothing to begin with.
        let cancelled = tokio::time::timeout(Duration::from_millis(500), limiter.acquire(10)).await;
        cancelled.unwrap_err();
        // one unit refilled after 100ms and none was consumed
        assert_eq!(limiter.try_acquire(5), Acquire::Granted);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_waiters_all_proceed() {
        let limiter = RateLimiter::from_rate(Rate::per_sec(10));
        limiter.acquire(10).await;

        let start = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..5 {
            let limiter = limiter.clone();
            set.spawn(async move { limiter.acquire(1).await });
        }
        while let Some(res) = set.join_next().await {
            res.unwrap();
        }
        // 5 units at 10/s from an empty bucket
        assert_eq!(start.elapsed(), Duration::from_millis(500));
    }
}
