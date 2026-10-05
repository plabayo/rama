use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use rama_utils::rate::{Acquire, Rate, RateLimiter, RefundWait, TokenBucket};
use tokio::time::{Instant, Sleep, sleep_until};

use super::ThrottleMode;
use crate::gate::StreamGate;

/// The [`StreamGate`] that throttles one direction of a single IO.
///
/// A [`ThrottledIo`](super::ThrottledIo) holds one per direction of a byte stream, and
/// [`ThrottleGates`](super::ThrottleGates) opens one per stream direction of a multiplexed
/// connection.
///
/// Must be polled within a tokio runtime context.
pub struct ThrottleBudget {
    bucket: Bucket,
    burst: u64,
    quantum: u64,
    /// Budget reserved for the IO poll currently in progress.
    reserved: u64,
    sleep: Option<Pin<Box<Sleep>>>,
    sleeping: bool,
    refund_wait: Option<RefundWait>,
}

impl fmt::Debug for ThrottleBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThrottleBudget")
            .field("bucket", &self.bucket)
            .field("burst", &self.burst)
            .field("quantum", &self.quantum)
            .field("reserved", &self.reserved)
            .field("sleep", &self.sleep)
            .field("sleeping", &self.sleeping)
            .field("waiting_for_refund", &self.refund_wait.is_some())
            .finish()
    }
}

impl ThrottleBudget {
    /// Create a [`ThrottleBudget`] spending from `mode`, with the default grant quantum.
    #[must_use]
    pub fn new(mode: ThrottleMode) -> Self {
        let (bucket, rate, burst) = match mode {
            ThrottleMode::PerConn { rate, burst } => (
                Bucket::Own {
                    bucket: TokenBucket::new(rate, burst),
                    epoch: Instant::now(),
                },
                rate,
                burst,
            ),
            ThrottleMode::Shared(limiter) => {
                let rate = limiter.rate();
                let burst = limiter.burst();
                (Bucket::Shared(limiter), rate, burst)
            }
        };
        Self {
            bucket,
            burst,
            quantum: super::default_quantum(rate).clamp(1, burst),
            reserved: 0,
            sleep: None,
            sleeping: false,
            refund_wait: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override the grant quantum in bytes: the budget reserved per IO operation (clamped
        /// to the burst capacity).
        ///
        /// Defaults to a tenth of a period worth of bytes, at most 16 KiB.
        pub fn quantum(mut self, quantum: Option<u64>) -> Self {
            self.quantum = quantum
                .unwrap_or_else(|| super::default_quantum(self.bucket.rate()))
                .clamp(1, self.burst);
            self
        }
    }
}

impl StreamGate for ThrottleBudget {
    /// Sleeps until the bucket allows the next IO operation (up to) `want` bytes, at most
    /// the quantum. A pending operation settles zero, so an idle IO holds no capacity.
    fn poll_admit(&mut self, cx: &mut Context<'_>, want: u64) -> Poll<u64> {
        loop {
            if self.reserved > 0 {
                return Poll::Ready(self.reserved);
            }
            if self
                .refund_wait
                .as_mut()
                .is_some_and(|wait| Pin::new(wait).poll(cx).is_ready())
            {
                self.refund_wait = None;
                self.sleeping = false;
                continue;
            }
            let want = want.min(self.quantum).max(1);
            let mut acquire = self.bucket.try_acquire(want);
            if matches!(acquire, Acquire::RetryAt(_)) && self.refund_wait.is_none() {
                self.refund_wait = self.bucket.refund_wait();
                if self
                    .refund_wait
                    .as_mut()
                    .is_some_and(|wait| Pin::new(wait).poll(cx).is_ready())
                {
                    self.refund_wait = None;
                    self.sleeping = false;
                    continue;
                }
                // The listener is registered now. Retry once to close the
                // window in which a refund could have landed after the first
                // budget check but before waker registration.
                acquire = self.bucket.try_acquire(want);
            }
            match acquire {
                Acquire::Granted => {
                    self.refund_wait = None;
                    self.sleeping = false;
                    self.reserved = want;
                    return Poll::Ready(want);
                }
                Acquire::RetryAt(at) => {
                    let deadline = self.bucket.deadline(at);
                    let sleep = self
                        .sleep
                        .get_or_insert_with(|| Box::pin(sleep_until(deadline)));
                    if !self.sleeping {
                        sleep.as_mut().reset(deadline);
                        self.sleeping = true;
                    }
                    ready!(sleep.as_mut().poll(cx));
                    self.sleeping = false;
                }
                Acquire::Never => {
                    // defence-in-depth: want is clamped to the quantum,
                    // which is clamped to the burst capacity
                    debug_assert!(false, "quantum-clamped reserve reported Acquire::Never");
                    self.reserved = want;
                    return Poll::Ready(want);
                }
            }
        }
    }

    /// The unused remainder of the admission is refunded.
    fn settle(&mut self, used: u64) {
        let unused = self.reserved.saturating_sub(used);
        if unused > 0 {
            self.bucket.refund(unused);
        }
        self.reserved = 0;
    }
}

#[derive(Debug)]
enum Bucket {
    Own { bucket: TokenBucket, epoch: Instant },
    Shared(RateLimiter),
}

impl Bucket {
    fn rate(&self) -> Rate {
        match self {
            Self::Own { bucket, .. } => bucket.rate(),
            Self::Shared(limiter) => limiter.rate(),
        }
    }

    fn try_acquire(&mut self, n: u64) -> Acquire {
        match self {
            Self::Own { bucket, epoch } => {
                let now =
                    u64::try_from(Instant::now().saturating_duration_since(*epoch).as_nanos())
                        .unwrap_or(u64::MAX);
                bucket.try_acquire(now, n)
            }
            Self::Shared(limiter) => limiter.try_acquire(n),
        }
    }

    fn refund(&mut self, n: u64) {
        match self {
            Self::Own { bucket, .. } => bucket.refund(n),
            Self::Shared(limiter) => limiter.refund(n),
        }
    }

    fn refund_wait(&self) -> Option<RefundWait> {
        match self {
            Self::Own { .. } => None,
            Self::Shared(limiter) => Some(limiter.notified_on_refund()),
        }
    }

    fn deadline(&self, retry_at_nanos: u64) -> Instant {
        match self {
            Self::Own { epoch, .. } => epoch
                .checked_add(Duration::from_nanos(retry_at_nanos))
                // saturated retry-at with an extreme rate config: far enough
                .unwrap_or_else(|| {
                    Instant::now()
                        .checked_add(Duration::from_hours(8_760))
                        .unwrap_or_else(Instant::now)
                }),
            Self::Shared(limiter) => limiter.deadline(retry_at_nanos),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_grant_replaces_a_stale_deadline() {
        let limiter = RateLimiter::new(Rate::per_sec(100), 100);
        let mut state = ThrottleBudget::new(ThrottleMode::shared(limiter)).with_quantum(100);
        let mut cx = Context::from_waker(std::task::Waker::noop());

        assert_eq!(state.poll_admit(&mut cx, 100), Poll::Ready(100));
        state.settle(100);
        assert!(state.poll_admit(&mut cx, 100).is_pending());

        tokio::time::advance(Duration::from_millis(10)).await;
        assert_eq!(state.poll_admit(&mut cx, 1), Poll::Ready(1));
        state.settle(1);
        assert!(!state.sleeping);

        let start = Instant::now();
        let reserved = std::future::poll_fn(|cx| state.poll_admit(cx, 10)).await;
        state.settle(reserved);
        assert_eq!(start.elapsed(), Duration::from_millis(100));
    }
}
