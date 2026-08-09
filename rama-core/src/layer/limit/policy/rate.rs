//! A [`Policy`] that limits the rate of inputs.
//!
//! See [`RatePolicy`].
//!
//! # Examples
//!
//! ```
//! use rama_core::layer::limit::{Limit, policy::RatePolicy};
//! use rama_core::service::service_fn;
//! use rama_core::{Service, ServiceInput};
//! use rama_utils::rate::Rate;
//! # use core::convert::Infallible;
//!
//! # #[tokio::main]
//! # async fn main() {
//!
//! let service = service_fn(async || {
//!     Ok::<_, Infallible>(())
//! });
//! let mut service = Limit::new(service, RatePolicy::abort(Rate::per_sec(100)));
//!
//! let response = service.serve(ServiceInput::new(())).await;
//! assert!(response.is_ok());
//! # }
//! ```

use core::fmt;
use core::time::Duration;

use super::{Policy, PolicyOutput, PolicyResult};
use rama_utils::rate::{Acquire, Rate, RateLimiter};

/// A [`Policy`] that limits the rate of inputs: one unit is spent from a
/// shared token bucket per input.
///
/// Two modes:
///
/// - [`RatePolicy::abort`]: an input beyond the budget is aborted with
///   [`RateLimitReached`] — the classic rate-limit path (e.g. mapped
///   to `429 Too Many Requests`, using the carried
///   [`retry_after`](RateLimitReached::retry_after)).
/// - [`RatePolicy::wait`]: an input beyond the budget waits until the
///   bucket allows it — natural pacing, no error path.
///
/// Cloning shares the underlying [`RateLimiter`] (same budget), just like
/// cloning a [`ConcurrentPolicy`] shares its tracker. To share one budget
/// across differently-configured policies or stacks, construct a
/// [`RateLimiter`] yourself and use [`RatePolicy::abort_with_limiter`] /
/// [`RatePolicy::wait_with_limiter`].
///
/// To combine "at most N in flight" with "at most M per second", stack
/// two limit layers, with the rate limit outside the concurrency limit
/// (cheap rejection first, no concurrency slot consumed).
///
/// [`ConcurrentPolicy`]: super::ConcurrentPolicy
#[derive(Debug, Clone)]
pub struct RatePolicy {
    limiter: RateLimiter,
    mode: Mode,
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Wait,
    Abort,
}

impl RatePolicy {
    /// Create a new [`RatePolicy`] that paces inputs beyond
    /// the given [`Rate`]: they wait, they never fail.
    #[must_use]
    pub fn wait(rate: Rate) -> Self {
        Self::wait_with_limiter(RateLimiter::from_rate(rate))
    }

    /// Create a new [`RatePolicy`] that aborts inputs beyond
    /// the given [`Rate`] with [`RateLimitReached`].
    #[must_use]
    pub fn abort(rate: Rate) -> Self {
        Self::abort_with_limiter(RateLimiter::from_rate(rate))
    }

    /// Like [`RatePolicy::wait`], with a caller-provided (shareable)
    /// [`RateLimiter`].
    #[must_use]
    pub fn wait_with_limiter(limiter: RateLimiter) -> Self {
        Self {
            limiter,
            mode: Mode::Wait,
        }
    }

    /// Like [`RatePolicy::abort`], with a caller-provided (shareable)
    /// [`RateLimiter`].
    #[must_use]
    pub fn abort_with_limiter(limiter: RateLimiter) -> Self {
        Self {
            limiter,
            mode: Mode::Abort,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override the burst capacity (default: one period worth of units).
        ///
        /// This rebuilds the policy's own [`RateLimiter`]: any previously
        /// shared budget handle is disconnected.
        pub fn burst(mut self, burst: u64) -> Self {
            self.limiter = RateLimiter::new(self.limiter.rate(), burst);
            self
        }
    }

    /// The [`RateLimiter`] enforcing this policy's budget
    /// (clone it to share the budget elsewhere).
    #[must_use]
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }
}

impl<Input> Policy<Input> for RatePolicy
where
    Input: Send + 'static,
{
    type Guard = ();
    type Error = RateLimitReached;

    async fn check(&self, input: Input) -> PolicyResult<Input, Self::Guard, Self::Error> {
        let output = match self.mode {
            Mode::Wait => {
                self.limiter.acquire(1).await;
                PolicyOutput::Ready(())
            }
            Mode::Abort => match self.limiter.try_acquire(1) {
                Acquire::Granted => PolicyOutput::Ready(()),
                Acquire::RetryAt(at) => {
                    let retry_after = self
                        .limiter
                        .deadline(at)
                        .saturating_duration_since(tokio::time::Instant::now());
                    PolicyOutput::Abort(RateLimitReached { retry_after })
                }
                Acquire::Never => {
                    // defence-in-depth: cost is 1 and burst is non-zero,
                    // so a single unit can always eventually be granted
                    debug_assert!(false, "single unit reported Acquire::Never");
                    PolicyOutput::Abort(RateLimitReached {
                        retry_after: Duration::ZERO,
                    })
                }
            },
        };
        PolicyResult { input, output }
    }
}

/// The error returned by [`RatePolicy`] in abort mode when the rate
/// limit is exhausted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateLimitReached {
    /// Duration after which a retry can be granted.
    ///
    /// Suitable to surface as a `Retry-After` header on a
    /// `429 Too Many Requests` response.
    pub retry_after: Duration,
}

impl RateLimitReached {
    /// Create a new [`RateLimitReached`] error.
    #[must_use]
    pub const fn new(retry_after: Duration) -> Self {
        Self { retry_after }
    }
}

impl fmt::Display for RateLimitReached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "serve aborted due to exhausted rate limit (retry after {:?})",
            self.retry_after
        )
    }
}

impl core::error::Error for RateLimitReached {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::std::sync::Arc;
    use std::time::Duration;
    use tokio::time::Instant;

    fn assert_ready<R, G, E>(result: PolicyResult<R, G, E>) -> G {
        match result.output {
            PolicyOutput::Ready(guard) => guard,
            PolicyOutput::Abort(_) | PolicyOutput::Retry => {
                panic!("unexpected output, expected ready")
            }
        }
    }

    fn assert_abort<R, G>(result: PolicyResult<R, G, RateLimitReached>) -> RateLimitReached {
        match result.output {
            PolicyOutput::Abort(err) => err,
            PolicyOutput::Ready(_) | PolicyOutput::Retry => {
                panic!("unexpected output, expected abort")
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn abort_mode_rejects_with_retry_after() {
        let policy = RatePolicy::abort(rama_utils::rate::Rate::per_sec(2));

        assert_ready(policy.check(()).await);
        assert_ready(policy.check(()).await);

        let err = assert_abort(policy.check(()).await);
        assert_eq!(err.retry_after, Duration::from_millis(500));

        tokio::time::advance(err.retry_after).await;
        assert_ready(policy.check(()).await);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_mode_paces() {
        let policy = RatePolicy::wait(rama_utils::rate::Rate::per_sec(10));

        let start = Instant::now();
        // burst of 10 passes instantly ...
        for _ in 0..10 {
            assert_ready(policy.check(()).await);
        }
        assert_eq!(start.elapsed(), Duration::ZERO);

        // ... after which every input waits for the next unit
        for i in 1..=3u64 {
            assert_ready(policy.check(()).await);
            assert_eq!(start.elapsed(), Duration::from_millis(i * 100));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn clone_shares_the_budget() {
        let policy = RatePolicy::abort(rama_utils::rate::Rate::per_sec(2));
        let policy_clone = policy.clone();

        assert_ready(policy.check(()).await);
        assert_ready(policy_clone.check(()).await);
        assert_abort(policy.check(()).await);
    }

    #[tokio::test(start_paused = true)]
    async fn shared_limiter_across_policies() {
        let limiter = rama_utils::rate::RateLimiter::from_rate(rama_utils::rate::Rate::per_sec(2));
        let policy_a = RatePolicy::abort_with_limiter(limiter.clone());
        let policy_b = RatePolicy::abort_with_limiter(limiter);

        assert_ready(policy_a.check(()).await);
        assert_ready(policy_b.check(()).await);
        assert_abort(policy_a.check(()).await);
        assert_abort(policy_b.check(()).await);
    }

    #[tokio::test(start_paused = true)]
    async fn burst_override() {
        let policy = RatePolicy::abort(rama_utils::rate::Rate::per_sec(1)).with_burst(3);

        for _ in 0..3 {
            assert_ready(policy.check(()).await);
        }
        assert_abort(policy.check(()).await);
    }

    #[tokio::test(start_paused = true)]
    async fn composes_with_matcher_policy_map() {
        use crate::extensions::Extensions;

        let policy = Arc::new(vec![(
            true,
            RatePolicy::abort(rama_utils::rate::Rate::per_sec(1)),
        )]);

        assert!(matches!(
            policy.check(Extensions::new()).await.output,
            PolicyOutput::Ready(_)
        ));
        assert!(matches!(
            policy.check(Extensions::new()).await.output,
            PolicyOutput::Abort(_)
        ));
    }
}
