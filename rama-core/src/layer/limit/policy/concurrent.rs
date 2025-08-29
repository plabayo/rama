//! A [`Policy`] that limits the number of concurrent requests.
//!
//! See [`ConcurrentPolicy`].
//!
//! # Examples
//!
//! ```
//! use rama_core::layer::limit::{Limit, policy::ConcurrentPolicy};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service};
//! # use std::convert::Infallible;
//!
//! # #[tokio::main]
//! # async fn main() {
//!
//! let service = service_fn(async |_, _| {
//!     Ok::<_, Infallible>(())
//! });
//! let mut service = Limit::new(service, ConcurrentPolicy::max(2));
//!
//! let response = service.serve(Context::default(), ()).await;
//! assert!(response.is_ok());
//! # }
//! ```

use super::{Policy, PolicyOutput, PolicyResult};
use crate::Context;
use parking_lot::Mutex;
use rama_utils::backoff::Backoff;
use std::fmt;
use std::sync::Arc;

/// A [`Policy`] that limits the number of concurrent requests.
pub struct ConcurrentPolicy<B, C> {
    tracker: C,
    backoff: B,
}

impl<B: fmt::Debug, C: fmt::Debug> std::fmt::Debug for ConcurrentPolicy<B, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrentPolicy")
            .field("tracker", &self.tracker)
            .field("backoff", &self.backoff)
            .finish()
    }
}

impl<B, C> Clone for ConcurrentPolicy<B, C>
where
    B: Clone,
    C: Clone,
{
    fn clone(&self) -> Self {
        Self {
            tracker: self.tracker.clone(),
            backoff: self.backoff.clone(),
        }
    }
}

impl<B, C> ConcurrentPolicy<B, C> {
    /// Create a new [`ConcurrentPolicy`], using the given [`ConcurrentTracker`],
    /// and the given [`Backoff`] policy.
    ///
    /// The [`Backoff`] policy is used to backoff when the concurrent request limit is reached.
    pub fn with_backoff(backoff: B, tracker: C) -> Self {
        Self { tracker, backoff }
    }
}

impl<C> ConcurrentPolicy<(), C> {
    /// Create a new [`ConcurrentPolicy`], using the given [`ConcurrentTracker`].
    pub const fn new(tracker: C) -> Self {
        Self {
            tracker,
            backoff: (),
        }
    }
}

impl ConcurrentPolicy<(), ConcurrentCounter> {
    /// Create a new concurrent policy,
    /// which aborts the request if the `max` limit is reached.
    #[must_use]
    pub fn max(max: usize) -> Self {
        Self {
            tracker: ConcurrentCounter::new(max),
            backoff: (),
        }
    }
}

impl<B> ConcurrentPolicy<B, ConcurrentCounter> {
    /// Create a new concurrent policy,
    /// which backs off if the limit is reached,
    /// using the given backoff policy.
    pub fn max_with_backoff(max: usize, backoff: B) -> Self {
        Self {
            tracker: ConcurrentCounter::new(max),
            backoff,
        }
    }
}

impl<B, C, Request> Policy<Request> for ConcurrentPolicy<B, C>
where
    B: Backoff,
    Request: Send + 'static,
    C: ConcurrentTracker,
{
    type Guard = C::Guard;
    type Error = C::Error;

    async fn check(
        &self,
        ctx: Context,
        request: Request,
    ) -> PolicyResult<Request, Self::Guard, Self::Error> {
        let tracker_err = match self.tracker.try_access() {
            Ok(guard) => {
                return PolicyResult {
                    ctx,
                    request,
                    output: PolicyOutput::Ready(guard),
                };
            }
            Err(err) => err,
        };

        let output = if !self.backoff.next_backoff().await {
            PolicyOutput::Abort(tracker_err)
        } else {
            PolicyOutput::Retry
        };

        PolicyResult {
            ctx,
            request,
            output,
        }
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "request aborted due to exhausted concurrency limit"]
    pub struct LimitReached;
}

/// The tracker trait that can be implemented to provide custom concurrent request tracking.
///
/// By default [`ConcurrentCounter`] is provided, but in case you need multi-instance tracking,
/// you can support that by implementing the [`ConcurrentTracker`] trait.
pub trait ConcurrentTracker: Send + Sync + 'static {
    /// The guard that is used to consume a resource and that is expected
    /// to release the resource when dropped.
    type Guard: Send + 'static;

    /// The error that is returned when the concurrent request limit is reached,
    /// which is also returned in case a used backoff failed.
    type Error: Send + 'static;

    /// Try to access the resource, returning a guard if successful,
    /// or an error if the limit is reached.
    ///
    /// When the limit is reached and a backoff is used in the parent structure,
    /// the backoff should tried to be used before returning the error.
    fn try_access(&self) -> Result<Self::Guard, Self::Error>;
}

/// The default [`ConcurrentTracker`] that uses a counter to track the concurrent requests.
#[derive(Debug, Clone)]
pub struct ConcurrentCounter {
    max: usize,
    current: Arc<Mutex<usize>>,
}

impl ConcurrentCounter {
    /// Create a new concurrent counter with the given maximum limit.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            max,
            current: Arc::new(Mutex::new(0)),
        }
    }
}

impl ConcurrentTracker for ConcurrentCounter {
    type Guard = ConcurrentCounterGuard;
    type Error = LimitReached;

    fn try_access(&self) -> Result<Self::Guard, Self::Error> {
        let mut current = self.current.lock();
        if *current < self.max {
            *current += 1;
            Ok(ConcurrentCounterGuard {
                current: self.current.clone(),
            })
        } else {
            Err(LimitReached)
        }
    }
}

/// The guard for [`ConcurrentCounter`] that releases the concurrent request limit.
#[derive(Debug)]
pub struct ConcurrentCounterGuard {
    current: Arc<Mutex<usize>>,
}

impl Drop for ConcurrentCounterGuard {
    fn drop(&mut self) {
        let mut current = self.current.lock();
        *current -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_ready<R, G, E>(result: PolicyResult<R, G, E>) -> G {
        match result.output {
            PolicyOutput::Ready(guard) => guard,
            _ => panic!("unexpected output, expected ready"),
        }
    }

    fn assert_abort<R, G, E>(result: &PolicyResult<R, G, E>) {
        match result.output {
            PolicyOutput::Abort(_) => (),
            _ => panic!("unexpected output, expected abort"),
        }
    }

    #[tokio::test]
    async fn concurrent_policy_zero() {
        // for cases where you want to also block specific requests as part of your rate limiting,
        // bit of a contrived example, but possible

        let policy = ConcurrentPolicy::max(0);
        assert_abort(&policy.check(Context::default(), ()).await);
    }

    #[tokio::test]
    async fn concurrent_policy() {
        let policy = ConcurrentPolicy::max(2);

        let guard_1 = assert_ready(policy.check(Context::default(), ()).await);
        let guard_2 = assert_ready(policy.check(Context::default(), ()).await);

        assert_abort(&policy.check(Context::default(), ()).await);

        drop(guard_1);
        let _guard_3 = assert_ready(policy.check(Context::default(), ()).await);

        assert_abort(&policy.check(Context::default(), ()).await);

        drop(guard_2);
        assert_ready(policy.check(Context::default(), ()).await);
    }

    #[tokio::test]
    async fn concurrent_policy_clone() {
        let policy = ConcurrentPolicy::max(2);
        let policy_clone = policy.clone();

        let guard_1 = assert_ready(policy.check(Context::default(), ()).await);
        let _guard_2 = assert_ready(policy_clone.check(Context::default(), ()).await);

        assert_abort(&policy.check(Context::default(), ()).await);

        drop(guard_1);
        assert_ready(policy.check(Context::default(), ()).await);
    }
}
