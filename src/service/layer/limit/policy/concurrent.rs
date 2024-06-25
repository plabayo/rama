//! A [`Policy`] that limits the number of concurrent requests.
//!
//! See [`ConcurrentPolicy`].
//!
//! # Examples
//!
//! ```
//! use rama::service::{
//!     layer::limit::{Limit, policy::ConcurrentPolicy},
//!     Context, Service, service_fn,
//! };
//! # use std::convert::Infallible;
//!
//! # #[tokio::main]
//! # async fn main() {
//!
//! let service = service_fn(|_, _| async {
//!     Ok::<_, Infallible>(())
//! });
//! let mut service = Limit::new(service, ConcurrentPolicy::max(2));
//!
//! let response = service.serve(Context::default(), ()).await;
//! assert!(response.is_ok());
//! # }
//! ```

use super::{Policy, PolicyOutput, PolicyResult};
use crate::service::Context;
use crate::utils::backoff::Backoff;
use parking_lot::Mutex;
use std::sync::Arc;

/// A [`Policy`] that limits the number of concurrent requests.
#[derive(Debug)]
pub struct ConcurrentPolicy<B, C> {
    tracker: C,
    backoff: B,
}

impl<B, C> Clone for ConcurrentPolicy<B, C>
where
    B: Clone,
    C: Clone,
{
    fn clone(&self) -> Self {
        ConcurrentPolicy {
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
        ConcurrentPolicy { tracker, backoff }
    }
}

impl<C> ConcurrentPolicy<(), C> {
    /// Create a new [`ConcurrentPolicy`], using the given [`ConcurrentTracker`].
    pub fn new(tracker: C) -> Self {
        ConcurrentPolicy {
            tracker,
            backoff: (),
        }
    }
}

impl ConcurrentPolicy<(), ConcurrentCounter> {
    /// Create a new concurrent policy,
    /// which aborts the request if the `max` limit is reached.
    pub fn max(max: usize) -> Self {
        ConcurrentPolicy {
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
        ConcurrentPolicy {
            tracker: ConcurrentCounter::new(max),
            backoff,
        }
    }
}

impl<B, C, State, Request> Policy<State, Request> for ConcurrentPolicy<B, C>
where
    B: Backoff,
    State: Send + Sync + 'static,
    Request: Send + 'static,
    C: ConcurrentTracker,
{
    type Guard = C::Guard;
    type Error = C::Error;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        let tracker_err = match self.tracker.try_access() {
            Ok(guard) => {
                return PolicyResult {
                    ctx,
                    request,
                    output: PolicyOutput::Ready(guard),
                }
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

impl<B, C, State, Request> Policy<State, Request> for ConcurrentPolicy<Option<B>, C>
where
    B: Backoff,
    C: ConcurrentTracker,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = C::Guard;
    type Error = C::Error;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        let tracker_err = match self.tracker.try_access() {
            Ok(guard) => {
                return PolicyResult {
                    ctx,
                    request,
                    output: PolicyOutput::Ready(guard),
                }
            }
            Err(err) => err,
        };
        let output = match &self.backoff {
            Some(backoff) => {
                if !backoff.next_backoff().await {
                    PolicyOutput::Abort(tracker_err)
                } else {
                    PolicyOutput::Retry
                }
            }
            None => PolicyOutput::Abort(tracker_err),
        };
        PolicyResult {
            ctx,
            request,
            output,
        }
    }
}

/// The error that indicates the request is aborted,
/// because the concurrent request limit is reached.
#[derive(Debug)]
pub struct LimitReached;

impl std::fmt::Display for LimitReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LimitReached")
    }
}

impl std::error::Error for LimitReached {}

impl<State, Request, C> Policy<State, Request> for ConcurrentPolicy<(), C>
where
    State: Send + Sync + 'static,
    Request: Send + 'static,
    C: ConcurrentTracker,
{
    type Guard = C::Guard;
    type Error = C::Error;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        let output = match self.tracker.try_access() {
            Ok(guard) => PolicyOutput::Ready(guard),
            Err(err) => PolicyOutput::Abort(err),
        };
        PolicyResult {
            ctx,
            request,
            output,
        }
    }
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
    type Error: Send + Sync + 'static;

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
    pub fn new(max: usize) -> Self {
        ConcurrentCounter {
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

    fn assert_ready<S, R, G, E>(result: PolicyResult<S, R, G, E>) -> G {
        match result.output {
            PolicyOutput::Ready(guard) => guard,
            _ => panic!("unexpected output, expected ready"),
        }
    }

    fn assert_abort<S, R, G, E>(result: PolicyResult<S, R, G, E>) {
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
        assert_abort(policy.check(Context::default(), ()).await);
    }

    #[tokio::test]
    async fn concurrent_policy() {
        let policy = ConcurrentPolicy::max(2);

        let guard_1 = assert_ready(policy.check(Context::default(), ()).await);
        let guard_2 = assert_ready(policy.check(Context::default(), ()).await);

        assert_abort(policy.check(Context::default(), ()).await);

        drop(guard_1);
        let _guard_3 = assert_ready(policy.check(Context::default(), ()).await);

        assert_abort(policy.check(Context::default(), ()).await);

        drop(guard_2);
        assert_ready(policy.check(Context::default(), ()).await);
    }

    #[tokio::test]
    async fn concurrent_policy_clone() {
        let policy = ConcurrentPolicy::max(2);
        let policy_clone = policy.clone();

        let guard_1 = assert_ready(policy.check(Context::default(), ()).await);
        let _guard_2 = assert_ready(policy_clone.check(Context::default(), ()).await);

        assert_abort(policy.check(Context::default(), ()).await);

        drop(guard_1);
        assert_ready(policy.check(Context::default(), ()).await);
    }
}
