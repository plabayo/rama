//! A policy that limits the number of concurrent requests.
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
//! let mut service = Limit::new(service, ConcurrentPolicy::new(2));
//!
//! let response = service.serve(Context::default(), ()).await;
//! assert!(response.is_ok());
//! # }
//! ```

use super::{Policy, PolicyOutput, PolicyResult};
use crate::service::{util::backoff::Backoff, Context};
use std::sync::{Arc, Mutex};

/// A policy that limits the number of concurrent requests.
#[derive(Debug)]
pub struct ConcurrentPolicy<B> {
    max: usize,
    current: Arc<Mutex<usize>>,
    backoff: B,
}

impl<B> Clone for ConcurrentPolicy<B>
where
    B: Clone,
{
    fn clone(&self) -> Self {
        ConcurrentPolicy {
            max: self.max,
            current: self.current.clone(),
            backoff: self.backoff.clone(),
        }
    }
}

impl ConcurrentPolicy<()> {
    /// Create a new concurrent policy,
    /// which aborts the request if the limit is reached.
    pub fn new(max: usize) -> Self {
        ConcurrentPolicy {
            max,
            current: Arc::new(Mutex::new(0)),
            backoff: (),
        }
    }
}

impl<B> ConcurrentPolicy<B> {
    /// Create a new concurrent policy,
    /// which backs off if the limit is reached,
    /// using the given backoff policy.
    pub fn with_backoff(max: usize, backoff: B) -> Self {
        ConcurrentPolicy {
            max,
            current: Arc::new(Mutex::new(0)),
            backoff,
        }
    }
}

/// The guard that releases the concurrent request limit.
#[derive(Debug)]
pub struct ConcurrentGuard {
    current: Arc<Mutex<usize>>,
}

impl Drop for ConcurrentGuard {
    fn drop(&mut self) {
        let mut current = self.current.lock().unwrap();
        *current -= 1;
    }
}

impl<B, State, Request> Policy<State, Request> for ConcurrentPolicy<B>
where
    B: Backoff,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = ConcurrentGuard;
    type Error = LimitReached;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        {
            let mut current = self.current.lock().unwrap();
            if *current < self.max {
                *current += 1;
                return PolicyResult {
                    ctx,
                    request,
                    output: PolicyOutput::Ready(ConcurrentGuard {
                        current: self.current.clone(),
                    }),
                };
            }
        }

        let output = if !self.backoff.next_backoff().await {
            PolicyOutput::Abort(LimitReached)
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

impl<B, State, Request> Policy<State, Request> for ConcurrentPolicy<Option<B>>
where
    B: Backoff,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = ConcurrentGuard;
    type Error = LimitReached;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        {
            let mut current = self.current.lock().unwrap();
            if *current < self.max {
                *current += 1;
                return PolicyResult {
                    ctx,
                    request,
                    output: PolicyOutput::Ready(ConcurrentGuard {
                        current: self.current.clone(),
                    }),
                };
            }
        }
        let output = match &self.backoff {
            Some(backoff) => {
                if !backoff.next_backoff().await {
                    PolicyOutput::Abort(LimitReached)
                } else {
                    PolicyOutput::Retry
                }
            }
            None => PolicyOutput::Abort(LimitReached),
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

impl<State, Request> Policy<State, Request> for ConcurrentPolicy<()>
where
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = ConcurrentGuard;
    type Error = LimitReached;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        let mut current = self.current.lock().unwrap();
        let output = if *current < self.max {
            *current += 1;
            PolicyOutput::Ready(ConcurrentGuard {
                current: self.current.clone(),
            })
        } else {
            PolicyOutput::Abort(LimitReached)
        };
        PolicyResult {
            ctx,
            request,
            output,
        }
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
    async fn concurrent_policy() {
        let policy = ConcurrentPolicy::new(2);

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
        let policy = ConcurrentPolicy::new(2);
        let policy_clone = policy.clone();

        let guard_1 = assert_ready(policy.check(Context::default(), ()).await);
        let _guard_2 = assert_ready(policy_clone.check(Context::default(), ()).await);

        assert_abort(policy.check(Context::default(), ()).await);

        drop(guard_1);
        assert_ready(policy.check(Context::default(), ()).await);
    }
}
