use std::sync::Arc;

use crate::service::{Context, Matcher};

use super::{Policy, PolicyOutput, PolicyResult};

/// Builder for [`MatcherPolicyMap`].
pub struct MatcherPolicyMapBuilder<M, P> {
    policies: Vec<(M, P)>,
}

impl<M, P> MatcherPolicyMapBuilder<M, P> {
    /// Create a new [`MatcherPolicyMap`].
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Add a [`Policy`] to the map, which is used when the given [`Matcher`] matches.
    pub fn add(mut self, matcher: M, policy: P) -> Self {
        self.policies.push((matcher, policy));
        self
    }

    /// Build the [`MatcherPolicyMap`].
    pub fn build(self) -> MatcherPolicyMap<M, P> {
        MatcherPolicyMap {
            policies: Arc::new(self.policies),
        }
    }
}

impl Default for MatcherPolicyMapBuilder<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MatcherPolicyMapBuilder<(), ()> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatcherPolicyMapBuilder").finish()
    }
}

/// A policy which applies a [`Policy`] based on a [`Matcher`].
///
/// The first matching policy is used.
/// If no policy matches, the request is allowed to proceed as well.
/// If you want to enforce a default policy, you can add a policy with a [`Matcher`] that always matches,
/// such as [`matcher::Always`].
///
/// Note that the [`Matcher`]s will not receive the mutable [`Extensions`],
/// as the [`MatcherPolicyMap`] is not intended to keep track of what is matched on.
///
/// It is this policy that you want to use in case you want to rate limit only
/// external sockets or you want to rate limit specific domains/paths only for http requests.
/// See the [`http_rate_limit.rs`] example for a use case.
///
/// [`matcher::Always`]: crate::service::matcher::Always
/// [`Extensions`]: crate::service::context::Extensions
/// [`http_listener_hello.rs`]: https://github.com/plabayo/rama/blob/main/examples/http_rate_limit.rs
pub struct MatcherPolicyMap<M, P> {
    policies: Arc<Vec<(M, P)>>,
}

impl std::fmt::Debug for MatcherPolicyMap<(), ()> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatcherPolicyMap").finish()
    }
}

impl<M, P> MatcherPolicyMap<M, P> {
    /// Create a new [`MatcherPolicyMap`].
    pub fn builder() -> MatcherPolicyMapBuilder<M, P> {
        MatcherPolicyMapBuilder::new()
    }
}

impl<M, P> Clone for MatcherPolicyMap<M, P> {
    fn clone(&self) -> Self {
        MatcherPolicyMap {
            policies: self.policies.clone(),
        }
    }
}

/// The guard that releases the matched limit.
pub struct MatcherGuard<G> {
    maybe_guard: Option<G>,
}

impl<G> MatcherGuard<G> {
    /// Return a reference to the inner guard,
    /// or None if no match was made.
    pub fn inner(&self) -> Option<&G> {
        self.maybe_guard.as_ref()
    }

    /// Consumes the guard, returning the inner guard,
    /// or None if no match was made.
    pub fn into_inner(self) -> Option<G> {
        self.maybe_guard
    }

    /// Return true if a match was made.
    pub fn matched(&self) -> bool {
        self.maybe_guard.is_some()
    }
}

impl<G> Clone for MatcherGuard<G>
where
    G: Clone,
{
    fn clone(&self) -> Self {
        MatcherGuard {
            maybe_guard: self.maybe_guard.clone(),
        }
    }
}

impl<G> std::fmt::Debug for MatcherGuard<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatcherGuard").finish()
    }
}

impl<M, P, State, Request> Policy<State, Request> for MatcherPolicyMap<M, P>
where
    M: Matcher<State, Request>,
    P: Policy<State, Request>,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = MatcherGuard<P::Guard>;
    type Error = P::Error;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        for (matcher, policy) in self.policies.iter() {
            if matcher.matches(None, &ctx, &request) {
                let result = policy.check(ctx, request).await;
                return match result.output {
                    PolicyOutput::Ready(guard) => {
                        let guard = MatcherGuard {
                            maybe_guard: Some(guard),
                        };
                        PolicyResult {
                            ctx: result.ctx,
                            request: result.request,
                            output: PolicyOutput::Ready(guard),
                        }
                    }
                    PolicyOutput::Abort(err) => PolicyResult {
                        ctx: result.ctx,
                        request: result.request,
                        output: PolicyOutput::Abort(err),
                    },
                    PolicyOutput::Retry => PolicyResult {
                        ctx: result.ctx,
                        request: result.request,
                        output: PolicyOutput::Retry,
                    },
                };
            }
        }
        PolicyResult {
            ctx,
            request,
            output: PolicyOutput::Ready(MatcherGuard { maybe_guard: None }),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::service::{
        context::Extensions, layer::limit::policy::ConcurrentPolicy, matcher::Always,
    };

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
    async fn matcher_policy_empty() {
        let policy = MatcherPolicyMap::<Always, ConcurrentPolicy<()>>::builder().build();

        for i in 0..10 {
            assert_ready(policy.check(Context::default(), i).await);
        }
    }

    #[tokio::test]
    async fn matcher_policy_always() {
        let concurrency_policy = ConcurrentPolicy::new(2);

        let policy = MatcherPolicyMap::builder()
            .add(Always, concurrency_policy)
            .build();

        let guard_1 = assert_ready(policy.check(Context::default(), ()).await);
        let guard_2 = assert_ready(policy.check(Context::default(), ()).await);

        assert_abort(policy.check(Context::default(), ()).await);

        drop(guard_1);
        let _guard_3 = assert_ready(policy.check(Context::default(), ()).await);

        assert_abort(policy.check(Context::default(), ()).await);

        drop(guard_2);
        assert_ready(policy.check(Context::default(), ()).await);
    }

    #[derive(Debug, Clone)]
    enum TestMatchers {
        Const(u8),
        Odd,
    }

    impl<State> Matcher<State, u8> for TestMatchers {
        fn matches(&self, _ext: Option<&mut Extensions>, _ctx: &Context<State>, req: &u8) -> bool {
            match self {
                TestMatchers::Const(n) => *n == *req,
                TestMatchers::Odd => *req % 2 == 1,
            }
        }
    }

    #[tokio::test]
    async fn matcher_policy_scoped_limits() {
        let policy = MatcherPolicyMap::builder()
            .add(TestMatchers::Odd, ConcurrentPolicy::new(2))
            .add(TestMatchers::Const(42), ConcurrentPolicy::new(1))
            .build();

        // even numbers (except 42) will always be allowed
        for i in 1..10 {
            assert_ready(policy.check(Context::default(), i * 2).await);
        }

        let odd_guard_1 = assert_ready(policy.check(Context::default(), 1).await);

        let const_guard_1 = assert_ready(policy.check(Context::default(), 42).await);

        let odd_guard_2 = assert_ready(policy.check(Context::default(), 3).await);

        // both the odd and 42 limit is reached
        assert_abort(policy.check(Context::default(), 5).await);
        assert_abort(policy.check(Context::default(), 42).await);

        // even numbers except 42 will match nothing and thus have no limit
        for i in 1..10 {
            assert_ready(policy.check(Context::default(), i * 2).await);
        }

        // only once we drop a guard can we make a new odd reuqest
        drop(odd_guard_1);
        let _odd_guard_3 = assert_ready(policy.check(Context::default(), 9).await);

        // only once we drop the current 42 guard can we get a new guard,
        // as the limit is 1 for 42
        assert_abort(policy.check(Context::default(), 42).await);
        drop(const_guard_1);
        assert_ready(policy.check(Context::default(), 42).await);

        // odd limit reached again so no luck here
        assert_abort(policy.check(Context::default(), 11).await);

        // droping another odd guard makes room for a new odd request
        drop(odd_guard_2);
        assert_ready(policy.check(Context::default(), 13).await);

        // even numbers (except 42) will always be allowed
        for i in 1..10 {
            assert_ready(policy.check(Context::default(), i * 2).await);
        }
    }
}
