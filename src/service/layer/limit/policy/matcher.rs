use std::sync::Arc;

use crate::service::{context::Extensions, Context, Matcher};

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
/// such as [`crate::service::matcher::Always`].
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
        let mut ext = Extensions::new();
        for (matcher, policy) in self.policies.iter() {
            if matcher.matches(Some(&mut ext), &ctx, &request) {
                let result = policy.check(ctx, request).await;
                return match result.output {
                    PolicyOutput::Ready(guard) => {
                        let mut ctx = result.ctx;
                        ctx.extend(ext);
                        let guard = MatcherGuard {
                            maybe_guard: Some(guard),
                        };
                        PolicyResult {
                            ctx,
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
