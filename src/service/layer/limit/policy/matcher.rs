use crate::service::{context::Extensions, Context, Matcher};

use super::{Policy, PolicyOutput, PolicyResult};

impl<M, P, State, Request> Policy<State, Request> for Vec<(M, P)>
where
    M: Matcher<State, Request>,
    P: Policy<State, Request>,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = Option<P::Guard>;
    type Error = P::Error;

    async fn check(
        &self,
        mut ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        let mut ext = Extensions::new();
        for (matcher, policy) in self.iter() {
            if matcher.matches(Some(&mut ext), &ctx, &request) {
                ctx.extend(ext);
                let result = policy.check(ctx, request).await;
                return match result.output {
                    PolicyOutput::Ready(guard) => {
                        let guard = Some(guard);
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
            ext.clear();
        }
        PolicyResult {
            ctx,
            request,
            output: PolicyOutput::Ready(None),
        }
    }
}

impl<M, P, State, Request> Policy<State, Request> for (Vec<(M, P)>, P)
where
    M: Matcher<State, Request>,
    P: Policy<State, Request>,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = P::Guard;
    type Error = P::Error;

    async fn check(
        &self,
        mut ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        let (matchers, default_policy) = self;
        let mut ext = Extensions::new();
        for (matcher, policy) in matchers.iter() {
            if matcher.matches(Some(&mut ext), &ctx, &request) {
                ctx.extend(ext);
                return policy.check(ctx, request).await;
            }
            ext.clear();
        }
        default_policy.check(ctx, request).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::service::{
        context::Extensions,
        layer::limit::policy::{ConcurrentCounter, ConcurrentPolicy},
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
        let policy = Vec::<(bool, ConcurrentPolicy<(), ConcurrentCounter>)>::new();

        for i in 0..10 {
            assert_ready(policy.check(Context::default(), i).await);
        }
    }

    #[tokio::test]
    async fn matcher_policy_always() {
        let concurrency_policy = ConcurrentPolicy::max(2);

        let policy = Arc::new(vec![(true, concurrency_policy)]);

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
        let policy = vec![
            (TestMatchers::Odd, ConcurrentPolicy::max(2)),
            (TestMatchers::Const(42), ConcurrentPolicy::max(1)),
        ];

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

        // only once we drop a guard can we make a new odd request
        drop(odd_guard_1);
        let _odd_guard_3 = assert_ready(policy.check(Context::default(), 9).await);

        // only once we drop the current 42 guard can we get a new guard,
        // as the limit is 1 for 42
        assert_abort(policy.check(Context::default(), 42).await);
        drop(const_guard_1);
        assert_ready(policy.check(Context::default(), 42).await);

        // odd limit reached again so no luck here
        assert_abort(policy.check(Context::default(), 11).await);

        // dropping another odd guard makes room for a new odd request
        drop(odd_guard_2);
        assert_ready(policy.check(Context::default(), 13).await);

        // even numbers (except 42) will always be allowed
        for i in 1..10 {
            assert_ready(policy.check(Context::default(), i * 2).await);
        }
    }
}
