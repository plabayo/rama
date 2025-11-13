use crate::{
    extensions::{Extensions, ExtensionsMut},
    matcher::Matcher,
};

use super::{Policy, PolicyOutput, PolicyResult};

impl<M, P, Request> Policy<Request> for Vec<(M, P)>
where
    M: Matcher<Request>,
    P: Policy<Request>,
    Request: Send + ExtensionsMut + 'static,
{
    type Guard = Option<P::Guard>;
    type Error = P::Error;

    async fn check(&self, mut request: Request) -> PolicyResult<Request, Self::Guard, Self::Error> {
        let mut ext = Extensions::new();
        for (matcher, policy) in self.iter() {
            if matcher.matches(Some(&mut ext), &request) {
                request.extensions_mut().extend(ext);
                let result = policy.check(request).await;
                return match result.output {
                    PolicyOutput::Ready(guard) => {
                        let guard = Some(guard);
                        PolicyResult {
                            request: result.request,
                            output: PolicyOutput::Ready(guard),
                        }
                    }
                    PolicyOutput::Abort(err) => PolicyResult {
                        request: result.request,
                        output: PolicyOutput::Abort(err),
                    },
                    PolicyOutput::Retry => PolicyResult {
                        request: result.request,
                        output: PolicyOutput::Retry,
                    },
                };
            }
            ext.clear();
        }
        PolicyResult {
            request,
            output: PolicyOutput::Ready(None),
        }
    }
}

impl<M, P, Request> Policy<Request> for (Vec<(M, P)>, P)
where
    M: Matcher<Request>,
    P: Policy<Request>,
    Request: Send + ExtensionsMut + 'static,
{
    type Guard = P::Guard;
    type Error = P::Error;

    async fn check(&self, mut request: Request) -> PolicyResult<Request, Self::Guard, Self::Error> {
        let (matchers, default_policy) = self;
        let mut ext = Extensions::new();
        for (matcher, policy) in matchers.iter() {
            if matcher.matches(Some(&mut ext), &request) {
                request.extensions_mut().extend(ext);
                return policy.check(request).await;
            }
            ext.clear();
        }
        default_policy.check(request).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        ServiceInput,
        extensions::Extensions,
        layer::limit::policy::{ConcurrentCounter, ConcurrentPolicy},
    };

    use super::*;

    fn assert_ready<R, G, E>(result: PolicyResult<R, G, E>) -> G {
        match result.output {
            PolicyOutput::Ready(guard) => guard,
            PolicyOutput::Abort(_) | PolicyOutput::Retry => {
                panic!("unexpected output, expected ready")
            }
        }
    }

    fn assert_abort<R, G, E>(result: &PolicyResult<R, G, E>) {
        match result.output {
            PolicyOutput::Abort(_) => (),
            PolicyOutput::Ready(_) | PolicyOutput::Retry => {
                panic!("unexpected output, expected abort")
            }
        }
    }

    type NumberedRequest = ServiceInput<usize>;

    #[tokio::test]
    async fn matcher_policy_empty() {
        let policy = Vec::<(bool, ConcurrentPolicy<(), ConcurrentCounter>)>::new();

        for i in 0..10 {
            assert_ready(policy.check(NumberedRequest::new(i)).await);
        }
    }

    #[tokio::test]
    async fn matcher_policy_always() {
        let concurrency_policy = ConcurrentPolicy::max(2);

        let policy = Arc::new(vec![(true, concurrency_policy)]);

        let guard_1 = assert_ready(policy.check(Extensions::new()).await);
        let guard_2 = assert_ready(policy.check(Extensions::new()).await);

        assert_abort(&policy.check(Extensions::new()).await);

        drop(guard_1);
        let _guard_3 = assert_ready(policy.check(Extensions::new()).await);

        assert_abort(&policy.check(Extensions::new()).await);

        drop(guard_2);
        assert_ready(policy.check(Extensions::new()).await);
    }

    #[derive(Debug, Clone)]
    enum TestMatchers {
        Const(usize),
        Odd,
    }

    impl Matcher<NumberedRequest> for TestMatchers {
        fn matches(&self, _ext: Option<&mut Extensions>, req: &NumberedRequest) -> bool {
            match self {
                Self::Const(n) => *n == req.input,
                Self::Odd => req.input % 2 == 1,
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
            assert_ready(policy.check(NumberedRequest::new(i * 2)).await);
        }

        let odd_guard_1 = assert_ready(policy.check(NumberedRequest::new(1)).await);

        let const_guard_1 = assert_ready(policy.check(NumberedRequest::new(42)).await);

        let odd_guard_2 = assert_ready(policy.check(NumberedRequest::new(3)).await);

        // both the odd and 42 limit is reached
        assert_abort(&policy.check(NumberedRequest::new(5)).await);
        assert_abort(&policy.check(NumberedRequest::new(42)).await);

        // even numbers except 42 will match nothing and thus have no limit
        for i in 1..10 {
            assert_ready(policy.check(NumberedRequest::new(i * 2)).await);
        }

        // only once we drop a guard can we make a new odd request
        drop(odd_guard_1);
        let _odd_guard_3 = assert_ready(policy.check(NumberedRequest::new(9)).await);

        // only once we drop the current 42 guard can we get a new guard,
        // as the limit is 1 for 42
        assert_abort(&policy.check(NumberedRequest::new(42)).await);
        drop(const_guard_1);
        assert_ready(policy.check(NumberedRequest::new(42)).await);

        // odd limit reached again so no luck here
        assert_abort(&policy.check(NumberedRequest::new(11)).await);

        // dropping another odd guard makes room for a new odd request
        drop(odd_guard_2);
        assert_ready(policy.check(NumberedRequest::new(13)).await);

        // even numbers (except 42) will always be allowed
        for i in 1..10 {
            assert_ready(policy.check(NumberedRequest::new(i * 2)).await);
        }
    }
}
