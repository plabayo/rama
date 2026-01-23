use crate::{
    extensions::{Extensions, ExtensionsMut},
    matcher::Matcher,
};

use super::{Policy, PolicyOutput, PolicyResult};

impl<M, P, Input> Policy<Input> for Vec<(M, P)>
where
    M: Matcher<Input>,
    P: Policy<Input>,
    Input: Send + ExtensionsMut + 'static,
{
    type Guard = Option<P::Guard>;
    type Error = P::Error;

    async fn check(&self, mut input: Input) -> PolicyResult<Input, Self::Guard, Self::Error> {
        for (matcher, policy) in self.iter() {
            let mut ext = Extensions::new();
            if matcher.matches(Some(&mut ext), &input) {
                input.extensions_mut().extend(ext);
                let result = policy.check(input).await;
                return match result.output {
                    PolicyOutput::Ready(guard) => {
                        let guard = Some(guard);
                        PolicyResult {
                            input: result.input,
                            output: PolicyOutput::Ready(guard),
                        }
                    }
                    PolicyOutput::Abort(err) => PolicyResult {
                        input: result.input,
                        output: PolicyOutput::Abort(err),
                    },
                    PolicyOutput::Retry => PolicyResult {
                        input: result.input,
                        output: PolicyOutput::Retry,
                    },
                };
            }
        }
        PolicyResult {
            input,
            output: PolicyOutput::Ready(None),
        }
    }
}

impl<M, P, Input> Policy<Input> for (Vec<(M, P)>, P)
where
    M: Matcher<Input>,
    P: Policy<Input>,
    Input: Send + ExtensionsMut + 'static,
{
    type Guard = P::Guard;
    type Error = P::Error;

    async fn check(&self, mut input: Input) -> PolicyResult<Input, Self::Guard, Self::Error> {
        let (matchers, default_policy) = self;
        for (matcher, policy) in matchers.iter() {
            let mut ext = Extensions::new();
            if matcher.matches(Some(&mut ext), &input) {
                input.extensions_mut().extend(ext);
                return policy.check(input).await;
            }
        }
        default_policy.check(input).await
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

    type NumberedInput = ServiceInput<usize>;

    #[tokio::test]
    async fn matcher_policy_empty() {
        let policy = Vec::<(bool, ConcurrentPolicy<(), ConcurrentCounter>)>::new();

        for i in 0..10 {
            assert_ready(policy.check(NumberedInput::new(i)).await);
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

    impl Matcher<NumberedInput> for TestMatchers {
        fn matches(&self, _ext: Option<&mut Extensions>, req: &NumberedInput) -> bool {
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
            assert_ready(policy.check(NumberedInput::new(i * 2)).await);
        }

        let odd_guard_1 = assert_ready(policy.check(NumberedInput::new(1)).await);

        let const_guard_1 = assert_ready(policy.check(NumberedInput::new(42)).await);

        let odd_guard_2 = assert_ready(policy.check(NumberedInput::new(3)).await);

        // both the odd and 42 limit is reached
        assert_abort(&policy.check(NumberedInput::new(5)).await);
        assert_abort(&policy.check(NumberedInput::new(42)).await);

        // even numbers except 42 will match nothing and thus have no limit
        for i in 1..10 {
            assert_ready(policy.check(NumberedInput::new(i * 2)).await);
        }

        // only once we drop a guard can we make a new odd input
        drop(odd_guard_1);
        let _odd_guard_3 = assert_ready(policy.check(NumberedInput::new(9)).await);

        // only once we drop the current 42 guard can we get a new guard,
        // as the limit is 1 for 42
        assert_abort(&policy.check(NumberedInput::new(42)).await);
        drop(const_guard_1);
        assert_ready(policy.check(NumberedInput::new(42)).await);

        // odd limit reached again so no luck here
        assert_abort(&policy.check(NumberedInput::new(11)).await);

        // dropping another odd guard makes room for a new odd input
        drop(odd_guard_2);
        assert_ready(policy.check(NumberedInput::new(13)).await);

        // even numbers (except 42) will always be allowed
        for i in 1..10 {
            assert_ready(policy.check(NumberedInput::new(i * 2)).await);
        }
    }
}
