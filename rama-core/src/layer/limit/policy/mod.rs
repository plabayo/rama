//! Limit policies for [`super::Limit`]
//! define how inputs are handled when the limit is reached
//! for a given input.
//!
//! [`Option`] can be used to disable a limit policy for some scenarios
//! while enabling it for others.
//!
//! # Policy Maps
//!
//! A policy which applies a [`Policy`] based on a [`Matcher`].
//! These can be made by using a Vec<([`Matcher`], [`Policy`])>.
//! To avoid cloning you best use an Arc<...> around the most outer vec.
//!
//! The first matching policy is used.
//! If no policy matches, the input is allowed to proceed as well.
//! If you want to enforce a default policy, you can add a policy with a [`Matcher`] that always matches,
//! such as the bool `true`.
//!
//! Note that the [`Matcher`]s will not receive the mutable [`Extensions`],
//! as polices are not intended to keep track of what is matched on.
//!
//! It is this policy that you want to use in case you want to rate limit only
//! external sockets or you want to rate limit specific domains/paths only for http requests.
//! See the [`http_rate_limit.rs`] example for a use case.
//!
//! [`Matcher`]: crate::matcher::Matcher
//! [`Extensions`]: crate::extensions::Extensions
//! [`http_rate_limit.rs`]: https://github.com/plabayo/rama/blob/main/examples/http_rate_limit.rs

use crate::error::BoxError;
use std::{convert::Infallible, fmt, sync::Arc};

mod concurrent;
#[doc(inline)]
pub use concurrent::{ConcurrentCounter, ConcurrentPolicy, ConcurrentTracker, LimitReached};

mod matcher;

/// The full result of a limit policy.
pub struct PolicyResult<Input, Guard, Error> {
    /// The input
    pub input: Input,
    /// The output part of the limit policy.
    pub output: PolicyOutput<Guard, Error>,
}

impl<Input: fmt::Debug, Guard: fmt::Debug, Error: fmt::Debug> std::fmt::Debug
    for PolicyResult<Input, Guard, Error>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyResult")
            .field("input", &self.input)
            .field("output", &self.output)
            .finish()
    }
}

/// The output part of a limit policy.
pub enum PolicyOutput<Guard, Error> {
    /// The input is allowed to proceed,
    /// and the guard is returned to release the limit when it is dropped,
    /// which should be done after the input is completed.
    Ready(Guard),
    /// The input is not allowed to proceed, and should be aborted.
    Abort(Error),
    /// The input is not allowed to proceed, but should be retried.
    Retry,
}

impl<Guard: fmt::Debug, Error: fmt::Debug> std::fmt::Debug for PolicyOutput<Guard, Error> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready(guard) => write!(f, "PolicyOutput::Ready({guard:?})"),
            Self::Abort(error) => write!(f, "PolicyOutput::Abort({error:?})"),
            Self::Retry => write!(f, "PolicyOutput::Retry"),
        }
    }
}

/// A limit [`Policy`] is used to determine whether a input is allowed to proceed,
/// and if not, how to handle it.
pub trait Policy<Input>: Send + Sync + 'static {
    /// The guard type that is returned when the input is allowed to proceed.
    ///
    /// See [`PolicyOutput::Ready`].
    type Guard: Send + 'static;
    /// The error type that is returned when the input is not allowed to proceed,
    /// and should be aborted.
    ///
    /// See [`PolicyOutput::Abort`].
    type Error: Send + 'static;

    /// Check whether the input is allowed to proceed.
    ///
    /// Optionally modify the input before it is passed to the inner service,
    /// which can be used to add metadata to the input regarding how the input
    /// was handled by this limit policy.
    fn check(
        &self,
        input: Input,
    ) -> impl Future<Output = PolicyResult<Input, Self::Guard, Self::Error>> + Send + '_;
}

impl<Input, P> Policy<Input> for Option<P>
where
    P: Policy<Input>,
    Input: Send + 'static,
{
    type Guard = Option<P::Guard>;
    type Error = P::Error;

    async fn check(&self, input: Input) -> PolicyResult<Input, Self::Guard, Self::Error> {
        match self {
            Some(policy) => {
                let result = policy.check(input).await;
                match result.output {
                    PolicyOutput::Ready(guard) => PolicyResult {
                        input: result.input,
                        output: PolicyOutput::Ready(Some(guard)),
                    },
                    PolicyOutput::Abort(err) => PolicyResult {
                        input: result.input,
                        output: PolicyOutput::Abort(err),
                    },
                    PolicyOutput::Retry => PolicyResult {
                        input: result.input,
                        output: PolicyOutput::Retry,
                    },
                }
            }
            None => PolicyResult {
                input,
                output: PolicyOutput::Ready(None),
            },
        }
    }
}

impl<Input, P> Policy<Input> for &'static P
where
    P: Policy<Input>,
    Input: Send + 'static,
{
    type Guard = P::Guard;
    type Error = P::Error;

    #[inline(always)]
    async fn check(&self, input: Input) -> PolicyResult<Input, Self::Guard, Self::Error> {
        (**self).check(input).await
    }
}

impl<Input, P> Policy<Input> for Arc<P>
where
    P: Policy<Input>,
    Input: Send + 'static,
{
    type Guard = P::Guard;
    type Error = P::Error;

    async fn check(&self, input: Input) -> PolicyResult<Input, Self::Guard, Self::Error> {
        self.as_ref().check(input).await
    }
}

impl<Input, P> Policy<Input> for Box<P>
where
    P: Policy<Input>,
    Input: Send + 'static,
{
    type Guard = P::Guard;
    type Error = P::Error;

    async fn check(&self, input: Input) -> PolicyResult<Input, Self::Guard, Self::Error> {
        self.as_ref().check(input).await
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// An unlimited policy that allows all inputs to proceed.
pub struct UnlimitedPolicy;

impl UnlimitedPolicy {
    /// Create a new [`UnlimitedPolicy`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<Input> Policy<Input> for UnlimitedPolicy
where
    Input: Send + 'static,
{
    type Guard = ();
    type Error = Infallible;

    async fn check(&self, input: Input) -> PolicyResult<Input, Self::Guard, Self::Error> {
        PolicyResult {
            input,
            output: PolicyOutput::Ready(()),
        }
    }
}

macro_rules! impl_limit_policy_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, Input> Policy<Input> for crate::combinators::$id<$($param),+>
        where
            $(
                $param: Policy<Input>,
                $param::Error: Into<BoxError>,
            )+
            Input: Send + 'static,

        {
            type Guard = crate::combinators::$id<$($param::Guard),+>;
            type Error = BoxError;

            async fn check(
                &self,
                req: Input,
            ) -> PolicyResult<Input, Self::Guard, Self::Error> {
                match self {
                    $(
                        crate::combinators::$id::$param(policy) => {
                            let result = policy.check(req).await;
                            match result.output {
                                PolicyOutput::Ready(guard) => PolicyResult {
                                    input: result.input,
                                    output: PolicyOutput::Ready(crate::combinators::$id::$param(guard)),
                                },
                                PolicyOutput::Abort(err) => PolicyResult {
                                    input: result.input,
                                    output: PolicyOutput::Abort(err.into()),
                                },
                                PolicyOutput::Retry => PolicyResult {
                                    input: result.input,
                                    output: PolicyOutput::Retry,
                                },
                            }
                        }
                    )+
                }
            }
        }
    };
}

crate::combinators::impl_either!(impl_limit_policy_either);
