//! Limit policies for [`super::Limit`]
//! define how requests are handled when the limit is reached
//! for a given request.
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
//! If no policy matches, the request is allowed to proceed as well.
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
//! [`Extensions`]: crate::context::Extensions
//! [`http_listener_hello.rs`]: https://github.com/plabayo/rama/blob/main/examples/http_rate_limit.rs

use crate::Context;
use crate::error::BoxError;
use std::{convert::Infallible, fmt, sync::Arc};

mod concurrent;
#[doc(inline)]
pub use concurrent::{ConcurrentCounter, ConcurrentPolicy, ConcurrentTracker, LimitReached};

mod matcher;

/// The full result of a limit policy.
pub struct PolicyResult<State, Request, Guard, Error> {
    /// The input context
    pub ctx: Context<State>,
    /// The input request
    pub request: Request,
    /// The output part of the limit policy.
    pub output: PolicyOutput<Guard, Error>,
}

impl<State: fmt::Debug, Request: fmt::Debug, Guard: fmt::Debug, Error: fmt::Debug> std::fmt::Debug
    for PolicyResult<State, Request, Guard, Error>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyResult")
            .field("ctx", &self.ctx)
            .field("request", &self.request)
            .field("output", &self.output)
            .finish()
    }
}

/// The output part of a limit policy.
pub enum PolicyOutput<Guard, Error> {
    /// The request is allowed to proceed,
    /// and the guard is returned to release the limit when it is dropped,
    /// which should be done after the request is completed.
    Ready(Guard),
    /// The request is not allowed to proceed, and should be aborted.
    Abort(Error),
    /// The request is not allowed to proceed, but should be retried.
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

/// A limit [`Policy`] is used to determine whether a request is allowed to proceed,
/// and if not, how to handle it.
pub trait Policy<State, Request>: Send + Sync + 'static {
    /// The guard type that is returned when the request is allowed to proceed.
    ///
    /// See [`PolicyOutput::Ready`].
    type Guard: Send + 'static;
    /// The error type that is returned when the request is not allowed to proceed,
    /// and should be aborted.
    ///
    /// See [`PolicyOutput::Abort`].
    type Error: Send + Sync + 'static;

    /// Check whether the request is allowed to proceed.
    ///
    /// Optionally modify the request before it is passed to the inner service,
    /// which can be used to add metadata to the request regarding how the request
    /// was handled by this limit policy.
    fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> impl std::future::Future<Output = PolicyResult<State, Request, Self::Guard, Self::Error>>
    + Send
    + '_;
}

impl<State, Request, P> Policy<State, Request> for Option<P>
where
    P: Policy<State, Request>,
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = Option<P::Guard>;
    type Error = P::Error;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        match self {
            Some(policy) => {
                let result = policy.check(ctx, request).await;
                match result.output {
                    PolicyOutput::Ready(guard) => PolicyResult {
                        ctx: result.ctx,
                        request: result.request,
                        output: PolicyOutput::Ready(Some(guard)),
                    },
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
                }
            }
            None => PolicyResult {
                ctx,
                request,
                output: PolicyOutput::Ready(None),
            },
        }
    }
}

impl<State, Request, P> Policy<State, Request> for &'static P
where
    P: Policy<State, Request>,
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = P::Guard;
    type Error = P::Error;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        (**self).check(ctx, request).await
    }
}

impl<State, Request, P> Policy<State, Request> for Arc<P>
where
    P: Policy<State, Request>,
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = P::Guard;
    type Error = P::Error;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        self.as_ref().check(ctx, request).await
    }
}

impl<State, Request, P> Policy<State, Request> for Box<P>
where
    P: Policy<State, Request>,
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = P::Guard;
    type Error = P::Error;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        self.as_ref().check(ctx, request).await
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// An unlimited policy that allows all requests to proceed.
pub struct UnlimitedPolicy;

impl UnlimitedPolicy {
    /// Create a new [`UnlimitedPolicy`].
    pub const fn new() -> Self {
        UnlimitedPolicy
    }
}

impl<State, Request> Policy<State, Request> for UnlimitedPolicy
where
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Guard = ();
    type Error = Infallible;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        PolicyResult {
            ctx,
            request,
            output: PolicyOutput::Ready(()),
        }
    }
}

macro_rules! impl_limit_policy_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, State, Request> Policy<State, Request> for crate::combinators::$id<$($param),+>
        where
            $(
                $param: Policy<State, Request>,
                $param::Error: Into<BoxError>,
            )+
            Request: Send + 'static,
            State: Clone + Send + Sync + 'static,
        {
            type Guard = crate::combinators::$id<$($param::Guard),+>;
            type Error = BoxError;

            async fn check(
                &self,
                ctx: Context<State>,
                req: Request,
            ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
                match self {
                    $(
                        crate::combinators::$id::$param(policy) => {
                            let result = policy.check(ctx, req).await;
                            match result.output {
                                PolicyOutput::Ready(guard) => PolicyResult {
                                    ctx: result.ctx,
                                    request: result.request,
                                    output: PolicyOutput::Ready(crate::combinators::$id::$param(guard)),
                                },
                                PolicyOutput::Abort(err) => PolicyResult {
                                    ctx: result.ctx,
                                    request: result.request,
                                    output: PolicyOutput::Abort(err.into()),
                                },
                                PolicyOutput::Retry => PolicyResult {
                                    ctx: result.ctx,
                                    request: result.request,
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
