//! Limit policies for [`super::Limit`]
//! define how requests are handled when the limit is reached
//! for a given request.

use crate::service::Context;

mod concurrent;
#[doc(inline)]
pub use concurrent::{ConcurrentPolicy, LimitReached};

mod matcher;
#[doc(inline)]
pub use matcher::{MatcherGuard, MatcherPolicyMap};

#[derive(Debug)]
/// The full result of a limit policy.
pub struct PolicyResult<State, Request, Guard, Error> {
    /// The input context
    pub ctx: Context<State>,
    /// The input request
    pub request: Request,
    /// The output part of the limit policy.
    pub output: PolicyOutput<Guard, Error>,
}

/// The output part of a limit policy.
#[derive(Debug)]
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

/// A limit policy is used to determine whether a request is allowed to proceed,
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
