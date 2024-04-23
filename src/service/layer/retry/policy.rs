use std::future::Future;

use crate::service::Context;

/// A "retry policy" to classify if a request should be retried.
///
/// # Example
///
/// ```
/// use rama::service::Context;
/// use rama::service::layer::retry::{Policy, PolicyResult};
/// use std::sync::{Arc, Mutex};
///
/// type Req = String;
/// type Res = String;
///
/// struct Attempts(Arc<Mutex<usize>>);
///
/// impl<State, E> Policy<State, Req, Res, E> for Attempts
///     where
///         State: Send + Sync + 'static,
///         E: Send + Sync + 'static,
/// {
///     async fn retry(&self, ctx: Context<State>, req: Req, result: Result<Res, E>) -> PolicyResult<State, Req, Res, E> {
///         match result {
///             Ok(_) => {
///                 // Treat all `Response`s as success,
///                 // so don't retry...
///                 PolicyResult::Abort(result)
///             },
///             Err(_) => {
///                 // Treat all errors as failures...
///                 // But we limit the number of attempts...
///                 let mut attempts = self.0.lock().unwrap();
///                 if *attempts > 0 {
///                     // Try again!
///                     *attempts -= 1;
///                     PolicyResult::Retry { ctx, req }
///                 } else {
///                     // Used all our attempts, no retry...
///                     PolicyResult::Abort(result)
///                 }
///             }
///         }
///     }
///
///     fn clone_input(&self, ctx: &Context<State>, req: &Req) -> Option<(Context<State>, Req)> {
///         Some((ctx.clone(), req.clone()))
///     }
/// }
/// ```
pub trait Policy<S, Req, Res, E>: Send + Sync + 'static {
    /// Check the policy if a certain request should be retried.
    ///
    /// This method is passed a reference to the original request, and either
    /// the [`Service::Response`] or [`Service::Error`] from the inner service.
    ///
    /// If the request should **not** be retried, return `None`.
    ///
    /// If the request *should* be retried, return `Some` future that will delay
    /// the next retry of the request. This can be used to sleep for a certain
    /// duration, to wait for some external condition to be met before retrying,
    /// or resolve right away, if the request should be retried immediately.
    ///
    /// ## Mutating Requests
    ///
    /// The policy MAY chose to mutate the `req`: if the request is mutated, the
    /// mutated request will be sent to the inner service in the next retry.
    /// This can be helpful for use cases like tracking the retry count in a
    /// header.
    ///
    /// ## Mutating Results
    ///
    /// The policy MAY chose to mutate the result. This enables the retry
    /// policy to convert a failure into a success and vice versa. For example,
    /// if the policy is used to poll while waiting for a state change, the
    /// policy can switch the result to emit a specific error when retries are
    /// exhausted.
    ///
    /// The policy can also record metadata on the request to include
    /// information about the number of retries required or to record that a
    /// failure failed after exhausting all retries.
    ///
    /// [`Service::Response`]: crate::service::Service::Response
    /// [`Service::Error`]: crate::service::Service::Error
    fn retry(
        &self,
        ctx: Context<S>,
        req: Req,
        result: Result<Res, E>,
    ) -> impl Future<Output = PolicyResult<S, Req, Res, E>> + Send + '_;

    /// Tries to clone a request before being passed to the inner service.
    ///
    /// If the request cannot be cloned, return [`None`]. Moreover, the retry
    /// function will not be called if the [`None`] is returned.
    fn clone_input(&self, ctx: &Context<S>, req: &Req) -> Option<(Context<S>, Req)>;
}

impl<P, S, Req, Res, E> Policy<S, Req, Res, E> for std::sync::Arc<P>
where
    P: Policy<S, Req, Res, E>,
{
    fn retry(
        &self,
        ctx: Context<S>,
        req: Req,
        result: Result<Res, E>,
    ) -> impl Future<Output = PolicyResult<S, Req, Res, E>> + Send + '_ {
        (**self).retry(ctx, req, result)
    }

    fn clone_input(&self, ctx: &Context<S>, req: &Req) -> Option<(Context<S>, Req)> {
        (**self).clone_input(ctx, req)
    }
}

/// The full result of a limit policy.
pub enum PolicyResult<S, Req, Res, E> {
    /// The result should not be retried,
    /// and the result should be returned to the caller.
    Abort(Result<Res, E>),
    /// The result should be retried,
    /// and the request should be passed to the inner service again.
    Retry {
        /// The context of the request.
        ctx: Context<S>,
        /// The request to be retried, with the above context.
        req: Req,
    },
}

impl<State, Request, Response, Error> std::fmt::Debug
    for PolicyResult<State, Request, Response, Error>
where
    State: std::fmt::Debug,
    Request: std::fmt::Debug,
    Response: std::fmt::Debug,
    Error: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyResult::Abort(err) => write!(f, "PolicyResult::Abort({:?})", err),
            PolicyResult::Retry { ctx, req } => write!(
                f,
                "PolicyResult::Retry {{ ctx: {:?}, req: {:?} }}",
                ctx, req
            ),
        }
    }
}
