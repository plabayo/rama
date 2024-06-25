use super::RetryBody;
use crate::{http::Request, service::Context};
use std::future::Future;

/// A "retry policy" to classify if a request should be retried.
///
/// # Example
///
/// ```
/// use rama::service::Context;
/// use rama::http::Request;
/// use rama::http::layer::retry::{Policy, PolicyResult, RetryBody};
/// use std::sync::Arc;
/// use parking_lot::Mutex;
///
/// struct Attempts(Arc<Mutex<usize>>);
///
/// impl<S, R, E> Policy<S, R, E> for Attempts
///     where
///         S: Send + Sync + 'static,
///         R: Send + 'static,
///         E: Send + Sync + 'static,
/// {
///     async fn retry(&self, ctx: Context<S>, req: Request<RetryBody>, result: Result<R, E>) -> PolicyResult<S, R, E> {
///         match result {
///             Ok(_) => {
///                 // Treat all `Response`s as success,
///                 // so don't retry...
///                 PolicyResult::Abort(result)
///             },
///             Err(_) => {
///                 // Treat all errors as failures...
///                 // But we limit the number of attempts...
///                 let mut attempts = self.0.lock();
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
///     fn clone_input(&self, ctx: &Context<S>, req: &Request<RetryBody>) -> Option<(Context<S>, Request<RetryBody>)> {
///         Some((ctx.clone(), req.clone()))
///     }
/// }
/// ```
pub trait Policy<S, R, E>: Send + Sync + 'static {
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
        req: Request<RetryBody>,
        result: Result<R, E>,
    ) -> impl Future<Output = PolicyResult<S, R, E>> + Send + '_;

    /// Tries to clone a request before being passed to the inner service.
    ///
    /// If the request cannot be cloned, return [`None`]. Moreover, the retry
    /// function will not be called if the [`None`] is returned.
    fn clone_input(
        &self,
        ctx: &Context<S>,
        req: &Request<RetryBody>,
    ) -> Option<(Context<S>, Request<RetryBody>)>;
}

impl<P, S, R, E> Policy<S, R, E> for std::sync::Arc<P>
where
    P: Policy<S, R, E>,
{
    fn retry(
        &self,
        ctx: Context<S>,
        req: Request<RetryBody>,
        result: Result<R, E>,
    ) -> impl Future<Output = PolicyResult<S, R, E>> + Send + '_ {
        (**self).retry(ctx, req, result)
    }

    fn clone_input(
        &self,
        ctx: &Context<S>,
        req: &Request<RetryBody>,
    ) -> Option<(Context<S>, Request<RetryBody>)> {
        (**self).clone_input(ctx, req)
    }
}

/// The full result of a limit policy.
pub enum PolicyResult<S, R, E> {
    /// The result should not be retried,
    /// and the result should be returned to the caller.
    Abort(Result<R, E>),
    /// The result should be retried,
    /// and the request should be passed to the inner service again.
    Retry {
        /// The context of the request.
        ctx: Context<S>,
        /// The request to be retried, with the above context.
        req: Request<RetryBody>,
    },
}

impl<S, R, E> std::fmt::Debug for PolicyResult<S, R, E>
where
    S: std::fmt::Debug,
    R: std::fmt::Debug,
    E: std::fmt::Debug,
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

macro_rules! impl_retry_policy_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, State, Response, Error> Policy<State, Response, Error> for crate::utils::combinators::$id<$($param),+>
        where
            $($param: Policy<State, Response, Error>),+,
            State: Send + Sync + 'static,
            Response: Send + 'static,
            Error: Send + Sync + 'static,
        {
            async fn retry(
                &self,
                ctx: Context<State>,
                req: http::Request<RetryBody>,
                result: Result<Response, Error>,
            ) -> PolicyResult<State, Response, Error> {
                match self {
                    $(
                        crate::utils::combinators::$id::$param(policy) => policy.retry(ctx, req, result).await,
                    )+
                }
            }

            fn clone_input(
                &self,
                ctx: &Context<State>,
                req: &http::Request<RetryBody>,
            ) -> Option<(Context<State>, http::Request<RetryBody>)> {
                match self {
                    $(
                        crate::utils::combinators::$id::$param(policy) => policy.clone_input(ctx, req),
                    )+
                }
            }
        }
    };
}

crate::utils::combinators::impl_either!(impl_retry_policy_either);
