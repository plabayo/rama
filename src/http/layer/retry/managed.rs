//! Managed retry [`Policy`].
//!
//! See [`ManagedPolicy`] for more details.
//!
//! [`Policy`]: super::Policy

use super::{Policy, PolicyResult, RetryBody};
use crate::{
    http::{Request, Response},
    service::{util::backoff::Backoff, Context},
};
use std::future::Future;

#[derive(Debug, Clone, Default)]
/// An [`Extensions`] value that can be added to the [`Context`]
/// of a [`Request`] to signal that the request should not be retried.
///
/// This requires the [`ManagedPolicy`] to be used.
///
/// [`Extensions`]: crate::service::context::Extensions
#[non_exhaustive]
pub struct DoNotRetry;

/// A managed retry [`Policy`],
/// which allows for an easier interface to configure retrying requests.
///
/// [`DoNotRetry`] can be added to the [`Context`] of a [`Request`]
/// to signal that the request should not be retried, regardless
/// of the retry functionality defined.
pub struct ManagedPolicy<B = Undefined, C = Undefined, R = Undefined> {
    backoff: B,
    clone: C,
    retry: R,
}

impl<B, C, R, State, Response, Error> Policy<State, Response, Error> for ManagedPolicy<B, C, R>
where
    B: Backoff,
    C: CloneInput<State>,
    R: RetryRule<State, Response, Error>,
    State: Send + Sync + 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    async fn retry(
        &self,
        ctx: Context<State>,
        req: Request<RetryBody>,
        result: Result<Response, Error>,
    ) -> PolicyResult<State, Response, Error> {
        if ctx.get::<DoNotRetry>().is_some() {
            // Custom extension to signal that the request should not be retried.
            return PolicyResult::Abort(result);
        }

        let (ctx, result, retry) = self.retry.retry(ctx, result).await;
        if retry && self.backoff.next_backoff().await {
            PolicyResult::Retry { ctx, req }
        } else {
            self.backoff.reset().await;
            PolicyResult::Abort(result)
        }
    }

    fn clone_input(
        &self,
        ctx: &Context<State>,
        req: &Request<RetryBody>,
    ) -> Option<(Context<State>, Request<RetryBody>)> {
        if ctx.get::<DoNotRetry>().is_some() {
            None
        } else {
            self.clone.clone_input(ctx, req)
        }
    }
}

impl<B, C, R> std::fmt::Debug for ManagedPolicy<B, C, R>
where
    B: std::fmt::Debug,
    C: std::fmt::Debug,
    R: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedPolicy")
            .field("backoff", &self.backoff)
            .field("clone", &self.clone)
            .field("retry", &self.retry)
            .finish()
    }
}

impl<B, C, R> Clone for ManagedPolicy<B, C, R>
where
    B: Clone,
    C: Clone,
    R: Clone,
{
    fn clone(&self) -> Self {
        ManagedPolicy {
            backoff: self.backoff.clone(),
            clone: self.clone.clone(),
            retry: self.retry.clone(),
        }
    }
}

impl Default for ManagedPolicy<Undefined, Undefined, Undefined> {
    fn default() -> Self {
        ManagedPolicy {
            backoff: Undefined,
            clone: Undefined,
            retry: Undefined,
        }
    }
}

impl<F> ManagedPolicy<Undefined, Undefined, F> {
    /// Create a new [`ManagedPolicy`] which uses the provided
    /// function to determine if a request should be retried.
    ///
    /// The default cloning is used and no backoff is applied.
    #[inline]
    pub fn new(retry: F) -> Self {
        ManagedPolicy::default().with_retry(retry)
    }
}

impl<C, R> ManagedPolicy<Undefined, C, R> {
    /// add a backoff to this [`ManagedPolicy`].
    pub fn with_backoff<B>(self, backoff: B) -> ManagedPolicy<B, C, R> {
        ManagedPolicy {
            backoff,
            clone: self.clone,
            retry: self.retry,
        }
    }
}

impl<B, R> ManagedPolicy<B, Undefined, R> {
    /// add a cloning function to this [`ManagedPolicy`].
    /// to determine if a request should be cloned
    pub fn with_clone<C>(self, clone: C) -> ManagedPolicy<B, C, R> {
        ManagedPolicy {
            backoff: self.backoff,
            clone,
            retry: self.retry,
        }
    }
}

impl<B, C> ManagedPolicy<B, C, Undefined> {
    /// add a retry function to this [`ManagedPolicy`].
    /// to determine if a request should be retried.
    pub fn with_retry<R>(self, retry: R) -> ManagedPolicy<B, C, R> {
        ManagedPolicy {
            backoff: self.backoff,
            clone: self.clone,
            retry,
        }
    }
}

/// A trait that is used to umbrella-cover all possible
/// implementation kinds for the retry rule functionality.
pub trait RetryRule<S, R, E>: private::Sealed<(S, R, E)> + Send + Sync + 'static {
    /// Check if the given result should be retried.
    fn retry(
        &self,
        ctx: Context<S>,
        result: Result<R, E>,
    ) -> impl Future<Output = (Context<S>, Result<R, E>, bool)> + Send + '_;
}

impl<S, Body, E> RetryRule<S, Response<Body>, E> for Undefined
where
    S: Send + Sync + 'static,
    E: std::fmt::Debug + Send + Sync + 'static,
    Body: Send + 'static,
{
    async fn retry(
        &self,
        ctx: Context<S>,
        result: Result<Response<Body>, E>,
    ) -> (Context<S>, Result<Response<Body>, E>, bool) {
        match &result {
            Ok(response) => {
                let status = response.status();
                if status.is_server_error() {
                    tracing::debug!(
                        "retrying server error http status code: {status} ({})",
                        status.as_u16()
                    );
                    (ctx, result, true)
                } else {
                    (ctx, result, false)
                }
            }
            Err(error) => {
                tracing::debug!("retrying error: {:?}", error);
                (ctx, result, true)
            }
        }
    }
}

impl<F, Fut, S, R, E> RetryRule<S, R, E> for F
where
    F: Fn(Context<S>, Result<R, E>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Context<S>, Result<R, E>, bool)> + Send + 'static,
    S: Send + Sync + 'static,
    R: Send + 'static,
    E: Send + Sync + 'static,
{
    async fn retry(
        &self,
        ctx: Context<S>,
        result: Result<R, E>,
    ) -> (Context<S>, Result<R, E>, bool) {
        self(ctx, result).await
    }
}

/// A trait that is used to umbrella-cover all possible
/// implementation kinds for the cloning functionality.
pub trait CloneInput<S>: private::Sealed<(S,)> + Send + Sync + 'static {
    /// Clone the input request if necessary.
    ///
    /// See [`Policy::clone_input`] for more details.
    ///
    /// [`Policy::clone_input`]: super::Policy::clone_input
    fn clone_input(
        &self,
        ctx: &Context<S>,
        req: &Request<RetryBody>,
    ) -> Option<(Context<S>, Request<RetryBody>)>;
}

impl<S> CloneInput<S> for Undefined {
    fn clone_input(
        &self,
        ctx: &Context<S>,
        req: &Request<RetryBody>,
    ) -> Option<(Context<S>, Request<RetryBody>)> {
        Some((ctx.clone(), req.clone()))
    }
}

impl<F, S> CloneInput<S> for F
where
    F: Fn(&Context<S>, &Request<RetryBody>) -> Option<(Context<S>, Request<RetryBody>)>
        + Send
        + Sync
        + 'static,
{
    fn clone_input(
        &self,
        ctx: &Context<S>,
        req: &Request<RetryBody>,
    ) -> Option<(Context<S>, Request<RetryBody>)> {
        self(ctx, req)
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// An type to represent the undefined default type,
/// which is used as the placeholder in the [`ManagedPolicy`],
/// when the user does not provide a specific type.
pub struct Undefined;

impl std::fmt::Display for Undefined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Undefined")
    }
}

impl Backoff for Undefined {
    async fn next_backoff(&self) -> bool {
        true
    }

    async fn reset(&self) {}
}

mod private {
    use super::*;

    pub trait Sealed<S> {}

    impl<S> Sealed<S> for Undefined {}
    impl<F, S> Sealed<(S,)> for F where
        F: Fn(&Context<S>, &Request<RetryBody>) -> Option<(Context<S>, Request<RetryBody>)>
            + Send
            + Sync
            + 'static
    {
    }
    impl<F, Fut, S, R, E> Sealed<(S, R, E)> for F
    where
        F: Fn(Context<S>, Result<R, E>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = (Context<S>, Result<R, E>, bool)> + Send + 'static,
    {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        http::{IntoResponse, StatusCode},
        service::util::{backoff::ExponentialBackoff, rng::HasherRng},
    };
    use std::time::Duration;

    fn assert_clone_input_none(
        ctx: &Context<()>,
        req: &Request<RetryBody>,
        policy: &impl Policy<(), Response, ()>,
    ) {
        assert!(policy.clone_input(ctx, req).is_none());
    }

    fn assert_clone_input_some(
        ctx: &Context<()>,
        req: &Request<RetryBody>,
        policy: &impl Policy<(), Response, ()>,
    ) {
        assert!(policy.clone_input(ctx, req).is_some());
    }

    async fn assert_retry(
        ctx: Context<()>,
        req: Request<RetryBody>,
        result: Result<Response, ()>,
        policy: &impl Policy<(), Response, ()>,
    ) {
        match policy.retry(ctx, req, result).await {
            PolicyResult::Retry { .. } => (),
            PolicyResult::Abort(_) => panic!("expected retry"),
        };
    }

    async fn assert_abort(
        ctx: Context<()>,
        req: Request<RetryBody>,
        result: Result<Response, ()>,
        policy: &impl Policy<(), Response, ()>,
    ) {
        match policy.retry(ctx, req, result).await {
            PolicyResult::Retry { .. } => panic!("expected abort"),
            PolicyResult::Abort(_) => (),
        };
    }

    #[tokio::test]
    async fn managed_policy_default() {
        let request = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(RetryBody::empty())
            .unwrap();

        let policy = ManagedPolicy::default();

        assert_clone_input_some(&Context::default(), &request, &policy);

        // do not retry HTTP Ok
        assert_abort(
            Context::default(),
            request.clone(),
            Ok(StatusCode::OK.into_response()),
            &policy,
        )
        .await;

        // do retry HTTP InternalServerError
        assert_retry(
            Context::default(),
            request.clone(),
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            &policy,
        )
        .await;

        // also retry any error case
        assert_retry(Context::default(), request, Err(()), &policy).await;
    }

    #[tokio::test]
    async fn managed_policy_default_do_not_retry() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(RetryBody::empty())
            .unwrap();

        let policy = ManagedPolicy::default();

        let mut ctx = Context::default();
        ctx.insert(DoNotRetry);

        assert_clone_input_none(&ctx, &req, &policy);

        // do not retry HTTP Ok (.... Of course)
        assert_abort(
            ctx.clone(),
            req.clone(),
            Ok(StatusCode::OK.into_response()),
            &policy,
        )
        .await;

        // do not retry HTTP InternalServerError
        assert_abort(
            ctx.clone(),
            req.clone(),
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            &policy,
        )
        .await;

        // also do not retry any error case
        assert_abort(ctx, req, Err(()), &policy).await;
    }

    #[tokio::test]
    async fn test_policy_custom_clone_fn() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(RetryBody::empty())
            .unwrap();

        fn clone_fn<S>(
            _: &Context<S>,
            _: &Request<RetryBody>,
        ) -> Option<(Context<S>, Request<RetryBody>)> {
            None
        }

        let policy = ManagedPolicy::default().with_clone(clone_fn);

        assert_clone_input_none(&Context::default(), &req, &policy);

        // retry should still be the default
        assert_abort(
            Context::default(),
            req,
            Ok(StatusCode::OK.into_response()),
            &policy,
        )
        .await;
    }

    #[tokio::test]
    async fn test_policy_custom_retry_fn() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(RetryBody::empty())
            .unwrap();

        async fn retry_fn<S, R, E>(
            ctx: Context<S>,
            result: Result<R, E>,
        ) -> (Context<S>, Result<R, E>, bool) {
            match result {
                Ok(_) => (ctx, result, false),
                Err(_) => (ctx, result, true),
            }
        }

        let policy = ManagedPolicy::new(retry_fn);

        // default clone should be used
        assert_clone_input_some(&Context::default(), &req, &policy);

        // retry should be the custom one
        assert_abort(
            Context::default(),
            req.clone(),
            Ok(StatusCode::OK.into_response()),
            &policy,
        )
        .await;
        assert_abort(
            Context::default(),
            req.clone(),
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            &policy,
        )
        .await;
        assert_retry(Context::default(), req, Err(()), &policy).await;
    }

    #[tokio::test]
    async fn test_policy_fully_custom() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(RetryBody::empty())
            .unwrap();

        fn clone_fn<S>(
            _: &Context<S>,
            _: &Request<RetryBody>,
        ) -> Option<(Context<S>, Request<RetryBody>)> {
            None
        }

        async fn retry_fn<S, R, E>(
            ctx: Context<S>,
            result: Result<R, E>,
        ) -> (Context<S>, Result<R, E>, bool) {
            match result {
                Ok(_) => (ctx, result, false),
                Err(_) => (ctx, result, true),
            }
        }

        let backoff = ExponentialBackoff::new(
            Duration::from_millis(1),
            Duration::from_millis(5),
            0.1,
            HasherRng::default,
        )
        .unwrap();

        let policy = ManagedPolicy::default()
            .with_backoff(backoff)
            .with_clone(clone_fn)
            .with_retry(retry_fn);

        assert_clone_input_none(&Context::default(), &req, &policy);

        // retry should be the custom one
        assert_abort(
            Context::default(),
            req.clone(),
            Ok(StatusCode::OK.into_response()),
            &policy,
        )
        .await;
        assert_abort(
            Context::default(),
            req.clone(),
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            &policy,
        )
        .await;
        assert_retry(Context::default(), req, Err(()), &policy).await;
    }
}
