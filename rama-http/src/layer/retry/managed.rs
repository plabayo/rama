//! Managed retry [`Policy`].
//!
//! See [`ManagedPolicy`] for more details.
//!
//! [`Policy`]: super::Policy

use super::{Policy, PolicyResult, RetryBody};
use crate::{Request, Response};
use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::tracing;
use rama_utils::backoff::Backoff;

#[derive(Debug, Clone, Default)]
/// An [`Extensions`] value that can be added to the [`Context`]
/// of a [`Request`] to signal that the request should not be retried.
///
/// This requires the [`ManagedPolicy`] to be used.
///
/// [`Extensions`]: rama_core::extensions::Extensions
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

impl<B, C, R, Response, Error> Policy<Response, Error> for ManagedPolicy<B, C, R>
where
    B: Backoff,
    C: CloneInput,
    R: RetryRule<Request<RetryBody>, Response, Error>,
    Response: Send + 'static,
    Error: Send + 'static,
{
    async fn retry(
        &self,
        req: Request<RetryBody>,
        result: Result<Response, Error>,
    ) -> PolicyResult<Response, Error> {
        if req.extensions().get::<DoNotRetry>().is_some() {
            // Custom extension to signal that the request should not be retried.
            return PolicyResult::Abort(result);
        }

        let (req, result, retry) = self.retry.retry(req, result).await;
        if retry && self.backoff.next_backoff().await {
            PolicyResult::Retry { req }
        } else {
            self.backoff.reset().await;
            PolicyResult::Abort(result)
        }
    }

    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        if req.extensions().get::<DoNotRetry>().is_some() {
            None
        } else {
            self.clone.clone_input(req)
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
        Self {
            backoff: self.backoff.clone(),
            clone: self.clone.clone(),
            retry: self.retry.clone(),
        }
    }
}

impl Default for ManagedPolicy<Undefined, Undefined, Undefined> {
    fn default() -> Self {
        Self {
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
pub trait RetryRule<Request, R, E>:
    private::Sealed<(Request, R, E)> + Send + Sync + 'static
{
    /// Check if the given result should be retried.
    fn retry(
        &self,
        request: Request,
        result: Result<R, E>,
    ) -> impl Future<Output = (Request, Result<R, E>, bool)> + Send + '_;
}

impl<Request, Body, E> RetryRule<Request, Response<Body>, E> for Undefined
where
    E: std::fmt::Debug + Send + Sync + 'static,
    Body: Send + 'static,
    Request: ExtensionsRef + Send + 'static,
{
    async fn retry(
        &self,
        request: Request,
        result: Result<Response<Body>, E>,
    ) -> (Request, Result<Response<Body>, E>, bool) {
        match &result {
            Ok(response) => {
                let status = response.status();
                if status.is_server_error() {
                    tracing::debug!(
                        "retrying server error http status code: {status} ({})",
                        status.as_u16()
                    );
                    (request, result, true)
                } else {
                    (request, result, false)
                }
            }
            Err(error) => {
                tracing::debug!("retrying error: {:?}", error);
                (request, result, true)
            }
        }
    }
}

impl<F, Fut, Request, R, E> RetryRule<Request, R, E> for F
where
    F: Fn(Request, Result<R, E>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Request, Result<R, E>, bool)> + Send + 'static,
    Request: Send + 'static,
    R: Send + 'static,
    E: Send + Sync + 'static,
{
    async fn retry(&self, request: Request, result: Result<R, E>) -> (Request, Result<R, E>, bool) {
        self(request, result).await
    }
}

/// A trait that is used to umbrella-cover all possible
/// implementation kinds for the cloning functionality.
pub trait CloneInput: private::Sealed<()> + Send + Sync + 'static {
    /// Clone the input request if necessary.
    ///
    /// See [`Policy::clone_input`] for more details.
    ///
    /// [`Policy::clone_input`]: super::Policy::clone_input
    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>>;
}

impl CloneInput for Undefined {
    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        Some(req.clone())
    }
}

impl<F> CloneInput for F
where
    F: Fn(&Request<RetryBody>) -> Option<Request<RetryBody>> + Send + Sync + 'static,
{
    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        self(req)
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// A type to represent the undefined default type,
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
    impl<F> Sealed<()> for F where
        F: Fn(&Request<RetryBody>) -> Option<Request<RetryBody>> + Send + Sync + 'static
    {
    }
    impl<F, Fut, Request, R, E> Sealed<(Request, R, E)> for F
    where
        F: Fn(Request, Result<R, E>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = (Request, Result<R, E>, bool)> + Send + 'static,
    {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StatusCode, service::web::response::IntoResponse};
    use rama_core::extensions::ExtensionsMut;
    use rama_utils::{backoff::ExponentialBackoff, rng::HasherRng};
    use std::time::Duration;

    fn assert_clone_input_none(req: &Request<RetryBody>, policy: &impl Policy<Response, ()>) {
        assert!(policy.clone_input(req).is_none());
    }

    fn assert_clone_input_some(req: &Request<RetryBody>, policy: &impl Policy<Response, ()>) {
        assert!(policy.clone_input(req).is_some());
    }

    async fn assert_retry(
        req: Request<RetryBody>,
        result: Result<Response, ()>,
        policy: &impl Policy<Response, ()>,
    ) {
        match policy.retry(req, result).await {
            PolicyResult::Retry { .. } => (),
            PolicyResult::Abort(_) => panic!("expected retry"),
        };
    }

    async fn assert_abort(
        req: Request<RetryBody>,
        result: Result<Response, ()>,
        policy: &impl Policy<Response, ()>,
    ) {
        match policy.retry(req, result).await {
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

        assert_clone_input_some(&request, &policy);

        // do not retry HTTP Ok
        assert_abort(request.clone(), Ok(StatusCode::OK.into_response()), &policy).await;

        // do retry HTTP InternalServerError
        assert_retry(
            request.clone(),
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            &policy,
        )
        .await;

        // also retry any error case
        assert_retry(request, Err(()), &policy).await;
    }

    #[tokio::test]
    async fn managed_policy_default_do_not_retry() {
        let mut req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(RetryBody::empty())
            .unwrap();

        let policy = ManagedPolicy::default();

        req.extensions_mut().insert(DoNotRetry);

        assert_clone_input_none(&req, &policy);

        // do not retry HTTP Ok (.... Of course)
        assert_abort(req.clone(), Ok(StatusCode::OK.into_response()), &policy).await;

        // do not retry HTTP InternalServerError
        assert_abort(
            req.clone(),
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            &policy,
        )
        .await;

        // also do not retry any error case
        assert_abort(req, Err(()), &policy).await;
    }

    #[tokio::test]
    async fn test_policy_custom_clone_fn() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(RetryBody::empty())
            .unwrap();

        fn clone_fn(_: &Request<RetryBody>) -> Option<Request<RetryBody>> {
            None
        }

        let policy = ManagedPolicy::default().with_clone(clone_fn);

        assert_clone_input_none(&req, &policy);

        // retry should still be the default
        assert_abort(req, Ok(StatusCode::OK.into_response()), &policy).await;
    }

    #[tokio::test]
    async fn test_policy_custom_retry_fn() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(RetryBody::empty())
            .unwrap();

        async fn retry_fn<Body, R, E>(
            request: Request<Body>,
            result: Result<R, E>,
        ) -> (Request<Body>, Result<R, E>, bool) {
            match result {
                Ok(_) => (request, result, false),
                Err(_) => (request, result, true),
            }
        }

        let policy = ManagedPolicy::new(retry_fn);

        // default clone should be used
        assert_clone_input_some(&req, &policy);

        // retry should be the custom one
        assert_abort(req.clone(), Ok(StatusCode::OK.into_response()), &policy).await;
        assert_abort(
            req.clone(),
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            &policy,
        )
        .await;
        assert_retry(req, Err(()), &policy).await;
    }

    #[tokio::test]
    async fn test_policy_fully_custom() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(RetryBody::empty())
            .unwrap();

        fn clone_fn(_: &Request<RetryBody>) -> Option<Request<RetryBody>> {
            None
        }

        async fn retry_fn<Body, R, E>(
            req: Request<Body>,
            result: Result<R, E>,
        ) -> (Request<Body>, Result<R, E>, bool) {
            match result {
                Ok(_) => (req, result, false),
                Err(_) => (req, result, true),
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

        assert_clone_input_none(&req, &policy);

        // retry should be the custom one
        assert_abort(req.clone(), Ok(StatusCode::OK.into_response()), &policy).await;
        assert_abort(
            req.clone(),
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            &policy,
        )
        .await;
        assert_retry(req, Err(()), &policy).await;
    }
}
