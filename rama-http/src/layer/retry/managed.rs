//! Managed retry [`Policy`].
//!
//! See [`ManagedPolicy`] for more details.
//!
//! [`Policy`]: super::Policy

use super::{
    Policy, PolicyResult, RetryBody,
    storage::{MemoryReplay, ReplayStore},
};
use crate::{
    Request, Response,
    body::{CollectOptions, SizeHint},
    request::Parts,
};
use rama_core::extensions::{Extension, ExtensionsRef};
use rama_core::telemetry::tracing;
use rama_utils::backoff::Backoff;

#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
/// A metadata value that can be added to the [`Extensions`]
/// of a [`Request`] to signal that the request should not be retried.
///
/// This requires the [`ManagedPolicy`] to be used.
///
/// Preparation is skipped as well, so the original body streams without buffering.
///
/// Only the caller can set it, i.e. anything _outside_ [`Retry`]: the policy reads it off the
/// request clone, which references the caller's store, so an insert made by an inner layer lands in
/// that attempt's own fork and goes unseen here.
///
/// [`Extensions`]: rama_core::extensions::Extensions
/// [`Retry`]: super::Retry
#[non_exhaustive]
pub struct DoNotRetry;

/// A managed retry [`Policy`],
/// which allows for an easier interface to configure retrying requests.
///
/// The default [`MemoryReplay`] retains up to 64 KiB per request for up to
/// 30 seconds. [`Self::with_replay_store`] configures a different budget or
/// storage backend. [`Self::with_prepare_body`] can skip capture or impose
/// tighter limits for individual requests.
///
/// [`DoNotRetry`] can be added to the [`Extensions`] of a [`Request`]
/// to signal that the request should not be retried, regardless
/// of the retry functionality defined.
///
/// [`Extensions`]: rama_core::extensions::Extensions
#[derive(Debug, Clone)]
pub struct ManagedPolicy<
    B = Undefined,
    C = Undefined,
    R = Undefined,
    P = Undefined,
    S = MemoryReplay,
> {
    backoff: B,
    clone: C,
    retry: R,
    prepare: P,
    store: S,
}

impl<B, C, R, P, S, Response, Error> Policy<Response, Error> for ManagedPolicy<B, C, R, P, S>
where
    B: Backoff,
    P: PrepareBody,
    S: ReplayStore,
    C: CloneInput,
    R: RetryRule<Request<RetryBody>, Response, Error>,
    Response: Send + 'static,
    Error: Send + 'static,
{
    fn prepare_body(
        &self,
        parts: &Parts,
        is_end_stream: bool,
        size_hint: &SizeHint,
    ) -> Option<CollectOptions> {
        if parts.extensions.contains::<DoNotRetry>() {
            None
        } else {
            self.prepare.prepare_body(parts, is_end_stream, size_hint)
        }
    }

    fn replay_store(&self, _: &Parts) -> &dyn ReplayStore {
        &self.store
    }

    async fn retry(
        &self,
        req: Request<RetryBody>,
        result: Result<Response, Error>,
    ) -> PolicyResult<Response, Error> {
        if req.extensions().get_ref::<DoNotRetry>().is_some() {
            // Custom extension to signal that the request should not be retried.
            return PolicyResult::Abort(result);
        }

        let (req, result, retry) = self.retry.retry(req, result).await;
        if retry {
            PolicyResult::Retry { req, result }
        } else {
            self.backoff.reset().await;
            PolicyResult::Abort(result)
        }
    }

    async fn next_attempt(&self) -> bool {
        if self.backoff.next_backoff().await {
            true
        } else {
            self.backoff.reset().await;
            false
        }
    }

    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        if req.extensions().get_ref::<DoNotRetry>().is_some() {
            None
        } else {
            self.clone.clone_input(req)
        }
    }
}

impl Default for ManagedPolicy<Undefined, Undefined, Undefined> {
    fn default() -> Self {
        Self {
            backoff: Undefined,
            clone: Undefined,
            retry: Undefined,
            prepare: Undefined,
            store: MemoryReplay::default(),
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

impl<C, R, P, S> ManagedPolicy<Undefined, C, R, P, S> {
    /// add a backoff to this [`ManagedPolicy`].
    pub fn with_backoff<B>(self, backoff: B) -> ManagedPolicy<B, C, R, P, S> {
        ManagedPolicy {
            backoff,
            clone: self.clone,
            retry: self.retry,
            prepare: self.prepare,
            store: self.store,
        }
    }
}

impl<B, R, P, S> ManagedPolicy<B, Undefined, R, P, S> {
    /// add a cloning function to this [`ManagedPolicy`].
    /// to determine if a request should be cloned
    pub fn with_clone<C>(self, clone: C) -> ManagedPolicy<B, C, R, P, S> {
        ManagedPolicy {
            backoff: self.backoff,
            clone,
            retry: self.retry,
            prepare: self.prepare,
            store: self.store,
        }
    }
}

impl<B, C, P, S> ManagedPolicy<B, C, Undefined, P, S> {
    /// add a retry function to this [`ManagedPolicy`].
    /// to determine if a request should be retried.
    pub fn with_retry<R>(self, retry: R) -> ManagedPolicy<B, C, R, P, S> {
        ManagedPolicy {
            backoff: self.backoff,
            clone: self.clone,
            retry,
            prepare: self.prepare,
            store: self.store,
        }
    }
}

impl<B, C, R, S> ManagedPolicy<B, C, R, Undefined, S> {
    /// Configure replay preparation before the body is read.
    ///
    /// Return `None` to stream once, or collection options to prepare a replay.
    /// `DoNotRetry` takes precedence over this function.
    pub fn with_prepare_body<P>(self, prepare: P) -> ManagedPolicy<B, C, R, P, S> {
        ManagedPolicy {
            backoff: self.backoff,
            clone: self.clone,
            retry: self.retry,
            prepare,
            store: self.store,
        }
    }
}

impl<B, C, R, P, S> ManagedPolicy<B, C, R, P, S> {
    /// Set the backend that captures approved bodies while the first attempt reads them.
    ///
    /// This store is shared across requests served by this policy. A custom
    /// backend can allocate a distinct writer for each capture in [`ReplayStore::start`].
    ///
    /// See the [storage examples](super::storage) for memory and filesystem configuration.
    pub fn with_replay_store<T: ReplayStore>(self, store: T) -> ManagedPolicy<B, C, R, P, T> {
        ManagedPolicy {
            backoff: self.backoff,
            clone: self.clone,
            retry: self.retry,
            prepare: self.prepare,
            store,
        }
    }
}

/// Decide whether to capture a body for replay and optionally tighten the store limits.
///
/// Implemented for functions taking request parts, the body's end-of-stream
/// assertion, and its size hint, and returning optional collection limits.
pub trait PrepareBody: private::Sealed<(Parts,)> + Send + Sync + 'static {
    /// Return collection options, or decline replay preparation.
    fn prepare_body(
        &self,
        parts: &Parts,
        is_end_stream: bool,
        size_hint: &SizeHint,
    ) -> Option<CollectOptions>;
}

impl PrepareBody for Undefined {
    fn prepare_body(&self, _: &Parts, _: bool, _: &SizeHint) -> Option<CollectOptions> {
        Some(CollectOptions::new())
    }
}

impl<F> PrepareBody for F
where
    F: Fn(&Parts, bool, &SizeHint) -> Option<CollectOptions> + Send + Sync + 'static,
{
    fn prepare_body(
        &self,
        parts: &Parts,
        is_end_stream: bool,
        size_hint: &SizeHint,
    ) -> Option<CollectOptions> {
        self(parts, is_end_stream, size_hint)
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
        Some(Request::from_parts(
            req.clone_parts(),
            req.body().try_clone()?,
        ))
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
    impl<F> Sealed<(Parts,)> for F where
        F: Fn(&Parts, bool, &SizeHint) -> Option<CollectOptions> + Send + Sync + 'static
    {
    }
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
    use crate::{
        Body, BodyExtractExt as _, StatusCode, body::Frame, layer::retry::Retry,
        service::web::response::IntoResponse,
    };
    use rama_core::{
        Service as _, bytes::Bytes, error::BoxError, extensions::ExtensionsRef, futures::stream,
        service::service_fn,
    };
    use rama_utils::{backoff::ExponentialBackoff, rng::HasherRng};
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

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
    async fn managed_policy_resets_exhausted_backoff() {
        #[derive(Default)]
        struct OneRetry(AtomicBool);

        impl Backoff for OneRetry {
            async fn next_backoff(&self) -> bool {
                !self.0.swap(true, Ordering::Relaxed)
            }

            async fn reset(&self) {
                self.0.store(false, Ordering::Relaxed);
            }
        }

        let policy = ManagedPolicy::default().with_backoff(OneRetry::default());
        assert!(Policy::<Response, ()>::next_attempt(&policy).await);
        assert!(!Policy::<Response, ()>::next_attempt(&policy).await);
        assert!(Policy::<Response, ()>::next_attempt(&policy).await);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_finishes_the_upload_before_backoff_starts() {
        #[derive(Clone)]
        struct DelayedBackoff;
        impl Backoff for DelayedBackoff {
            async fn next_backoff(&self) -> bool {
                tokio::time::sleep(Duration::from_secs(1)).await;
                true
            }

            async fn reset(&self) {}
        }

        let first = AtomicBool::new(true);
        let policy = ManagedPolicy::default()
            .with_replay_store(MemoryReplay::new(32).with_timeout(Duration::from_millis(10)))
            .with_backoff(DelayedBackoff);
        let retry = Retry::new(
            policy,
            service_fn(move |req: Request<RetryBody>| {
                let is_first = first.swap(false, Ordering::Relaxed);
                async move {
                    let status = if is_first {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        assert_eq!(req.try_into_string().await.unwrap(), "hello");
                        StatusCode::OK
                    };
                    Ok::<_, BoxError>(status.into_response())
                }
            }),
        );
        let body = Body::from_frame_stream(stream::iter([Ok::<_, BoxError>(Frame::data(
            Bytes::from_static(b"hello"),
        ))]));
        assert_eq!(
            retry.serve(Request::new(body)).await.unwrap().status(),
            StatusCode::OK
        );
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
        assert_abort(
            Request::from_parts(request.clone_parts(), request.body().try_clone().unwrap()),
            Ok(StatusCode::OK.into_response()),
            &policy,
        )
        .await;

        // do retry HTTP InternalServerError
        assert_retry(
            Request::from_parts(request.clone_parts(), request.body().try_clone().unwrap()),
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            &policy,
        )
        .await;

        // also retry any error case
        assert_retry(request, Err(()), &policy).await;
    }

    #[tokio::test]
    async fn managed_policy_default_do_not_retry() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(RetryBody::empty())
            .unwrap();

        let policy = ManagedPolicy::default();

        req.extensions().insert(DoNotRetry);

        assert_clone_input_none(&req, &policy);

        // do not retry HTTP Ok (.... Of course)
        assert_abort(
            Request::from_parts(req.clone_parts(), req.body().try_clone().unwrap()),
            Ok(StatusCode::OK.into_response()),
            &policy,
        )
        .await;

        // do not retry HTTP InternalServerError
        assert_abort(
            Request::from_parts(req.clone_parts(), req.body().try_clone().unwrap()),
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

    #[test]
    fn custom_clone_result_and_placeholder_display_are_preserved() {
        let req = Request::builder()
            .uri("http://example.com/original")
            .body(RetryBody::empty())
            .unwrap();
        let clone = |req: &Request<RetryBody>| {
            let mut cloned =
                Request::from_parts(req.clone_parts(), req.body().try_clone().unwrap());
            *cloned.uri_mut() = "http://example.com/cloned".try_into().unwrap();
            Some(cloned)
        };

        let cloned = CloneInput::clone_input(&clone, &req).unwrap();
        assert_eq!(cloned.uri().as_str(), "http://example.com/cloned");
        assert_eq!(Undefined.to_string(), "Undefined");
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
        assert_abort(
            Request::from_parts(req.clone_parts(), req.body().try_clone().unwrap()),
            Ok(StatusCode::OK.into_response()),
            &policy,
        )
        .await;
        assert_abort(
            Request::from_parts(req.clone_parts(), req.body().try_clone().unwrap()),
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
        assert_abort(
            Request::from_parts(req.clone_parts(), req.body().try_clone().unwrap()),
            Ok(StatusCode::OK.into_response()),
            &policy,
        )
        .await;
        assert_abort(
            Request::from_parts(req.clone_parts(), req.body().try_clone().unwrap()),
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            &policy,
        )
        .await;
        assert_retry(req, Err(()), &policy).await;
    }
}
