//! Middleware for retrying "failed" requests.
//!
//! Every attempt runs on its own [`fork`](Request::fork_extensions_in_place) of the caller's
//! request [`Extensions`](rama_core::extensions::Extensions): an attempt reads everything the
//! caller inserted, while what it (or any inner layer) inserts stays isolated from the caller and
//! from every other attempt. A failed attempt therefore cannot steer the next one by inserting.
//!
//! Isolation is structural, not deep: an inherited value is shared by handle, so interior mutation
//! through it stays visible to the caller and to every other attempt — which is exactly how a
//! caller-owned counter or budget is meant to work. Only the entries an attempt inserts itself are
//! private to it.
//!
//! This holds whether or not the request turns out to be retryable: what the [`Policy`] decides
//! about retrying has no bearing on who owns the request's extensions.
//!
//! The [`Policy`] itself is the one exception to that isolation: it is handed a request backed by
//! the caller's own store, so metadata it records there (a retry count, an exhaustion marker)
//! reaches the next attempt and stays visible to the caller. Only the inner service's inserts are
//! private to an attempt.
//!
//! # Layer placement
//!
//! Place [`RetryLayer`] as early — as far outward — in the stack as your use case allows, in front
//! of everything whose work depends on the request: route or proxy selection, DNS overwrites,
//! per-target limits. Such a layer placed _outside_ runs exactly once, and every attempt then
//! reuses its verdict — retrying through the very proxy or address that just failed. Placed
//! _inside_, it is consulted per attempt.
//!
//! Retrying requires a replayable body. [`Policy::prepare_body`] decides before
//! reading whether to collect data and trailers into [`RetryBody`]. Declined
//! requests stream once; size/time-limited collection also falls back to the
//! complete original stream. The default policy still collects without bounds.
//!
//! [`follow_redirect`](crate::layer::follow_redirect) follows the same rules for redirect hops. Keep
//! that middleware outside this one, so a retry replays one hop instead of the entire chain.

use crate::{
    Body, Request, StreamingBody,
    body::util::{BodyExt, BodyStream},
};
use rama_core::Service;
use rama_core::bytes::Buf as _;
use rama_core::error::BoxError;
use rama_utils::macros::define_inner_service_accessors;

mod layer;
mod policy;

mod body;
#[doc(inline)]
pub use body::RetryBody;

pub mod early_data;
pub mod managed;
pub use managed::ManagedPolicy;

#[cfg(test)]
mod preparation_tests;
#[cfg(test)]
mod tests;

pub use self::layer::RetryLayer;
pub use self::policy::{Policy, PolicyResult};

/// Configure retrying requests of "failed" responses.
///
/// A [`Policy`] classifies what is a "failed" response.
#[derive(Debug, Clone)]
pub struct Retry<P, S> {
    policy: P,
    inner: S,
}

// ===== impl Retry =====

impl<P, S> Retry<P, S> {
    /// Retry the inner service depending on this [`Policy`].
    pub const fn new(policy: P, service: S) -> Self {
        Self {
            policy,
            inner: service,
        }
    }

    define_inner_service_accessors!();
}

#[derive(Debug)]
/// Error type for [`Retry`]
pub struct RetryError {
    kind: RetryErrorKind,
    inner: Option<BoxError>,
}

#[derive(Debug)]
enum RetryErrorKind {
    BodyConsume,
    Service,
}

impl std::fmt::Display for RetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::fmt::Display for RetryErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BodyConsume => write!(f, "failed to consume body"),
            Self::Service => write!(f, "service error"),
        }
    }
}

impl std::error::Error for RetryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner
            .as_ref()
            .map(|error| error.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl<P, S, RequestBody> Service<Request<RequestBody>> for Retry<P, S>
where
    P: Policy<S::Output, S::Error>,
    S: Service<Request<RetryBody>, Error: Into<BoxError>>,
    RequestBody: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
{
    type Output = S::Output;
    type Error = RetryError;

    async fn serve(&self, request: Request<RequestBody>) -> Result<Self::Output, Self::Error> {
        let (parts, body) = request.into_parts();
        let is_end_stream = body.is_end_stream();
        let size_hint = body.size_hint();
        let options = self.policy.prepare_body(&parts, is_end_stream, &size_hint);
        let body = match options {
            Some(_) if is_end_stream => RetryBody::empty(),
            None if is_end_stream => RetryBody::streaming(Body::empty(), size_hint),
            options => {
                // The frame-stream adapter keeps Send-only bodies supported;
                // Bytes chunks remain zero-copy and trailers remain frames.
                let body = Body::from_frame_stream(BodyStream::new(body.map_frame(|frame| {
                    frame.map_data(|mut data| data.copy_to_bytes(data.remaining()))
                })));
                match options {
                    None => RetryBody::streaming(body, size_hint),
                    Some(options) => match body.collect_with(options).await {
                        Ok(body) => RetryBody::collected(body),
                        Err(error) if error.is_cap_reached() || error.is_timed_out() => {
                            RetryBody::streaming(
                                error.into_full_body().ok_or(RetryError {
                                    kind: RetryErrorKind::BodyConsume,
                                    inner: None,
                                })?,
                                size_hint,
                            )
                        }
                        Err(error) => {
                            return Err(RetryError {
                                kind: RetryErrorKind::BodyConsume,
                                inner: Some(error.into()),
                            });
                        }
                    },
                }
            }
        };
        let mut request = Request::from_parts(parts, body);
        let mut cloned = request
            .body()
            .is_replayable()
            .then(|| self.policy.clone_input(&request))
            .flatten();

        // Fork per attempt, so an attempt's inserts reach neither the next attempt nor the caller —
        // unconditionally, as whether a request can be retried is no business of who owns its
        // extensions. Clones are taken before the fork so a retry forks from the caller's store,
        // not from the failed attempt's.
        let parent_ext = request.fork_extensions_in_place();
        loop {
            let resp = self.inner.serve(request).await;
            match cloned.take() {
                Some(cloned_req) => {
                    let cloned_req = match self.policy.retry(cloned_req, resp).await {
                        PolicyResult::Abort(result) => {
                            return result.map_err(|e| RetryError {
                                kind: RetryErrorKind::Service,
                                inner: Some(e.into()),
                            });
                        }
                        PolicyResult::Retry { req } => req,
                    };

                    request = cloned_req;
                    // A policy may return a freshly built request. Restore the
                    // caller store before cloning the next policy view, then
                    // fork the request actually sent to the service.
                    request.set_extensions(parent_ext.clone());
                    cloned = request
                        .body()
                        .is_replayable()
                        .then(|| self.policy.clone_input(&request))
                        .flatten();
                    request.set_extensions(parent_ext.fork());
                }
                // no clone was made, so no possibility to retry
                None => {
                    return resp.map_err(|e| RetryError {
                        kind: RetryErrorKind::Service,
                        inner: Some(e.into()),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        BodyExtractExt, Response, StatusCode,
        body::{CollectOptions, SizeHint},
        layer::retry::managed::DoNotRetry,
        request::Parts,
        service::web::response::IntoResponse,
    };
    use rama_core::{
        Layer,
        error::BoxErrorExt,
        extensions::{Extension, Extensions, ExtensionsRef},
        service::service_fn,
    };
    use rama_utils::{backoff::ExponentialBackoff, rng::HasherRng};
    use std::{sync::atomic::AtomicUsize, time::Duration};

    #[tokio::test]
    async fn test_service_with_managed_retry() {
        let backoff = ExponentialBackoff::new(
            Duration::from_millis(1),
            Duration::from_millis(5),
            0.1,
            HasherRng::default,
        )
        .unwrap();

        #[derive(Debug, Extension)]
        struct State {
            retry_counter: AtomicUsize,
        }

        async fn retry<Body, E>(
            req: Request<Body>,
            result: Result<Response, E>,
        ) -> (Request<Body>, Result<Response, E>, bool) {
            if req.extensions().contains::<DoNotRetry>() {
                panic!("unexpected retry: should be disabled");
            }

            if let Ok(ref res) = result {
                if res.status().is_server_error() {
                    req.extensions()
                        .get_ref::<State>()
                        .unwrap()
                        .retry_counter
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    (req, result, true)
                } else {
                    (req, result, false)
                }
            } else {
                req.extensions()
                    .get_ref::<State>()
                    .unwrap()
                    .retry_counter
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                (req, result, true)
            }
        }

        let retry_policy = ManagedPolicy::new(retry).with_backoff(backoff);

        let service = RetryLayer::new(retry_policy).into_layer(service_fn(
            async |req: Request<RetryBody>| {
                let txt = req.try_into_string().await.unwrap();
                match txt.as_str() {
                    "internal" => Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
                    "error" => Err(BoxError::from_static_str("custom error")),
                    _ => Ok(txt.into_response()),
                }
            },
        ));

        fn request(s: &'static str) -> Request {
            Request::builder().body(s.into()).unwrap()
        }

        fn extensions() -> Extensions {
            let extensions = Extensions::new();
            extensions.insert(State {
                retry_counter: AtomicUsize::new(0),
            });
            extensions
        }

        fn do_not_retry_extensions() -> Extensions {
            let extensions = extensions();
            extensions.insert(DoNotRetry::default());
            extensions
        }

        async fn assert_serve_ok<E: std::fmt::Debug>(
            msg: &'static str,
            input: &'static str,
            output: &'static str,
            extensions: Extensions,
            retried: bool,
            service: &impl Service<Request, Output = Response, Error = E>,
        ) {
            let state = extensions.get_arc::<State>().unwrap();

            let request = request(input);
            request.extensions().extend(&extensions);

            let fut = service.serve(request);
            let res = fut.await.unwrap();

            let body = res.try_into_string().await.unwrap();
            assert_eq!(body, output, "{msg}");
            if retried {
                assert!(
                    state
                        .retry_counter
                        .load(std::sync::atomic::Ordering::Acquire)
                        > 0,
                    "{msg}"
                );
            } else {
                assert_eq!(
                    state
                        .retry_counter
                        .load(std::sync::atomic::Ordering::Acquire),
                    0,
                    "{msg}"
                );
            }
        }

        async fn assert_serve_err<E: std::fmt::Debug>(
            msg: &'static str,
            input: &'static str,
            extensions: Extensions,
            retried: bool,
            service: &impl Service<Request, Output = Response, Error = E>,
        ) {
            let state = extensions.get_arc::<State>().unwrap();

            let request = request(input);
            request.extensions().extend(&extensions);

            let fut = service.serve(request);
            let res = fut.await;

            assert!(res.is_err(), "{msg}");
            if retried {
                assert!(
                    state
                        .retry_counter
                        .load(std::sync::atomic::Ordering::Acquire)
                        > 0,
                    "{msg}"
                );
            } else {
                assert_eq!(
                    state
                        .retry_counter
                        .load(std::sync::atomic::Ordering::Acquire),
                    0,
                    "{msg}"
                )
            }
        }

        assert_serve_ok(
            "ok response should be aborted as response without retry",
            "hello",
            "hello",
            extensions(),
            false,
            &service,
        )
        .await;
        assert_serve_ok(
            "internal will trigger 500 with a retry",
            "internal",
            "",
            extensions(),
            true,
            &service,
        )
        .await;
        assert_serve_err(
            "error will trigger an actual non-http error with a retry",
            "error",
            extensions(),
            true,
            &service,
        )
        .await;

        assert_serve_ok(
            "normally internal will trigger a 500 with retry, but using DoNotRetry will disable retrying",
            "internal",
            "",
            do_not_retry_extensions(),
            false,
            &service,
        ).await;
    }

    #[tokio::test]
    async fn inner_layer_do_not_retry_insert_does_not_stop_retries() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        async fn retry_on_server_error<Body, E>(
            req: Request<Body>,
            result: Result<Response, E>,
        ) -> (Request<Body>, Result<Response, E>, bool) {
            let retry = matches!(&result, Ok(res) if res.status().is_server_error());
            (req, result, retry)
        }

        let backoff = ExponentialBackoff::new(
            Duration::from_millis(1),
            Duration::from_millis(5),
            0.1,
            HasherRng::default,
        )
        .unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let inner_calls = calls.clone();
        let service =
            RetryLayer::new(ManagedPolicy::new(retry_on_server_error).with_backoff(backoff))
                .into_layer(service_fn(move |req: Request<RetryBody>| {
                    let inner_calls = inner_calls.clone();
                    async move {
                        let n = inner_calls.fetch_add(1, Ordering::SeqCst);
                        // an inner layer marking the request writes into this
                        // attempt's own fork, so the policy (reading the caller's
                        // store) must not see it and must still retry the 500
                        req.extensions().insert(DoNotRetry::default());
                        if n == 0 {
                            Ok::<_, BoxError>(StatusCode::INTERNAL_SERVER_ERROR.into_response())
                        } else {
                            Ok(StatusCode::OK.into_response())
                        }
                    }
                }));

        let request: Request = Request::builder().body("x".into()).unwrap();
        let res = service.serve(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "an inner-layer DoNotRetry insert must not suppress the retry"
        );
    }

    #[tokio::test]
    async fn fresh_policy_requests_keep_the_caller_extension_view() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug, Extension)]
        struct CallerState(AtomicUsize);
        #[derive(Debug, Extension)]
        struct AttemptOnly;

        #[derive(Clone)]
        struct FreshRequestPolicy;

        impl Policy<Response, BoxError> for FreshRequestPolicy {
            fn prepare_body(&self, _: &Parts, _: bool, _: &SizeHint) -> Option<CollectOptions> {
                Some(CollectOptions::new())
            }

            async fn retry(
                &self,
                req: Request<RetryBody>,
                result: Result<Response, BoxError>,
            ) -> PolicyResult<Response, BoxError> {
                assert!(!req.extensions().contains::<AttemptOnly>());
                let call = req
                    .extensions()
                    .get_ref::<CallerState>()
                    .expect("every policy round sees the caller store")
                    .0
                    .fetch_add(1, Ordering::SeqCst);
                if call < 2 {
                    PolicyResult::Retry {
                        req: Request::new(RetryBody::empty()),
                    }
                } else {
                    PolicyResult::Abort(result)
                }
            }

            fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
                Some(Request::from_parts(
                    req.clone_parts(),
                    req.body().try_clone()?,
                ))
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let inner_attempts = attempts.clone();
        let service = RetryLayer::new(FreshRequestPolicy).into_layer(service_fn(
            move |req: Request<RetryBody>| {
                let inner_attempts = inner_attempts.clone();
                async move {
                    assert!(req.extensions().contains::<CallerState>());
                    req.extensions().insert(AttemptOnly);
                    inner_attempts.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, BoxError>(StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
            },
        ));

        let caller_extensions = Extensions::new();
        caller_extensions.insert(CallerState(AtomicUsize::new(0)));
        let mut request = Request::new(RetryBody::empty());
        request.set_extensions(caller_extensions.clone());

        let response = service.serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(
            caller_extensions
                .get_ref::<CallerState>()
                .unwrap()
                .0
                .load(Ordering::SeqCst),
            3
        );
        assert!(!caller_extensions.contains::<AttemptOnly>());
    }
}
