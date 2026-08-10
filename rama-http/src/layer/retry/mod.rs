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
//! One counterweight: retrying requires a replayable body, so this middleware buffers the request
//! body in full ([`RetryBody`]) and every layer inside it sees that buffered body instead of the
//! original stream.
//!
//! [`follow_redirect`](crate::layer::follow_redirect) follows the same rules for redirect hops. Keep
//! that middleware outside this one, so a retry replays one hop instead of the entire chain.

use crate::{Request, StreamingBody, body::util::BodyExt};
use rama_core::Service;
use rama_core::error::BoxError;
use rama_utils::macros::define_inner_service_accessors;

mod layer;
mod policy;

mod body;
#[doc(inline)]
pub use body::RetryBody;

pub mod managed;
pub use managed::ManagedPolicy;

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
        match &self.inner {
            Some(inner) => write!(f, "{}: {}", self.kind, inner),
            None => write!(f, "{}", self.kind),
        }
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
        self.inner.as_ref().and_then(|e| e.source())
    }
}

impl<P, S, Body> Service<Request<Body>> for Retry<P, S>
where
    P: Policy<S::Output, S::Error>,
    S: Service<Request<RetryBody>, Error: Into<BoxError>>,
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
{
    type Output = S::Output;
    type Error = RetryError;

    async fn serve(&self, request: Request<Body>) -> Result<Self::Output, Self::Error> {
        // consume body so we can clone the request if desired
        let (parts, body) = request.into_parts();
        let body = body.collect().await.map_err(|e| RetryError {
            kind: RetryErrorKind::BodyConsume,
            inner: Some(e.into()),
        })?;
        let body = RetryBody::new(body.to_bytes());
        let mut request = Request::from_parts(parts, body);

        let mut cloned = self.policy.clone_input(&request);

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

                    cloned = self.policy.clone_input(&cloned_req);
                    request = cloned_req;
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
        BodyExtractExt, Response, StatusCode, layer::retry::managed::DoNotRetry,
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
}
