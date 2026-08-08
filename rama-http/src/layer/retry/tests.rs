#![expect(
    clippy::unreachable,
    reason = "test policy stub: `retry` is only invoked after a request clone, which the test fixture deliberately prevents"
)]

use super::*;
use crate::BodyExtractExt;
use crate::service::web::response::IntoResponse;
use crate::{Request, Response};
use parking_lot::Mutex;
use rama_core::error::BoxError;
use rama_core::error::BoxErrorExt as _;
use rama_core::extensions::{Extension, ExtensionsRef};
use rama_core::service::service_fn;
use rama_core::{Layer, Service};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[tokio::test]
async fn retry_errors() {
    struct Svc {
        errored: AtomicBool,
        response_counter: Arc<AtomicUsize>,
        error_counter: Arc<AtomicUsize>,
    }

    impl Service<Request<RetryBody>> for Svc {
        type Output = Response;
        type Error = BoxError;

        async fn serve(&self, req: Request<RetryBody>) -> Result<Self::Output, Self::Error> {
            assert_eq!(req.try_into_string().await.unwrap(), "hello");
            if self.errored.swap(true, Ordering::AcqRel) {
                self.response_counter.fetch_add(1, Ordering::AcqRel);
                Ok("world".into_response())
            } else {
                self.error_counter.fetch_add(1, Ordering::AcqRel);
                Err(BoxError::from_static_str("retry me"))
            }
        }
    }

    let response_counter = Arc::new(AtomicUsize::new(0));
    let error_counter = Arc::new(AtomicUsize::new(0));

    let svc = RetryLayer::new(RetryErrors).into_layer(Svc {
        errored: AtomicBool::new(false),
        response_counter: response_counter.clone(),
        error_counter: error_counter.clone(),
    });

    let resp = svc.serve(request("hello")).await.unwrap();
    assert_eq!(resp.try_into_string().await.unwrap(), "world");
    assert_eq!(response_counter.load(Ordering::Acquire), 1);
    assert_eq!(error_counter.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn retry_limit() {
    struct Svc {
        error_counter: Arc<AtomicUsize>,
    }

    impl Service<Request<RetryBody>> for Svc {
        type Output = Response;
        type Error = BoxError;

        async fn serve(&self, req: Request<RetryBody>) -> Result<Self::Output, Self::Error> {
            assert_eq!(req.try_into_string().await.unwrap(), "hello");
            self.error_counter.fetch_add(1, Ordering::AcqRel);
            Err(BoxError::from_static_str("error forever"))
        }
    }

    let error_counter = Arc::new(AtomicUsize::new(0));

    let svc = RetryLayer::new(Limit(Arc::new(Mutex::new(2)))).into_layer(Svc {
        error_counter: error_counter.clone(),
    });

    let err = svc.serve(request("hello")).await.unwrap_err();
    assert_eq!(err.to_string(), "service error: error forever");
    assert_eq!(error_counter.load(Ordering::Acquire), 3);
}

#[tokio::test]
async fn retry_error_inspection() {
    struct Svc {
        errored: AtomicBool,
    }

    impl Service<Request<RetryBody>> for Svc {
        type Output = Response;
        type Error = BoxError;

        async fn serve(&self, req: Request<RetryBody>) -> Result<Self::Output, Self::Error> {
            assert_eq!(req.try_into_string().await.unwrap(), "hello");
            if self.errored.swap(true, Ordering::AcqRel) {
                Err(BoxError::from_static_str("reject"))
            } else {
                Err(BoxError::from_static_str("retry me"))
            }
        }
    }

    let svc = RetryLayer::new(UnlessErr("reject")).into_layer(Svc {
        errored: AtomicBool::new(false),
    });

    let err = svc.serve(request("hello")).await.unwrap_err();
    assert_eq!(err.to_string(), "service error: reject");
}

#[tokio::test]
async fn retry_cannot_clone_request() {
    struct Svc;

    impl Service<Request<RetryBody>> for Svc {
        type Output = Response;
        type Error = BoxError;

        async fn serve(&self, req: Request<RetryBody>) -> Result<Self::Output, Self::Error> {
            assert_eq!(req.try_into_string().await.unwrap(), "hello");
            Err(BoxError::from_static_str("failed"))
        }
    }

    let svc = RetryLayer::new(CannotClone).into_layer(Svc);

    let err = svc.serve(request("hello")).await.unwrap_err();
    assert_eq!(err.to_string(), "service error: failed");
}

#[tokio::test]
async fn success_with_cannot_clone() {
    struct Svc;

    impl Service<Request<RetryBody>> for Svc {
        type Output = Response;
        type Error = BoxError;

        async fn serve(&self, req: Request<RetryBody>) -> Result<Self::Output, Self::Error> {
            assert_eq!(req.try_into_string().await.unwrap(), "hello");
            Ok("world".into_response())
        }
    }

    let svc = RetryLayer::new(CannotClone).into_layer(Svc);

    let resp = svc.serve(request("hello")).await.unwrap();
    assert_eq!(resp.try_into_string().await.unwrap(), "world");
}

#[tokio::test]
async fn retry_mutating_policy() {
    struct Svc {
        responded: AtomicBool,
        response_counter: Arc<AtomicUsize>,
    }

    impl Service<Request<RetryBody>> for Svc {
        type Output = Response;
        type Error = BoxError;

        async fn serve(&self, req: Request<RetryBody>) -> Result<Self::Output, Self::Error> {
            self.response_counter.fetch_add(1, Ordering::AcqRel);
            if self.responded.swap(true, Ordering::AcqRel) {
                assert_eq!(req.try_into_string().await.unwrap(), "retrying");
            } else {
                assert_eq!(req.try_into_string().await.unwrap(), "hello");
            }
            Ok("world".into_response())
        }
    }

    let response_counter = Arc::new(AtomicUsize::new(0));

    let svc = RetryLayer::new(MutatingPolicy {
        remaining: Arc::new(Mutex::new(2)),
    })
    .into_layer(Svc {
        responded: AtomicBool::new(false),
        response_counter: response_counter.clone(),
    });

    let err = svc.serve(request("hello")).await.unwrap_err();
    assert_eq!(err.to_string(), "service error: out of retries");
    assert_eq!(response_counter.load(Ordering::Acquire), 3);
}

/// A per-request decider: stamps a fresh `AttemptDecision` unless this attempt already carries one
/// — the shape of every request-dependent decider (route selection, DNS overwrite, ...).
struct AttemptDecider<S> {
    inner: S,
    seen: Arc<Mutex<Vec<usize>>>,
    next: AtomicUsize,
}

#[derive(Debug, Extension)]
struct AttemptDecision(usize);

impl<S> Service<Request<RetryBody>> for AttemptDecider<S>
where
    S: Service<Request<RetryBody>>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<RetryBody>) -> Result<Self::Output, Self::Error> {
        if req.extensions().get_ref::<AttemptDecision>().is_none() {
            req.extensions()
                .insert(AttemptDecision(self.next.fetch_add(1, Ordering::AcqRel)));
        }
        self.seen
            .lock()
            .push(req.extensions().get_ref::<AttemptDecision>().unwrap().0);
        self.inner.serve(req).await
    }
}

#[tokio::test]
async fn inner_per_attempt_decision_does_not_leak_into_the_next_attempt() {
    // Regression: an inner decider is consulted afresh per attempt, so a retry can never reuse the
    // verdict of the attempt that just failed.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let svc = RetryLayer::new(Limit(Arc::new(Mutex::new(2)))).into_layer(AttemptDecider {
        inner: service_fn(async |_req: Request<RetryBody>| {
            Err::<Response, _>(BoxError::from_static_str("nope"))
        }),
        seen: seen.clone(),
        next: AtomicUsize::new(0),
    });

    svc.serve(request("hello")).await.unwrap_err();
    assert_eq!(seen.lock().as_slice(), [0, 1, 2]);
}

#[tokio::test]
async fn attempt_inserts_never_reach_the_callers_request_store() {
    let svc = RetryLayer::new(Limit(Arc::new(Mutex::new(1)))).into_layer(AttemptDecider {
        inner: service_fn(async |_req: Request<RetryBody>| {
            Err::<Response, _>(BoxError::from_static_str("nope"))
        }),
        seen: Arc::new(Mutex::new(Vec::new())),
        next: AtomicUsize::new(0),
    });
    let req = request("hello");
    let caller_extensions = req.extensions().clone();

    svc.serve(req).await.unwrap_err();
    assert!(
        !caller_extensions.contains::<AttemptDecision>(),
        "an attempt's insert leaked back into the caller's request extensions",
    );
}

#[tokio::test]
async fn every_attempt_reads_the_callers_extensions() {
    #[derive(Clone, Debug, PartialEq, Extension)]
    struct Marker(u32);

    let seen = Arc::new(Mutex::new(Vec::new()));
    let svc = RetryLayer::new(Limit(Arc::new(Mutex::new(2)))).into_layer(service_fn({
        let seen = seen.clone();
        move |req: Request<RetryBody>| {
            seen.lock()
                .push(req.extensions().get_ref::<Marker>().cloned());
            async { Err::<Response, _>(BoxError::from_static_str("nope")) }
        }
    }));
    let req = request("hello");
    req.extensions().insert(Marker(7));

    svc.serve(req).await.unwrap_err();
    assert_eq!(
        seen.lock().as_slice(),
        [Some(Marker(7)), Some(Marker(7)), Some(Marker(7))],
    );
}

type InnerError = &'static str;
type Error = rama_core::error::BoxError;

fn request(s: &'static str) -> Request<RetryBody> {
    Request::builder()
        .method("POST")
        .uri("http://localhost")
        .body(RetryBody::new(s.into()))
        .unwrap()
}

#[derive(Clone)]
struct RetryErrors;

impl Policy<Response, Error> for RetryErrors {
    async fn retry(
        &self,

        req: Request<RetryBody>,
        result: Result<Response, Error>,
    ) -> PolicyResult<Response, Error> {
        if result.is_err() {
            PolicyResult::Retry { req }
        } else {
            PolicyResult::Abort(result)
        }
    }

    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        Some(req.clone())
    }
}

#[derive(Clone)]
struct Limit(Arc<Mutex<usize>>);

impl Policy<Response, Error> for Limit {
    async fn retry(
        &self,

        req: Request<RetryBody>,
        result: Result<Response, Error>,
    ) -> PolicyResult<Response, Error> {
        let mut attempts = self.0.lock();
        if result.is_err() && *attempts > 0 {
            *attempts -= 1;
            PolicyResult::Retry { req }
        } else {
            PolicyResult::Abort(result)
        }
    }

    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        Some(req.clone())
    }
}

#[derive(Clone)]
struct UnlessErr(InnerError);

impl Policy<Response, Error> for UnlessErr {
    async fn retry(
        &self,

        req: Request<RetryBody>,
        result: Result<Response, Error>,
    ) -> PolicyResult<Response, Error> {
        if result
            .as_ref()
            .err()
            .map(|err| err.to_string() != self.0)
            .unwrap_or_default()
        {
            PolicyResult::Retry { req }
        } else {
            PolicyResult::Abort(result)
        }
    }

    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        Some(req.clone())
    }
}

#[derive(Clone)]
struct CannotClone;

impl Policy<Response, Error> for CannotClone {
    async fn retry(
        &self,

        _: Request<RetryBody>,
        _: Result<Response, Error>,
    ) -> PolicyResult<Response, Error> {
        unreachable!("retry cannot be called since request isn't cloned");
    }

    fn clone_input(&self, _req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        None
    }
}

/// Test policy that changes the request to `retrying` during retries and the result to `"out of retries"`
/// when retries are exhausted.
#[derive(Clone)]
struct MutatingPolicy {
    remaining: Arc<Mutex<usize>>,
}

impl Policy<Response, Error> for MutatingPolicy
where
    Error: Into<BoxError>,
{
    async fn retry(
        &self,
        _req: Request<RetryBody>,
        _result: Result<Response, Error>,
    ) -> PolicyResult<Response, Error> {
        let mut remaining = self.remaining.lock();
        if *remaining == 0 {
            PolicyResult::Abort(Err(BoxError::from_static_str("out of retries")))
        } else {
            *remaining -= 1;
            PolicyResult::Retry {
                req: request("retrying"),
            }
        }
    }

    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        Some(req.clone())
    }
}
