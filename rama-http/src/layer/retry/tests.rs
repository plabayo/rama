use super::*;
use crate::BodyExtractExt;
use crate::service::web::response::IntoResponse;
use crate::{Request, Response};
use parking_lot::Mutex;
use rama_core::error::BoxError;
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
                Err(BoxError::from("retry me"))
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
            Err(BoxError::from("error forever"))
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
                Err(BoxError::from("reject"))
            } else {
                Err(BoxError::from("retry me"))
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
            Err(BoxError::from("failed"))
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
            PolicyResult::Abort(Err(BoxError::from("out of retries")))
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
