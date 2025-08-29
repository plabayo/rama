//! Middleware for retrying "failed" requests.

use crate::Request;
use crate::dep::http_body::Body as HttpBody;
use crate::dep::http_body_util::BodyExt;
use rama_core::error::BoxError;
use rama_core::{Context, Service};
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
pub struct Retry<P, S> {
    policy: P,
    inner: S,
}

impl<P, S> std::fmt::Debug for Retry<P, S>
where
    P: std::fmt::Debug,
    S: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Retry")
            .field("policy", &self.policy)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<P, S> Clone for Retry<P, S>
where
    P: Clone,
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
            inner: self.inner.clone(),
        }
    }
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
    P: Policy<S::Response, S::Error>,
    S: Service<Request<RetryBody>, Error: Into<BoxError>>,
    Body: HttpBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
{
    type Response = S::Response;
    type Error = RetryError;

    async fn serve(
        &self,
        ctx: Context,
        request: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let mut ctx = ctx;

        // consume body so we can clone the request if desired
        let (parts, body) = request.into_parts();
        let body = body.collect().await.map_err(|e| RetryError {
            kind: RetryErrorKind::BodyConsume,
            inner: Some(e.into()),
        })?;
        let body = RetryBody::new(body.to_bytes());
        let mut request = Request::from_parts(parts, body);

        let mut cloned = self.policy.clone_input(&ctx, &request);

        loop {
            let resp = self.inner.serve(ctx, request).await;
            match cloned.take() {
                Some((cloned_ctx, cloned_req)) => {
                    let (cloned_ctx, cloned_req) =
                        match self.policy.retry(cloned_ctx, cloned_req, resp).await {
                            PolicyResult::Abort(result) => {
                                return result.map_err(|e| RetryError {
                                    kind: RetryErrorKind::Service,
                                    inner: Some(e.into()),
                                });
                            }
                            PolicyResult::Retry { ctx, req } => (ctx, req),
                        };

                    cloned = self.policy.clone_input(&cloned_ctx, &cloned_req);
                    ctx = cloned_ctx;
                    request = cloned_req;
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
    use rama_core::{Context, Layer, service::service_fn};
    use rama_utils::{backoff::ExponentialBackoff, rng::HasherRng};
    use std::{
        sync::{Arc, atomic::AtomicUsize},
        time::Duration,
    };

    #[tokio::test]
    async fn test_service_with_managed_retry() {
        let backoff = ExponentialBackoff::new(
            Duration::from_millis(1),
            Duration::from_millis(5),
            0.1,
            HasherRng::default,
        )
        .unwrap();

        #[derive(Debug, Clone)]
        struct State {
            retry_counter: Arc<AtomicUsize>,
        }

        async fn retry<E>(
            ctx: Context,
            result: Result<Response, E>,
        ) -> (Context, Result<Response, E>, bool) {
            if ctx.contains::<DoNotRetry>() {
                panic!("unexpected retry: should be disabled");
            }

            if let Ok(ref res) = result {
                if res.status().is_server_error() {
                    ctx.get::<State>()
                        .unwrap()
                        .retry_counter
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    (ctx, result, true)
                } else {
                    (ctx, result, false)
                }
            } else {
                ctx.get::<State>()
                    .unwrap()
                    .retry_counter
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                (ctx, result, true)
            }
        }

        let retry_policy = ManagedPolicy::new(retry).with_backoff(backoff);

        let service = RetryLayer::new(retry_policy).into_layer(service_fn(
            async |_ctx, req: Request<RetryBody>| {
                let txt = req.try_into_string().await.unwrap();
                match txt.as_str() {
                    "internal" => Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
                    "error" => Err(rama_core::error::BoxError::from("custom error")),
                    _ => Ok(txt.into_response()),
                }
            },
        ));

        fn request(s: &'static str) -> Request {
            Request::builder().body(s.into()).unwrap()
        }

        fn ctx() -> Context {
            let mut ctx = Context::default();
            ctx.insert(State {
                retry_counter: Arc::new(AtomicUsize::new(0)),
            });
            ctx
        }

        fn ctx_do_not_retry() -> Context {
            let mut ctx = ctx();
            ctx.insert(DoNotRetry::default());
            ctx
        }

        async fn assert_serve_ok<E: std::fmt::Debug>(
            msg: &'static str,
            input: &'static str,
            output: &'static str,
            ctx: Context,
            retried: bool,
            service: &impl Service<Request, Response = Response, Error = E>,
        ) {
            let state = ctx.get::<State>().unwrap().clone();

            let fut = service.serve(ctx, request(input));
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
            ctx: Context,
            retried: bool,
            service: &impl Service<Request, Response = Response, Error = E>,
        ) {
            let state = ctx.get::<State>().unwrap().clone();

            let fut = service.serve(ctx, request(input));
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
            ctx(),
            false,
            &service,
        )
        .await;
        assert_serve_ok(
            "internal will trigger 500 with a retry",
            "internal",
            "",
            ctx(),
            true,
            &service,
        )
        .await;
        assert_serve_err(
            "error will trigger an actual non-http error with a retry",
            "error",
            ctx(),
            true,
            &service,
        )
        .await;

        assert_serve_ok(
            "normally internal will trigger a 500 with retry, but using DoNotRetry will disable retrying",
            "internal",
            "",
            ctx_do_not_retry(),
            false,
            &service,
        ).await;
    }
}
