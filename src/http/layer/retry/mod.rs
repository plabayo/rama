//! Middleware for retrying "failed" requests.

use crate::error::BoxError;
use crate::http::dep::http_body::Body as HttpBody;
use crate::http::dep::http_body_util::BodyExt;
use crate::http::Request;
use crate::service::{Context, Service};

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
        Retry {
            policy: self.policy.clone(),
            inner: self.inner.clone(),
        }
    }
}

// ===== impl Retry =====

impl<P, S> Retry<P, S> {
    /// Retry the inner service depending on this [`Policy`].
    pub fn new(policy: P, service: S) -> Self {
        Retry {
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
            RetryErrorKind::BodyConsume => write!(f, "failed to consume body"),
            RetryErrorKind::Service => write!(f, "service error"),
        }
    }
}

impl std::error::Error for RetryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.as_ref().and_then(|e| e.source())
    }
}

impl<P, S, State, Body> Service<State, Request<Body>> for Retry<P, S>
where
    P: Policy<State, S::Response, S::Error>,
    S: Service<State, Request<RetryBody>>,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    State: Send + Sync + 'static,
    Body: HttpBody + Send + 'static,
    Body::Data: Send + 'static,
    Body::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = RetryError;

    async fn serve(
        &self,
        ctx: Context<State>,
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
                                })
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
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        http::{
            layer::retry::managed::DoNotRetry, BodyExtractExt, IntoResponse, Response, StatusCode,
        },
        service::{Context, ServiceBuilder},
        utils::{backoff::ExponentialBackoff, rng::HasherRng},
    };
    use std::{
        sync::{atomic::AtomicUsize, Arc},
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

        #[derive(Debug)]
        struct State {
            retry_counter: AtomicUsize,
        }

        async fn retry<E>(
            ctx: Context<State>,
            result: Result<Response, E>,
        ) -> (Context<State>, Result<Response, E>, bool) {
            if ctx.contains::<DoNotRetry>() {
                panic!("unexpected retry: should be disabled");
            }

            match result {
                Ok(ref res) => {
                    if res.status().is_server_error() {
                        ctx.state()
                            .retry_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        (ctx, result, true)
                    } else {
                        (ctx, result, false)
                    }
                }
                Err(_) => {
                    ctx.state()
                        .retry_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    (ctx, result, true)
                }
            }
        }

        let retry_policy = ManagedPolicy::new(retry).with_backoff(backoff);

        let service = ServiceBuilder::new()
            .layer(RetryLayer::new(retry_policy))
            .service_fn(|_ctx, req: Request<RetryBody>| async {
                let txt = req.try_into_string().await.unwrap();
                match txt.as_str() {
                    "internal" => Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
                    "error" => Err(crate::error::BoxError::from("custom error")),
                    _ => Ok(txt.into_response()),
                }
            });

        fn request(s: &'static str) -> Request {
            Request::builder().body(s.into()).unwrap()
        }

        fn ctx() -> Context<State> {
            Context::with_state(Arc::new(State {
                retry_counter: AtomicUsize::new(0),
            }))
        }

        fn ctx_do_not_retry() -> Context<State> {
            let mut ctx = ctx();
            ctx.insert(DoNotRetry::default());
            ctx
        }

        async fn assert_serve_ok<E: std::fmt::Debug>(
            msg: &'static str,
            input: &'static str,
            output: &'static str,
            ctx: Context<State>,
            retried: bool,
            service: &impl Service<State, Request, Response = Response, Error = E>,
        ) {
            let state = ctx.state_clone();

            let fut = service.serve(ctx, request(input));
            let res = fut.await.unwrap();

            let body = res.try_into_string().await.unwrap();
            assert_eq!(body, output, "{msg}");
            if retried {
                assert!(
                    state
                        .retry_counter
                        .load(std::sync::atomic::Ordering::SeqCst)
                        > 0,
                    "{msg}"
                );
            } else {
                assert_eq!(
                    state
                        .retry_counter
                        .load(std::sync::atomic::Ordering::SeqCst),
                    0,
                    "{msg}"
                );
            }
        }

        async fn assert_serve_err<E: std::fmt::Debug>(
            msg: &'static str,
            input: &'static str,
            ctx: Context<State>,
            retried: bool,
            service: &impl Service<State, Request, Response = Response, Error = E>,
        ) {
            let state = ctx.state_clone();

            let fut = service.serve(ctx, request(input));
            let res = fut.await;

            assert!(res.is_err(), "{msg}");
            if retried {
                assert!(
                    state
                        .retry_counter
                        .load(std::sync::atomic::Ordering::SeqCst)
                        > 0,
                    "{msg}"
                );
            } else {
                assert_eq!(
                    state
                        .retry_counter
                        .load(std::sync::atomic::Ordering::SeqCst),
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
