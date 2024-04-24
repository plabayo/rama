//! Middleware for retrying "failed" requests.

use crate::error::BoxError;
use crate::http::dep::http_body::Body as HttpBody;
use crate::http::dep::http_body_util::BodyExt;
use crate::http::Request;
use crate::service::{Context, Service};

pub mod budget;
mod layer;
mod policy;

mod body;
#[doc(inline)]
pub use body::RetryBody;

#[cfg(test)]
mod tests;

pub use self::layer::RetryLayer;
pub use self::policy::{Policy, PolicyResult};

/// Configure retrying requests of "failed" responses.
///
/// A [`Policy`] classifies what is a "failed" response.
pub struct Retry<P, S> {
    policy: P,
    service: S,
}

impl<P, S> std::fmt::Debug for Retry<P, S>
where
    P: std::fmt::Debug,
    S: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Retry")
            .field("policy", &self.policy)
            .field("service", &self.service)
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
            service: self.service.clone(),
        }
    }
}

// ===== impl Retry =====

impl<P, S> Retry<P, S> {
    /// Retry the inner service depending on this [`Policy`].
    pub fn new(policy: P, service: S) -> Self {
        Retry { policy, service }
    }

    /// Get a reference to the inner service
    pub fn get_ref(&self) -> &S {
        &self.service
    }

    /// Get a mutable reference to the inner service
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.service
    }

    /// Consume `self`, returning the inner service
    pub fn into_inner(self) -> S {
        self.service
    }
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
    Body::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
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
            let resp = self.service.serve(ctx, request).await;
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
