//! Apply a limit to the request body.
//!
//! # Example
//!
//! ```
//! use rama::http::{Body, Request, Response};
//! use std::convert::Infallible;
//! use rama::service::{self, ServiceBuilder, Service};
//! use rama::http::layer::body_limit::BodyLimitLayer;
//!
//! async fn handle<B>(_: Request<B>) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::default()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut svc = ServiceBuilder::new()
//!      // Limit the request body to 2MB
//!     .layer(BodyLimitLayer::new(2*1024*1024))
//!     .service_fn(handle);
//!
//! // Call the service
//! let request = Request::new(Body::default());
//!
//! svc.serve(service::Context::default(), request).await?;
//! # Ok(())
//! # }
//! ```

use crate::http::dep::http_body_util::Limited;
use crate::http::Request;
use crate::service::{Context, Layer, Service};
use std::fmt;

/// Apply a limit to the request body's size.
///
/// See the [module docs](crate::http::layer::body_limit) for an example.
#[derive(Debug, Clone)]
pub struct BodyLimitLayer {
    size: usize,
}

impl BodyLimitLayer {
    /// Create a new [`BodyLimitLayer`].
    pub fn new(size: usize) -> Self {
        Self { size }
    }
}

impl<S> Layer<S> for BodyLimitLayer {
    type Service = BodyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyLimitService::new(inner, self.size)
    }
}

/// Apply a transformation to the request body.
///
/// See the [module docs](crate::http::layer::body_limit) for an example.
#[derive(Clone)]
pub struct BodyLimitService<S> {
    inner: S,
    size: usize,
}

impl<S> BodyLimitService<S> {
    /// Create a new [`BodyLimitService`].
    pub fn new(service: S, size: usize) -> Self {
        Self {
            inner: service,
            size,
        }
    }

    define_inner_service_accessors!();
}

impl<S, State, ReqBody> Service<State, Request<ReqBody>> for BodyLimitService<S>
where
    S: Service<State, Request<Limited<ReqBody>>>,
    State: Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let req = req.map(|body| Limited::new(body, self.size));
        self.inner.serve(ctx, req).await
    }
}

impl<S> fmt::Debug for BodyLimitService<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyLimitService")
            .field("inner", &self.inner)
            .field("size", &self.size)
            .finish()
    }
}
