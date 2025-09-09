//! Apply a limit to the request body.
//!
//! # Example
//!
//! ```
//! use rama_http::{Body, Request, Response};
//! use std::convert::Infallible;
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Layer, Service};
//! use rama_http::layer::body_limit::BodyLimitLayer;
//!
//! async fn handle<B>(_: Request<B>) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::default()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut svc = (
//!      // Limit the request body to 2MB
//!     BodyLimitLayer::new(2*1024*1024),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service
//! let request = Request::new(Body::default());
//!
//! svc.serve(Context::default(), request).await?;
//! # Ok(())
//! # }
//! ```

use crate::{Body, Request, StreamingBody, body::util::Limited};
use rama_core::{Context, Layer, Service, bytes::Bytes, error::BoxError};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Apply a limit to the request body's size.
///
/// See the [module docs](crate::layer::body_limit) for an example.
#[derive(Debug, Clone)]
pub struct BodyLimitLayer {
    size: usize,
}

impl BodyLimitLayer {
    /// Create a new [`BodyLimitLayer`].
    #[must_use]
    pub const fn new(size: usize) -> Self {
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
/// See the [module docs](crate::layer::body_limit) for an example.
#[derive(Clone)]
pub struct BodyLimitService<S> {
    inner: S,
    size: usize,
}

impl<S> BodyLimitService<S> {
    /// Create a new [`BodyLimitService`].
    pub const fn new(service: S, size: usize) -> Self {
        Self {
            inner: service,
            size,
        }
    }

    define_inner_service_accessors!();
}

impl<S, ReqBody> Service<Request<ReqBody>> for BodyLimitService<S>
where
    S: Service<Request<Body>>,
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let req = req.map(|body| {
            if self.size == 0 {
                Body::new(body)
            } else {
                Body::new(Limited::new(body, self.size))
            }
        });
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
