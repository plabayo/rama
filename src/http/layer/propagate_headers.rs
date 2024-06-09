//! Propagate a header from the request to the response.
//!
//! # Example
//!
//! ```rust
//! use std::convert::Infallible;
//! use rama::error::BoxError;
//! use rama::service::{Context, Service, ServiceBuilder};
//! use rama::http::{Body, Request, Response, header::HeaderName};
//! use rama::http::layer::propagate_headers::PropagateHeaderLayer;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::default()))
//! }
//!
//! let mut svc = ServiceBuilder::new()
//!     // This will copy `x-request-id` headers from requests onto responses.
//!     .layer(PropagateHeaderLayer::new(HeaderName::from_static("x-request-id")))
//!     .service_fn(handle);
//!
//! // Call the service.
//! let request = Request::builder()
//!     .header("x-request-id", "1337")
//!     .body(Body::default())?;
//!
//! let response = svc.serve(Context::default(), request).await?;
//!
//! assert_eq!(response.headers()["x-request-id"], "1337");
//! #
//! # Ok(())
//! # }
//! ```

use crate::http::{header::HeaderName, Request, Response};
use crate::service::{Context, Layer, Service};

/// Layer that applies [`PropagateHeader`] which propagates headers from requests to responses.
///
/// If the header is present on the request it'll be applied to the response as well. This could
/// for example be used to propagate headers such as `X-Request-Id`.
///
/// See the [module docs](crate::http::layer::propagate_headers) for more details.
#[derive(Clone, Debug)]
pub struct PropagateHeaderLayer {
    header: HeaderName,
}

impl PropagateHeaderLayer {
    /// Create a new [`PropagateHeaderLayer`].
    pub fn new(header: HeaderName) -> Self {
        Self { header }
    }
}

impl<S> Layer<S> for PropagateHeaderLayer {
    type Service = PropagateHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PropagateHeader {
            inner,
            header: self.header.clone(),
        }
    }
}

/// Middleware that propagates headers from requests to responses.
///
/// If the header is present on the request it'll be applied to the response as well. This could
/// for example be used to propagate headers such as `X-Request-Id`.
///
/// See the [module docs](crate::http::layer::propagate_headers) for more details.
#[derive(Clone, Debug)]
pub struct PropagateHeader<S> {
    inner: S,
    header: HeaderName,
}

impl<S> PropagateHeader<S> {
    /// Create a new [`PropagateHeader`] that propagates the given header.
    pub fn new(inner: S, header: HeaderName) -> Self {
        Self { inner, header }
    }

    define_inner_service_accessors!();
}

impl<ReqBody, ResBody, S, State> Service<State, Request<ReqBody>> for PropagateHeader<S>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    State: Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let value = req.headers().get(&self.header).cloned();

        let mut res = self.inner.serve(ctx, req).await?;

        if let Some(value) = value {
            res.headers_mut().insert(self.header.clone(), value);
        }

        Ok(res)
    }
}
