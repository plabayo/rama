//! Propagate a header from the request to the response.
//!
//! # Example
//!
//! ```rust
//! use std::convert::Infallible;
//! use rama_core::error::BoxError;
//! use rama_core::service::service_fn;
//! use rama_core::{Service, Layer};
//! use rama_http::{Body, Request, Response, header::HeaderName};
//! use rama_http::layer::propagate_headers::PropagateHeaderLayer;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::default()))
//! }
//!
//! let mut svc = (
//!     // This will copy `x-request-id` headers from requests onto responses.
//!     PropagateHeaderLayer::new(HeaderName::from_static("x-request-id")),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service.
//! let request = Request::builder()
//!     .header("x-request-id", "1337")
//!     .body(Body::default())?;
//!
//! let response = svc.serve(request).await?;
//!
//! assert_eq!(response.headers()["x-request-id"], "1337");
//! #
//! # Ok(())
//! # }
//! ```

use crate::{Request, Response, header::HeaderName};
use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;

/// Layer that applies [`PropagateHeader`] which propagates headers from requests to responses.
///
/// If the header is present on the request it'll be applied to the response as well. This could
/// for example be used to propagate headers such as `X-Request-Id`.
///
/// See the [module docs](crate::layer::propagate_headers) for more details.
#[derive(Clone, Debug)]
pub struct PropagateHeaderLayer {
    header: HeaderName,
}

impl PropagateHeaderLayer {
    /// Create a new [`PropagateHeaderLayer`].
    pub const fn new(header: HeaderName) -> Self {
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

    fn into_layer(self, inner: S) -> Self::Service {
        PropagateHeader {
            inner,
            header: self.header,
        }
    }
}

/// Middleware that propagates headers from requests to responses.
///
/// If the header is present on the request it'll be applied to the response as well. This could
/// for example be used to propagate headers such as `X-Request-Id`.
///
/// See the [module docs](crate::layer::propagate_headers) for more details.
#[derive(Clone, Debug)]
pub struct PropagateHeader<S> {
    inner: S,
    header: HeaderName,
}

impl<S> PropagateHeader<S> {
    /// Create a new [`PropagateHeader`] that propagates the given header.
    pub const fn new(inner: S, header: HeaderName) -> Self {
        Self { inner, header }
    }

    define_inner_service_accessors!();
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for PropagateHeader<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let value = req.headers().get(&self.header).cloned();

        let mut res = self.inner.serve(req).await?;

        if let Some(value) = value {
            res.headers_mut().insert(self.header.clone(), value);
        }

        Ok(res)
    }
}
