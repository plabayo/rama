//! Middleware to override status codes.
//!
//! # Example
//!
//! ```
//! use std::{iter::once, convert::Infallible};
//! use rama_core::bytes::Bytes;
//! use rama_http::layer::set_status::SetStatusLayer;
//! use rama_http::{Body, Request, Response, StatusCode};
//! use rama_core::service::service_fn;
//! use rama_core::{Layer, Service};
//! use rama_core::error::BoxError;
//!
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let mut service = (
//!     // change the status to `404 Not Found` regardless what the inner service returns
//!     SetStatusLayer::new(StatusCode::NOT_FOUND),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service.
//! let request = Request::builder().body(Body::empty())?;
//!
//! let response = service.serve(request).await?;
//!
//! assert_eq!(response.status(), StatusCode::NOT_FOUND);
//! #
//! # Ok(())
//! # }
//! ```

use std::fmt;

use crate::{Request, Response, StatusCode};
use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;

/// Layer that applies [`SetStatus`] which overrides the status codes.
#[derive(Debug, Clone)]
pub struct SetStatusLayer {
    status: StatusCode,
}

impl SetStatusLayer {
    /// Create a new [`SetStatusLayer`].
    ///
    /// The response status code will be `status` regardless of what the inner service returns.
    #[must_use]
    pub const fn new(status: StatusCode) -> Self {
        Self { status }
    }

    /// Create a new [`SetStatusLayer`] layer which will create
    /// a service that will always set the status code at [`StatusCode::OK`].
    #[inline]
    #[must_use]
    pub const fn ok() -> Self {
        Self::new(StatusCode::OK)
    }
}

impl<S> Layer<S> for SetStatusLayer {
    type Service = SetStatus<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SetStatus::new(inner, self.status)
    }
}

/// Middleware to override status codes.
///
/// See the [module docs](self) for more details.
pub struct SetStatus<S> {
    inner: S,
    status: StatusCode,
}

impl<S> SetStatus<S> {
    /// Create a new [`SetStatus`].
    ///
    /// The response status code will be `status` regardless of what the inner service returns.
    pub const fn new(inner: S, status: StatusCode) -> Self {
        Self { status, inner }
    }

    /// Create a new [`SetStatus`] service which will always set the
    /// status code at [`StatusCode::OK`].
    #[inline]
    pub const fn ok(inner: S) -> Self {
        Self::new(inner, StatusCode::OK)
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug> fmt::Debug for SetStatus<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetStatus")
            .field("inner", &self.inner)
            .field("status", &self.status)
            .finish()
    }
}

impl<S: Clone> Clone for SetStatus<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            status: self.status,
        }
    }
}

impl<S: Copy> Copy for SetStatus<S> {}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SetStatus<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        let mut response = self.inner.serve(req).await?;
        *response.status_mut() = self.status;
        Ok(response)
    }
}
