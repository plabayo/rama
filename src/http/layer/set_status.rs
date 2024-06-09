//! Middleware to override status codes.
//!
//! # Example
//!
//! ```
//! use std::{iter::once, convert::Infallible};
//! use bytes::Bytes;
//! use rama::http::layer::set_status::SetStatusLayer;
//! use rama::http::{Body, Request, Response, StatusCode};
//! use rama::service::{Context, ServiceBuilder, Service};
//! use rama::error::BoxError;
//!
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let mut service = ServiceBuilder::new()
//!     // change the status to `404 Not Found` regardless what the inner service returns
//!     .layer(SetStatusLayer::new(StatusCode::NOT_FOUND))
//!     .service_fn(handle);
//!
//! // Call the service.
//! let request = Request::builder().body(Body::empty())?;
//!
//! let response = service.serve(Context::default(), request).await?;
//!
//! assert_eq!(response.status(), StatusCode::NOT_FOUND);
//! #
//! # Ok(())
//! # }
//! ```

use crate::http::{Request, Response, StatusCode};
use crate::service::{Context, Layer, Service};

/// Layer that applies [`SetStatus`] which overrides the status codes.
#[derive(Debug, Clone, Copy)]
pub struct SetStatusLayer {
    status: StatusCode,
}

impl SetStatusLayer {
    /// Create a new [`SetStatusLayer`].
    ///
    /// The response status code will be `status` regardless of what the inner service returns.
    pub fn new(status: StatusCode) -> Self {
        SetStatusLayer { status }
    }

    /// Create a new [`SetStatusLayer`] layer which will create
    /// a service that will always set the status code at [`StatusCode::OK`].
    #[inline]
    pub fn ok() -> Self {
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
#[derive(Debug, Clone, Copy)]
pub struct SetStatus<S> {
    inner: S,
    status: StatusCode,
}

impl<S> SetStatus<S> {
    /// Create a new [`SetStatus`].
    ///
    /// The response status code will be `status` regardless of what the inner service returns.
    pub fn new(inner: S, status: StatusCode) -> Self {
        Self { status, inner }
    }

    /// Create a new [`SetStatus`] service which will always set the
    /// status code at [`StatusCode::OK`].
    #[inline]
    pub fn ok(inner: S) -> Self {
        Self::new(inner, StatusCode::OK)
    }

    define_inner_service_accessors!();
}

impl<State, S, ReqBody, ResBody> Service<State, Request<ReqBody>> for SetStatus<S>
where
    State: Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
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
        let mut response = self.inner.serve(ctx, req).await?;
        *response.status_mut() = self.status;
        Ok(response)
    }
}
