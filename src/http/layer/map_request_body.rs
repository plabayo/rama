//! Apply a transformation to the request body.
//!
//! # Example
//!
//! ```
//! use rama::http::{Body, Request, Response};
//! use rama::http::dep::http_body;
//! use bytes::Bytes;
//! use std::convert::Infallible;
//! use std::{pin::Pin, task::{ready, Context, Poll}};
//! use rama::service::{self, ServiceBuilder, service_fn, Service};
//! use rama::http::layer::map_request_body::MapRequestBodyLayer;
//! use rama::error::BoxError;
//!
//! // A wrapper for a `Full<Bytes>`
//! struct BodyWrapper {
//!     inner: Body,
//! }
//!
//! impl BodyWrapper {
//!     fn new(inner: Body) -> Self {
//!         Self { inner }
//!     }
//! }
//!
//! impl http_body::Body for BodyWrapper {
//!     // ...
//!     # type Data = Bytes;
//!     # type Error = BoxError;
//!     # fn poll_frame(
//!     #     self: Pin<&mut Self>,
//!     #     cx: &mut Context<'_>
//!     # ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> { unimplemented!() }
//!     # fn is_end_stream(&self) -> bool { unimplemented!() }
//!     # fn size_hint(&self) -> http_body::SizeHint { unimplemented!() }
//! }
//!
//! async fn handle<B>(_: Request<B>) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::default()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut svc = ServiceBuilder::new()
//!     // Wrap response bodies in `BodyWrapper`
//!     .layer(MapRequestBodyLayer::new(BodyWrapper::new))
//!     .service_fn(handle);
//!
//! // Call the service
//! let request = Request::new(Body::default());
//!
//! svc.serve(service::Context::default(), request).await?;
//! # Ok(())
//! # }
//! ```

use crate::http::{Request, Response};
use crate::service::{Context, Layer, Service};
use std::fmt;

/// Apply a transformation to the request body.
///
/// See the [module docs](crate::http::layer::map_request_body) for an example.
#[derive(Clone)]
pub struct MapRequestBodyLayer<F> {
    f: F,
}

impl<F> MapRequestBodyLayer<F> {
    /// Create a new [`MapRequestBodyLayer`].
    ///
    /// `F` is expected to be a function that takes a body and returns another body.
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

impl<S, F> Layer<S> for MapRequestBodyLayer<F>
where
    F: Clone,
{
    type Service = MapRequestBody<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapRequestBody::new(inner, self.f.clone())
    }
}

impl<F> fmt::Debug for MapRequestBodyLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapRequestBodyLayer")
            .field("f", &std::any::type_name::<F>())
            .finish()
    }
}

/// Apply a transformation to the request body.
///
/// See the [module docs](crate::http::layer::map_request_body) for an example.
#[derive(Clone)]
pub struct MapRequestBody<S, F> {
    inner: S,
    f: F,
}

impl<S, F> MapRequestBody<S, F> {
    /// Create a new [`MapRequestBody`].
    ///
    /// `F` is expected to be a function that takes a body and returns another body.
    pub fn new(service: S, f: F) -> Self {
        Self { inner: service, f }
    }

    define_inner_service_accessors!();
}

impl<F, S, State, ReqBody, ResBody, NewReqBody> Service<State, Request<ReqBody>>
    for MapRequestBody<S, F>
where
    S: Service<State, Request<NewReqBody>, Response = Response<ResBody>>,
    State: Send + Sync + 'static,
    ReqBody: Send + 'static,
    NewReqBody: Send + 'static,
    ResBody: Send + Sync + 'static,
    F: Fn(ReqBody) -> NewReqBody + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let req = req.map(&self.f);
        self.inner.serve(ctx, req).await
    }
}

impl<S, F> fmt::Debug for MapRequestBody<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapRequestBody")
            .field("inner", &self.inner)
            .field("f", &std::any::type_name::<F>())
            .finish()
    }
}
