//! Apply a transformation to the request body.
//!
//! # Example
//!
//! ```
//! use rama_http::{Body, Request, Response, StreamingBody, body::{Frame, SizeHint}};
//! use rama_core::bytes::Bytes;
//! use std::convert::Infallible;
//! use std::{pin::Pin, task::{ready, Context, Poll}};
//! use rama_core::{Layer, Service};
//! use rama_core::service::service_fn;
//! use rama_http::layer::map_request_body::MapRequestBodyLayer;
//! use rama_core::error::BoxError;
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
//! impl StreamingBody for BodyWrapper {
//!     // ...
//!     # type Data = Bytes;
//!     # type Error = BoxError;
//!     # fn poll_frame(
//!     #     self: Pin<&mut Self>,
//!     #     cx: &mut Context<'_>
//!     # ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> { unimplemented!() }
//!     # fn is_end_stream(&self) -> bool { unimplemented!() }
//!     # fn size_hint(&self) -> SizeHint { unimplemented!() }
//! }
//!
//! async fn handle<B>(_: Request<B>) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::default()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut svc = (
//!     // Wrap response bodies in `BodyWrapper`
//!     MapRequestBodyLayer::new(BodyWrapper::new),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service
//! let request = Request::new(Body::default());
//!
//! svc.serve(request).await?;
//! # Ok(())
//! # }
//! ```

use crate::{Request, Response};
use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Apply a transformation to the request body.
///
/// See the [module docs](crate::layer::map_request_body) for an example.
#[derive(Clone)]
pub struct MapRequestBodyLayer<F> {
    f: F,
}

impl<F> MapRequestBodyLayer<F> {
    /// Create a new [`MapRequestBodyLayer`].
    ///
    /// `F` is expected to be a function that takes a body and returns another body.
    pub const fn new(f: F) -> Self {
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

    fn into_layer(self, inner: S) -> Self::Service {
        MapRequestBody::new(inner, self.f)
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
/// See the [module docs](crate::layer::map_request_body) for an example.
#[derive(Clone)]
pub struct MapRequestBody<S, F> {
    inner: S,
    f: F,
}

impl<S, F> MapRequestBody<S, F> {
    /// Create a new [`MapRequestBody`].
    ///
    /// `F` is expected to be a function that takes a body and returns another body.
    pub const fn new(service: S, f: F) -> Self {
        Self { inner: service, f }
    }

    define_inner_service_accessors!();
}

impl<F, S, ReqBody, ResBody, NewReqBody> Service<Request<ReqBody>> for MapRequestBody<S, F>
where
    S: Service<Request<NewReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    NewReqBody: Send + 'static,
    ResBody: Send + Sync + 'static,
    F: Fn(ReqBody) -> NewReqBody + Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let req = req.map(&self.f);
        self.inner.serve(req).await
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
