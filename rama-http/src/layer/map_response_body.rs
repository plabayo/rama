//! Apply a transformation to the response body.
//!
//! # Example
//!
//! ```
//! use rama_core::bytes::Bytes;
//! use rama_http::{Body, Request, Response};
//! use rama_http::dep::http_body;
//! use std::convert::Infallible;
//! use std::{pin::Pin, task::{Context, Poll}};
//! use rama_core::{Layer, Service, context};
//! use rama_core::service::service_fn;
//! use rama_http::layer::map_response_body::MapResponseBodyLayer;
//! use rama_core::error::BoxError;
//! use futures_lite::ready;
//!
//! // A wrapper for a `http_body::Body` that prints the size of data chunks
//! pin_project_lite::pin_project! {
//!     struct PrintChunkSizesBody<B> {
//!         #[pin]
//!         inner: B,
//!     }
//! }
//!
//! impl<B> PrintChunkSizesBody<B> {
//!     fn new(inner: B) -> Self {
//!         Self { inner }
//!     }
//! }
//!
//! impl<B> http_body::Body for PrintChunkSizesBody<B>
//!     where B: http_body::Body<Data = Bytes, Error = BoxError>,
//! {
//!     type Data = Bytes;
//!     type Error = BoxError;
//!
//!     fn poll_frame(
//!         mut self: Pin<&mut Self>,
//!         cx: &mut Context<'_>,
//!     ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
//!         let inner_body = self.as_mut().project().inner;
//!         if let Some(frame) = ready!(inner_body.poll_frame(cx)?) {
//!             if let Some(chunk) = frame.data_ref() {
//!                 println!("chunk size = {}", chunk.len());
//!             } else {
//!                 eprintln!("no data chunk found");
//!             }
//!             Poll::Ready(Some(Ok(frame)))
//!         } else {
//!             Poll::Ready(None)
//!         }
//!     }
//!
//!     fn is_end_stream(&self) -> bool {
//!         self.inner.is_end_stream()
//!     }
//!
//!     fn size_hint(&self) -> http_body::SizeHint {
//!         self.inner.size_hint()
//!     }
//! }
//!
//! async fn handle(_: Request) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::default()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut svc = (
//!     // Wrap response bodies in `PrintChunkSizesBody`
//!     MapResponseBodyLayer::new(PrintChunkSizesBody::new),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service
//! let request = Request::new(Body::from("foobar"));
//!
//! svc.serve(context::Context::default(), request).await?;
//! # Ok(())
//! # }
//! ```

use crate::{Request, Response};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Apply a transformation to the response body.
///
/// See the [module docs](crate::layer::map_response_body) for an example.
#[derive(Clone)]
pub struct MapResponseBodyLayer<F> {
    f: F,
}

impl<F> MapResponseBodyLayer<F> {
    /// Create a new [`MapResponseBodyLayer`].
    ///
    /// `F` is expected to be a function that takes a body and returns another body.
    pub const fn new(f: F) -> Self {
        Self { f }
    }
}

impl<S, F> Layer<S> for MapResponseBodyLayer<F>
where
    F: Clone,
{
    type Service = MapResponseBody<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapResponseBody::new(inner, self.f.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        MapResponseBody::new(inner, self.f)
    }
}

impl<F> fmt::Debug for MapResponseBodyLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapResponseBodyLayer")
            .field("f", &std::any::type_name::<F>())
            .finish()
    }
}

/// Apply a transformation to the response body.
///
/// See the [module docs](crate::layer::map_response_body) for an example.
#[derive(Clone)]
pub struct MapResponseBody<S, F> {
    inner: S,
    f: F,
}

impl<S, F> MapResponseBody<S, F> {
    /// Create a new [`MapResponseBody`].
    ///
    /// `F` is expected to be a function that takes a body and returns another body.
    pub const fn new(service: S, f: F) -> Self {
        Self { inner: service, f }
    }

    define_inner_service_accessors!();
}

impl<F, S, State, ReqBody, ResBody, NewResBody> Service<State, Request<ReqBody>>
    for MapResponseBody<S, F>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    State: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + Sync + 'static,
    NewResBody: Send + Sync + 'static,
    F: Fn(ResBody) -> NewResBody + Clone + Send + Sync + 'static,
{
    type Response = Response<NewResBody>;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let res = self.inner.serve(ctx, req).await?;
        Ok(res.map(self.f.clone()))
    }
}

impl<S, F> fmt::Debug for MapResponseBody<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapResponseBody")
            .field("inner", &self.inner)
            .field("f", &std::any::type_name::<F>())
            .finish()
    }
}
