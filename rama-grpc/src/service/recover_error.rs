//! Middleware which recovers from error and returns a Grpc status.

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use rama_core::{Layer, Service, error::BoxError};
use rama_http_types::{
    Response, StreamingBody,
    body::{Frame, SizeHint},
};

use pin_project_lite::pin_project;

use crate::Status;

/// Layer which applies the [`RecoverError`] middleware.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct RecoverErrorLayer;

impl RecoverErrorLayer {
    /// Create a new `RecoverErrorLayer`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RecoverErrorLayer {
    type Service = RecoverError<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RecoverError::new(inner)
    }
}

/// Middleware that attempts to recover from service errors by turning them into a response built
/// from the [`Status`].
#[derive(Debug, Clone)]
pub struct RecoverError<S> {
    inner: S,
}

impl<S> RecoverError<S> {
    /// Create a new `RecoverError` middleware.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, Req, ResBody> Service<Req> for RecoverError<S>
where
    S: Service<Req, Output = Response<ResBody>, Error: Into<BoxError>>,
    Req: Send + 'static,
    ResBody: Send + Sync + 'static,
{
    type Output = Response<ResponseBody<ResBody>>;
    type Error = BoxError;

    async fn serve(&self, req: Req) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(req).await {
            Ok(response) => {
                let response = response.map(ResponseBody::full);
                Ok(response)
            }
            Err(err) => match Status::try_from_error(err.into()) {
                Ok(status) => {
                    let (parts, ()) = status.try_into_http::<()>()?.into_parts();
                    let res = Response::from_parts(parts, ResponseBody::empty());
                    Ok(res)
                }
                Err(err) => Err(err),
            },
        }
    }
}

pin_project! {
    /// Response body for [`RecoverError`].
    pub struct ResponseBody<B> {
        #[pin]
        inner: Option<B>,
    }
}

impl<B> fmt::Debug for ResponseBody<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseBody").finish()
    }
}

impl<B> ResponseBody<B> {
    fn full(inner: B) -> Self {
        Self { inner: Some(inner) }
    }

    const fn empty() -> Self {
        Self { inner: None }
    }
}

impl<B> StreamingBody for ResponseBody<B>
where
    B: StreamingBody,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project().inner.as_pin_mut() {
            Some(b) => b.poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Some(b) => b.is_end_stream(),
            None => true,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Some(body) => body.size_hint(),
            None => SizeHint::with_exact(0),
        }
    }
}
