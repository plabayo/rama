//! Collect the http `Body`

use crate::{Body, Request, Response, StreamingBody, body::util::BodyExt};
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext},
};
use rama_utils::macros::define_inner_service_accessors;

/// An http layer to collect the http `Body`
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CollectBodyLayer;

impl CollectBodyLayer {
    /// Create a new [`CollectBodyLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for CollectBodyLayer {
    type Service = CollectBody<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CollectBody::new(inner)
    }
}

/// Service to collect the http `Body`
#[derive(Debug, Clone)]
pub struct CollectBody<S> {
    inner: S,
}

impl<S> CollectBody<S> {
    /// Create a new [`CollectBody`].
    pub const fn new(service: S) -> Self {
        Self { inner: service }
    }

    define_inner_service_accessors!();
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CollectBody<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data: Send, Error: std::error::Error + Send + Sync + 'static>
        + Send
        + Sync
        + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let resp = self
            .inner
            .serve(req)
            .await
            .context("CollectBody::inner:serve")?;
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.context("collect body")?.to_bytes();
        let body = Body::from(bytes);
        Ok(Response::from_parts(parts, body))
    }
}
