//! Collect the http `Body`

use crate::dep::http_body_util::BodyExt;
use crate::{Request, Response, dep::http_body::Body};
use rama_core::{
    Context, Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

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

impl<S, State, ReqBody, ResBody> Service<State, Request<ReqBody>> for CollectBody<S>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>, Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody:
        Body<Data: Send, Error: std::error::Error + Send + Sync + 'static> + Send + Sync + 'static,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let resp = self
            .inner
            .serve(ctx, req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))
            .context("CollectBody::inner:serve")?;
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.context("collect body")?.to_bytes();
        let body = crate::Body::from(bytes);
        Ok(Response::from_parts(parts, body))
    }
}

impl<S> fmt::Debug for CollectBody<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CollectBody")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S> Clone for CollectBody<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
