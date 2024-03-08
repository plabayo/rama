use crate::service::{Context, Layer, Service};
use std::fmt;

/// Service returned by the [`map_result`] combinator.
///
/// [`map_result`]: crate::service::ServiceBuilder::map_result
pub struct MapResult<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for MapResult<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapResult")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<S, F> Clone for MapResult<S, F>
where
    S: Clone,
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            f: self.f.clone(),
        }
    }
}

/// A [`Layer`] that produces a [`MapResult`] service.
///
/// [`Layer`]: crate::service::Layer
#[derive(Debug)]
pub struct MapResultLayer<F> {
    f: F,
}

impl<F> Clone for MapResultLayer<F>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self { f: self.f.clone() }
    }
}

impl<S, F> MapResult<S, F> {
    /// Creates a new [`MapResult`] service.
    pub fn new(inner: S, f: F) -> Self {
        MapResult { f, inner }
    }
}

impl<S, F, State, Request, Response, Error> Service<State, Request> for MapResult<S, F>
where
    S: Service<State, Request>,
    F: FnOnce(Result<S::Response, S::Error>) -> Result<Response, Error>
        + Clone
        + Send
        + Sync
        + 'static,
    State: Send + Sync + 'static,
    Request: Send + 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let result = self.inner.serve(ctx, req).await;
        (self.f.clone())(result)
    }
}

impl<F> MapResultLayer<F> {
    /// Creates a new [`MapResultLayer`] layer.
    pub fn new(f: F) -> Self {
        MapResultLayer { f }
    }
}

impl<S, F> Layer<S> for MapResultLayer<F>
where
    F: Clone,
{
    type Service = MapResult<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapResult {
            f: self.f.clone(),
            inner,
        }
    }
}
