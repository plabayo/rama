use crate::service::{Context, Layer, Service};
use futures_util::FutureExt;
use std::fmt;
use std::future::Future;

/// Service returned by the [`map_result`] combinator.
///
/// [`map_result`]: crate::service::ServiceBuilder::map_result
#[derive(Clone)]
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

/// A [`Layer`] that produces a [`MapResult`] service.
///
/// [`Layer`]: crate::service::Layer
#[derive(Debug, Clone)]
pub struct MapResultLayer<F> {
    f: F,
}

impl<S, F> MapResult<S, F> {
    /// Creates a new [`MapResult`] service.
    pub fn new(inner: S, f: F) -> Self {
        MapResult { f, inner }
    }

    /// Returns a new [`Layer`] that produces [`MapResult`] services.
    ///
    /// This is a convenience function that simply calls [`MapResultLayer::new`].
    ///
    /// [`Layer`]: crate::service::Layer
    pub fn layer(f: F) -> MapResultLayer<F> {
        MapResultLayer { f }
    }
}

impl<S, F, State, Request, Response, Error> Service<State, Request> for MapResult<S, F>
where
    S: Service<State, Request>,
    F: Fn(Result<S::Response, S::Error>) -> Result<Response, Error> + Clone + Send + 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.inner.serve(ctx, req).map(self.f.clone())
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