use crate::service::{Context, Layer, Service};
use futures_util::TryFutureExt;
use std::fmt;
use std::future::Future;

/// Service returned by the [`map_response`] combinator.
///
/// [`map_response`]: crate::service::ServiceBuilder::map_response
#[derive(Clone)]
pub struct MapResponse<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for MapResponse<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapResponse")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

/// A [`Layer`] that produces a [`MapResponse`] service.
///
/// [`Layer`]: crate::service::Layer
#[derive(Debug, Clone)]
pub struct MapResponseLayer<F> {
    f: F,
}

impl<S, F> MapResponse<S, F> {
    /// Creates a new `MapResponse` service.
    pub fn new(inner: S, f: F) -> Self {
        MapResponse { f, inner }
    }

    /// Returns a new [`Layer`] that produces [`MapResponse`] services.
    ///
    /// This is a convenience function that simply calls [`MapResponseLayer::new`].
    ///
    /// [`Layer`]: crate::service::Layer
    pub fn layer(f: F) -> MapResponseLayer<F> {
        MapResponseLayer { f }
    }
}

impl<S, F, State, Request, Response> Service<State, Request> for MapResponse<S, F>
where
    S: Service<State, Request>,
    F: Fn(S::Response) -> Response + Clone + Send + 'static,
    Response: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.inner.serve(ctx, request).map_ok(self.f.clone())
    }
}

impl<F> MapResponseLayer<F> {
    /// Creates a new [`MapResponseLayer`] layer.
    pub fn new(f: F) -> Self {
        MapResponseLayer { f }
    }
}

impl<S, F> Layer<S> for MapResponseLayer<F>
where
    F: Clone,
{
    type Service = MapResponse<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapResponse {
            f: self.f.clone(),
            inner,
        }
    }
}
