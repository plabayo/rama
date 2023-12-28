use crate::service::{Context, Layer, Service};
use futures_util::TryFutureExt;
use std::fmt;
use std::future::Future;

/// Service returned by the [`map_err`] combinator.
///
/// [`map_err`]: crate::service::ServiceBuilder::map_err
#[derive(Clone)]
pub struct MapErr<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for MapErr<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapErr")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

/// A [`Layer`] that produces [`MapErr`] services.
///
/// [`Layer`]: crate::service::Layer
#[derive(Clone, Debug)]
pub struct MapErrLayer<F> {
    f: F,
}

impl<S, F> MapErr<S, F> {
    /// Creates a new [`MapErr`] service.
    pub fn new(inner: S, f: F) -> Self {
        MapErr { f, inner }
    }

    /// Returns a new [`Layer`] that produces [`MapErr`] services.
    ///
    /// This is a convenience function that simply calls [`MapErrLayer::new`].
    ///
    /// [`Layer`]: crate::service::Layer
    pub fn layer(f: F) -> MapErrLayer<F> {
        MapErrLayer { f }
    }
}

impl<S, F, State, Request, Error> Service<State, Request> for MapErr<S, F>
where
    S: Service<State, Request>,
    F: Fn(S::Error) -> Error + Clone + Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.inner.serve(ctx, req).map_err(self.f.clone())
    }
}

impl<F> MapErrLayer<F> {
    /// Creates a new [`MapErrLayer`].
    pub fn new(f: F) -> Self {
        MapErrLayer { f }
    }
}

impl<S, F> Layer<S> for MapErrLayer<F>
where
    F: Clone,
{
    type Service = MapErr<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapErr {
            f: self.f.clone(),
            inner,
        }
    }
}
