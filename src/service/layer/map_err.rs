use crate::service::{Context, Layer, Service};
use std::fmt;

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
}

impl<S, F, State, Request, Error> Service<State, Request> for MapErr<S, F>
where
    S: Service<State, Request>,
    F: Fn(S::Error) -> Error + Send + Sync + 'static,
    State: Send + Sync + 'static,
    Request: Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        match self.inner.serve(ctx, req).await {
            Ok(resp) => Ok(resp),
            Err(err) => Err((self.f)(err)),
        }
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
