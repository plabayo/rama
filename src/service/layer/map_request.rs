use crate::service::{Context, Layer, Service};
use std::fmt;
use std::future::Future;

/// Composes a function *in front of* the service.
///
/// This adapter produces a new service that passes each value through the
/// given function `f` before sending it to `self`.
#[derive(Clone)]
pub struct MapRequest<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for MapRequest<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapRequest")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<S, F> MapRequest<S, F> {
    /// Creates a new [`MapRequest`] service.
    pub fn new(inner: S, f: F) -> Self {
        MapRequest { inner, f }
    }
}

impl<S, F, State, R1, R2> Service<State, R1> for MapRequest<S, F>
where
    S: Service<State, R2>,
    F: FnOnce(R1) -> R2 + Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context<State>,
        request: R1,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.inner.serve(ctx, (self.f.clone())(request))
    }
}

/// A [`Layer`] that produces [`MapRequest`] services.
///
/// [`Layer`]: crate::service::Layer
#[derive(Clone)]
pub struct MapRequestLayer<F> {
    f: F,
}

impl<F> fmt::Debug for MapRequestLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapRequestLayer")
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<F> MapRequestLayer<F> {
    /// Creates a new [`MapRequestLayer`].
    pub fn new(f: F) -> Self {
        MapRequestLayer { f }
    }
}

impl<S, F> Layer<S> for MapRequestLayer<F>
where
    F: Clone,
{
    type Service = MapRequest<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapRequest {
            f: self.f.clone(),
            inner,
        }
    }
}
