use crate::service::{Context, Layer, Service};
use std::{future::Future, sync::Arc};

/// Middleware that can be used to map the state,
/// and pass it as the new state for the inner service.
pub struct MapState<S, F> {
    inner: S,
    f: F,
}

impl<S: std::fmt::Debug, F> std::fmt::Debug for MapState<S, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapState")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<S, F> Clone for MapState<S, F>
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

impl<S, F> MapState<S, F> {
    /// Create a new `MapState` with the given constructor.
    pub fn new(inner: S, f: F) -> Self {
        Self { inner, f }
    }

    define_inner_service_accessors!();
}

impl<S, F, W, State, Request> Service<State, Request> for MapState<S, F>
where
    S: Service<W, Request>,
    State: Send + Sync + 'static,
    W: Send + Sync + 'static,
    F: FnOnce(Arc<State>) -> Arc<W> + Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let ctx = ctx.map_state(self.f.clone());
        self.inner.serve(ctx, req)
    }
}

/// Middleware that can be used to map the state,
/// and pass it as the new state for the inner service.
pub struct MapStateLayer<F> {
    f: F,
}

impl<F> std::fmt::Debug for MapStateLayer<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapStateLayer")
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<F: Clone> Clone for MapStateLayer<F> {
    fn clone(&self) -> Self {
        Self { f: self.f.clone() }
    }
}

impl<F> MapStateLayer<F> {
    /// Create a new [`MapStateLayer`] with the given constructor.
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

impl<S, F: Clone> Layer<S> for MapStateLayer<F> {
    type Service = MapState<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapState::new(inner, self.f.clone())
    }
}
