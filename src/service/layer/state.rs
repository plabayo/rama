use std::{future::Future, marker::PhantomData, sync::Arc};

use crate::service::{Context, Layer, Service};

/// Middleware that can be used to wrap the state,
/// and pass it as the new state for the inner service.
pub struct StateWrapperService<S, F, W> {
    inner: S,
    f: F,
    _phantom: PhantomData<W>,
}

impl<S, F, W> std::fmt::Debug for StateWrapperService<S, F, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateWrapperService").finish()
    }
}

impl<S, F, W> Clone for StateWrapperService<S, F, W>
where
    S: Clone,
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            f: self.f.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S, F, W> StateWrapperService<S, F, W> {
    /// Create a new `StateWrapperService` with the given constructor.
    pub fn new(inner: S, f: F) -> Self {
        Self {
            inner,
            f,
            _phantom: PhantomData,
        }
    }
}

impl<S, F, W, State, Request> Service<State, Request> for StateWrapperService<S, F, W>
where
    S: Service<W, Request>,
    State: Send + Sync + 'static,
    W: Send + Sync + 'static,
    F: FnOnce(Arc<State>) -> Arc<W> + Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let ctx = ctx.map_state(self.f.clone());
        self.inner.serve(ctx, req)
    }
}

/// Middleware that can be used to wrap the state,
/// and pass it as the new state for the inner service.
pub struct StateWrapperLayer<F, W> {
    f: F,
    _phantom: PhantomData<W>,
}

impl<F, W> std::fmt::Debug for StateWrapperLayer<F, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateWrapperLayer").finish()
    }
}

impl<F: Clone, W> Clone for StateWrapperLayer<F, W> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<F: Clone, W> StateWrapperLayer<F, W> {
    /// Create a new [`StateWrapperLayer`] with the given constructor.
    pub fn new(f: F) -> Self {
        Self {
            f,
            _phantom: PhantomData,
        }
    }
}

impl<S, F: Clone, W> Layer<S> for StateWrapperLayer<F, W> {
    type Service = StateWrapperService<S, F, W>;

    fn layer(&self, inner: S) -> Self::Service {
        StateWrapperService::new(inner, self.f.clone())
    }
}
