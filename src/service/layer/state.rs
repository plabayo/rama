use std::{future::Future, marker::PhantomData, sync::Arc};

use crate::service::{Context, Layer, Service};

/// Middleware that can be used to wrap the state,
/// and pass it as the new state for the inner service.
pub struct StateWrapperService<S, W> {
    inner: S,
    _phantom: PhantomData<W>,
}

impl<S, W> std::fmt::Debug for StateWrapperService<S, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateWrapperService").finish()
    }
}

impl<S, W> Clone for StateWrapperService<S, W>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S, W> StateWrapperService<S, W> {
    /// Create a new `StateWrapperService`.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }
}

impl<S, W, State, Request> Service<State, Request> for StateWrapperService<S, W>
where
    S: Service<W, Request>,
    State: Send + Sync + 'static,
    W: From<Arc<State>> + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let ctx = ctx.map_state(|s| Arc::new(W::from(s)));
        self.inner.serve(ctx, req)
    }
}

/// Middleware that can be used to wrap the state,
/// and pass it as the new state for the inner service.
pub struct StateWrapperLayer<W> {
    _phantom: PhantomData<W>,
}

impl<W> std::fmt::Debug for StateWrapperLayer<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateWrapperLayer").finish()
    }
}

impl<W> Clone for StateWrapperLayer<W> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<W> StateWrapperLayer<W> {
    /// Create a new [`StateWrapperLayer`].
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<W> Default for StateWrapperLayer<W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, W> Layer<S> for StateWrapperLayer<W> {
    type Service = StateWrapperService<S, W>;

    fn layer(&self, inner: S) -> Self::Service {
        StateWrapperService::new(inner)
    }
}
