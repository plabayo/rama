use super::service_ready::Ready;
use crate::core::Layer as TowerLayer;
use crate::core::Service as TowerService;
use rama_core::error::{BoxError, ErrorContext};
use std::{
    fmt,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
};

#[derive(Clone)]
/// Wrapper type that can be used to smuggle a ctx into a request's extensions.
pub struct ContextWrap<S>(pub rama_core::Context<S>);

impl<S: fmt::Debug> fmt::Debug for ContextWrap<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ContextWrap").field(&self.0).finish()
    }
}

/// Trait to be implemented for any request that can "smuggle" [`Context`]s.
///
/// - if the `http` feature is enabled it will already be implemented for
///   [`rama_http_types::Request`];
/// - for types that do have this capability and you work with tower services
///   which do not care about the specific type of the request that passes through it,
///   you can make use of [`RequestStatePair`] using the tower map-request capabilities,
///   to easily swap between the pair and direct request format.
///
/// [`Context`]: rama_core::Context
pub trait ContextSmuggler<S> {
    /// inject the context into the smuggler.
    fn inject_ctx(&mut self, ctx: rama_core::Context<S>);

    /// try to extract the smuggled context out of the smuggle,
    /// which is only possible once.
    fn try_extract_ctx(&mut self) -> Option<rama_core::Context<S>>;
}

#[cfg(feature = "http")]
mod http {
    use super::*;
    use rama_http_types::Request;

    impl<B, S: Clone + Send + Sync + 'static> ContextSmuggler<S> for Request<B> {
        fn inject_ctx(&mut self, ctx: rama_core::Context<S>) {
            let wrap = ContextWrap(ctx);
            self.extensions_mut().insert(wrap);
        }

        fn try_extract_ctx(&mut self) -> Option<rama_core::Context<S>> {
            let wrap: ContextWrap<_> = self.extensions_mut().remove()?;
            Some(wrap.0)
        }
    }
}

/// Simple implementation of a [`ContextSmuggler`].
pub struct RequestStatePair<R, S> {
    /// the inner reuqest
    pub request: R,
    /// the storage to "smuggle" the ctx"
    pub ctx: Option<rama_core::Context<S>>,
}

impl<R: fmt::Debug, S: fmt::Debug> fmt::Debug for RequestStatePair<R, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestStatePair")
            .field("request", &self.request)
            .field("ctx", &self.ctx)
            .finish()
    }
}

impl<R: Clone, S: Clone> Clone for RequestStatePair<R, S> {
    fn clone(&self) -> Self {
        Self {
            request: self.request.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

impl<R, S> RequestStatePair<R, S> {
    pub const fn new(req: R) -> Self {
        Self {
            request: req,
            ctx: None,
        }
    }
}

impl<R, S> Deref for RequestStatePair<R, S> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

impl<R, S> DerefMut for RequestStatePair<R, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.request
    }
}

impl<R, S> ContextSmuggler<S> for RequestStatePair<R, S> {
    fn inject_ctx(&mut self, ctx: rama_core::Context<S>) {
        self.ctx = Some(ctx);
    }

    fn try_extract_ctx(&mut self) -> Option<rama_core::Context<S>> {
        self.ctx.take()
    }
}

/// Adapter to use a [`tower::Layer`]-[`tower::Service`] as a [`rama::Layer`]-[`rama::Service`].
///
/// The produced [`tower::Service`] will be wrapped by a [`LayerServiceAdapter`] making it
/// a fully compatible [`rama::Service`] ready to be plugged into a rama stack.
///
/// Note that you should use [`ServiceAdapter`] or [`SharedServiceAdapter`] for non-layer services.
///
/// [`tower::Service`]: tower_service::Service
/// [`tower::Layer`]: tower_layer::Layer
/// [`rama::Layer`]: crate::Layer
/// [`rama::Service`]: crate::Service
/// [`ServiceAdapter`]: super::ServiceAdapter.
pub struct LayerAdapter<L, State> {
    inner: L,
    _state: PhantomData<fn() -> State>,
}

impl<L: Send + Sync + 'static, State> LayerAdapter<L, State> {
    /// Adapt a [`tower::Layer`] into a [`rama::Layer`].
    ///
    /// See [`LayerAdapter`] for more information.
    ///
    /// [`tower::Layer`]: tower_layer::Layer
    /// [`rama::Layer`]: crate::Layer
    pub fn new(layer: L) -> Self {
        Self {
            inner: layer,
            _state: PhantomData,
        }
    }

    /// Consume itself to return the inner [`tower::Layer`] back.
    ///
    /// [`tower::Layer`]: tower_layer::Layer
    pub fn into_inner(self) -> L {
        self.inner
    }
}

impl<L: fmt::Debug, State> fmt::Debug for LayerAdapter<L, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LayerAdapter")
            .field("inner", &self.inner)
            .finish()
    }
}

/// Adapter to use a [`rama::Service`] as a [`tower::Service`]
/// in functio nof [`tower::Layer`].
///
/// [`tower::Service`]: tower_service::Service
/// [`tower::Layer`]: tower_layer::Layer
/// [`rama::Service`]: rama_core::Service
pub struct TowerAdapterService<S, State> {
    inner: Arc<S>,
    _state: PhantomData<fn() -> State>,
}

impl<S, State> TowerAdapterService<S, State> {
    /// Reference to the inner [`rama::Service`].
    ///
    /// [`rama::Service`]: rama_core::Service
    #[must_use]
    pub fn inner(&self) -> &S {
        self.inner.as_ref()
    }
}

impl<S: fmt::Debug, State> fmt::Debug for TowerAdapterService<S, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TowerAdapterService")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S, State> Clone for TowerAdapterService<S, State> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _state: PhantomData,
        }
    }
}

/// Adapter to use a [`tower::Service`] as a [`rama::Service`]
/// in function of [`tower::Layer`].
///
/// [`tower::Service`]: tower_service::Service
/// [`tower::Layer`]: tower_layer::Layer
/// [`rama::Service`]: rama_core::Service
#[derive(Clone)]
pub struct LayerAdapterService<T>(T);

impl<T: fmt::Debug> fmt::Debug for LayerAdapterService<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LayerAdapterService").field(&self.0).finish()
    }
}

impl<L, S, State> rama_core::Layer<S> for LayerAdapter<L, State>
where
    L: TowerLayer<TowerAdapterService<S, State>, Service: Clone + Send + Sync + 'static>,
{
    type Service = LayerAdapterService<L::Service>;

    fn layer(&self, inner: S) -> Self::Service {
        let tower_svc = TowerAdapterService {
            inner: Arc::new(inner),
            _state: PhantomData,
        };
        let layered_tower_svc = self.inner.layer(tower_svc);
        LayerAdapterService(layered_tower_svc)
    }
}

impl<T, State, Request> TowerService<Request> for TowerAdapterService<T, State>
where
    T: rama_core::Service<State, Request, Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
    Request: ContextSmuggler<State> + Send + 'static,
{
    type Response = T::Response;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let svc = self.inner.clone();
        Box::pin(async move {
            let ctx: rama_core::Context<State> = req
                .try_extract_ctx()
                .context("extract context from req smuggler")?;
            svc.serve(ctx, req).await.map_err(Into::into)
        })
    }
}

impl<T, State, Request> rama_core::Service<State, Request> for LayerAdapterService<T>
where
    T: TowerService<Request, Response: Send + 'static, Error: Send + 'static, Future: Send>
        + Clone
        + Send
        + Sync
        + 'static,
    State: Clone + Send + Sync + 'static,
    Request: ContextSmuggler<State> + Send + 'static,
{
    type Response = T::Response;
    type Error = T::Error;

    fn serve(
        &self,
        ctx: rama_core::Context<State>,
        mut req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        req.inject_ctx(ctx);
        let svc = self.0.clone();
        async move {
            let mut svc = svc;
            let ready = Ready::new(&mut svc);
            let ready_svc = ready.await?;
            ready_svc.call(req).await
        }
    }
}
