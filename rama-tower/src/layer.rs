use super::service_ready::Ready;
use crate::core::Layer as TowerLayer;
use crate::core::Service as TowerService;
use rama_core::error::BoxError;
use rama_core::error::ErrorContext as _;
use std::{fmt, pin::Pin};

/// Adapter to use a [`tower::Layer`]-[`tower::Service`] as a [`rama::Layer`]-[`rama::Service`].
///
/// The produced [`tower::Service`] will be wrapped by a [`LayerAdapterService`] making it
/// a fully compatible [`rama::Service`] ready to be plugged into a rama stack.
///
/// Note that you should use [`ServiceAdapter`] or [`SharedServiceAdapter`] for non-layer services.
///
/// [`tower::Service`]: tower_service::Service
/// [`tower::Layer`]: tower_layer::Layer
/// [`rama::Layer`]: rama_core::Layer
/// [`rama::Service`]: rama_core::Service
/// [`ServiceAdapter`]: super::ServiceAdapter
/// [`SharedServiceAdapter`]: super::SharedServiceAdapter
pub struct LayerAdapter<L> {
    inner: L,
}

impl<L: Send + Sync + 'static> LayerAdapter<L> {
    /// Adapt a [`tower::Layer`] into a [`rama::Layer`].
    ///
    /// See [`LayerAdapter`] for more information.
    ///
    /// [`tower::Layer`]: tower_layer::Layer
    /// [`rama::Layer`]: rama_core::Layer
    pub fn new(layer: L) -> Self {
        Self { inner: layer }
    }

    /// Consume itself to return the inner [`tower::Layer`] back.
    ///
    /// [`tower::Layer`]: tower_layer::Layer
    pub fn into_inner(self) -> L {
        self.inner
    }
}

impl<L: fmt::Debug> fmt::Debug for LayerAdapter<L> {
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
pub struct TowerAdapterService<S> {
    inner: S,
}

impl<S> TowerAdapterService<S> {
    /// Reference to the inner [`rama::Service`].
    ///
    /// [`rama::Service`]: rama_core::Service
    #[must_use]
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: fmt::Debug> fmt::Debug for TowerAdapterService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TowerAdapterService")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Clone> Clone for TowerAdapterService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
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

impl<L, S> rama_core::Layer<S> for LayerAdapter<L>
where
    L: TowerLayer<TowerAdapterService<S>, Service: Clone + Send + Sync + 'static>,
{
    type Service = LayerAdapterService<L::Service>;

    fn layer(&self, inner: S) -> Self::Service {
        let tower_svc = TowerAdapterService { inner };
        let layered_tower_svc = self.inner.layer(tower_svc);
        LayerAdapterService(layered_tower_svc)
    }
}

impl<T, Input> TowerService<Input> for TowerAdapterService<T>
where
    T: rama_core::Service<Input, Error: Into<BoxError>> + Clone,
    Input: Send + 'static,
{
    type Response = T::Output;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, input: Input) -> Self::Future {
        let svc = self.inner.clone();
        Box::pin(async move { svc.serve(input).await.into_box_error() })
    }
}

impl<T, Input> rama_core::Service<Input> for LayerAdapterService<T>
where
    T: TowerService<Input, Response: Send + 'static, Error: Send + 'static, Future: Send>
        + Clone
        + Send
        + Sync
        + 'static,
    Input: Send + 'static,
{
    type Output = T::Response;
    type Error = T::Error;

    fn serve(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        let svc = self.0.clone();
        async move {
            let mut svc = svc;
            let ready = Ready::new(&mut svc);
            let ready_svc = ready.await?;
            ready_svc.call(input).await
        }
    }
}
