use crate::core::Service as TowerService;
use crate::service_ready::Ready;
use std::{fmt, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone)]
/// Adapter to use a [`tower::Service`] as a [`rama::Service`],
/// cloning the servicer for each request it has to serve.
///
/// Note that:
/// - you should use [`SharedServiceAdapter`] in case you do not want it to be [`Clone`]d,
///   but instead shared across serve calls (we'll wrap your tower service with a [`Mutex`]);
/// - you are required to use the [`LayerServiceAdapter`] for tower layer services,
///   which will automatically be the case if you use [`LayerAdapter`] to wrap a [`tower::Layer`].
///
/// ## Halting
///
/// This adapter assumes that a service will always become ready eventually,
/// as it will call [`poll_ready`] until ready prior to [`calling`] the [`tower::Service`].
/// Please ensure that your [`tower::Service`] does not require a side-step to prevent such halting.
///
/// [`tower::Service`]: tower_service::Service
/// [`tower::Layer`]: tower_layer::Layer
/// [`rama::Service`]: ::Service
/// [`LayerAdapter`]: super::LayerServiceAdapter.
/// [`LayerServiceAdapter`]: super::LayerServiceAdapter.
/// [`poll_ready`]: tower_service::Service::poll_ready
/// [`calling`]: tower_service::Service::call
pub struct ServiceAdapter<T>(T);

impl<T: Clone + Send + Sync + 'static> ServiceAdapter<T> {
    /// Adapt a [`Clone`]/call [`tower::Service`] into a [`rama::Service`].
    ///
    /// See [`ServiceAdapter`] for more information.
    ///
    /// [`tower::Service`]: tower_service::Service
    /// [`rama::Service`]: rama_core::Service
    pub fn new(svc: T) -> Self {
        Self(svc)
    }

    /// Consume itself to return the inner [`tower::Service`] back.
    ///
    /// [`tower::Service`]: tower_service::Service
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: fmt::Debug> fmt::Debug for ServiceAdapter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ServiceAdapter").field(&self.0).finish()
    }
}

impl<T, Request> rama_core::Service<Request> for ServiceAdapter<T>
where
    T: TowerService<Request, Response: Send + 'static, Error: Send + 'static, Future: Send>
        + Clone
        + Send
        + Sync
        + 'static,
    Request: Send + 'static,
{
    type Response = T::Response;
    type Error = T::Error;

    fn serve(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let svc = self.0.clone();
        async move {
            let mut svc = svc;
            let ready = Ready::new(&mut svc);
            let ready_svc = ready.await?;
            ready_svc.call(req).await
        }
    }
}

/// Adapter to use a [`tower::Service`] as a [`rama::Service`],
/// sharing the service between each request it has to serve.
///
/// Note that:
/// - you should use [`ServiceAdapter`] in case you do not want it to be shared,
///   and prefer it to be [`Clone`]d instead, which is anyway the more "normal" scenario;
/// - you are required to use the [`LayerServiceAdapter`] for tower layer services,
///   which will automatically be the case if you use [`LayerAdapter`] to wrap a [`tower::Layer`].
///
/// ## Halting
///
/// This adapter assumes that a service will always become ready eventually,
/// as it will call [`poll_ready`] until ready prior to [`calling`] the [`tower::Service`].
/// Please ensure that your [`tower::Service`] does not require a side-step to prevent such halting.
///
/// [`tower::Service`]: tower_service::Service
/// [`tower::Layer`]: tower_layer::Layer
/// [`rama::Service`]: rama_core::Service
/// [`LayerAdapter`]: super::LayerServiceAdapter.
/// [`LayerServiceAdapter`]: super::LayerServiceAdapter.
/// [`poll_ready`]: tower_service::Service::poll_ready
/// [`calling`]: tower_service::Service::call
pub struct SharedServiceAdapter<T>(Arc<Mutex<T>>);

impl<T: Send + Sync + 'static> SharedServiceAdapter<T> {
    /// Adapt a shared [`tower::Service`] into a [`rama::Service`].
    ///
    /// See [`SharedServiceAdapter`] for more information.
    ///
    /// [`tower::Service`]: tower_service::Service
    /// [`rama::Service`]: rama_core::Service
    pub fn new(svc: T) -> Self {
        Self(Arc::new(Mutex::new(svc)))
    }
}

impl<T> Clone for SharedServiceAdapter<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: fmt::Debug> fmt::Debug for SharedServiceAdapter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SharedServiceAdapter")
            .field(&self.0)
            .finish()
    }
}

impl<T, Request> rama_core::Service<Request> for SharedServiceAdapter<T>
where
    T: TowerService<Request, Response: Send + 'static, Error: Send + 'static, Future: Send>
        + Send
        + Sync
        + 'static,
    Request: Send + 'static,
{
    type Response = T::Response;
    type Error = T::Error;

    fn serve(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let svc = self.0.clone();
        async move {
            let svc = svc;
            let mut svc_guard = svc.lock().await;
            let ready = Ready::new(&mut *svc_guard);
            let ready_svc = ready.await?;
            ready_svc.call(req).await
        }
    }
}
