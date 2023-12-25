//! Async functions that can be used to handle requests.

use std::{convert::Infallible, fmt, future::Future, marker::PhantomData, pin::Pin};
use tower::ServiceExt;
use tower_layer::Layer;
use tower_service::Service;

pub mod future;
mod service;

mod into_make_service;
pub use into_make_service::IntoMakeService;

pub use self::service::HandlerService;

/// Trait for async functions that can be used to handle requests.
///
/// You shouldn't need to depend on this trait directly. It is automatically
/// implemented to closures of the right types.
///
/// See the [module docs](crate::handler) for more details.
pub trait Handler<Request, Response, T, S>: Clone + Send + Sized + 'static
where
    Request: Send + 'static,
    Response: Send + 'static,
{
    /// The type of future calling this handler returns.
    type Future: Future<Output = Response> + Send + 'static;

    /// Call the handler with the given request.
    fn call(self, req: Request, state: S) -> Self::Future;

    /// Apply a [`tower::Layer`] to the handler.
    ///
    /// All requests to the handler will be processed by the layer's
    /// corresponding middleware.
    ///
    /// This can be used to add additional processing to a request for a single
    /// handler.
    fn layer<L>(self, layer: L) -> Layered<L, Self, T, S>
    where
        L: Layer<HandlerService<Self, T, S>> + Clone,
        L::Service: Service<Request>,
    {
        Layered {
            layer,
            handler: self,
            _marker: PhantomData,
        }
    }

    /// Convert the handler into a [`Service`] by providing the state
    fn with_state(self, state: S) -> HandlerService<Self, T, S> {
        HandlerService::new(self, state)
    }
}

impl<F, Fut, Request, Response, IntoResponse, S> Handler<Request, Response, ((),), S> for F
where
    F: FnOnce() -> Fut + Clone + Send + 'static,
    Fut: Future<Output = IntoResponse> + Send,
    IntoResponse: Into<Response> + Send + 'static,
    Request: Send + 'static,
    Response: Send + 'static,
{
    type Future = Pin<Box<dyn Future<Output = Response> + Send>>;

    fn call(self, _req: Request, _state: S) -> Self::Future {
        Box::pin(async move { self().await.into() })
    }
}

/// A [`Service`] created from a [`Handler`] by applying a Tower middleware.
///
/// Created with [`Handler::layer`]. See that method for more details.
pub struct Layered<L, H, T, S> {
    layer: L,
    handler: H,
    _marker: PhantomData<fn() -> (T, S)>,
}

impl<L, H, T, S> fmt::Debug for Layered<L, H, T, S>
where
    L: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Layered")
            .field("layer", &self.layer)
            .finish()
    }
}

impl<L, H, T, S> Clone for Layered<L, H, T, S>
where
    L: Clone,
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            layer: self.layer.clone(),
            handler: self.handler.clone(),
            _marker: PhantomData,
        }
    }
}

impl<Request, Response, H, S, T, L> Handler<Request, Response, T, S> for Layered<L, H, T, S>
where
    L: Layer<HandlerService<H, T, S>> + Clone + Send + 'static,
    H: Handler<Request, Response, T, S>,
    L::Service: Service<Request, Error = Infallible> + Clone + Send + 'static,
    <L::Service as Service<Request>>::Response: Into<Response> + Send + 'static,
    <L::Service as Service<Request>>::Future: Send,
    Request: Send + 'static,
    Response: Send + 'static,
    T: 'static,
    S: 'static,
{
    type Future = future::LayeredFuture<Request, Response, L::Service>;

    fn call(self, req: Request, state: S) -> Self::Future {
        use futures_util::future::{FutureExt, Map};

        let svc = self.handler.with_state(state);
        let svc = self.layer.layer(svc);

        let future: Map<
            _,
            fn(
                Result<
                    <L::Service as Service<Request>>::Response,
                    <L::Service as Service<Request>>::Error,
                >,
            ) -> _,
        > = svc.oneshot(req).map(|result| match result {
            Ok(res) => res.into(),
            Err(err) => match err {},
        });

        future::LayeredFuture::new(future)
    }
}

/// Extension trait for [`Handler`]s that don't have state.
///
/// This provides convenience methods to convert the [`Handler`] into a [`Service`] or [`MakeService`].
///
/// [`MakeService`]: tower::make::MakeService
pub trait HandlerWithoutStateExt<Request, Response, T>: Handler<Request, Response, T, ()>
where
    Request: Send + 'static,
    Response: Send + 'static,
{
    /// Convert the handler into a [`Service`] and no state.
    fn into_service(self) -> HandlerService<Self, T, ()>;

    /// Convert the handler into a [`MakeService`] and no state.
    ///
    /// See [`HandlerService::into_make_service`] for more details.
    ///
    /// [`MakeService`]: tower::make::MakeService
    fn into_make_service(self) -> IntoMakeService<HandlerService<Self, T, ()>>;
}

impl<Request, Response, H, T> HandlerWithoutStateExt<Request, Response, T> for H
where
    H: Handler<Request, Response, T, ()>,
    Request: Send + 'static,
    Response: Send + 'static,
{
    fn into_service(self) -> HandlerService<Self, T, ()> {
        self.with_state(())
    }

    fn into_make_service(self) -> IntoMakeService<HandlerService<Self, T, ()>> {
        self.into_service().into_make_service()
    }
}
