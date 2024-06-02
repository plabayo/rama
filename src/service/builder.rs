//! Builder types to compose layers and services

use super::{
    handler::{Factory, ServiceFn},
    layer::{
        layer_fn, AndThenLayer, Identity, LayerFn, MapErrLayer, MapRequestLayer, MapResponseLayer,
        MapResultLayer, MapStateLayer, Stack, ThenLayer, TraceErrLayer,
    },
    service_fn, BoxService, Layer, Service,
};
use std::fmt;
use std::future::Future;

/// Declaratively construct [`Service`] values.
///
/// [`ServiceBuilder`] provides a [builder-like interface][builder] for composing
/// layers to be applied to a [`Service`].
///
/// [`Service`]: crate::service::Service
/// [builder]: https://doc.rust-lang.org/1.0.0/style/ownership/builders.html
pub struct ServiceBuilder<L> {
    layer: L,
}

impl Default for ServiceBuilder<Identity> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L> Clone for ServiceBuilder<L>
where
    L: Clone,
{
    fn clone(&self) -> Self {
        ServiceBuilder {
            layer: self.layer.clone(),
        }
    }
}

impl ServiceBuilder<Identity> {
    /// Create a new [`ServiceBuilder`].
    pub fn new() -> Self {
        ServiceBuilder {
            layer: Identity::new(),
        }
    }
}

impl<L> ServiceBuilder<L> {
    /// Add a new layer `T` into the [`ServiceBuilder`].
    ///
    /// This wraps the inner service with the service provided by a user-defined
    /// [`Layer`]. The provided layer must implement the [`Layer`] trait.
    ///
    /// [`Layer`]: crate::service::Layer
    pub fn layer<T>(self, layer: T) -> ServiceBuilder<Stack<T, L>> {
        ServiceBuilder {
            layer: Stack::new(layer, self.layer),
        }
    }

    /// Add a [`Layer`] built from a function that accepts a service and returns another service.
    ///
    /// See the documentation for [`layer_fn`] for more details.
    ///
    /// [`layer_fn`]: crate::service::layer::layer_fn
    pub fn layer_fn<F>(self, f: F) -> ServiceBuilder<Stack<LayerFn<F>, L>> {
        self.layer(layer_fn(f))
    }

    /// Map one request type to another.
    ///
    /// This wraps the inner service with an instance of the [`MapRequest`]
    /// middleware.
    ///
    /// [`MapRequest`]: crate::service::layer::MapRequest
    pub fn map_request<F>(self, f: F) -> ServiceBuilder<Stack<MapRequestLayer<F>, L>> {
        self.layer(MapRequestLayer::new(f))
    }

    /// Map one state to another
    ///
    /// This wraps the inner service with an instance of the [`MapState`]
    /// middleware.
    ///
    /// [`MapState`]: crate::service::layer::MapState
    pub fn map_state<F>(self, f: F) -> ServiceBuilder<Stack<MapStateLayer<F>, L>> {
        self.layer(MapStateLayer::new(f))
    }

    /// Map one response type to another.
    ///
    /// This wraps the inner service with an instance of the [`MapResponse`]
    /// middleware.
    ///
    /// [`MapResponse`]: crate::service::layer::MapResponse
    pub fn map_response<F>(self, f: F) -> ServiceBuilder<Stack<MapResponseLayer<F>, L>> {
        self.layer(MapResponseLayer::new(f))
    }

    /// Map one error type to another.
    ///
    /// This wraps the inner service with an instance of the [`MapErr`]
    /// middleware.
    ///
    /// [`MapErr`]: crate::service::layer::MapErr
    pub fn map_err<F>(self, f: F) -> ServiceBuilder<Stack<MapErrLayer<F>, L>> {
        self.layer(MapErrLayer::new(f))
    }

    /// Trace errors that occur when serving requests.
    pub fn trace_err(self) -> ServiceBuilder<Stack<TraceErrLayer, L>> {
        self.layer(TraceErrLayer::new())
    }

    /// Trace errors that occur when serving requests at the given [`tracing::Level`].
    pub fn trace_err_with_level(
        self,
        level: tracing::Level,
    ) -> ServiceBuilder<Stack<TraceErrLayer, L>> {
        self.layer(TraceErrLayer::with_level(level))
    }

    /// Apply an asynchronous function after the service, regardless of whether the future
    /// succeeds or fails.
    ///
    /// This wraps the inner service with an instance of the [`Then`]
    /// middleware.
    ///
    /// This is similar to the [`map_response`] and [`map_err`] functions,
    /// except that the *same* function is invoked when the service's future
    /// completes, whether it completes successfully or fails. This function
    /// takes the [`Result`] returned by the service's future, and returns a
    /// [`Result`].
    ///
    /// [`Then`]: crate::service::layer::Then
    /// [`map_response`]: ServiceBuilder::map_response
    /// [`map_err`]: ServiceBuilder::map_err
    pub fn then<F>(self, f: F) -> ServiceBuilder<Stack<ThenLayer<F>, L>> {
        self.layer(ThenLayer::new(f))
    }

    /// Executes a new future after this service's future resolves.
    ///
    /// This method can be used to change the [`Response`] type of the service
    /// into a different type. You can use this method to chain along a computation once the
    /// service's response has been resolved.
    ///
    /// This wraps the inner service with an instance of the [`AndThen`]
    /// middleware.
    ///
    /// [`Response`]: crate::service::Service::Response
    /// [`AndThen`]: crate::service::layer::AndThen
    pub fn and_then<F>(self, f: F) -> ServiceBuilder<Stack<AndThenLayer<F>, L>> {
        self.layer(AndThenLayer::new(f))
    }

    /// Maps this service's result type (`Result<Self::Response, Self::Error>`)
    /// to a different value, regardless of whether the future succeeds or
    /// fails.
    ///
    /// This wraps the inner service with an instance of the [`MapResult`]
    /// middleware.
    ///
    /// [`MapResult`]: crate::service::layer::MapResult
    pub fn map_result<F>(self, f: F) -> ServiceBuilder<Stack<MapResultLayer<F>, L>> {
        self.layer(MapResultLayer::new(f))
    }

    /// Returns the underlying `Layer` implementation.
    pub fn into_inner(self) -> L {
        self.layer
    }

    /// Wrap the service `S` with the middleware provided by this
    /// [`ServiceBuilder`]'s [`Layer`]'s, returning a new [`Service`].
    ///
    /// [`Layer`]: crate::service::Layer
    /// [`Service`]: crate::service::Service
    pub fn service<S>(&self, service: S) -> L::Service
    where
        L: Layer<S>,
    {
        self.layer.layer(service)
    }

    /// Wrap the async function `F` with the middleware provided by this [`ServiceBuilder`]'s
    /// [`Layer`]s, returning a new [`Service`].
    ///
    /// [`Layer`]: crate::service::Layer
    /// [`Service`]: crate::service::Service
    /// [`service_fn`]: crate::service::service_fn
    pub fn service_fn<F, T, R, O, E>(self, f: F) -> L::Service
    where
        L: Layer<ServiceFn<F, T, R, O, E>>,
        F: Factory<T, R, O, E>,
        R: Future<Output = Result<O, E>>,
    {
        self.service(service_fn(f))
    }

    /// This ensures the service produced
    /// by the inner [`Layer`] is Boxed as [`BoxService`] and can be used in situations where
    /// dynamic dispatch is required.
    ///
    /// See that method for more details.
    pub fn boxed<S, R, State>(
        self,
    ) -> ServiceBuilder<
        Stack<
            LayerFn<
                fn(
                    L::Service,
                ) -> crate::service::BoxService<
                    State,
                    R,
                    <L::Service as Service<State, R>>::Response,
                    <L::Service as Service<State, R>>::Error,
                >,
            >,
            L,
        >,
    >
    where
        L: Layer<S>,
        L::Service: Service<State, R> + Clone,
    {
        self.layer_fn(BoxService::new)
    }
}

impl<L: fmt::Debug> fmt::Debug for ServiceBuilder<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ServiceBuilder").field(&self.layer).finish()
    }
}

impl<S, L> Layer<S> for ServiceBuilder<L>
where
    L: Layer<S>,
{
    type Service = L::Service;

    fn layer(&self, inner: S) -> Self::Service {
        self.layer.layer(inner)
    }
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;

    use crate::service::{Context, Service};

    use super::*;

    #[test]
    fn assert_send() {
        use crate::utils::test_helpers::*;

        assert_send::<ServiceBuilder<Identity>>();
        assert_send::<ServiceBuilder<Stack<Identity, Identity>>>();
        assert_send::<ServiceBuilder<Stack<Identity, Stack<Identity, Identity>>>>();
    }

    #[test]
    fn assert_sync() {
        use crate::utils::test_helpers::*;

        assert_sync::<ServiceBuilder<Identity>>();
        assert_sync::<ServiceBuilder<Stack<Identity, Identity>>>();
        assert_sync::<ServiceBuilder<Stack<Identity, Stack<Identity, Identity>>>>();
    }

    #[derive(Debug)]
    struct ToUpper<S>(S);

    impl<S, State, Request> Service<State, Request> for ToUpper<S>
    where
        Request: Send + 'static,
        S: Service<State, Request>,
        S::Response: AsRef<str>,
        State: Send + Sync + 'static,
    {
        type Response = String;
        type Error = S::Error;

        async fn serve(
            &self,
            ctx: Context<State>,
            req: Request,
        ) -> Result<Self::Response, Self::Error> {
            let res = self.0.serve(ctx, req).await;
            res.map(|msg| msg.as_ref().to_uppercase())
        }
    }

    impl<S> Clone for ToUpper<S>
    where
        S: Clone,
    {
        fn clone(&self) -> Self {
            ToUpper(self.0.clone())
        }
    }

    #[tokio::test]
    async fn test_layer_service_fn_static_and_dynamic() {
        let service = ServiceBuilder::new()
            .layer_fn(ToUpper)
            .service_fn(|_, s: &'static str| async move { Ok::<_, Infallible>(s.trim()) });

        let res = service.serve(Context::default(), "  hello world  ").await;
        assert_eq!(res, Ok("HELLO WORLD".to_owned()));

        let boxed_service = service.boxed();
        let res = boxed_service
            .serve(Context::default(), "  ola mundo  ")
            .await;
        assert_eq!(res, Ok("OLA MUNDO".to_owned()));
    }
}
