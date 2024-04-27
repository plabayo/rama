use super::Layer;
use std::fmt;

/// Returns a new [`LayerFn`] that implements [`Layer`] by calling the
/// given function.
///
/// The [`Layer::layer`] method takes a type implementing [`Service`] and
/// returns a different type implementing [`Service`]. In many cases, this can
/// be implemented by a function or a closure. The [`LayerFn`] helper allows
/// writing simple [`Layer`] implementations without needing the boilerplate of
/// a new struct implementing [`Layer`].
///
/// [`Service`]: crate::service::Service
/// [`Layer::layer`]: crate::service::Layer::layer
pub fn layer_fn<T>(f: T) -> LayerFn<T> {
    LayerFn { f }
}

/// A `Layer` implemented by a closure. See the docs for [`layer_fn`] for more details.
#[derive(Clone, Copy)]
pub struct LayerFn<F> {
    f: F,
}

impl<F, S, Out> Layer<S> for LayerFn<F>
where
    F: FnOnce(S) -> Out + Clone,
{
    type Service = Out;

    fn layer(&self, inner: S) -> Self::Service {
        (self.f.clone())(inner)
    }
}

impl<F> fmt::Debug for LayerFn<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LayerFn")
            .field("f", &format_args!("<{}>", std::any::type_name::<F>()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This test shows how one can make a LayerFn that wraps a service.
    /// Due to the immature state of Async Rust, possibly combined with the usage of the current type resolver,
    /// it is at the moment not possible to use closures for `layer_fn` as it cannot infer the type of the inner service.
    /// One can probably try to declare it explicitly, but that can get unwieldy very quickly,
    /// and has pretty poor UX.
    ///
    /// Therefore the approach as shown in this test is probably also the only approach that we should document,
    /// for users that want to declare a Layer without implementing the Layer trait explicitly themselves.
    #[tokio::test]
    async fn test_layer_fn() {
        use crate::service::{service_fn, Context, Service};
        use std::convert::Infallible;

        #[derive(Debug)]
        struct ToUpper<S>(S);

        impl<S, State, Request> Service<State, Request> for ToUpper<S>
        where
            Request: Send + 'static,
            S: Service<State, Request, Response = &'static str>,
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
                res.map(|msg| msg.to_uppercase())
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

        let layer = layer_fn(ToUpper);
        let f = |_, req| async move { Ok::<_, Infallible>(req) };

        let res = layer
            .layer(service_fn(f))
            .serve(Context::default(), "hello")
            .await;
        assert_eq!(res, Ok("HELLO".to_owned()));

        // can be cloned the layer, and the service
        let svc = layer.layer(service_fn(f));
        let res = svc.serve(Context::default(), "hello").await;
        assert_eq!(res, Ok("HELLO".to_owned()));
        let res = svc.clone().serve(Context::default(), "hello").await;
        assert_eq!(res, Ok("HELLO".to_owned()));
    }

    #[allow(dead_code)]
    #[test]
    fn layer_fn_has_useful_debug_impl() {
        struct WrappedService<S> {
            inner: S,
        }
        let layer = layer_fn(|svc| WrappedService { inner: svc });
        let _svc = layer.layer("foo");

        assert_eq!(
            "LayerFn { f: <rama::service::layer::layer_fn::tests::layer_fn_has_useful_debug_impl::{{closure}}> }".to_owned(),
            format!("{:?}", layer),
        );
    }
}
