//! Middleware that gets called if a reference to given type is available in the current [`Context`].
//!
//! [Context]: https://docs.rs/rama/latest/rama/service/context/struct.Context.html

use std::{fmt, future::Future, marker::PhantomData};

use crate::service::{Context, Layer, Service};

/// [`Layer`] for adding some shareable value to incoming [Context].
///
/// [Context]: https://docs.rs/rama/latest/rama/service/context/struct.Context.html
pub struct GetExtensionLayer<T, Fut, F> {
    callback: F,
    _phantom: PhantomData<fn(T) -> Fut>,
}

impl<T, Fut, F: fmt::Debug> std::fmt::Debug for GetExtensionLayer<T, Fut, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetExtensionLayer")
            .field("callback", &self.callback)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(T) -> Fut>()),
            )
            .finish()
    }
}

impl<T, Fut, F> Clone for GetExtensionLayer<T, Fut, F>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            callback: self.callback.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T, Fut, F> GetExtensionLayer<T, Fut, F>
where
    F: FnOnce(T) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + Sync + 'static,
{
    /// Create a new [`GetExtensionLayer`].
    pub fn new(callback: F) -> Self {
        GetExtensionLayer {
            callback,
            _phantom: PhantomData,
        }
    }
}

impl<S, T, Fut, F> Layer<S> for GetExtensionLayer<T, Fut, F>
where
    F: Clone,
{
    type Service = GetExtension<S, T, Fut, F>;

    fn layer(&self, inner: S) -> Self::Service {
        GetExtension {
            inner,
            callback: self.callback.clone(),
            _phantom: PhantomData,
        }
    }
}

/// Middleware for adding some shareable value to incoming [Context].
///
/// [Context]: https://docs.rs/rama/latest/rama/service/context/struct.Context.html
pub struct GetExtension<S, T, Fut, F> {
    inner: S,
    callback: F,
    _phantom: PhantomData<fn(T) -> Fut>,
}

impl<S: fmt::Debug, T, Fut, F: fmt::Debug> std::fmt::Debug for GetExtension<S, T, Fut, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetExtension")
            .field("inner", &self.inner)
            .field("callback", &self.callback)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(T) -> Fut>()),
            )
            .finish()
    }
}

impl<S, T, Fut, F> Clone for GetExtension<S, T, Fut, F>
where
    S: Clone,
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            callback: self.callback.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S, T, Fut, F> GetExtension<S, T, Fut, F> {
    /// Create a new [`GetExtension`].
    pub fn new(inner: S, callback: F) -> Self
    where
        F: FnOnce(T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + Sync + 'static,
    {
        Self {
            inner,
            callback,
            _phantom: PhantomData,
        }
    }

    define_inner_service_accessors!();
}

impl<State, Request, S, T, Fut, F> Service<State, Request> for GetExtension<S, T, Fut, F>
where
    State: Send + Sync + 'static,
    Request: Send + 'static,
    S: Service<State, Request>,
    T: Clone + Send + Sync + 'static,
    F: FnOnce(T) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl std::future::Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        if let Some(value) = ctx.get::<T>() {
            (self.callback.clone())(value.clone());
        }
        self.inner.serve(ctx, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{service_fn, Context, ServiceBuilder};
    use std::convert::Infallible;

    #[derive(Debug, Clone)]
    struct State(i32);

    #[tokio::test]
    async fn basic() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let svc = ServiceBuilder::new()
            .layer(GetExtensionLayer::new(|state: State| async move {
                tx.send(state.0).await.expect("value to be sent");
            }))
            .service(service_fn(|ctx: Context<()>, _req: ()| async move {
                let state = ctx.get::<State>().unwrap();
                Ok::<_, Infallible>(state.0)
            }));

        let mut ctx = Context::default();
        ctx.insert(State(42));
        let res = svc.serve(ctx, ()).await.unwrap();

        let value = rx.recv().await.expect("value");
        assert_eq!(42, value);
        assert_eq!(42, res);
    }
}
