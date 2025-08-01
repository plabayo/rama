//! Middleware that gets called with a clone of the value of to given type if it is available in the current [`Context`].
//!
//! [Context]: https://docs.rs/rama/latest/rama/context/struct.Context.html

use crate::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::{fmt, marker::PhantomData};

/// [`Layer`] for retrieving some shareable value from incoming [Context].
///
/// [Context]: https://docs.rs/rama/latest/rama/context/struct.Context.html
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
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    /// Create a new [`GetExtensionLayer`].
    pub const fn new(callback: F) -> Self {
        Self {
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

    fn into_layer(self, inner: S) -> Self::Service {
        GetExtension {
            inner,
            callback: self.callback,
            _phantom: PhantomData,
        }
    }
}

/// Middleware for retrieving some shareable value from incoming [Context].
///
/// [Context]: https://docs.rs/rama/latest/rama/context/struct.Context.html
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
    pub const fn new(inner: S, callback: F) -> Self
    where
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
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
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
    S: Service<State, Request>,
    T: Clone + Send + Sync + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(value) = ctx.get::<T>() {
            let value = value.clone();
            (self.callback)(value).await;
        }
        self.inner.serve(ctx, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Context, service::service_fn};
    use std::{convert::Infallible, sync::Arc};

    #[derive(Debug, Clone)]
    struct State(i32);

    #[tokio::test]
    async fn get_extension_basic() {
        let value = Arc::new(std::sync::atomic::AtomicI32::new(0));

        let cloned_value = value.clone();
        let svc = GetExtensionLayer::new(move |state: State| {
            let cloned_value = cloned_value.clone();
            async move {
                cloned_value.store(state.0, std::sync::atomic::Ordering::Release);
            }
        })
        .into_layer(service_fn(async |ctx: Context<()>, _req: ()| {
            let state = ctx.get::<State>().unwrap();
            Ok::<_, Infallible>(state.0)
        }));

        let mut ctx = Context::default();
        ctx.insert(State(42));

        let res = svc.serve(ctx, ()).await.unwrap();
        assert_eq!(42, res);

        let value = value.load(std::sync::atomic::Ordering::Acquire);
        assert_eq!(42, value);
    }
}
