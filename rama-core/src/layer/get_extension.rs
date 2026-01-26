//! Middleware that gets called with a clone of the value of to given type
//! if it is available in the current input/output extensions.

use crate::{
    Layer, Service,
    extensions::{Extension, ExtensionsRef},
};
use rama_utils::macros::define_inner_service_accessors;
use std::{fmt, marker::PhantomData};

/// [`Layer`] for retrieving some shareable value from input extensions.
pub struct GetInputExtensionLayer<T, Fut, F> {
    callback: F,
    _phantom: PhantomData<fn(T) -> Fut>,
}

impl<T, Fut, F: fmt::Debug> std::fmt::Debug for GetInputExtensionLayer<T, Fut, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetInputExtensionLayer")
            .field("callback", &self.callback)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(T) -> Fut>()),
            )
            .finish()
    }
}

impl<T, Fut, F> Clone for GetInputExtensionLayer<T, Fut, F>
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

impl<T, Fut, F> GetInputExtensionLayer<T, Fut, F>
where
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    /// Create a new [`GetInputExtensionLayer`].
    pub const fn new(callback: F) -> Self {
        Self {
            callback,
            _phantom: PhantomData,
        }
    }
}

impl<S, T, Fut, F> Layer<S> for GetInputExtensionLayer<T, Fut, F>
where
    F: Clone,
{
    type Service = GetInputExtension<S, T, Fut, F>;

    fn layer(&self, inner: S) -> Self::Service {
        GetInputExtension {
            inner,
            callback: self.callback.clone(),
            _phantom: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        GetInputExtension {
            inner,
            callback: self.callback,
            _phantom: PhantomData,
        }
    }
}

/// Middleware for retrieving shareable value from input extensions.
pub struct GetInputExtension<S, T, Fut, F> {
    inner: S,
    callback: F,
    _phantom: PhantomData<fn(T) -> Fut>,
}

impl<S: fmt::Debug, T, Fut, F: fmt::Debug> std::fmt::Debug for GetInputExtension<S, T, Fut, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetInputExtension")
            .field("inner", &self.inner)
            .field("callback", &self.callback)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(T) -> Fut>()),
            )
            .finish()
    }
}

impl<S, T, Fut, F> Clone for GetInputExtension<S, T, Fut, F>
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

impl<S, T, Fut, F> GetInputExtension<S, T, Fut, F> {
    /// Create a new [`GetInputExtension`].
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

impl<Input, S, T, Fut, F> Service<Input> for GetInputExtension<S, T, Fut, F>
where
    Input: Send + ExtensionsRef + 'static,
    S: Service<Input>,
    T: Extension + Clone,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if let Some(value) = input.extensions().get::<T>() {
            let value = value.clone();
            (self.callback)(value).await;
        }
        self.inner.serve(input).await
    }
}

/// [`Layer`] for retrieving some shareable value from output extensions.
pub struct GetOutputExtensionLayer<T, Fut, F> {
    callback: F,
    _phantom: PhantomData<fn(T) -> Fut>,
}

impl<T, Fut, F: fmt::Debug> std::fmt::Debug for GetOutputExtensionLayer<T, Fut, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetOutputExtensionLayer")
            .field("callback", &self.callback)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(T) -> Fut>()),
            )
            .finish()
    }
}

impl<T, Fut, F> Clone for GetOutputExtensionLayer<T, Fut, F>
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

impl<T, Fut, F> GetOutputExtensionLayer<T, Fut, F>
where
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    /// Create a new [`GetOutputExtensionLayer`].
    pub const fn new(callback: F) -> Self {
        Self {
            callback,
            _phantom: PhantomData,
        }
    }
}

impl<S, T, Fut, F> Layer<S> for GetOutputExtensionLayer<T, Fut, F>
where
    F: Clone,
{
    type Service = GetOutputExtension<S, T, Fut, F>;

    fn layer(&self, inner: S) -> Self::Service {
        GetOutputExtension {
            inner,
            callback: self.callback.clone(),
            _phantom: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        GetOutputExtension {
            inner,
            callback: self.callback,
            _phantom: PhantomData,
        }
    }
}

/// Middleware for retrieving shareable value from output extensions.
pub struct GetOutputExtension<S, T, Fut, F> {
    inner: S,
    callback: F,
    _phantom: PhantomData<fn(T) -> Fut>,
}

impl<S: fmt::Debug, T, Fut, F: fmt::Debug> std::fmt::Debug for GetOutputExtension<S, T, Fut, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetOutputExtension")
            .field("inner", &self.inner)
            .field("callback", &self.callback)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(T) -> Fut>()),
            )
            .finish()
    }
}

impl<S, T, Fut, F> Clone for GetOutputExtension<S, T, Fut, F>
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

impl<S, T, Fut, F> GetOutputExtension<S, T, Fut, F> {
    /// Create a new [`GetOutputExtension`].
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

impl<Input, S, T, Fut, F> Service<Input> for GetOutputExtension<S, T, Fut, F>
where
    Input: Send + 'static,
    S: Service<Input, Output: Send + ExtensionsRef + 'static>,
    T: Extension + Clone,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(input).await?;
        if let Some(value) = res.extensions().get::<T>() {
            let value = value.clone();
            (self.callback)(value).await;
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceInput, extensions::ExtensionsMut, service::service_fn};
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{self, AtomicI32},
        },
    };

    #[derive(Debug, Clone)]
    struct State(i32);

    #[tokio::test]
    async fn get_extension_basic() {
        let value = Arc::new(AtomicI32::new(0));

        let cloned_value = value.clone();
        let svc = GetInputExtensionLayer::new(move |state: State| {
            let cloned_value = cloned_value.clone();
            async move {
                cloned_value.store(state.0, atomic::Ordering::Release);
            }
        })
        .into_layer(service_fn(async |req: ServiceInput<Arc<AtomicI32>>| {
            let State(n) = req.extensions().get().cloned().unwrap();
            assert_eq!(42, n);

            let value = req.input.load(atomic::Ordering::Acquire);
            assert_eq!(42, value);

            Ok::<_, Infallible>(ServiceInput::new(()))
        }));

        let mut input = ServiceInput::new(value.clone());
        input.extensions_mut().insert(State(42));

        let res = svc.serve(input).await.unwrap();

        assert!(res.extensions.get::<State>().is_none());

        let value = value.load(atomic::Ordering::Acquire);
        assert_eq!(42, value);
    }

    #[tokio::test]
    async fn get_extension_output() {
        let value = Arc::new(AtomicI32::new(0));

        let cloned_value = value.clone();
        let svc = GetOutputExtensionLayer::new(move |state: State| {
            let cloned_value = cloned_value.clone();
            async move {
                cloned_value.store(state.0, atomic::Ordering::Release);
            }
        })
        .into_layer(service_fn(async |req: ServiceInput<Arc<AtomicI32>>| {
            let value = req.input.load(atomic::Ordering::Acquire);
            assert_eq!(0, value);

            assert!(req.extensions.get::<State>().is_none());

            let mut res = ServiceInput::new(());
            res.extensions_mut().insert(State(42));
            Ok::<_, Infallible>(res)
        }));

        let res = svc.serve(ServiceInput::new(value.clone())).await.unwrap();
        let State(n) = res.extensions.get().cloned().unwrap();
        assert_eq!(42, n);

        let value = value.load(atomic::Ordering::Acquire);
        assert_eq!(42, value);
    }
}
