//! Middleware that gets called with either a shared reference or owned [`Arc`]
//! to the given type if it is available in the current input/output extensions.

use crate::{
    Layer, Service,
    extensions::{Extension, ExtensionsRef},
};
use rama_utils::macros::define_inner_service_accessors;
use std::{fmt, future::Future, marker::PhantomData, sync::Arc};

/// [`Layer`] for retrieving an owned [`Arc`] value from input extensions.
pub struct GetInputExtensionOwnedLayer<T, Fut, F> {
    callback: F,
    _phantom: PhantomData<fn(Arc<T>) -> Fut>,
}

impl<T, Fut, F: fmt::Debug> std::fmt::Debug for GetInputExtensionOwnedLayer<T, Fut, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetInputExtensionOwnedLayer")
            .field("callback", &self.callback)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(Arc<T>) -> Fut>()),
            )
            .finish()
    }
}

impl<T, Fut, F> Clone for GetInputExtensionOwnedLayer<T, Fut, F>
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

impl<T, Fut, F> GetInputExtensionOwnedLayer<T, Fut, F>
where
    F: Fn(Arc<T>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    /// Create a new [`GetInputExtensionOwnedLayer`].
    pub const fn new(callback: F) -> Self {
        Self {
            callback,
            _phantom: PhantomData,
        }
    }
}

impl<S, T, Fut, F> Layer<S> for GetInputExtensionOwnedLayer<T, Fut, F>
where
    F: Clone,
{
    type Service = GetInputExtensionOwned<S, T, Fut, F>;

    fn layer(&self, inner: S) -> Self::Service {
        GetInputExtensionOwned {
            inner,
            callback: self.callback.clone(),
            _phantom: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        GetInputExtensionOwned {
            inner,
            callback: self.callback,
            _phantom: PhantomData,
        }
    }
}

/// Middleware for retrieving an owned [`Arc`] value from input extensions.
pub struct GetInputExtensionOwned<S, T, Fut, F> {
    inner: S,
    callback: F,
    _phantom: PhantomData<fn(Arc<T>) -> Fut>,
}

impl<S: fmt::Debug, T, Fut, F: fmt::Debug> std::fmt::Debug
    for GetInputExtensionOwned<S, T, Fut, F>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetInputExtensionOwned")
            .field("inner", &self.inner)
            .field("callback", &self.callback)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(Arc<T>) -> Fut>()),
            )
            .finish()
    }
}

impl<S, T, Fut, F> Clone for GetInputExtensionOwned<S, T, Fut, F>
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

impl<S, T, Fut, F> GetInputExtensionOwned<S, T, Fut, F> {
    /// Create a new [`GetInputExtensionOwned`].
    pub const fn new(inner: S, callback: F) -> Self
    where
        F: Fn(Arc<T>) -> Fut + Send + Sync + 'static,
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

impl<Input, S, T, Fut, F> Service<Input> for GetInputExtensionOwned<S, T, Fut, F>
where
    Input: Send + ExtensionsRef + 'static,
    S: Service<Input>,
    T: Extension,
    F: Fn(Arc<T>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if let Some(value) = input.extensions().get_arc::<T>() {
            (self.callback)(value).await;
        }
        self.inner.serve(input).await
    }
}

/// [`Layer`] for retrieving a shared reference from input extensions.
pub struct GetInputExtensionRefLayer<T, F> {
    callback: F,
    _phantom: PhantomData<fn(&T)>,
}

impl<T, F: fmt::Debug> std::fmt::Debug for GetInputExtensionRefLayer<T, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetInputExtensionRefLayer")
            .field("callback", &self.callback)
            .field("_phantom", &format_args!("{}", std::any::type_name::<&T>()))
            .finish()
    }
}

impl<T, F> Clone for GetInputExtensionRefLayer<T, F>
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

impl<T, F> GetInputExtensionRefLayer<T, F>
where
    F: Fn(&T) + Send + Sync + 'static,
{
    /// Create a new [`GetInputExtensionRefLayer`].
    pub const fn new(callback: F) -> Self {
        Self {
            callback,
            _phantom: PhantomData,
        }
    }
}

impl<S, T, F> Layer<S> for GetInputExtensionRefLayer<T, F>
where
    F: Clone,
{
    type Service = GetInputExtensionRef<S, T, F>;

    fn layer(&self, inner: S) -> Self::Service {
        GetInputExtensionRef {
            inner,
            callback: self.callback.clone(),
            _phantom: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        GetInputExtensionRef {
            inner,
            callback: self.callback,
            _phantom: PhantomData,
        }
    }
}

/// Middleware for retrieving a shared reference from input extensions.
pub struct GetInputExtensionRef<S, T, F> {
    inner: S,
    callback: F,
    _phantom: PhantomData<fn(&T)>,
}

impl<S: fmt::Debug, T, F: fmt::Debug> std::fmt::Debug for GetInputExtensionRef<S, T, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetInputExtensionRef")
            .field("inner", &self.inner)
            .field("callback", &self.callback)
            .field("_phantom", &format_args!("{}", std::any::type_name::<&T>()))
            .finish()
    }
}

impl<S, T, F> Clone for GetInputExtensionRef<S, T, F>
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

impl<S, T, F> GetInputExtensionRef<S, T, F> {
    /// Create a new [`GetInputExtensionRef`].
    pub const fn new(inner: S, callback: F) -> Self
    where
        F: Fn(&T) + Send + Sync + 'static,
    {
        Self {
            inner,
            callback,
            _phantom: PhantomData,
        }
    }

    define_inner_service_accessors!();
}

impl<Input, S, T, F> Service<Input> for GetInputExtensionRef<S, T, F>
where
    Input: Send + ExtensionsRef + 'static,
    S: Service<Input>,
    T: Extension,
    F: Fn(&T) + Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if let Some(value) = input.extensions().get_ref::<T>() {
            (self.callback)(value);
        }
        self.inner.serve(input).await
    }
}

/// [`Layer`] for retrieving an owned [`Arc`] value from output extensions.
pub struct GetOutputExtensionOwnedLayer<T, Fut, F> {
    callback: F,
    _phantom: PhantomData<fn(Arc<T>) -> Fut>,
}

impl<T, Fut, F: fmt::Debug> std::fmt::Debug for GetOutputExtensionOwnedLayer<T, Fut, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetOutputExtensionOwnedLayer")
            .field("callback", &self.callback)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(Arc<T>) -> Fut>()),
            )
            .finish()
    }
}

impl<T, Fut, F> Clone for GetOutputExtensionOwnedLayer<T, Fut, F>
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

impl<T, Fut, F> GetOutputExtensionOwnedLayer<T, Fut, F>
where
    F: Fn(Arc<T>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    /// Create a new [`GetOutputExtensionOwnedLayer`].
    pub const fn new(callback: F) -> Self {
        Self {
            callback,
            _phantom: PhantomData,
        }
    }
}

impl<S, T, Fut, F> Layer<S> for GetOutputExtensionOwnedLayer<T, Fut, F>
where
    F: Clone,
{
    type Service = GetOutputExtensionOwned<S, T, Fut, F>;

    fn layer(&self, inner: S) -> Self::Service {
        GetOutputExtensionOwned {
            inner,
            callback: self.callback.clone(),
            _phantom: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        GetOutputExtensionOwned {
            inner,
            callback: self.callback,
            _phantom: PhantomData,
        }
    }
}

/// Middleware for retrieving an owned [`Arc`] value from output extensions.
pub struct GetOutputExtensionOwned<S, T, Fut, F> {
    inner: S,
    callback: F,
    _phantom: PhantomData<fn(Arc<T>) -> Fut>,
}

impl<S: fmt::Debug, T, Fut, F: fmt::Debug> std::fmt::Debug
    for GetOutputExtensionOwned<S, T, Fut, F>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetOutputExtensionOwned")
            .field("inner", &self.inner)
            .field("callback", &self.callback)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(Arc<T>) -> Fut>()),
            )
            .finish()
    }
}

impl<S, T, Fut, F> Clone for GetOutputExtensionOwned<S, T, Fut, F>
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

impl<S, T, Fut, F> GetOutputExtensionOwned<S, T, Fut, F> {
    /// Create a new [`GetOutputExtensionOwned`].
    pub const fn new(inner: S, callback: F) -> Self
    where
        F: Fn(Arc<T>) -> Fut + Send + Sync + 'static,
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

impl<Input, S, T, Fut, F> Service<Input> for GetOutputExtensionOwned<S, T, Fut, F>
where
    Input: Send + 'static,
    S: Service<Input, Output: Send + ExtensionsRef + 'static>,
    T: Extension,
    F: Fn(Arc<T>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(input).await?;
        if let Some(value) = res.extensions().get_arc::<T>() {
            (self.callback)(value).await;
        }
        Ok(res)
    }
}

/// [`Layer`] for retrieving a shared reference from output extensions.
pub struct GetOutputExtensionRefLayer<T, F> {
    callback: F,
    _phantom: PhantomData<fn(&T)>,
}

impl<T, F: fmt::Debug> std::fmt::Debug for GetOutputExtensionRefLayer<T, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetOutputExtensionRefLayer")
            .field("callback", &self.callback)
            .field("_phantom", &format_args!("{}", std::any::type_name::<&T>()))
            .finish()
    }
}

impl<T, F> Clone for GetOutputExtensionRefLayer<T, F>
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

impl<T, F> GetOutputExtensionRefLayer<T, F>
where
    F: Fn(&T) + Send + Sync + 'static,
{
    /// Create a new [`GetOutputExtensionRefLayer`].
    pub const fn new(callback: F) -> Self {
        Self {
            callback,
            _phantom: PhantomData,
        }
    }
}

impl<S, T, F> Layer<S> for GetOutputExtensionRefLayer<T, F>
where
    F: Clone,
{
    type Service = GetOutputExtensionRef<S, T, F>;

    fn layer(&self, inner: S) -> Self::Service {
        GetOutputExtensionRef {
            inner,
            callback: self.callback.clone(),
            _phantom: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        GetOutputExtensionRef {
            inner,
            callback: self.callback,
            _phantom: PhantomData,
        }
    }
}

/// Middleware for retrieving a shared reference from output extensions.
pub struct GetOutputExtensionRef<S, T, F> {
    inner: S,
    callback: F,
    _phantom: PhantomData<fn(&T)>,
}

impl<S: fmt::Debug, T, F: fmt::Debug> std::fmt::Debug for GetOutputExtensionRef<S, T, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetOutputExtensionRef")
            .field("inner", &self.inner)
            .field("callback", &self.callback)
            .field("_phantom", &format_args!("{}", std::any::type_name::<&T>()))
            .finish()
    }
}

impl<S, T, F> Clone for GetOutputExtensionRef<S, T, F>
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

impl<S, T, F> GetOutputExtensionRef<S, T, F> {
    /// Create a new [`GetOutputExtensionRef`].
    pub const fn new(inner: S, callback: F) -> Self
    where
        F: Fn(&T) + Send + Sync + 'static,
    {
        Self {
            inner,
            callback,
            _phantom: PhantomData,
        }
    }

    define_inner_service_accessors!();
}

impl<Input, S, T, F> Service<Input> for GetOutputExtensionRef<S, T, F>
where
    Input: Send + 'static,
    S: Service<Input, Output: Send + ExtensionsRef + 'static>,
    T: Extension,
    F: Fn(&T) + Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(input).await?;
        if let Some(value) = res.extensions().get_ref::<T>() {
            (self.callback)(value);
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceInput, extensions::ExtensionsRef, service::service_fn};
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{self, AtomicI32},
        },
    };

    #[derive(Debug)]
    struct State(i32);

    #[tokio::test]
    async fn get_input_extension_owned() {
        let value = Arc::new(AtomicI32::new(0));

        let cloned_value = value.clone();
        let svc = GetInputExtensionOwnedLayer::new(move |state: Arc<State>| {
            let cloned_value = cloned_value.clone();
            async move {
                cloned_value.store(state.0, atomic::Ordering::Release);
            }
        })
        .into_layer(service_fn(async |req: ServiceInput<Arc<AtomicI32>>| {
            let State(n) = req.extensions().get_ref().unwrap();
            assert_eq!(42, *n);

            let value = req.input.load(atomic::Ordering::Acquire);
            assert_eq!(42, value);

            Ok::<_, Infallible>(ServiceInput::new(()))
        }));

        let input = ServiceInput::new(value.clone());
        input.extensions().insert(State(42));

        let res = svc.serve(input).await.unwrap();

        assert!(res.extensions.get_ref::<State>().is_none());

        let value = value.load(atomic::Ordering::Acquire);
        assert_eq!(42, value);
    }

    #[tokio::test]
    async fn get_input_extension_ref() {
        let value = Arc::new(AtomicI32::new(0));

        let cloned_value = value.clone();
        let svc = GetInputExtensionRefLayer::new(move |state: &State| {
            cloned_value.store(state.0, atomic::Ordering::Release);
        })
        .into_layer(service_fn(async |req: ServiceInput<Arc<AtomicI32>>| {
            let State(n) = req.extensions().get_ref().unwrap();
            assert_eq!(42, *n);

            let value = req.input.load(atomic::Ordering::Acquire);
            assert_eq!(42, value);

            Ok::<_, Infallible>(ServiceInput::new(()))
        }));

        let input = ServiceInput::new(value.clone());
        input.extensions().insert(State(42));

        let res = svc.serve(input).await.unwrap();

        assert!(res.extensions.get_ref::<State>().is_none());

        let value = value.load(atomic::Ordering::Acquire);
        assert_eq!(42, value);
    }

    #[tokio::test]
    async fn get_output_extension_owned() {
        let value = Arc::new(AtomicI32::new(0));

        let cloned_value = value.clone();
        let svc = GetOutputExtensionOwnedLayer::new(move |state: Arc<State>| {
            let cloned_value = cloned_value.clone();
            async move {
                cloned_value.store(state.0, atomic::Ordering::Release);
            }
        })
        .into_layer(service_fn(async |req: ServiceInput<Arc<AtomicI32>>| {
            let value = req.input.load(atomic::Ordering::Acquire);
            assert_eq!(0, value);

            assert!(req.extensions.get_ref::<State>().is_none());

            let res = ServiceInput::new(());
            res.extensions().insert(State(42));
            Ok::<_, Infallible>(res)
        }));

        let res = svc.serve(ServiceInput::new(value.clone())).await.unwrap();
        let State(n) = res.extensions.get_ref().unwrap();
        assert_eq!(42, *n);

        let value = value.load(atomic::Ordering::Acquire);
        assert_eq!(42, value);
    }

    #[tokio::test]
    async fn get_output_extension_ref() {
        let value = Arc::new(AtomicI32::new(0));

        let cloned_value = value.clone();
        let svc = GetOutputExtensionRefLayer::new(move |state: &State| {
            cloned_value.store(state.0, atomic::Ordering::Release);
        })
        .into_layer(service_fn(async |req: ServiceInput<Arc<AtomicI32>>| {
            let value = req.input.load(atomic::Ordering::Acquire);
            assert_eq!(0, value);

            assert!(req.extensions.get_ref::<State>().is_none());

            let res = ServiceInput::new(());
            res.extensions().insert(State(42));
            Ok::<_, Infallible>(res)
        }));

        let res = svc.serve(ServiceInput::new(value.clone())).await.unwrap();
        let State(n) = res.extensions.get_ref().unwrap();
        assert_eq!(42, *n);

        let value = value.load(atomic::Ordering::Acquire);
        assert_eq!(42, value);
    }
}
