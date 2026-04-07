//! Middleware that clones a value into an incoming input's or an output's extensions
//!
//! Note though that extensions are best not used for State that you expect to be there,
//! but instead use extensions for optional behaviour to change. Static typed state
//! is better embedded in service structs or as state for routers.

use std::sync::Arc;

use crate::{
    Layer, Service,
    extensions::{Extension, ExtensionsRef},
};
use rama_utils::macros::define_inner_service_accessors;

/// [`Layer`] for adding some shareable value to incoming input's extensions.
#[derive(Debug)]
pub struct AddInputExtensionLayer<T> {
    value: Arc<T>,
}

impl<T> Clone for AddInputExtensionLayer<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl<T> AddInputExtensionLayer<T> {
    /// Create a new [`AddInputExtensionLayer`].
    ///
    /// If you are insterting `Arc<T>`, use [`AddInputExtensionLayer::new_arc()`] instead
    pub fn new(value: T) -> Self {
        Self {
            value: Arc::new(value),
        }
    }

    /// Create a new [`AddInputExtensionLayer`].
    pub fn new_arc(value: Arc<T>) -> Self {
        Self { value }
    }
}

impl<S, T> Layer<S> for AddInputExtensionLayer<T> {
    type Service = AddInputExtension<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        AddInputExtension {
            inner,
            value: self.value.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        AddInputExtension {
            inner,
            value: self.value,
        }
    }
}

/// Middleware for adding some shareable value to incoming input's extensions.
#[derive(Debug)]
pub struct AddInputExtension<S, T> {
    inner: S,
    value: Arc<T>,
}

impl<S: Clone, T> Clone for AddInputExtension<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            value: self.value.clone(),
        }
    }
}

impl<S, T> AddInputExtension<S, T> {
    /// Create a new [`AddInputExtension`].
    ///
    /// If you are insterting `Arc<T>`, use [`AddInputExtension::new_arc()`] instead
    pub fn new(inner: S, value: T) -> Self {
        Self {
            inner,
            value: Arc::new(value),
        }
    }

    /// Create a new [`AddInputExtension`].
    pub const fn new_arc(inner: S, value: Arc<T>) -> Self {
        Self { inner, value }
    }

    define_inner_service_accessors!();
}

impl<Input, S, T> Service<Input> for AddInputExtension<S, T>
where
    Input: Send + ExtensionsRef + 'static,
    S: Service<Input>,
    T: Extension,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        input.extensions().insert_arc(self.value.clone());
        self.inner.serve(input).await
    }
}

/// [`Layer`] for adding some shareable value to an output's extensions.
#[derive(Debug)]
pub struct AddOutputExtensionLayer<T> {
    value: Arc<T>,
}

impl<T> Clone for AddOutputExtensionLayer<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl<T> AddOutputExtensionLayer<T> {
    /// Create a new [`AddOutputExtensionLayer`].
    ///
    /// If you are insterting `Arc<T>`, use [`AddOutputExtensionLayer::new_arc()`] instead
    pub fn new(value: T) -> Self {
        Self {
            value: Arc::new(value),
        }
    }

    /// Create a new [`AddOutputExtensionLayer`].
    pub const fn new_arc(value: Arc<T>) -> Self {
        Self { value }
    }
}

impl<S, T> Layer<S> for AddOutputExtensionLayer<T> {
    type Service = AddOutputExtension<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        AddOutputExtension {
            inner,
            value: self.value.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        AddOutputExtension {
            inner,
            value: self.value,
        }
    }
}

/// Middleware for adding some shareable value to an output's extensions.
#[derive(Debug)]
pub struct AddOutputExtension<S, T> {
    inner: S,
    value: Arc<T>,
}

impl<S: Clone, T> Clone for AddOutputExtension<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            value: self.value.clone(),
        }
    }
}

impl<S, T> AddOutputExtension<S, T> {
    /// Create a new [`AddOutputExtension`].
    ///
    /// If you are insterting `Arc<T>`, use [`AddOutputExtension::new_arc()`] instead
    pub fn new(inner: S, value: T) -> Self {
        Self {
            inner,
            value: Arc::new(value),
        }
    }

    /// Create a new [`AddOutputExtension`].
    pub const fn new_arc(inner: S, value: Arc<T>) -> Self {
        Self { inner, value }
    }

    define_inner_service_accessors!();
}

impl<Input, S, T> Service<Input> for AddOutputExtension<S, T>
where
    Input: Send + 'static,
    S: Service<Input, Output: Send + ExtensionsRef + 'static>,
    T: Extension,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(input).await?;
        res.extensions().insert_arc(self.value.clone());
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceInput, extensions::ExtensionsRef, service::service_fn};
    use std::convert::Infallible;

    #[derive(Debug, Clone, Copy)]
    struct Counter(i32);

    #[tokio::test]
    async fn basic_input() {
        let svc = AddInputExtensionLayer::new(Counter(42)).into_layer(service_fn(
            async |req: ServiceInput<()>| {
                let Counter(n) = req.extensions().get_ref().copied().unwrap();
                assert_eq!(42, n);
                Ok::<_, Infallible>(ServiceInput::new(()))
            },
        ));

        let res = svc.serve(ServiceInput::new(())).await.unwrap();
        assert!(res.extensions.get_ref::<Counter>().is_none());
    }

    #[tokio::test]
    async fn basic_output() {
        let svc = AddOutputExtensionLayer::new(Counter(42)).into_layer(service_fn(
            async |req: ServiceInput<()>| {
                assert!(req.extensions.get_ref::<Counter>().is_none());
                Ok::<_, Infallible>(ServiceInput::new(()))
            },
        ));

        let res = svc.serve(ServiceInput::new(())).await.unwrap();
        let Counter(n) = res.extensions().get_ref().copied().unwrap();
        assert_eq!(42, n);
    }
}
