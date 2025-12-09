//! Middleware that clones a value into an incoming input's or an output's extensions
//!
//! # Example
//!
//! ```
//! use std::{sync::Arc, convert::Infallible};
//!
//! use rama_core::{extensions::{Extensions, ExtensionsRef}, Service, Layer, service::service_fn};
//! use rama_core::layer::add_extension::AddInputExtensionLayer;
//! use rama_core::error::BoxError;
//! # #[derive(Debug)]
//! # struct DatabaseConnectionPool;
//! # impl DatabaseConnectionPool {
//! #     fn new() -> DatabaseConnectionPool { DatabaseConnectionPool }
//! # }
//! #
//! // Shared state across all request handlers --- in this case, a pool of database connections.
//! #[derive(Debug)]
//! struct State {
//!     pool: DatabaseConnectionPool,
//! }
//!
//! // Request can be any type that implements [`ExtensionsRef`]
//! async fn handle(req: Extensions) -> Result<(), Infallible>
//! {
//!     // Grab the state from the request extensions.
//!     let state = req.extensions().get::<Arc<State>>().unwrap();
//!
//!     Ok(())
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! // Construct the shared state.
//! let state = State {
//!     pool: DatabaseConnectionPool::new(),
//! };
//!
//! let mut service = (
//!     // Share an `Arc<State>` with all requests.
//!     AddInputExtensionLayer::new(Arc::new(state)),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service.
//! let response = service
//!     .serve(Extensions::new())
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Example
//!
//! ```
//! use std::{sync::Arc, convert::Infallible};
//!
//! use rama_core::{extensions::{Extensions, ExtensionsRef}, Service, Layer, service::service_fn};
//! use rama_core::layer::add_extension::AddOutputExtensionLayer;
//! use rama_core::error::BoxError;
//! # #[derive(Debug)]
//! # struct ResponseCounter;
//! # impl ResponseCounter {
//! #     fn new() -> ResponseCounter { ResponseCounter }
//! # }
//! #
//! // Shared state across all responses --- in this case, a counter of handled requests.
//! #[derive(Debug)]
//! struct State {
//!     counter: ResponseCounter,
//! }
//!
//! // Response can be any type that implements [`ExtensionsMut`]
//! async fn handle(req: ()) -> Result<Extensions, Infallible>
//! {
//!     Ok(Extensions::new())
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! // Construct the shared state.
//! let state = State {
//!     counter: ResponseCounter::new(),
//! };
//!
//! let mut service = (
//!     // Add an `Arc<State>` to all responses.
//!     AddOutputExtensionLayer::new(Arc::new(state)),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service.
//! let response = service
//!     .serve(())
//!     .await?;
//! // Retrieve state from response
//! let counter_state = response.extensions().get::<Arc<State>>().unwrap();
//! # Ok(())
//! # }
//! ```
//!
//! Note though that extensions are best not used for State that you expect to be there,
//! but instead use extensions for optional behaviour to change. Static typed state
//! is better embedded in service structs or as state for routers.

use crate::{Layer, Service, extensions::ExtensionsMut};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// [`Layer`] for adding some shareable value to incoming input's extensions.
pub struct AddInputExtensionLayer<T> {
    value: T,
}

impl<T: fmt::Debug> std::fmt::Debug for AddInputExtensionLayer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddInputExtensionLayer")
            .field("value", &self.value)
            .finish()
    }
}

impl<T> Clone for AddInputExtensionLayer<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl<T> AddInputExtensionLayer<T> {
    /// Create a new [`AddInputExtensionLayer`].
    pub const fn new(value: T) -> Self {
        Self { value }
    }
}

impl<S, T> Layer<S> for AddInputExtensionLayer<T>
where
    T: Clone,
{
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
pub struct AddInputExtension<S, T> {
    inner: S,
    value: T,
}

impl<S: fmt::Debug, T: fmt::Debug> std::fmt::Debug for AddInputExtension<S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddInputExtension")
            .field("inner", &self.inner)
            .field("value", &self.value)
            .finish()
    }
}

impl<S, T> Clone for AddInputExtension<S, T>
where
    S: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            value: self.value.clone(),
        }
    }
}

impl<S, T> AddInputExtension<S, T> {
    /// Create a new [`AddInputExtension`].
    pub const fn new(inner: S, value: T) -> Self {
        Self { inner, value }
    }

    define_inner_service_accessors!();
}

impl<Input, S, T> Service<Input> for AddInputExtension<S, T>
where
    Input: Send + ExtensionsMut + 'static,
    S: Service<Input>,
    T: Clone + Send + Sync + std::fmt::Debug + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        input.extensions_mut().insert(self.value.clone());
        self.inner.serve(input).await
    }
}

/// [`Layer`] for adding some shareable value to an output's extensions.
pub struct AddOutputExtensionLayer<T> {
    value: T,
}

impl<T: fmt::Debug> std::fmt::Debug for AddOutputExtensionLayer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddOutputExtensionLayer")
            .field("value", &self.value)
            .finish()
    }
}

impl<T> Clone for AddOutputExtensionLayer<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl<T> AddOutputExtensionLayer<T> {
    /// Create a new [`AddOutputExtensionLayer`].
    pub const fn new(value: T) -> Self {
        Self { value }
    }
}

impl<S, T> Layer<S> for AddOutputExtensionLayer<T>
where
    T: Clone,
{
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
pub struct AddOutputExtension<S, T> {
    inner: S,
    value: T,
}

impl<S: fmt::Debug, T: fmt::Debug> std::fmt::Debug for AddOutputExtension<S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddOutputExtension")
            .field("inner", &self.inner)
            .field("value", &self.value)
            .finish()
    }
}

impl<S, T> Clone for AddOutputExtension<S, T>
where
    S: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            value: self.value.clone(),
        }
    }
}

impl<S, T> AddOutputExtension<S, T> {
    /// Create a new [`AddOutputExtension`].
    pub const fn new(inner: S, value: T) -> Self {
        Self { inner, value }
    }

    define_inner_service_accessors!();
}

impl<Input, S, T> Service<Input> for AddOutputExtension<S, T>
where
    Input: Send + 'static,
    S: Service<Input, Output: Send + ExtensionsMut + 'static>,
    T: Clone + Send + Sync + std::fmt::Debug + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let mut res = self.inner.serve(input).await?;
        res.extensions_mut().insert(self.value.clone());
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceInput, extensions::ExtensionsRef, service::service_fn};
    use std::{convert::Infallible, sync::Arc};

    #[derive(Debug)]
    struct State(i32);

    #[tokio::test]
    async fn basic_input() {
        let state = Arc::new(State(1));

        let svc = AddInputExtensionLayer::new(state).into_layer(service_fn(
            async |req: ServiceInput<()>| {
                let state = req.extensions().get::<Arc<State>>().unwrap();
                Ok::<_, Infallible>(state.0)
            },
        ));

        let res = svc.serve(ServiceInput::new(())).await.unwrap();

        assert_eq!(1, res);
    }

    #[tokio::test]
    async fn basic_output() {
        let state = Arc::new(State(1));

        let svc = AddOutputExtensionLayer::new(state).into_layer(service_fn(
            async |req: ServiceInput<()>| Ok::<_, Infallible>(req),
        ));

        let res = svc.serve(ServiceInput::new(())).await.unwrap();

        assert_eq!(1, res.extensions().get::<Arc<State>>().unwrap().0);
    }
}
