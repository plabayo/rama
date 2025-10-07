//! Middleware that clones a value into the incoming input extensions
//!
//! # Example
//!
//! ```
//! use std::{sync::Arc, convert::Infallible};
//!
//! use rama_core::{extensions::{Extensions, ExtensionsRef}, Service, Layer, service::service_fn};
//! use rama_core::layer::add_extension::AddExtensionLayer;
//! use rama_core::error::BoxError;
//!
//! # struct DatabaseConnectionPool;
//! # impl DatabaseConnectionPool {
//! #     fn new() -> DatabaseConnectionPool { DatabaseConnectionPool }
//! # }
//! #
//! // Shared state across all request handlers --- in this case, a pool of database connections.
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
//!     AddExtensionLayer::new(Arc::new(state)),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service.
//! let response = service
//!     .serve(Extensions::new())
//!     .await?;
//! # Ok(())
//! # }
//! ```

use crate::{Layer, Service, extensions::ExtensionsMut};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// [`Layer`] for adding some shareable value to incoming [Context].
///
/// [Context]: https://docs.rs/rama/latest/rama/context/struct.Context.html
pub struct AddExtensionLayer<T> {
    value: T,
}

impl<T: fmt::Debug> std::fmt::Debug for AddExtensionLayer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddExtensionLayer")
            .field("value", &self.value)
            .finish()
    }
}

impl<T> Clone for AddExtensionLayer<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl<T> AddExtensionLayer<T> {
    /// Create a new [`AddExtensionLayer`].
    pub const fn new(value: T) -> Self {
        Self { value }
    }
}

impl<S, T> Layer<S> for AddExtensionLayer<T>
where
    T: Clone,
{
    type Service = AddExtension<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        AddExtension {
            inner,
            value: self.value.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        AddExtension {
            inner,
            value: self.value,
        }
    }
}

/// Middleware for adding some shareable value to incoming [Context].
///
/// [Context]: https://docs.rs/rama/latest/rama/context/struct.Context.html
pub struct AddExtension<S, T> {
    inner: S,
    value: T,
}

impl<S: fmt::Debug, T: fmt::Debug> std::fmt::Debug for AddExtension<S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddExtension")
            .field("inner", &self.inner)
            .field("value", &self.value)
            .finish()
    }
}

impl<S, T> Clone for AddExtension<S, T>
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

impl<S, T> AddExtension<S, T> {
    /// Create a new [`AddExtension`].
    pub const fn new(inner: S, value: T) -> Self {
        Self { inner, value }
    }

    define_inner_service_accessors!();
}

impl<Request, S, T> Service<Request> for AddExtension<S, T>
where
    Request: Send + ExtensionsMut + 'static,
    S: Service<Request>,
    T: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,

        mut req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        req.extensions_mut().insert(self.value.clone());
        self.inner.serve(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceInput, extensions::ExtensionsRef, service::service_fn};
    use std::{convert::Infallible, sync::Arc};

    struct State(i32);

    #[tokio::test]
    async fn basic() {
        let state = Arc::new(State(1));

        let svc =
            AddExtensionLayer::new(state).into_layer(service_fn(async |req: ServiceInput<()>| {
                let state = req.extensions().get::<Arc<State>>().unwrap();
                Ok::<_, Infallible>(state.0)
            }));

        let res = svc.serve(ServiceInput::new(())).await.unwrap();

        assert_eq!(1, res);
    }
}
