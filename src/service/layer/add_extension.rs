//! Middleware that clones a value into the incoming [Context].
//!
//! [Context]: https://docs.rs/rama/latest/rama/service/context/struct.Context.html
//!
//! # Example
//!
//! ```
//! use std::{sync::Arc, convert::Infallible};
//!
//! use rama::service::{Context, Service, ServiceBuilder, service_fn};
//! use rama::service::layer::add_extension::AddExtensionLayer;
//! use rama::error::BoxError;
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
//! async fn handle<S>(ctx: Context<S>, req: ()) -> Result<(), Infallible>
//! where
//!    S: Send + Sync + 'static,
//! {
//!     // Grab the state from the request extensions.
//!     let state = ctx.get::<Arc<State>>().unwrap();
//!
//!     Ok(req)
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! // Construct the shared state.
//! let state = State {
//!     pool: DatabaseConnectionPool::new(),
//! };
//!
//! let mut service = ServiceBuilder::new()
//!     // Share an `Arc<State>` with all requests.
//!     .layer(AddExtensionLayer::new(Arc::new(state)))
//!     .service_fn(handle);
//!
//! // Call the service.
//! let response = service
//!     .serve(Context::default(), ())
//!     .await?;
//! # Ok(())
//! # }
//! ```

use crate::service::{Context, Layer, Service};

/// [`Layer`] for adding some shareable value to incoming [Context].
///
/// [Context]: https://docs.rs/rama/latest/rama/service/context/struct.Context.html
#[derive(Clone, Copy, Debug)]
pub struct AddExtensionLayer<T> {
    value: T,
}

impl<T> AddExtensionLayer<T> {
    /// Create a new [`AddExtensionLayer`].
    pub fn new(value: T) -> Self {
        AddExtensionLayer { value }
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
}

/// Middleware for adding some shareable value to incoming [Context].
///
/// [Context]: https://docs.rs/rama/latest/rama/service/context/struct.Context.html
#[derive(Clone, Copy, Debug)]
pub struct AddExtension<S, T> {
    inner: S,
    value: T,
}

impl<S, T> AddExtension<S, T> {
    /// Create a new [`AddExtension`].
    pub fn new(inner: S, value: T) -> Self {
        Self { inner, value }
    }

    define_inner_service_accessors!();
}

impl<State, Request, S, T> Service<State, Request> for AddExtension<S, T>
where
    State: Send + Sync + 'static,
    Request: Send + 'static,
    S: Service<State, Request>,
    T: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request,
    ) -> impl std::future::Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        ctx.insert(self.value.clone());
        self.inner.serve(ctx, req)
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    use std::{convert::Infallible, sync::Arc};

    use crate::service::{service_fn, Context, ServiceBuilder};

    struct State(i32);

    #[tokio::test]
    async fn basic() {
        let state = Arc::new(State(1));

        let svc = ServiceBuilder::new()
            .layer(AddExtensionLayer::new(state))
            .service(service_fn(|ctx: Context<()>, _req: ()| async move {
                let state = ctx.get::<Arc<State>>().unwrap();
                Ok::<_, Infallible>(state.0)
            }));

        let res = svc.serve(Context::default(), ()).await.unwrap();

        assert_eq!(1, res);
    }
}
