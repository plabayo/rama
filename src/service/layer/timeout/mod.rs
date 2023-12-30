//! Middleware that applies a timeout to requests.
//!
//! If the response does not complete within the specified timeout, the response
//! will be aborted.

use super::{LayerErrorFn, LayerErrorStatic, MakeLayerError};
use crate::service::{Context, Service};
use std::future::Future;
use std::time::Duration;

mod error;
pub use error::Elapsed;

mod layer;
pub use layer::TimeoutLayer;

/// Applies a timeout to requests.
#[derive(Debug, Clone)]
pub struct Timeout<T, F> {
    inner: T,
    into_error: F,
    timeout: Duration,
}

// ===== impl Timeout =====

impl<T> Timeout<T, LayerErrorStatic<Elapsed>> {
    /// Creates a new [`Timeout`]
    pub fn new(inner: T, timeout: Duration) -> Self {
        Self::with_error(inner, timeout, error::Elapsed::new(timeout))
    }
}

impl<T, E> Timeout<T, LayerErrorStatic<E>> {
    /// Creates a new [`Timeout`] with a custom error
    /// value.
    pub fn with_error(inner: T, timeout: Duration, error: E) -> Self
    where
        E: Clone + Send + 'static,
    {
        Self {
            inner,
            timeout,
            into_error: LayerErrorStatic::new(error),
        }
    }
}

impl<T, F> Timeout<T, LayerErrorFn<F>> {
    /// Creates a new [`Timeout`] with a custom error
    /// function.
    pub fn with_error_fn<E>(inner: T, timeout: Duration, error_fn: F) -> Self
    where
        F: Fn() -> E + Clone + Send + 'static,
        E: Send + 'static,
    {
        Self {
            inner,
            timeout,
            into_error: LayerErrorFn::new(error_fn),
        }
    }
}

impl<T, F> Timeout<T, F>
where
    F: MakeLayerError,
{
    /// Creates a new [`Timeout`] with a custom error
    /// value.
    pub(crate) fn with(inner: T, timeout: Duration, into_error: F) -> Self {
        Self {
            inner,
            timeout,
            into_error,
        }
    }
}

impl<T, F, S, Request, E> Service<S, Request> for Timeout<T, F>
where
    Request: Send + 'static,
    S: Clone + Send + 'static,
    F: MakeLayerError<Error = E>,
    E: Into<T::Error> + Send + 'static,
    T: Service<S, Request> + Clone,
{
    type Response = T::Response;
    type Error = T::Error;

    fn serve(
        &self,
        ctx: Context<S>,
        request: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let error_fn = self.into_error.clone();
        let timeout = self.timeout;
        let inner = self.inner.clone();

        async move {
            tokio::select! {
                res = inner.serve(ctx, request) => res,
                _ = tokio::time::sleep(timeout) => Err(error_fn.make_layer_error().into()),
            }
        }
    }
}
