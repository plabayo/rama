//! Middleware that applies a timeout to requests.
//!
//! If the response does not complete within the specified timeout, the response
//! will be aborted.

use super::{LayerErrorFn, LayerErrorStatic, MakeLayerError};
use crate::service::{Context, Service};
use std::time::Duration;

mod error;
#[doc(inline)]
pub use error::Elapsed;

mod layer;
#[doc(inline)]
pub use layer::TimeoutLayer;

/// Applies a timeout to requests.
#[derive(Debug)]
pub struct Timeout<T, F> {
    inner: T,
    into_error: F,
    timeout: Duration,
}

impl<T, F> Clone for Timeout<T, F>
where
    T: Clone,
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            into_error: self.into_error.clone(),
            timeout: self.timeout,
        }
    }
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
        E: Clone + Send + Sync + 'static,
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
        F: FnOnce() -> E + Clone + Send + Sync + 'static,
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
    S: Send + Sync + 'static,
    F: MakeLayerError<Error = E>,
    E: Into<T::Error> + Send + 'static,
    T: Service<S, Request>,
{
    type Response = T::Response;
    type Error = T::Error;

    async fn serve(
        &self,
        ctx: Context<S>,
        request: Request,
    ) -> Result<Self::Response, Self::Error> {
        tokio::select! {
            res = self.inner.serve(ctx, request) => res,
            _ = tokio::time::sleep(self.timeout) => Err(self.into_error.make_layer_error().into()),
        }
    }
}
