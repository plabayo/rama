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
pub struct Timeout<S, F> {
    inner: S,
    into_error: F,
    timeout: Duration,
}

impl<S, F> Timeout<S, F> {
    define_inner_service_accessors!();
}

impl<S, F> Clone for Timeout<S, F>
where
    S: Clone,
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

impl<S> Timeout<S, LayerErrorStatic<Elapsed>> {
    /// Creates a new [`Timeout`]
    pub fn new(inner: S, timeout: Duration) -> Self {
        Self::with_error(inner, timeout, error::Elapsed::new(timeout))
    }
}

impl<S, E> Timeout<S, LayerErrorStatic<E>> {
    /// Creates a new [`Timeout`] with a custom error
    /// value.
    pub fn with_error(inner: S, timeout: Duration, error: E) -> Self
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

impl<S, F> Timeout<S, LayerErrorFn<F>> {
    /// Creates a new [`Timeout`] with a custom error
    /// function.
    pub fn with_error_fn<E>(inner: S, timeout: Duration, error_fn: F) -> Self
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

impl<S, F> Timeout<S, F>
where
    F: MakeLayerError,
{
    /// Creates a new [`Timeout`] with a custom error
    /// value.
    pub(crate) fn with(inner: S, timeout: Duration, into_error: F) -> Self {
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
