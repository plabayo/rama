//! Middleware that applies a timeout to requests.
//!
//! If the response does not complete within the specified timeout, the response
//! will be aborted.

use super::{LayerErrorFn, LayerErrorStatic, MakeLayerError};
use crate::Service;
use rama_utils::macros::define_inner_service_accessors;
use std::{fmt, time::Duration};

mod error;
#[doc(inline)]
pub use error::Elapsed;

mod layer;
#[doc(inline)]
pub use layer::TimeoutLayer;

/// Applies a timeout to requests.
pub struct Timeout<S, F> {
    inner: S,
    into_error: F,
    timeout: Option<Duration>,
}

impl<S, F> Timeout<S, F> {
    define_inner_service_accessors!();
}

impl<S: fmt::Debug, F: fmt::Debug> fmt::Debug for Timeout<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Timeout")
            .field("inner", &self.inner)
            .field("into_error", &self.into_error)
            .field("timeout", &self.timeout)
            .finish()
    }
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

/// default [`Timeout`]
pub type DefaultTimeout<S> = Timeout<S, LayerErrorStatic<Elapsed>>;

// ===== impl Timeout =====

impl<S> DefaultTimeout<S> {
    /// Creates a new [`Timeout`]
    pub fn new(inner: S, timeout: Duration) -> Self {
        Self::with_error(inner, timeout, error::Elapsed::new(Some(timeout)))
    }

    /// Creates a new [`Timeout`] which never times out.
    pub fn never(inner: S) -> Self {
        Self {
            inner,
            timeout: None,
            into_error: LayerErrorStatic::new(error::Elapsed::new(None)),
        }
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
            timeout: Some(timeout),
            into_error: LayerErrorStatic::new(error),
        }
    }
}

impl<S, F> Timeout<S, LayerErrorFn<F>> {
    /// Creates a new [`Timeout`] with a custom error
    /// function.
    pub fn with_error_fn<E>(inner: S, timeout: Duration, error_fn: F) -> Self
    where
        F: Fn() -> E + Send + Sync + 'static,
        E: Send + 'static,
    {
        Self {
            inner,
            timeout: Some(timeout),
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
    pub(crate) fn with(inner: S, timeout: Option<Duration>, into_error: F) -> Self {
        Self {
            inner,
            timeout,
            into_error,
        }
    }
}

impl<T, F, Request, E> Service<Request> for Timeout<T, F>
where
    Request: Send + 'static,
    F: MakeLayerError<Error = E>,
    E: Into<T::Error> + Send + 'static,
    T: Service<Request>,
{
    type Response = T::Response;
    type Error = T::Error;

    async fn serve(&self, request: Request) -> Result<Self::Response, Self::Error> {
        match self.timeout {
            Some(duration) => tokio::select! {
                res = self.inner.serve(request) => res,
                _ = tokio::time::sleep(duration) => Err(self.into_error.make_layer_error().into()),
            },
            None => self.inner.serve(request).await,
        }
    }
}
