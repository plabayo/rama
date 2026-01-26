//! Middleware that applies a timeout to inputs.
//!
//! If the inner service does not complete within the specified timeout, the output
//! will be aborted.

use super::{LayerErrorFn, LayerErrorStatic, MakeLayerError};
use crate::Service;
use rama_utils::macros::define_inner_service_accessors;
use std::time::Duration;

mod error;
#[doc(inline)]
pub use error::Elapsed;

mod layer;
#[doc(inline)]
pub use layer::TimeoutLayer;

/// Applies a timeout to inputs.
#[derive(Debug, Clone)]
pub struct Timeout<S, F> {
    inner: S,
    into_error: F,
    timeout: Option<Duration>,
}

impl<S, F> Timeout<S, F> {
    define_inner_service_accessors!();
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

impl<T, F, Input, E> Service<Input> for Timeout<T, F>
where
    Input: Send + 'static,
    F: MakeLayerError<Error = E>,
    E: Into<T::Error> + Send + 'static,
    T: Service<Input>,
{
    type Output = T::Output;
    type Error = T::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        match self.timeout {
            Some(duration) => tokio::select! {
                res = self.inner.serve(input) => res,
                _ = tokio::time::sleep(duration) => Err(self.into_error.make_layer_error().into()),
            },
            None => self.inner.serve(input).await,
        }
    }
}
