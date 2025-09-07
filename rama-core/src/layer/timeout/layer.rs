use std::{fmt, time::Duration};

use crate::{
    Layer,
    layer::{LayerErrorFn, LayerErrorStatic, MakeLayerError},
};

use super::{Timeout, error::Elapsed};

/// Applies a timeout to requests via the supplied inner service.
pub struct TimeoutLayer<F> {
    timeout: Duration,
    into_error: F,
}

impl<P: fmt::Debug> fmt::Debug for TimeoutLayer<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeoutLayer")
            .field("timeout", &self.timeout)
            .field("into_error", &self.into_error)
            .finish()
    }
}

impl<F> Clone for TimeoutLayer<F>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            timeout: self.timeout,
            into_error: self.into_error.clone(),
        }
    }
}

impl TimeoutLayer<LayerErrorStatic<Elapsed>> {
    /// Create a timeout from a duration
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            into_error: LayerErrorStatic::new(Elapsed::new(timeout)),
        }
    }
}

impl<E> TimeoutLayer<LayerErrorStatic<E>> {
    /// Creates a new [`TimeoutLayer`] with a custom error
    /// value.
    pub const fn with_error(timeout: Duration, error: E) -> Self
    where
        E: Clone + Send + Sync + 'static,
    {
        Self {
            timeout,
            into_error: LayerErrorStatic::new(error),
        }
    }
}

impl<F> TimeoutLayer<LayerErrorFn<F>> {
    /// Creates a new [`TimeoutLayer`] with a custom error
    /// function.
    pub const fn with_error_fn<E>(timeout: Duration, error_fn: F) -> Self
    where
        F: Fn() -> E + Send + Sync + 'static,
        E: Send + 'static,
    {
        Self {
            timeout,
            into_error: LayerErrorFn::new(error_fn),
        }
    }
}

impl<S, F> Layer<S> for TimeoutLayer<F>
where
    F: MakeLayerError + Clone,
{
    type Service = Timeout<S, F>;

    fn layer(&self, service: S) -> Self::Service {
        Timeout::with(service, self.timeout, self.into_error.clone())
    }

    fn into_layer(self, service: S) -> Self::Service {
        Timeout::with(service, self.timeout, self.into_error)
    }
}
