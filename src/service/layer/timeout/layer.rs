use std::time::Duration;

use crate::service::{
    layer::{LayerErrorFn, LayerErrorStatic, MakeLayerError},
    Layer,
};

use super::{error::Elapsed, Timeout};

/// Applies a timeout to requests via the supplied inner service.
#[derive(Debug, Clone)]
pub struct TimeoutLayer<F> {
    timeout: Duration,
    into_error: F,
}

impl TimeoutLayer<LayerErrorStatic<Elapsed>> {
    /// Create a timeout from a duration
    pub fn new(timeout: Duration) -> Self {
        TimeoutLayer {
            timeout,
            into_error: LayerErrorStatic::new(Elapsed::new(timeout)),
        }
    }
}

impl<E> TimeoutLayer<LayerErrorStatic<E>> {
    /// Creates a new [`TimeoutLayer`] with a custom error
    /// value.
    pub fn with_error(timeout: Duration, error: E) -> Self
    where
        E: Clone + Send + 'static,
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
    pub fn with_error_fn<E>(timeout: Duration, error_fn: F) -> Self
    where
        F: Fn() -> E + Clone + Send + 'static,
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
    F: MakeLayerError,
{
    type Service = Timeout<S, F>;

    fn layer(&self, service: S) -> Self::Service {
        Timeout::with(service, self.timeout, self.into_error.clone())
    }
}
