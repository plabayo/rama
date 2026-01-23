use crate::{
    Layer,
    layer::{LayerErrorFn, LayerErrorStatic, MakeLayerError},
};

use super::{Abortable, Aborted};

/// Applies the option to abort an inner service.
#[derive(Debug, Clone)]
pub struct AbortableLayer<F> {
    into_error: F,
}

impl AbortableLayer<LayerErrorStatic<Aborted>> {
    /// Create an abortable layer
    #[must_use]
    pub fn new() -> Self {
        Self {
            into_error: LayerErrorStatic::new(Aborted::new()),
        }
    }
}

impl Default for AbortableLayer<LayerErrorStatic<Aborted>> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<E> AbortableLayer<LayerErrorStatic<E>> {
    /// Creates a new [`AbortableLayer`] with a custom error
    /// value.
    pub const fn with_error(error: E) -> Self
    where
        E: Clone + Send + Sync + 'static,
    {
        Self {
            into_error: LayerErrorStatic::new(error),
        }
    }
}

impl<F> AbortableLayer<LayerErrorFn<F>> {
    /// Creates a new [`AbortableLayer`] with a custom error
    /// function.
    pub const fn with_error_fn<E>(error_fn: F) -> Self
    where
        F: Fn() -> E + Send + Sync + 'static,
        E: Send + 'static,
    {
        Self {
            into_error: LayerErrorFn::new(error_fn),
        }
    }
}

impl<S, F> Layer<S> for AbortableLayer<F>
where
    F: MakeLayerError + Clone,
{
    type Service = Abortable<S, F>;

    fn layer(&self, service: S) -> Self::Service {
        Abortable::with(service, self.into_error.clone())
    }

    fn into_layer(self, service: S) -> Self::Service {
        Abortable::with(service, self.into_error)
    }
}
