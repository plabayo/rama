//! Utility error trait for Layers.
//!
//! See [`MakeLayerError`] for more details.

/// Utility error trait to allow Rama layers
/// to return a default error as well as a user-defined one,
/// being it a [`Clone`]-able type or a [`Fn`] returning an error type.
pub trait MakeLayerError: Clone + Send + 'static {
    /// The error type returned by the layer.
    ///
    /// It does not need to be an actual error type,
    /// but it must be [`Send`] and of `'static` lifetime.
    type Error;

    /// Create a new error value that can
    /// be turned into the inner [`Service`]'s error type.
    ///
    /// [`Service`]: crate::service::Service
    fn make_layer_error(&self) -> Self::Error;
}

#[derive(Debug, Clone)]
pub(crate) struct LayerErrorFn<F>(F);

impl<F, E> LayerErrorFn<F>
where
    F: Fn() -> E + Clone + Send + 'static,
    E: Send + 'static,
{
    pub(crate) fn new(f: F) -> Self {
        Self(f)
    }
}

impl<F, E> MakeLayerError for LayerErrorFn<F>
where
    F: Fn() -> E + Clone + Send + 'static,
    E: Send + 'static,
{
    type Error = E;

    fn make_layer_error(&self) -> Self::Error {
        self.0()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LayerErrorStatic<E>(E);

impl<E> LayerErrorStatic<E>
where
    E: Clone + Send + 'static,
{
    pub(crate) fn new(e: E) -> Self {
        Self(e)
    }
}

impl<E> MakeLayerError for LayerErrorStatic<E>
where
    E: Clone + Send + 'static,
{
    type Error = E;

    fn make_layer_error(&self) -> Self::Error {
        self.0.clone()
    }
}

mod sealed {
    pub(super) trait Sealed {}

    impl<F> Sealed for super::LayerErrorFn<F> {}
    impl<E> Sealed for super::LayerErrorStatic<E> {}
}
