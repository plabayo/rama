//! Utility error trait for Layers.
//!
//! See [`MakeLayerError`] for more details.

use std::fmt;

/// Utility error trait to allow Rama layers
/// to return a default error as well as a user-defined one,
/// being it a [`Clone`]-able type or a [`Fn`] returning an error type.
pub trait MakeLayerError: sealed::Sealed + Send + Sync + 'static {
    /// The error type returned by the layer.
    ///
    /// It does not need to be an actual error type,
    /// but it must be [`Send`] and of `'static` lifetime.
    type Error;

    /// Create a new error value that can
    /// be turned into the inner [`Service`]'s error type.
    ///
    /// [`Service`]: crate
    fn make_layer_error(&self) -> Self::Error;
}

/// A [`MakeLayerError`] implementation that
/// returns a new error value every time.
pub struct LayerErrorFn<F>(F);

impl<F, E> LayerErrorFn<F>
where
    F: Fn() -> E + Send + Sync + 'static,
    E: Send + 'static,
{
    pub(crate) const fn new(f: F) -> Self {
        Self(f)
    }
}

impl<F> fmt::Debug for LayerErrorFn<F>
where
    F: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LayerErrorFn").field(&self.0).finish()
    }
}

impl<F> Clone for LayerErrorFn<F>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<F, E> MakeLayerError for LayerErrorFn<F>
where
    F: Fn() -> E + Send + Sync + 'static,
    E: Send + 'static,
{
    type Error = E;

    fn make_layer_error(&self) -> Self::Error {
        self.0()
    }
}

/// A [`MakeLayerError`] implementation that
/// always returns clone of the same error value.
pub struct LayerErrorStatic<E>(E);

impl<E> fmt::Debug for LayerErrorStatic<E>
where
    E: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LayerErrorStatic").field(&self.0).finish()
    }
}

impl<E> Clone for LayerErrorStatic<E>
where
    E: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<E> LayerErrorStatic<E>
where
    E: Clone + Send + Sync + 'static,
{
    pub(crate) const fn new(e: E) -> Self {
        Self(e)
    }
}

impl<E> MakeLayerError for LayerErrorStatic<E>
where
    E: Clone + Send + Sync + 'static,
{
    type Error = E;

    fn make_layer_error(&self) -> Self::Error {
        self.0.clone()
    }
}

mod sealed {
    pub trait Sealed {}

    impl<F> Sealed for super::LayerErrorFn<F> {}
    impl<E> Sealed for super::LayerErrorStatic<E> {}
}
