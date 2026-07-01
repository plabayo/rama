use core::marker::PhantomData;

use rama_error::BoxError;

use crate::{Layer, Service};

/// [`Service`] which converts errors using [`Into`] trait
#[derive(Debug, Clone)]
pub struct IntoErr<S, E> {
    inner: S,
    _error: PhantomData<fn(E)>,
}

impl<S, E> IntoErr<S, E> {
    /// Create a new [`IntoErr`] service
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            _error: Default::default(),
        }
    }
}

impl<S, I, E> Service<I> for IntoErr<S, E>
where
    S: Service<I, Error: Into<E>>,
    I: Send + 'static,
    E: Send + 'static,
{
    type Output = S::Output;
    type Error = E;

    async fn serve(&self, input: I) -> Result<Self::Output, Self::Error> {
        self.inner.serve(input).await.map_err(Into::into)
    }
}

/// A [`Layer`] that produces [`IntoErr`] services.
#[derive(Debug)]
pub struct IntoErrLayer<E>(PhantomData<fn(E)>);

impl<E> Clone for IntoErrLayer<E> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<E> Default for IntoErrLayer<E> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<E> IntoErrLayer<E> {
    /// Create a new [`IntoErrLayer`] layer
    pub fn new() -> Self {
        Self(Default::default())
    }
}

impl IntoErrLayer<()> {
    pub fn into_box_error() -> IntoErrLayer<BoxError> {
        Default::default()
    }
}

impl<S, E> Layer<S> for IntoErrLayer<E> {
    type Service = IntoErr<S, E>;

    fn layer(&self, inner: S) -> Self::Service {
        IntoErr::new(inner)
    }
}
