use crate::{Layer, Service};
use rama_error::{BoxError, ErrorExt, extra::OpaqueError};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;
use std::marker::PhantomData;

/// Maps this service's error value to a different value.
///
/// This method can be used to change the [`Error`] type of the service
/// into a different type. It is similar to the [`Result::map_err`] method.
///
/// [`Error`]: crate::error::BoxError
#[derive(Clone)]
pub struct MapErr<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for MapErr<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapErr")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

/// A [`Layer`] that produces [`MapErr`] services.
///
/// [`Layer`]: crate::Layer
#[derive(Clone)]
pub struct MapErrLayer<F> {
    f: F,
}

impl<F> std::fmt::Debug for MapErrLayer<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapErrLayer")
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<S, F> MapErr<S, F> {
    /// Creates a new [`MapErr`] service.
    pub const fn new(inner: S, f: F) -> Self {
        Self { f, inner }
    }

    define_inner_service_accessors!();
}

impl<S, Error> MapErr<S, fn(Error) -> BoxError>
where
    Error: Into<BoxError>,
{
    /// Turn the error into a [`BoxError`].
    pub const fn into_box_error(inner: S) -> Self {
        Self::new(inner, ErrorExt::into_box_error)
    }
}

impl<S, Error> MapErr<S, fn(Error) -> OpaqueError>
where
    Error: Into<BoxError>,
{
    /// Turn the error into a [`OpaqueError`].
    ///
    /// Usually you'll want a custom map function or [`Self::into_box_error`],
    /// but this method can come in handy if you need to deal with higher-rank
    /// lifetime issues.
    pub const fn into_opaque_error(inner: S) -> Self {
        Self::new(inner, ErrorExt::into_opaque_error)
    }
}

impl<S, F, Input, Error> Service<Input> for MapErr<S, F>
where
    S: Service<Input>,
    F: Fn(S::Error) -> Error + Send + Sync + 'static,
    Input: Send + 'static,
    Error: Send + 'static,
{
    type Output = S::Output;
    type Error = Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(input).await {
            Ok(resp) => Ok(resp),
            Err(err) => Err((self.f)(err)),
        }
    }
}

impl<F> MapErrLayer<F> {
    /// Creates a new [`MapErrLayer`].
    pub const fn new(f: F) -> Self {
        Self { f }
    }
}

impl<Error> MapErrLayer<fn(Error) -> BoxError>
where
    BoxError: From<Error>,
{
    /// Turn the error into a [`BoxError`].
    ///
    /// This is shorthand for `MapErrLayer::new(BoxError::from)`.
    pub const fn into_box_error() -> Self {
        Self::new(BoxError::from)
    }
}

impl<Error> MapErrLayer<fn(Error) -> OpaqueError>
where
    BoxError: From<Error>,
{
    /// Turn the error into a [`OpaqueError`].
    ///
    /// Usually you'll want a custom map function or [`Self::into_box_error`],
    /// but this method can come in handy if you need to deal with higher-rank
    /// lifetime issues.
    pub const fn into_opaque_error() -> Self {
        Self::new(|err| err.into_opaque_error())
    }
}

impl<S, F> Layer<S> for MapErrLayer<F>
where
    F: Clone,
{
    type Service = MapErr<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapErr {
            f: self.f.clone(),
            inner,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        MapErr { f: self.f, inner }
    }
}

/// [`Service`] which converts errors using [`Into`] trait
#[derive(Debug, Clone)]
pub struct IntoErr<S, E> {
    inner: S,
    _error: PhantomData<E>,
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
    E: Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = E;

    async fn serve(&self, input: I) -> Result<Self::Output, Self::Error> {
        self.inner.serve(input).await.map_err(Into::into)
    }
}

/// A [`Layer`] that produces [`IntoErr`] services.
#[derive(Debug, Clone)]
pub struct IntoErrLayer<E>(PhantomData<E>);

impl<E> IntoErrLayer<E> {
    /// Create a new [`IntoErrLayer`] layer
    pub fn new() -> Self {
        Self(Default::default())
    }
}

impl<S, E> Layer<S> for IntoErrLayer<E> {
    type Service = IntoErr<S, E>;

    fn layer(&self, inner: S) -> Self::Service {
        IntoErr::new(inner)
    }
}
