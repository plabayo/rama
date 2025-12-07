use crate::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Composes a function *in front of* the service.
///
/// This adapter produces a new service that passes each value through the
/// given function `f` before sending it to `self`.
#[derive(Clone)]
pub struct MapInput<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for MapInput<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapInput")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<S, F> MapInput<S, F> {
    /// Creates a new [`MapInput`] service.
    pub const fn new(inner: S, f: F) -> Self {
        Self { inner, f }
    }

    define_inner_service_accessors!();
}

impl<S, F, Input1, Input2> Service<Input1> for MapInput<S, F>
where
    S: Service<Input2>,
    F: Fn(Input1) -> Input2 + Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    #[inline]
    fn serve(
        &self,
        input: Input1,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        self.inner.serve((self.f)(input))
    }
}

/// A [`Layer`] that produces [`MapInput`] services.
///
/// [`Layer`]: crate::Layer
#[derive(Clone)]
pub struct MapInputLayer<F> {
    f: F,
}

impl<F> fmt::Debug for MapInputLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapInputLayer")
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<F> MapInputLayer<F> {
    /// Creates a new [`MapInputLayer`].
    pub const fn new(f: F) -> Self {
        Self { f }
    }
}

impl<S, F> Layer<S> for MapInputLayer<F>
where
    F: Clone,
{
    type Service = MapInput<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapInput {
            f: self.f.clone(),
            inner,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        MapInput { f: self.f, inner }
    }
}
