use crate::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Maps this service's output value to a different value.
///
/// This method can be used to change the `Output` type of the service
/// into a different type. It is similar to the [`Result::map`]
/// method. You can use this method to chain along a computation once the
/// service's output has been resolved.
#[derive(Clone)]
pub struct MapOutput<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for MapOutput<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapOutput")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

/// A [`Layer`] that produces a [`MapOutput`] service.
///
/// [`Layer`]: crate::Layer
#[derive(Clone)]
pub struct MapOutputLayer<F> {
    f: F,
}

impl<F> fmt::Debug for MapOutputLayer<F>
where
    F: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapOutputLayer")
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<S, F> MapOutput<S, F> {
    /// Creates a new `MapOutput` service.
    pub const fn new(inner: S, f: F) -> Self {
        Self { f, inner }
    }

    define_inner_service_accessors!();
}

impl<S, F, Input, Output> Service<Input> for MapOutput<S, F>
where
    S: Service<Input>,
    F: Fn(S::Output) -> Output + Send + Sync + 'static,
    Input: Send + 'static,
    Output: Send + 'static,
{
    type Output = Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(input).await {
            Ok(resp) => Ok((self.f)(resp)),
            Err(err) => Err(err),
        }
    }
}

impl<F> MapOutputLayer<F> {
    /// Creates a new [`MapOutputLayer`] layer.
    pub const fn new(f: F) -> Self {
        Self { f }
    }
}

impl<S, F> Layer<S> for MapOutputLayer<F>
where
    F: Clone,
{
    type Service = MapOutput<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapOutput {
            f: self.f.clone(),
            inner,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        MapOutput { f: self.f, inner }
    }
}
