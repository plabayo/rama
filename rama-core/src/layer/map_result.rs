use crate::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Maps this service's result type (`Result<Self::Response, Self::Error>`)
/// to a different value, regardless of whether the future succeeds or
/// fails.
///
/// This is similar to the [`MapOutput`] and [`MapErr`] combinators,
/// except that the *same* function is invoked when the service's future
/// completes, whether it completes successfully or fails. This function
/// takes the [`Result`] returned by the service's future, and returns a
/// [`Result`].
///
/// Like the standard library's [`Result::and_then`], this method can be
/// used to implement control flow based on `Result` values. For example, it
/// may be used to implement error recovery, by turning some [`Err`]
/// responses from the service into [`Ok`] responses. Similarly, some
/// successful responses from the service could be rejected, by returning an
/// [`Err`] conditionally, depending on the value inside the [`Ok`]. Finally,
/// this method can also be used to implement behaviors that must run when a
/// service's future completes, regardless of whether it succeeded or failed.
///
/// This method can be used to change the `Response` type of the service
/// into a different type. It can also be used to change the `Error` type
/// of the service.
///
/// [`MapOutput`]: crate::layer::MapOutput
/// [`MapErr`]: crate::layer::MapErr
#[derive(Clone)]
pub struct MapResult<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for MapResult<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapResult")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

/// A [`Layer`] that produces a [`MapResult`] service.
///
/// [`Layer`]: crate::Layer
#[derive(Clone)]
pub struct MapResultLayer<F> {
    f: F,
}

impl<F> fmt::Debug for MapResultLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapResultLayer")
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<S, F> MapResult<S, F> {
    /// Creates a new [`MapResult`] service.
    pub const fn new(inner: S, f: F) -> Self {
        Self { f, inner }
    }

    define_inner_service_accessors!();
}

impl<S, F, Input, Output, Error> Service<Input> for MapResult<S, F>
where
    S: Service<Input>,
    F: Fn(Result<S::Output, S::Error>) -> Result<Output, Error> + Send + Sync + 'static,
    Input: Send + 'static,
    Output: Send + 'static,
    Error: Send + 'static,
{
    type Output = Output;
    type Error = Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let result = self.inner.serve(input).await;
        (self.f)(result)
    }
}

impl<F> MapResultLayer<F> {
    /// Creates a new [`MapResultLayer`] layer.
    pub const fn new(f: F) -> Self {
        Self { f }
    }
}

impl<S, F> Layer<S> for MapResultLayer<F>
where
    F: Clone,
{
    type Service = MapResult<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        MapResult {
            f: self.f.clone(),
            inner,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        MapResult { f: self.f, inner }
    }
}
