use crate::service::{Context, Layer, Service};
use futures_util::TryFutureExt;
use std::fmt;
use std::future::Future;

/// Service returned by the [`and_then`] combinator.
///
/// [`and_then`]: crate::service::ServiceBuilder::and_then
#[derive(Clone)]
pub struct AndThen<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for AndThen<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AndThen")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

/// A [`Layer`] that produces a [`AndThen`] service.
///
/// [`Layer`]: crate::service::Layer
#[derive(Clone, Debug)]
pub struct AndThenLayer<F> {
    f: F,
}

impl<S, F> AndThen<S, F> {
    /// Creates a new `AndThen` service.
    pub fn new(inner: S, f: F) -> Self {
        AndThen { f, inner }
    }

    /// Returns a new [`Layer`] that produces [`AndThen`] services.
    ///
    /// This is a convenience function that simply calls [`AndThenLayer::new`].
    ///
    /// [`Layer`]: crate::service::Layer
    pub fn layer(f: F) -> AndThenLayer<F> {
        AndThenLayer { f }
    }
}

impl<S, F, State, Request, Fut, Output> Service<State, Request> for AndThen<S, F>
where
    S: Service<State, Request>,
    F: Fn(S::Response) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = Result<Output, S::Error>> + Send + 'static,
    Output: Send + 'static,
{
    type Response = Output;
    type Error = S::Error;

    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.inner.serve(ctx, req).and_then(self.f.clone())
    }
}

impl<F> AndThenLayer<F> {
    /// Creates a new [`AndThenLayer`] layer.
    pub fn new(f: F) -> Self {
        AndThenLayer { f }
    }
}

impl<S, F> Layer<S> for AndThenLayer<F>
where
    F: Clone,
{
    type Service = AndThen<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        AndThen {
            f: self.f.clone(),
            inner,
        }
    }
}
