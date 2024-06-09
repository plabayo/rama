use crate::service::{Context, Layer, Service};
use std::fmt;

/// Executes a new future after this service's future resolves.
///
/// This method can be used to change the `Response` type of the service
/// into a different type. You can use this method to chain along a computation once the
/// service's response has been resolved.
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

impl<S, F> Clone for AndThen<S, F>
where
    S: Clone,
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            f: self.f.clone(),
        }
    }
}

/// A [`Layer`] that produces a [`AndThen`] service.
///
/// [`Layer`]: crate::service::Layer
#[derive(Debug)]
pub struct AndThenLayer<F> {
    f: F,
}

impl<S, F> AndThen<S, F> {
    /// Creates a new `AndThen` service.
    pub fn new(inner: S, f: F) -> Self {
        AndThen { f, inner }
    }

    define_inner_service_accessors!();
}

impl<F> Clone for AndThenLayer<F>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self { f: self.f.clone() }
    }
}

impl<S, F, State, Request, Fut, Output> Service<State, Request> for AndThen<S, F>
where
    S: Service<State, Request>,
    F: FnOnce(S::Response) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Output, S::Error>> + Send + 'static,
    State: Send + Sync + 'static,
    Request: Send + 'static,
    Output: Send + 'static,
{
    type Response = Output;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        match self.inner.serve(ctx, req).await {
            Ok(resp) => (self.f.clone())(resp).await,
            Err(err) => Err(err),
        }
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
