use std::fmt;
use std::future::Future;

use crate::service::{Context, Layer, Service};

/// Layer to map the result of a service.
pub struct Then<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for Then<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Then")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<S, F> Clone for Then<S, F>
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

/// A [`Layer`] that produces a [`Then`] service.
///
/// [`Layer`]: crate::service::Layer
#[derive(Debug)]
pub struct ThenLayer<F> {
    f: F,
}

impl<S, F> Then<S, F> {
    /// Creates a new `Then` service.
    pub fn new(inner: S, f: F) -> Self {
        Then { f, inner }
    }

    define_inner_service_accessors!();
}

impl<F> Clone for ThenLayer<F>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self { f: self.f.clone() }
    }
}

impl<S, F, State, Request, Response, Error, Fut> Service<State, Request> for Then<S, F>
where
    S: Service<State, Request>,
    S::Error: Into<Error>,
    F: FnOnce(Result<S::Response, S::Error>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Response, Error>> + Send + 'static,
    State: Send + Sync + 'static,
    Request: Send + 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let result = self.inner.serve(ctx, req).await;
        (self.f.clone())(result).await
    }
}

impl<F> ThenLayer<F> {
    /// Creates a new [`ThenLayer`] layer.
    pub fn new(f: F) -> Self {
        ThenLayer { f }
    }
}

impl<S, F> Layer<S> for ThenLayer<F>
where
    F: Clone,
{
    type Service = Then<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        Then {
            f: self.f.clone(),
            inner,
        }
    }
}
