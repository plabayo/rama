use futures_util::FutureExt;
use std::fmt;
use std::future::Future;

use crate::service::{Context, Layer, Service};

/// Layer to map the result of a service.
#[derive(Clone)]
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

/// A [`Layer`] that produces a [`Then`] service.
///
/// [`Layer`]: crate::service::Layer
#[derive(Debug, Clone)]
pub struct ThenLayer<F> {
    f: F,
}

impl<S, F> Then<S, F> {
    /// Creates a new `Then` service.
    pub fn new(inner: S, f: F) -> Self {
        Then { f, inner }
    }
}

impl<S, F, State, Request, Response, Error, Fut> Service<State, Request> for Then<S, F>
where
    S: Service<State, Request>,
    S::Error: Into<Error>,
    F: Fn(Result<S::Response, S::Error>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<Response, Error>> + Send + 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.inner.serve(ctx, req).then(self.f.clone())
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
