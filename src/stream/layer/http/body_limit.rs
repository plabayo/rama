use std::fmt;

use crate::{
    service::{Context, Layer, Service},
    stream::Stream,
};

/// Communicate to the downstream http service to apply a limit to the body.
///
/// The difference with [`crate::http::layer::body_limit`] is that this middleware
/// does not apply the limit to the body, but instead communicates to the downstream
/// service to apply the limit, by adding a [`BodyLimit`] value to the [`Context`].
///
/// [`Context`]: crate::service::Context`
#[derive(Debug, Clone)]
pub struct BodyLimitLayer {
    size: usize,
}

/// Communicate to the downstream http service to apply a limit to the body.
///
/// See [`BodyLimitService`] for more information.
#[derive(Debug, Clone)]
pub struct BodyLimit(pub usize);

impl BodyLimitLayer {
    /// Create a new [`BodyLimitLayer`].
    pub fn new(size: usize) -> Self {
        Self { size }
    }
}

impl<S> Layer<S> for BodyLimitLayer {
    type Service = BodyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyLimitService::new(inner, self.size)
    }
}

/// Communicate to the downstream http service to apply a limit to the body.
///
/// See [`BodyLimitService`] for more information.
#[derive(Clone)]
pub struct BodyLimitService<S> {
    inner: S,
    size: usize,
}

impl<S> BodyLimitService<S> {
    /// Create a new [`BodyLimitService`].
    pub fn new(service: S, size: usize) -> Self {
        Self {
            inner: service,
            size,
        }
    }

    /// Returns a new [`Layer`] that wraps services with a `BodyLimitLayer` middleware.
    ///
    /// [`Layer`]: crate::service::Layer
    pub fn layer(size: usize) -> BodyLimitLayer {
        BodyLimitLayer::new(size)
    }

    define_inner_service_accessors!();
}

impl<S, State, IO> Service<State, IO> for BodyLimitService<S>
where
    S: Service<State, IO>,
    State: Send + Sync + 'static,
    IO: Stream,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        stream: IO,
    ) -> Result<Self::Response, Self::Error> {
        ctx.insert(BodyLimit(self.size));
        self.inner.serve(ctx, stream).await
    }
}

impl<S> fmt::Debug for BodyLimitService<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyLimitService")
            .field("inner", &self.inner)
            .field("size", &self.size)
            .finish()
    }
}
