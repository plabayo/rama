use crate::{
    error::BoxError,
    service::{Context, Layer, Service},
};
use std::{convert::Infallible, fmt};

use sealed::Trace;

/// Consumes this service's error value and returns [`Infallible`].
#[derive(Clone)]
pub struct ConsumeErr<S, F> {
    inner: S,
    f: F,
}

impl<S, F> fmt::Debug for ConsumeErr<S, F>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumeErr")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

/// A [`Layer`] that produces [`ConsumeErr`] services.
///
/// [`Layer`]: crate::service::Layer
#[derive(Clone)]
pub struct ConsumeErrLayer<F> {
    f: F,
}

impl<F> fmt::Debug for ConsumeErrLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumeErrLayer")
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl Default for ConsumeErrLayer<Trace> {
    fn default() -> Self {
        Self::trace(tracing::Level::ERROR)
    }
}

impl<S, F> ConsumeErr<S, F> {
    /// Creates a new [`ConsumeErr`] service.
    pub fn new(inner: S, f: F) -> Self {
        ConsumeErr { f, inner }
    }
}

impl<S> ConsumeErr<S, Trace> {
    /// Trace the error passed to this [`ConsumeErr`] service for the provided trace level.
    pub fn trace(inner: S, level: tracing::Level) -> Self {
        Self::new(inner, Trace(level))
    }
}

impl<S, F, State, Request> Service<State, Request> for ConsumeErr<S, F>
where
    S: Service<State, Request>,
    S::Response: Default,
    F: FnOnce(S::Error) + Clone + Send + Sync + 'static,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = Infallible;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        match self.inner.serve(ctx, req).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                (self.f.clone())(err);
                Ok(S::Response::default())
            }
        }
    }
}

impl<S, State, Request> Service<State, Request> for ConsumeErr<S, Trace>
where
    S: Service<State, Request>,
    S::Response: Default,
    S::Error: Into<BoxError>,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = Infallible;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        match self.inner.serve(ctx, req).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                const MESSAGE: &str = "unhandled service error consumed";
                match self.f.0 {
                    tracing::Level::TRACE => {
                        tracing::trace!(error = err.into(), MESSAGE);
                    }
                    tracing::Level::DEBUG => {
                        tracing::debug!(error = err.into(), MESSAGE);
                    }
                    tracing::Level::INFO => {
                        tracing::info!(error = err.into(), MESSAGE);
                    }
                    tracing::Level::WARN => {
                        tracing::warn!(error = err.into(), MESSAGE);
                    }
                    tracing::Level::ERROR => {
                        tracing::error!(error = err.into(), MESSAGE);
                    }
                }
                Ok(S::Response::default())
            }
        }
    }
}

impl<F> ConsumeErrLayer<F> {
    /// Creates a new [`ConsumeErrLayer`].
    pub fn new(f: F) -> Self {
        ConsumeErrLayer { f }
    }
}

impl ConsumeErrLayer<Trace> {
    /// Creates a new [`ConsumeErrLayer`] to trace the consumed error.
    pub fn trace(level: tracing::Level) -> Self {
        Self::new(Trace(level))
    }
}

impl<S, F> Layer<S> for ConsumeErrLayer<F>
where
    F: Clone,
{
    type Service = ConsumeErr<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        ConsumeErr {
            f: self.f.clone(),
            inner,
        }
    }
}

mod sealed {
    #[derive(Debug, Clone)]
    /// A sealed new type to prevent downstream users from
    /// passing the trace level directly to the [`ConsumeErr::new`] method.
    ///
    /// [`ConsumeErr::new`]: crate::service::layer::ConsumeErr::new
    pub struct Trace(pub tracing::Level);
}
