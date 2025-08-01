use crate::{Context, Layer, Service, error::BoxError};
use rama_utils::macros::define_inner_service_accessors;
use std::{convert::Infallible, fmt};

use sealed::{DefaulResponse, StaticResponse, Trace};

/// Consumes this service's error value and returns [`Infallible`].
#[derive(Clone)]
pub struct ConsumeErr<S, F, R = DefaulResponse> {
    inner: S,
    f: F,
    response: R,
}

impl<S, F, R> fmt::Debug for ConsumeErr<S, F, R>
where
    S: fmt::Debug,
    R: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumeErr")
            .field("inner", &self.inner)
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .field("response", &self.response)
            .finish()
    }
}

/// A [`Layer`] that produces [`ConsumeErr`] services.
///
/// [`Layer`]: crate::Layer
#[derive(Clone)]
pub struct ConsumeErrLayer<F, R = DefaulResponse> {
    f: F,
    response: R,
}

impl<F, R: fmt::Debug> fmt::Debug for ConsumeErrLayer<F, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumeErrLayer")
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .field("response", &self.response)
            .finish()
    }
}

impl Default for ConsumeErrLayer<Trace> {
    fn default() -> Self {
        Self::trace(tracing::Level::ERROR)
    }
}

impl<S, F> ConsumeErr<S, F, DefaulResponse> {
    /// Creates a new [`ConsumeErr`] service.
    pub const fn new(inner: S, f: F) -> Self {
        Self {
            f,
            inner,
            response: DefaulResponse,
        }
    }

    define_inner_service_accessors!();
}

impl<S, F> ConsumeErr<S, F, DefaulResponse> {
    /// Set a response to be used in case of errors,
    /// instead of requiring and using the [`Default::default`] implementation
    /// of the inner service's response type.
    pub fn with_response<R>(self, response: R) -> ConsumeErr<S, F, StaticResponse<R>> {
        ConsumeErr {
            f: self.f,
            inner: self.inner,
            response: StaticResponse(response),
        }
    }
}

impl<S> ConsumeErr<S, Trace, DefaulResponse> {
    /// Trace the error passed to this [`ConsumeErr`] service for the provided trace level.
    pub const fn trace(inner: S, level: tracing::Level) -> Self {
        Self::new(inner, Trace(level))
    }
}

impl<S, F, State, Request> Service<State, Request> for ConsumeErr<S, F, DefaulResponse>
where
    S: Service<State, Request, Response: Default>,
    F: Fn(S::Error) + Send + Sync + 'static,
    State: Clone + Send + Sync + 'static,
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
                (self.f)(err);
                Ok(S::Response::default())
            }
        }
    }
}

impl<S, F, State, Request, R> Service<State, Request> for ConsumeErr<S, F, StaticResponse<R>>
where
    S: Service<State, Request>,
    F: Fn(S::Error) + Send + Sync + 'static,
    R: Into<S::Response> + Clone + Send + Sync + 'static,
    State: Clone + Send + Sync + 'static,
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
                (self.f)(err);
                Ok(self.response.0.clone().into())
            }
        }
    }
}

impl<S, State, Request> Service<State, Request> for ConsumeErr<S, Trace, DefaulResponse>
where
    S: Service<State, Request, Response: Default, Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
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
                        tracing::trace!("{MESSAGE}: {:?}", err.into());
                    }
                    tracing::Level::DEBUG => {
                        tracing::debug!("{MESSAGE}: {:?}", err.into());
                    }
                    tracing::Level::INFO => {
                        tracing::info!("{MESSAGE}: {:?}", err.into());
                    }
                    tracing::Level::WARN => {
                        tracing::warn!("{MESSAGE}: {:?}", err.into());
                    }
                    tracing::Level::ERROR => {
                        tracing::error!("{MESSAGE}: {:?}", err.into());
                    }
                }
                Ok(S::Response::default())
            }
        }
    }
}

impl<S, State, Request, R> Service<State, Request> for ConsumeErr<S, Trace, StaticResponse<R>>
where
    S: Service<State, Request, Error: Into<BoxError>>,
    R: Into<S::Response> + Clone + Send + Sync + 'static,
    State: Clone + Send + Sync + 'static,
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
                Ok(self.response.0.clone().into())
            }
        }
    }
}

impl<F> ConsumeErrLayer<F> {
    /// Creates a new [`ConsumeErrLayer`].
    pub const fn new(f: F) -> Self {
        Self {
            f,
            response: DefaulResponse,
        }
    }
}

impl ConsumeErrLayer<Trace> {
    /// Creates a new [`ConsumeErrLayer`] to trace the consumed error.
    #[must_use]
    pub const fn trace(level: tracing::Level) -> Self {
        Self::new(Trace(level))
    }
}

impl<F> ConsumeErrLayer<F, DefaulResponse> {
    /// Set a response to be used in case of errors,
    /// instead of requiring and using the [`Default::default`] implementation
    /// of the inner service's response type.
    pub fn with_response<R>(self, response: R) -> ConsumeErrLayer<F, StaticResponse<R>> {
        ConsumeErrLayer {
            f: self.f,
            response: StaticResponse(response),
        }
    }
}

impl<S, F, R> Layer<S> for ConsumeErrLayer<F, R>
where
    F: Clone,
    R: Clone,
{
    type Service = ConsumeErr<S, F, R>;

    fn layer(&self, inner: S) -> Self::Service {
        ConsumeErr {
            f: self.f.clone(),
            inner,
            response: self.response.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ConsumeErr {
            f: self.f,
            inner,
            response: self.response,
        }
    }
}

mod sealed {
    #[derive(Debug, Clone)]
    /// A sealed new type to prevent downstream users from
    /// passing the trace level directly to the [`ConsumeErr::new`] method.
    ///
    /// [`ConsumeErr::new`]: crate::layer::ConsumeErr::new
    pub struct Trace(pub tracing::Level);

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    /// A sealed type to indicate default response is to be used.
    pub struct DefaulResponse;

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    /// A sealed type to indicate static response is to be used.
    pub struct StaticResponse<R>(pub(super) R);
}
