use crate::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Service which traces the error using [`tracing`],
/// of the inner [`Service`].
pub struct TraceErr<S> {
    inner: S,
    level: tracing::Level,
}

impl<S> fmt::Debug for TraceErr<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TraceErr")
            .field("inner", &self.inner)
            .field("level", &self.level)
            .finish()
    }
}

impl<S> Clone for TraceErr<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            level: self.level,
        }
    }
}

/// A [`Layer`] that produces [`TraceErr`] services.
///
/// [`Layer`]: crate::Layer
#[derive(Clone, Debug)]
pub struct TraceErrLayer {
    level: tracing::Level,
}

impl<S> TraceErr<S> {
    /// Creates a new [`TraceErr`] service.
    pub const fn new(inner: S) -> Self {
        Self::with_level(inner, tracing::Level::ERROR)
    }

    /// Crates a new [`TraceErr`] service with the given [`tracing::Level`].
    pub const fn with_level(inner: S, level: tracing::Level) -> Self {
        Self { inner, level }
    }

    define_inner_service_accessors!();
}

impl<S, State, Request> Service<State, Request> for TraceErr<S>
where
    Request: Send + 'static,
    S: Service<State, Request, Error: std::fmt::Display + Send + Sync + 'static>,
    State: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    #[inline]
    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let level = self.level;
        let res = self.inner.serve(ctx, req).await;
        if let Err(ref err) = res {
            match level {
                tracing::Level::TRACE => tracing::trace!("rama service failed: {err}"),
                tracing::Level::DEBUG => tracing::debug!("rama service failed: {err}"),
                tracing::Level::INFO => tracing::info!("rama service failed: {err}"),
                tracing::Level::WARN => tracing::warn!("rama service failed: {err}"),
                tracing::Level::ERROR => tracing::error!("rama service failed: {err}"),
            }
        }
        res
    }
}

impl TraceErrLayer {
    /// Creates a new [`TraceErrLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self::with_level(tracing::Level::ERROR)
    }

    /// Creates a new [`TraceErrLayer`] with the given [`tracing::Level`].
    #[must_use]
    pub const fn with_level(level: tracing::Level) -> Self {
        Self { level }
    }
}

impl Default for TraceErrLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for TraceErrLayer {
    type Service = TraceErr<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceErr::with_level(inner, self.level)
    }
}
