use crate::service::{Context, Layer, Service};
use futures_util::FutureExt;
use std::fmt;
use std::future::Future;

/// Service returned by the [`trace_err`] combinator.
///
/// [`trace_err`]: crate::service::ServiceBuilder::trace_err
#[derive(Clone)]
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

/// A [`Layer`] that produces [`TraceErr`] services.
///
/// [`Layer`]: crate::service::Layer
#[derive(Clone, Debug)]
pub struct TraceErrLayer {
    level: tracing::Level,
}

impl<S> TraceErr<S> {
    /// Creates a new [`TraceErr`] service.
    pub fn new(inner: S) -> Self {
        Self::with_level(inner, tracing::Level::ERROR)
    }

    /// Crates a new [`TraceErr`] service with the given [`tracing::Level`].
    pub fn with_level(inner: S, level: tracing::Level) -> Self {
        TraceErr { inner, level }
    }
}

impl<S, State, Request> Service<State, Request> for TraceErr<S>
where
    S: Service<State, Request>,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let level = self.level;
        self.inner.serve(ctx, req).map(move |res| {
            if let Err(ref err) = res {
                match level {
                    tracing::Level::TRACE => tracing::trace!(error = %err, "rama service failed"),
                    tracing::Level::DEBUG => tracing::debug!(error = %err, "rama service failed"),
                    tracing::Level::INFO => tracing::info!(error = %err, "rama service failed"),
                    tracing::Level::WARN => tracing::warn!(error = %err, "rama service failed"),
                    tracing::Level::ERROR => tracing::error!(error = %err, "rama service failed"),
                }
            }
            res
        })
    }
}

impl TraceErrLayer {
    /// Creates a new [`TraceErrLayer`].
    pub fn new() -> Self {
        Self::with_level(tracing::Level::ERROR)
    }

    /// Creates a new [`TraceErrLayer`] with the given [`tracing::Level`].
    pub fn with_level(level: tracing::Level) -> Self {
        TraceErrLayer { level }
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
