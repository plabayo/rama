use crate::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;

/// Service which traces the error using [`tracing`],
/// of the inner [`Service`].
#[derive(Debug, Clone)]
pub struct TraceErr<S> {
    inner: S,
    level: tracing::Level,
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

impl<S, Input> Service<Input> for TraceErr<S>
where
    Input: Send + 'static,
    S: Service<Input, Error: std::fmt::Display + Send + Sync + 'static>,
{
    type Output = S::Output;
    type Error = S::Error;

    #[inline]
    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let level = self.level;
        let res = self.inner.serve(input).await;
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
