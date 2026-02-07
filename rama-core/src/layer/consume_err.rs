use crate::{Layer, Service, error::BoxError};
use rama_utils::macros::define_inner_service_accessors;
use std::{convert::Infallible, fmt};

use sealed::{DefaultOutput, StaticOutput, Trace};

/// Consumes this service's error value and returns [`Infallible`].
#[derive(Clone)]
pub struct ConsumeErr<S, F, O = DefaultOutput> {
    inner: S,
    f: F,
    output: O,
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
            .field("output", &self.output)
            .finish()
    }
}

/// A [`Layer`] that produces [`ConsumeErr`] services.
///
/// [`Layer`]: crate::Layer
#[derive(Clone)]
pub struct ConsumeErrLayer<F, O = DefaultOutput> {
    f: F,
    output: O,
}

impl<F, R: fmt::Debug> fmt::Debug for ConsumeErrLayer<F, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumeErrLayer")
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .field("output", &self.output)
            .finish()
    }
}

impl Default for ConsumeErrLayer<Trace> {
    fn default() -> Self {
        Self::trace_as(tracing::Level::ERROR)
    }
}

impl<S, F> ConsumeErr<S, F, DefaultOutput> {
    /// Creates a new [`ConsumeErr`] service.
    pub const fn new(inner: S, f: F) -> Self {
        Self {
            f,
            inner,
            output: DefaultOutput,
        }
    }

    define_inner_service_accessors!();
}

impl<S, F> ConsumeErr<S, F, DefaultOutput> {
    /// Set an output to be used in case of errors,
    /// instead of requiring and using the [`Default::default`] implementation
    /// of the inner service's response type.
    pub fn with_output<R>(self, output: R) -> ConsumeErr<S, F, StaticOutput<R>> {
        ConsumeErr {
            f: self.f,
            inner: self.inner,
            output: StaticOutput(output),
        }
    }
}

impl<S> ConsumeErr<S, Trace, DefaultOutput> {
    /// Trace the error passed to this [`ConsumeErr`] service
    /// for the provided [`tracing::Level`].
    pub const fn trace_as(inner: S, level: tracing::Level) -> Self {
        Self::new(inner, Trace(level))
    }

    /// Creates a new [`ConsumeErr`] to trace the consumed error.
    /// at level [`tracing::Level::DEBUG`].
    #[must_use]
    #[inline]
    pub const fn trace_as_debug(inner: S) -> Self {
        Self::new(inner, Trace(tracing::Level::DEBUG))
    }

    /// Creates a new [`ConsumeErr`] to trace the consumed error.
    /// at level [`tracing::Level::INFO`].
    #[must_use]
    #[inline]
    pub const fn trace_as_info(inner: S) -> Self {
        Self::new(inner, Trace(tracing::Level::INFO))
    }

    /// Creates a new [`ConsumeErr`] to trace the consumed error.
    /// at level [`tracing::Level::WARN`].
    #[must_use]
    #[inline]
    pub const fn trace_as_warning(inner: S) -> Self {
        Self::new(inner, Trace(tracing::Level::WARN))
    }

    /// Creates a new [`ConsumeErr`] to trace the consumed error.
    /// at level [`tracing::Level::ERROR`].
    #[must_use]
    #[inline]
    pub const fn trace_as_err(inner: S) -> Self {
        Self::new(inner, Trace(tracing::Level::ERROR))
    }
}

impl<S, F, Input> Service<Input> for ConsumeErr<S, F, DefaultOutput>
where
    S: Service<Input, Output: Default>,
    F: Fn(S::Error) + Send + Sync + 'static,
    Input: Send + 'static,
{
    type Output = S::Output;
    type Error = Infallible;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(input).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                (self.f)(err);
                Ok(S::Output::default())
            }
        }
    }
}

impl<S, F, Input, R> Service<Input> for ConsumeErr<S, F, StaticOutput<R>>
where
    S: Service<Input>,
    F: Fn(S::Error) + Send + Sync + 'static,
    R: Into<S::Output> + Clone + Send + Sync + 'static,
    Input: Send + 'static,
{
    type Output = S::Output;
    type Error = Infallible;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(input).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                (self.f)(err);
                Ok(self.output.0.clone().into())
            }
        }
    }
}

impl<S, Input> Service<Input> for ConsumeErr<S, Trace, DefaultOutput>
where
    S: Service<Input, Output: Default, Error: Into<BoxError>>,
    Input: Send + 'static,
{
    type Output = S::Output;
    type Error = Infallible;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(input).await {
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
                Ok(S::Output::default())
            }
        }
    }
}

impl<S, Input, R> Service<Input> for ConsumeErr<S, Trace, StaticOutput<R>>
where
    S: Service<Input, Error: Into<BoxError>>,
    R: Into<S::Output> + Clone + Send + Sync + 'static,
    Input: Send + 'static,
{
    type Output = S::Output;
    type Error = Infallible;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(input).await {
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
                Ok(self.output.0.clone().into())
            }
        }
    }
}

impl<F> ConsumeErrLayer<F> {
    /// Creates a new [`ConsumeErrLayer`].
    pub const fn new(f: F) -> Self {
        Self {
            f,
            output: DefaultOutput,
        }
    }
}

impl ConsumeErrLayer<Trace> {
    /// Creates a new [`ConsumeErrLayer`] to trace the consumed error
    /// using the specified [`tracing::Level`].
    #[must_use]
    #[inline]
    pub const fn trace_as(level: tracing::Level) -> Self {
        Self::new(Trace(level))
    }

    /// Creates a new [`ConsumeErrLayer`] to trace the consumed error.
    /// at level [`tracing::Level::DEBUG`].
    #[must_use]
    #[inline]
    pub const fn trace_as_debug() -> Self {
        Self::new(Trace(tracing::Level::DEBUG))
    }

    /// Creates a new [`ConsumeErrLayer`] to trace the consumed error.
    /// at level [`tracing::Level::INFO`].
    #[must_use]
    #[inline]
    pub const fn trace_as_info() -> Self {
        Self::new(Trace(tracing::Level::INFO))
    }

    /// Creates a new [`ConsumeErrLayer`] to trace the consumed error.
    /// at level [`tracing::Level::WARN`].
    #[must_use]
    #[inline]
    pub const fn trace_as_warning() -> Self {
        Self::new(Trace(tracing::Level::WARN))
    }

    /// Creates a new [`ConsumeErrLayer`] to trace the consumed error.
    /// at level [`tracing::Level::ERROR`].
    #[must_use]
    #[inline]
    pub const fn trace_as_error() -> Self {
        Self::new(Trace(tracing::Level::ERROR))
    }
}

impl<F> ConsumeErrLayer<F, DefaultOutput> {
    /// Set a response to be used in case of errors,
    /// instead of requiring and using the [`Default::default`] implementation
    /// of the inner service's response type.
    pub fn with_response<R>(self, output: R) -> ConsumeErrLayer<F, StaticOutput<R>> {
        ConsumeErrLayer {
            f: self.f,
            output: StaticOutput(output),
        }
    }
}

impl<S, F, O> Layer<S> for ConsumeErrLayer<F, O>
where
    F: Clone,
    O: Clone,
{
    type Service = ConsumeErr<S, F, O>;

    fn layer(&self, inner: S) -> Self::Service {
        ConsumeErr {
            f: self.f.clone(),
            inner,
            output: self.output.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ConsumeErr {
            f: self.f,
            inner,
            output: self.output,
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
    /// A sealed type to indicate default output is to be used.
    pub struct DefaultOutput;

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    /// A sealed type to indicate static output is to be used.
    pub struct StaticOutput<R>(pub(super) R);
}
