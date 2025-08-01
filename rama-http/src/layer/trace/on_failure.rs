use super::{DEFAULT_ERROR_LEVEL, Latency};
use rama_core::telemetry::tracing::{Level, Span};
use rama_utils::latency::LatencyUnit;
use std::{fmt, time::Duration};

/// Trait used to tell [`Trace`] what to do when a request fails.
///
/// See the [module docs](../trace/index.html#on_failure) for details on exactly when the
/// `on_failure` callback is called.
///
/// [`Trace`]: super::Trace
pub trait OnFailure<FailureClass>: Send + Sync + 'static {
    /// Do the thing.
    ///
    /// `latency` is the duration since the request was received.
    ///
    /// `span` is the `tracing` [`Span`], corresponding to this request, produced by the closure
    /// passed to [`TraceLayer::make_span_with`]. It can be used to [record field values][record]
    /// that weren't known when the span was created.
    ///
    /// [`Span`]: https://docs.rs/tracing/latest/tracing/span/index.html
    /// [record]: https://docs.rs/tracing/latest/tracing/span/struct.Span.html#method.record
    /// [`TraceLayer::make_span_with`]: crate::layer::trace::TraceLayer::make_span_with
    fn on_failure(&self, failure_classification: FailureClass, latency: Duration, span: &Span);
}

impl<FailureClass> OnFailure<FailureClass> for () {
    #[inline]
    fn on_failure(&self, _: FailureClass, _: Duration, _: &Span) {}
}

impl<F, FailureClass> OnFailure<FailureClass> for F
where
    F: Fn(FailureClass, Duration, &Span) + Send + Sync + 'static,
{
    fn on_failure(&self, failure_classification: FailureClass, latency: Duration, span: &Span) {
        self(failure_classification, latency, span)
    }
}

/// The default [`OnFailure`] implementation used by [`Trace`].
///
/// [`Trace`]: super::Trace
#[derive(Clone, Debug)]
pub struct DefaultOnFailure {
    level: Level,
    latency_unit: LatencyUnit,
}

impl Default for DefaultOnFailure {
    fn default() -> Self {
        Self {
            level: DEFAULT_ERROR_LEVEL,
            latency_unit: LatencyUnit::Millis,
        }
    }
}

impl DefaultOnFailure {
    /// Create a new `DefaultOnFailure`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [`Level`] used for [tracing events].
    ///
    /// Defaults to [`Level::ERROR`].
    ///
    /// [tracing events]: https://docs.rs/tracing/latest/tracing/#events
    #[must_use]
    pub fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Set the [`Level`] used for [tracing events].
    ///
    /// Defaults to [`Level::ERROR`].
    ///
    /// [tracing events]: https://docs.rs/tracing/latest/tracing/#events
    pub fn set_level(&mut self, level: Level) -> &mut Self {
        self.level = level;
        self
    }

    /// Set the [`LatencyUnit`] latencies will be reported in.
    ///
    /// Defaults to [`LatencyUnit::Millis`].
    #[must_use]
    pub fn latency_unit(mut self, latency_unit: LatencyUnit) -> Self {
        self.latency_unit = latency_unit;
        self
    }

    /// Set the [`LatencyUnit`] latencies will be reported in.
    ///
    /// Defaults to [`LatencyUnit::Millis`].
    pub fn set_latency_unit(&mut self, latency_unit: LatencyUnit) -> &mut Self {
        self.latency_unit = latency_unit;
        self
    }
}

impl<FailureClass> OnFailure<FailureClass> for DefaultOnFailure
where
    FailureClass: fmt::Display,
{
    fn on_failure(&self, failure_classification: FailureClass, latency: Duration, _: &Span) {
        let latency = Latency {
            unit: self.latency_unit,
            duration: latency,
        };
        event_dynamic_lvl!(
            self.level,
            classification = %failure_classification,
            %latency,
            "response failed"
        );
    }
}
