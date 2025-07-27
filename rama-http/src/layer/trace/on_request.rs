use super::DEFAULT_MESSAGE_LEVEL;
use crate::Request;
use rama_core::telemetry::tracing::{Level, Span};

/// Trait used to tell [`Trace`] what to do when a request is received.
///
/// See the [module docs](../trace/index.html#on_request) for details on exactly when the
/// `on_request` callback is called.
///
/// [`Trace`]: super::Trace
pub trait OnRequest<B>: Send + Sync + 'static {
    /// Do the thing.
    ///
    /// `span` is the `tracing` [`Span`], corresponding to this request, produced by the closure
    /// passed to [`TraceLayer::make_span_with`]. It can be used to [record field values][record]
    /// that weren't known when the span was created.
    ///
    /// [`Span`]: https://docs.rs/tracing/latest/tracing/span/index.html
    /// [record]: https://docs.rs/tracing/latest/tracing/span/struct.Span.html#method.record
    /// [`TraceLayer::make_span_with`]: crate::layer::trace::TraceLayer::make_span_with
    fn on_request(&self, request: &Request<B>, span: &Span);
}

impl<B> OnRequest<B> for () {
    #[inline]
    fn on_request(&self, _: &Request<B>, _: &Span) {}
}

impl<B, F> OnRequest<B> for F
where
    F: Fn(&Request<B>, &Span) + Send + Sync + 'static,
{
    fn on_request(&self, request: &Request<B>, span: &Span) {
        self(request, span)
    }
}

/// The default [`OnRequest`] implementation used by [`Trace`].
///
/// [`Trace`]: super::Trace
#[derive(Clone, Debug)]
pub struct DefaultOnRequest {
    level: Level,
}

impl Default for DefaultOnRequest {
    fn default() -> Self {
        Self {
            level: DEFAULT_MESSAGE_LEVEL,
        }
    }
}

impl DefaultOnRequest {
    /// Create a new `DefaultOnRequest`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [`Level`] used for [tracing events].
    ///
    /// Please note that while this will set the level for the tracing events
    /// themselves, it might cause them to lack expected information, like
    /// request method or path. You can address this using
    /// [`DefaultMakeSpan::level`].
    ///
    /// Defaults to [`Level::DEBUG`].
    ///
    /// [tracing events]: https://docs.rs/tracing/latest/tracing/#events
    /// [`DefaultMakeSpan::level`]: crate::layer::trace::DefaultMakeSpan::level
    #[must_use]
    pub fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Set the [`Level`] used for [tracing events].
    ///
    /// Please note that while this will set the level for the tracing events
    /// themselves, it might cause them to lack expected information, like
    /// request method or path. You can address this using
    /// [`DefaultMakeSpan::level`].
    ///
    /// Defaults to [`Level::DEBUG`].
    ///
    /// [tracing events]: https://docs.rs/tracing/latest/tracing/#events
    /// [`DefaultMakeSpan::level`]: crate::layer::trace::DefaultMakeSpan::level
    pub fn set_level(&mut self, level: Level) -> &mut Self {
        self.level = level;
        self
    }
}

impl<B> OnRequest<B> for DefaultOnRequest {
    fn on_request(&self, _: &Request<B>, _: &Span) {
        event_dynamic_lvl!(self.level, "started processing request");
    }
}
