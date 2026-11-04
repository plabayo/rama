use core::fmt;

use super::Span;
use crate::telemetry::event::{Emitted, SpanAdapter, SpanStart};

/// Carries rama spans over into tracing spans.
///
/// `make` builds the span, usually with the `trace_root_span!` macro, and
/// `on_close` records what only the end event knows. A span that tracing has
/// disabled is skipped.
pub struct TracingSpans<S: SpanStart> {
    make: fn(&S) -> Span,
    on_close: fn(&Span, &S::End),
}

impl<S: SpanStart> TracingSpans<S> {
    /// Open tracing spans with `make` and record their end with `on_close`.
    #[must_use]
    pub fn new(make: fn(&S) -> Span, on_close: fn(&Span, &S::End)) -> Self {
        Self { make, on_close }
    }
}

impl<S: SpanStart> SpanAdapter<S> for TracingSpans<S> {
    type State = Span;

    fn open(&self, start: &Emitted<'_, S>) -> Option<Span> {
        let span = (self.make)(start.event());
        (!span.is_disabled()).then_some(span)
    }

    fn enter(&self, span: &Span, poll: &mut dyn FnMut()) {
        span.in_scope(poll);
    }

    fn close(&self, span: Span, end: &Emitted<'_, S::End>) {
        (self.on_close)(&span, end.event());
    }
}

impl<S: SpanStart> fmt::Debug for TracingSpans<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TracingSpans").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::event;
    use crate::telemetry::event::{Event, EventDispatcher, SpanEmitter};
    use crate::telemetry::tracing::{Level, span};
    use tracing_subscriber::{
        filter::LevelFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _,
    };

    #[derive(Clone, Event, SpanStart)]
    #[span(end = Ended)]
    struct Started;

    #[derive(Clone, Event)]
    struct Ended;

    fn spans() -> TracingSpans<Started> {
        TracingSpans::new(
            |_: &Started| span!(target: "test", Level::INFO, "unit",),
            |span: &Span, _: &Ended| {
                span.record("done", true);
            },
        )
    }

    fn current_span_name() -> Option<&'static str> {
        Span::current().metadata().map(|metadata| metadata.name())
    }

    // Both subscribers run in one test: tracing caches a callsite's interest
    // process-wide, so a second test installing another subscriber could flip
    // it underneath this one.
    #[event::isolated]
    #[test]
    fn a_span_is_entered_around_the_work_and_only_when_enabled(dispatcher: EventDispatcher) {
        {
            let _subscriber = tracing_subscriber::registry()
                .with(LevelFilter::ERROR)
                .set_default();
            assert!(
                spans().open(&Emitted::new(&Started)).is_none(),
                "an INFO span is filtered"
            );
        }

        let _subscriber = tracing_subscriber::registry()
            .with(LevelFilter::TRACE)
            .set_default();

        let _adapter = dispatcher.add_span_adapter(spans());
        let span = SpanEmitter::<Started>::new().open_with(|| Started, || Ended);

        assert_eq!(span.observe_sync(current_span_name), Some("unit"));
        assert_eq!(current_span_name(), None, "the tracing span is left again");
    }
}
