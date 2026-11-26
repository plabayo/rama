use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use rama_core::telemetry::tracing::{
    Event, Level, Metadata, Subscriber, span, subscriber::with_default,
    test_utils::prepare_for_captures,
};

/// Counts warn-level events emitted on the current thread.
#[derive(Clone, Default)]
pub(super) struct WarnCapture(Arc<AtomicUsize>);

impl WarnCapture {
    pub(super) fn record<R>(&self, f: impl FnOnce() -> R) -> R {
        prepare_for_captures();
        with_default(self.clone(), f)
    }

    pub(super) fn warnings(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl Subscriber for WarnCapture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        if *event.metadata().level() == Level::WARN {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}
