use core::fmt;

use super::{Operation, Outcome};
use crate::telemetry::event::{Emitted, SpanAdapter, SpanStart};

/// Carries rama spans over into dial9 operations.
///
/// `outcome` reads from the end event what dial9 needs to finish the
/// operation: its outcome and the bytes sent and received at this boundary.
/// With no recorder attached no operation is started and the span is skipped.
pub struct Dial9Operations<S: SpanStart> {
    name: &'static str,
    outcome: fn(&S::End) -> (Outcome, u64, u64),
}

impl<S: SpanStart> Dial9Operations<S> {
    /// Record operations called `name`, reading their end with `outcome`.
    #[must_use]
    pub fn new(name: &'static str, outcome: fn(&S::End) -> (Outcome, u64, u64)) -> Self {
        Self { name, outcome }
    }
}

impl<S: SpanStart> SpanAdapter<S> for Dial9Operations<S> {
    type State = Operation;

    fn open(&self, _start: &Emitted<'_, S>) -> Option<Operation> {
        let operation = Operation::new(self.name);
        operation.is_recorded().then_some(operation)
    }

    fn enter(&self, operation: &Operation, poll: &mut dyn FnMut()) {
        operation.context().scope_sync(poll);
    }

    fn close(&self, operation: Operation, end: &Emitted<'_, S::End>) {
        let (outcome, sent, received) = (self.outcome)(end.event());
        operation.finish_with_bytes(outcome, sent, received);
    }
}

impl<S: SpanStart> fmt::Debug for Dial9Operations<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dial9Operations")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::event;
    use crate::telemetry::event::{Event, EventDispatcher, SpanEmitter, SpanStart};

    #[derive(Clone, Event, SpanStart)]
    #[span(end = Ended)]
    struct Started;

    #[derive(Clone, Event)]
    struct Ended;

    fn operations() -> Dial9Operations<Started> {
        Dial9Operations::new("test.operation", |_: &Ended| (Outcome::Success, 1, 2))
    }

    #[test]
    fn without_a_recorder_no_operation_is_started() {
        assert!(operations().open(&Emitted::new(&Started)).is_none());
    }

    #[event::isolated]
    #[test]
    fn a_span_without_a_recorder_still_runs_its_work(dispatcher: EventDispatcher) {
        let _adapter = dispatcher.add_span_adapter(operations());
        let emitter = SpanEmitter::<Started>::new();

        let span = emitter.open_with(|| Started, || Ended);
        assert!(span.observe_sync(|| true));
    }
}
