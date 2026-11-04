//! Typed events and spans: a crate emits the facts it owns, listeners record
//! them.
//!
//! How events, spans and span adapters work is explained in the book:
//! <https://ramaproxy.org/book/intro/events.html>.

mod builder;
mod dispatcher;
mod emitted;
mod emitter;
mod id;
mod pool;
mod slot;
mod span;

#[cfg(test)]
mod tests;

pub use builder::{Listeners, SpanAdapters, Subscriptions};
pub use dispatcher::{EventDispatcher, Subscription};
pub use emitted::Emitted;
pub use emitter::Emitter;
pub use id::next_id;
pub use span::{Observed, OpenSpan, SpanAdapter, SpanEmitter, SpanFutureExt, SpanStart};

pub(crate) use dispatcher::inherit;

pub use rama_macros::{Event, SpanStart, isolated};

/// A fact some crate emits. Derive it with `#[derive(Event)]`.
pub trait Event: Clone + Send + 'static {
    /// The module the event type is defined in. Tracing listeners use it as
    /// their target, so all events of a module filter together.
    const MODULE: &'static str;
}

/// Something that acts on one event type. Any `Fn(&Emitted<E>)` is a listener.
///
/// A listener runs inline at the emit site, possibly while the emitting
/// component holds internal locks. It must be fast, never block, and never
/// call back into the component that emitted. Hand heavy work off.
pub trait Listener<E: Event>: Send + Sync + 'static {
    /// Act on one event.
    fn on_event(&self, event: &Emitted<'_, E>);
}

impl<E, F> Listener<E> for F
where
    E: Event,
    F: Fn(&Emitted<'_, E>) + Send + Sync + 'static,
{
    fn on_event(&self, event: &Emitted<'_, E>) {
        self(event);
    }
}
