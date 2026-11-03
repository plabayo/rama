//! Typed events: a crate emits the facts it owns, listeners record them.
//!
//! A crate defines a struct per fact, derives [`Event`] and emits it through an
//! [`Emitter`]. Listeners subscribe per event type on an [`EventDispatcher`].
//! There is one per process ([`EventDispatcher::global`]), plus an override for
//! tests ([`EventDispatcher::scope`]) that follows rama spawns.
//!
//! Events are for side effects only: a listener can not change the flow. If
//! something must act on a fact to change behavior, it is not an event.
//!
//! All events of a type reach all its listeners, so an event must say what it
//! belongs to: the typed id of its unit, and of the bigger unit it lives in (a
//! request carries its connection). The event that starts a unit carries what
//! listeners filter on, later events carry only ids.

mod dispatcher;
mod emitted;
mod emitter;
mod id;
mod slot;

#[cfg(test)]
mod tests;

pub use dispatcher::{EventDispatcher, Subscription};
pub use emitted::Emitted;
pub use emitter::Emitter;
pub use id::next_id;

pub(crate) use dispatcher::inherit;

pub use rama_macros::{Event, isolated};

/// A fact some crate emits. Derive it with `#[derive(Event)]`.
pub trait Event: Clone + Send + 'static {}

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
