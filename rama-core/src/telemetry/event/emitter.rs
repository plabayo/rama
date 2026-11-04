use core::fmt;

use tokio::time::Instant;

use super::slot::Slot;
use super::{Emitted, Event, EventDispatcher, Listener};

/// Emits one event type. `Copy` and pointer sized: resolve it once in a
/// long-lived component and copy it into units. Resolving takes a lock shared
/// by all emitters, so do not resolve one per request or connection.
#[derive(Clone)]
pub struct Emitter<E: Event> {
    slot: &'static Slot<dyn Listener<E>>,
}

/// Manual since we dont require `E` to be Copy
impl<E: Event> Copy for Emitter<E> {}

impl<E: Event> Emitter<E> {
    /// Resolve an emitter from [`EventDispatcher::current`].
    #[must_use]
    pub fn new() -> Self {
        Self::from_dispatcher(&EventDispatcher::current())
    }

    /// Resolve an emitter from a specific dispatcher.
    #[must_use]
    pub fn from_dispatcher(dispatcher: &EventDispatcher) -> Self {
        Self {
            slot: dispatcher.slot::<E>(),
        }
    }

    /// Whether anyone listens to this event.
    ///
    /// Only needed to skip work that [`emit_with`](Self::emit_with) cannot skip
    /// for you, such as measuring something nobody reads.
    #[must_use]
    #[inline]
    pub fn is_active(self) -> bool {
        self.slot.is_active()
    }

    /// Emit an event, building it only when someone listens.
    #[inline]
    pub fn emit_with(self, event: impl FnOnce() -> E) {
        self.slot.emit_with(event);
    }

    /// Emit an event that happened at `at`, so listeners reading
    /// [`Emitted::at`](super::Emitted::at) get that time and no clock is read.
    #[inline]
    pub fn emit_at(self, at: Instant, event: impl FnOnce() -> E) {
        self.slot.emit_at(at, event);
    }

    pub(super) fn active(self) -> usize {
        self.slot.active()
    }

    pub(super) fn emit(self, emitted: &Emitted<'_, E>) {
        self.slot.emit(emitted);
    }
}

impl<E: Event> Default for Emitter<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Event> fmt::Debug for Emitter<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Emitter")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}
