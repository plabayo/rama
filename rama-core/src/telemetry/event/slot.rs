use core::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use smallvec::SmallVec;
use tokio::time::Instant;

use super::{Emitted, Event, Listener};
use crate::std::sync::Arc;

pub(super) type Registered<E> = Arc<dyn Listener<E>>;

// Inline for the common one or two listeners, so emitting skips a heap hop.
type Listeners<E> = SmallVec<[(u64, Registered<E>); 2]>;

/// Removes a listener by the key its slot returned on insert, without the
/// caller knowing the event type.
pub(super) trait Unsubscribe: Send + Sync {
    fn unsubscribe(&self, key: u64);
}

// Copy-on-write, so a listener can subscribe or emit from inside its callback.
pub(super) struct Slot<E: Event> {
    active: AtomicUsize,
    listeners: ArcSwap<Listeners<E>>,
    // Serializes insert and remove and holds the next listener key; emitting
    // never takes it.
    write: Mutex<u64>,
}

impl<E: Event> Slot<E> {
    pub(super) fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            listeners: ArcSwap::from_pointee(Listeners::new()),
            write: Mutex::new(0),
        }
    }

    #[inline]
    pub(super) fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed) != 0
    }

    pub(super) fn emit_with(&self, event: impl FnOnce() -> E) {
        self.dispatch(None, event);
    }

    pub(super) fn emit_at(&self, at: Instant, event: impl FnOnce() -> E) {
        self.dispatch(Some(at), event);
    }

    #[inline]
    fn dispatch(&self, at: Option<Instant>, event: impl FnOnce() -> E) {
        if !self.is_active() {
            return;
        }
        let listeners = self.listeners.load();
        if listeners.is_empty() {
            return;
        }

        let event = event();
        let emitted = match at {
            Some(at) => Emitted::at_time(&event, at),
            None => Emitted::new(&event),
        };
        for (_, listener) in listeners.iter() {
            listener.on_event(&emitted);
        }
    }

    pub(super) fn insert(&self, listener: Registered<E>) -> u64 {
        let mut next_key = self.write.lock();
        let key = *next_key;
        *next_key += 1;
        let mut listeners = (**self.listeners.load()).clone();
        listeners.push((key, listener));
        self.store(listeners);
        key
    }

    // Callers hold the write lock, which serializes these two stores. An
    // emitter that reads the raised count with the old list finds no listener
    // and skips that one event.
    fn store(&self, listeners: Listeners<E>) {
        let active = listeners.len();
        self.listeners.store(Arc::new(listeners));
        self.active.store(active, Ordering::Relaxed);
    }
}

impl<E: Event> Unsubscribe for Slot<E> {
    fn unsubscribe(&self, key: u64) {
        let removed = {
            let _write = self.write.lock();
            let listeners = self.listeners.load();
            let Some(index) = listeners
                .iter()
                .position(|(registered, _)| *registered == key)
            else {
                return;
            };
            let mut listeners = (**listeners).clone();
            let removed = listeners.remove(index);
            self.store(listeners);
            removed
        };
        // Dropped after the lock: a listener drop impl may subscribe again.
        drop(removed);
    }
}
