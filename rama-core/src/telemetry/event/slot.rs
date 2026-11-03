use core::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use smallvec::SmallVec;
use tokio::time::Instant;

use super::{Emitted, Event, Listener};
use crate::std::sync::Arc;

// Inline for the common one or two entries, so emitting skips a heap hop.
pub(super) type Entries<L> = SmallVec<[(u64, Arc<L>); 2]>;

/// Removes an entry by the key its slot returned on insert, without the
/// caller knowing the entry type.
pub(super) trait Unsubscribe: Send + Sync {
    fn unsubscribe(&self, key: u64);
}

// The listeners of one event type, or the span adapters of one span type.
// Copy-on-write, so an entry can (un)subscribe or emit from inside its callback.
pub(super) struct Slot<L: ?Sized> {
    active: AtomicUsize,
    entries: ArcSwap<Entries<L>>,
    // Serializes insert and remove and holds the next key; emitting never
    // takes it.
    write: Mutex<u64>,
}

impl<L: ?Sized> Slot<L> {
    pub(super) fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            entries: ArcSwap::from_pointee(Entries::new()),
            write: Mutex::new(0),
        }
    }

    #[inline]
    pub(super) fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    #[inline]
    pub(super) fn is_active(&self) -> bool {
        self.active() != 0
    }

    pub(super) fn snapshot(&self) -> Arc<Entries<L>> {
        self.entries.load_full()
    }

    pub(super) fn insert(&self, entry: Arc<L>) -> u64 {
        let mut next_key = self.write.lock();
        let key = *next_key;
        *next_key += 1;
        let mut entries = (**self.entries.load()).clone();
        entries.push((key, entry));
        self.store(entries);
        key
    }

    // Callers hold the write lock, which serializes these two stores. An
    // emitter that reads the raised count with the old list finds no entry
    // and skips that one event.
    fn store(&self, entries: Entries<L>) {
        let active = entries.len();
        self.entries.store(Arc::new(entries));
        self.active.store(active, Ordering::Relaxed);
    }
}

impl<L: ?Sized + Send + Sync> Unsubscribe for Slot<L> {
    fn unsubscribe(&self, key: u64) {
        let removed = {
            let _write = self.write.lock();
            let entries = self.entries.load();
            let Some(index) = entries
                .iter()
                .position(|(registered, _)| *registered == key)
            else {
                return;
            };
            let mut entries = (**entries).clone();
            let removed = entries.remove(index);
            self.store(entries);
            removed
        };
        // Dropped after the lock: an entry's drop impl may subscribe again.
        drop(removed);
    }
}

impl<E: Event> Slot<dyn Listener<E>> {
    pub(super) fn emit_with(&self, event: impl FnOnce() -> E) {
        self.dispatch(None, event);
    }

    pub(super) fn emit_at(&self, at: Instant, event: impl FnOnce() -> E) {
        self.dispatch(Some(at), event);
    }

    pub(super) fn emit(&self, emitted: &Emitted<'_, E>) {
        if !self.is_active() {
            return;
        }
        for (_, listener) in self.entries.load().iter() {
            listener.on_event(emitted);
        }
    }

    #[inline]
    fn dispatch(&self, at: Option<Instant>, event: impl FnOnce() -> E) {
        if !self.is_active() {
            return;
        }
        let listeners = self.entries.load();
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
}
