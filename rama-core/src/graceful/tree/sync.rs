//! Synchronisation primitives, swapped for loom's in `cfg(rama_loom)` tests.

#[cfg(not(all(rama_loom, test)))]
pub(super) use {
    parking_lot::Mutex,
    std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering, fence},
    },
};

#[cfg(all(rama_loom, test))]
pub(super) use loom::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering, fence},
};

#[cfg(all(rama_loom, test))]
pub(super) struct Mutex<T>(loom::sync::Mutex<T>);

#[cfg(all(rama_loom, test))]
impl<T> Mutex<T> {
    pub(super) fn new(value: T) -> Self {
        Self(loom::sync::Mutex::new(value))
    }

    pub(super) fn lock(&self) -> loom::sync::MutexGuard<'_, T> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn try_lock(&self) -> Option<loom::sync::MutexGuard<'_, T>> {
        self.0.try_lock().ok()
    }
}

#[cfg(all(rama_loom, test))]
impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}
