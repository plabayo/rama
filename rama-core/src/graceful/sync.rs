//! Synchronisation primitives, swapped for loom's in `cfg(rama_loom)` tests.

#[cfg(not(all(rama_loom, test)))]
pub(super) use {
    parking_lot::Mutex,
    std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering, fence},
    },
    std::thread_local,
};

#[cfg(all(rama_loom, test))]
pub(super) use loom::thread_local;

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

/// A step of a composite observation: a loom model may switch threads there, and a test may
/// run its own code there; nothing outside tests.
#[cfg(not(test))]
#[inline(always)]
pub(super) fn yield_point() {}

#[cfg(test)]
pub(super) fn yield_point() {
    observation::run();
    #[cfg(rama_loom)]
    loom::thread::yield_now();
}

/// Code a test runs at each step of a composite observation on its thread, to place a racing
/// cancel at an exact step.
#[cfg(test)]
pub(super) mod observation {
    use std::cell::RefCell;

    type Hook = Box<dyn FnMut()>;

    super::thread_local! {
        static HOOK: RefCell<Option<Hook>> = RefCell::new(None);
    }

    /// Runs `hook` at every step on this thread until it is replaced.
    pub(in super::super) fn set(hook: Option<Hook>) {
        HOOK.with(|slot| *slot.borrow_mut() = hook);
    }

    pub(super) fn run() {
        // Taken while it runs, so code it runs may observe composites too.
        let Some(mut hook) = HOOK.with(|slot| slot.borrow_mut().take()) else {
            return;
        };
        hook();
        HOOK.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(hook);
            }
        });
    }
}
