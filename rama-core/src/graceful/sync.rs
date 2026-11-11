//! Synchronisation primitives, swapped for loom's in `cfg(rama_loom)` tests.

#[cfg(not(all(rama_loom, test)))]
pub(super) use {
    parking_lot::Mutex,
    std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering, fence},
    },
    std::thread_local,
    tokio::time::{Sleep, sleep_until},
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

#[cfg(all(rama_loom, test))]
pub(super) use timer::{Sleep, sleep_until};

/// A timer for loom models, in place of tokio's: it never elapses, and a model makes it ask
/// for a poll by hand, as any future may at any time.
#[cfg(all(rama_loom, test))]
pub(super) mod timer {
    use std::{
        cell::RefCell,
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    use tokio::time::Instant;

    use super::Mutex;

    pub(in super::super) struct Sleep {
        deadline: Instant,
        shared: std::sync::Arc<Mutex<Shared>>,
    }

    // Behind a lock: the model explores the wait, not this stand-in.
    #[derive(Default)]
    struct Shared {
        asked: bool,
        answered: bool,
        waker: Option<Waker>,
    }

    /// The timer a model asks for a poll.
    pub(in super::super) struct Handle(std::sync::Arc<Mutex<Shared>>);

    super::thread_local! {
        static LAST: RefCell<Option<std::sync::Arc<Mutex<Shared>>>> = RefCell::new(None);
    }

    pub(in super::super) fn sleep_until(deadline: Instant) -> Sleep {
        let shared = std::sync::Arc::new(Mutex::new(Shared::default()));
        LAST.with(|last| *last.borrow_mut() = Some(shared.clone()));
        Sleep { deadline, shared }
    }

    /// The timer made last on this thread.
    pub(in super::super) fn last() -> Option<Handle> {
        LAST.with(|last| last.borrow().clone()).map(Handle)
    }

    impl Sleep {
        pub(in super::super) fn deadline(&self) -> Instant {
            self.deadline
        }

        pub(in super::super) fn reset(mut self: Pin<&mut Self>, deadline: Instant) {
            self.deadline = deadline;
        }
    }

    impl Future for Sleep {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let waker = cx.waker().clone();
            let replaced = {
                let mut shared = self.shared.lock();
                // Answered by this poll; it has nothing to report, so it stays pending.
                shared.answered |= std::mem::take(&mut shared.asked);
                shared.waker.replace(waker)
            };
            drop(replaced);
            Poll::Pending
        }
    }

    impl Handle {
        /// Asks for a poll, as a timer that elapsed does: once per waker it was polled with.
        pub(in super::super) fn ask(&self) {
            let waker = {
                let mut shared = self.0.lock();
                shared.asked = true;
                shared.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        /// Whether it asked for a poll that it did not get yet.
        pub(in super::super) fn is_waiting(&self) -> bool {
            self.0.lock().asked
        }

        /// Whether it ever got a poll it asked for.
        pub(in super::super) fn was_answered(&self) -> bool {
            self.0.lock().answered
        }
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
