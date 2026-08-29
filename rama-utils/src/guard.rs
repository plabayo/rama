//! Scope guards for synchronous cleanup on every return path.

/// Runs a closure exactly once when fired explicitly or when dropped while armed.
#[must_use = "dropping an armed DropGuard invokes its callback"]
pub struct DropGuard<F: FnOnce()> {
    callback: Option<F>,
}

impl<F: FnOnce()> DropGuard<F> {
    /// Create an armed guard.
    #[inline]
    pub const fn new(callback: F) -> Self {
        Self {
            callback: Some(callback),
        }
    }

    /// Prevent the callback from running.
    #[inline]
    pub fn disarm(&mut self) {
        self.callback = None;
    }

    /// Run the callback now. Dropping the guard afterward is a no-op.
    #[inline]
    pub fn fire(&mut self) {
        if let Some(callback) = self.callback.take() {
            callback();
        }
    }

    /// Return whether the callback is still armed.
    #[inline]
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.callback.is_some()
    }
}

impl<F: FnOnce()> Drop for DropGuard<F> {
    #[inline]
    fn drop(&mut self) {
        self.fire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn fires_once_on_drop() {
        let calls = AtomicUsize::new(0);
        drop(DropGuard::new(|| {
            calls.fetch_add(1, Ordering::Relaxed);
        }));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn explicit_fire_is_exactly_once() {
        let calls = AtomicUsize::new(0);
        let mut guard = DropGuard::new(|| {
            calls.fetch_add(1, Ordering::Relaxed);
        });
        assert!(guard.is_armed());
        guard.fire();
        assert!(!guard.is_armed());
        drop(guard);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn disarm_suppresses_callback() {
        let calls = AtomicUsize::new(0);
        let mut guard = DropGuard::new(|| {
            calls.fetch_add(1, Ordering::Relaxed);
        });
        guard.disarm();
        drop(guard);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}
