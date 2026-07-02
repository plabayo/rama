//! A lock-free-read value paired with a race-free change signal.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::watch;

/// A value that can be stored in a [`Reactive`] as a `usize`.
pub trait ReactiveRepr: Copy {
    /// Encode the value into the backing `usize`.
    fn to_usize(self) -> usize;
    /// Decode the value from the backing `usize`.
    fn from_usize(value: usize) -> Self;
}

impl ReactiveRepr for usize {
    #[inline]
    fn to_usize(self) -> usize {
        self
    }
    #[inline]
    fn from_usize(value: usize) -> Self {
        value
    }
}

/// A [`ReactiveRepr`] value with **lock-free reads** and a **race-free typed
/// change signal**.
///
/// [`Reactive::get`] is a plain atomic load. [`Reactive::watch`] hands out a
/// [`Changed`] whose [`Changed::changed`] awaits the next change and returns the
/// new value. tokio's `watch` handles the wakeup race, versioning, and multiple
/// independent subscribers.
///
/// The value is held in the atomic (for lock-free reads) *and* carried on the
/// `watch` (so `changed()` can return it without a separate read). `set` stores
/// the atomic and then `send`s, which is a no-op when nobody is subscribed, so
/// an idle value costs nothing beyond the atomic store.
#[derive(Debug)]
pub struct Reactive<T> {
    value: AtomicUsize,
    signal: watch::Sender<usize>,
    _repr: PhantomData<fn() -> T>,
}

impl<T: ReactiveRepr> Reactive<T> {
    /// Create a new [`Reactive`] holding `value`.
    #[must_use]
    pub fn new(value: T) -> Self {
        let bits = value.to_usize();
        // Drop the initial receiver: no watchers until someone calls `watch`.
        let (signal, _) = watch::channel(bits);
        Self {
            value: AtomicUsize::new(bits),
            signal,
            _repr: PhantomData,
        }
    }

    /// Read the current value (lock-free).
    #[must_use]
    pub fn get(&self) -> T {
        T::from_usize(self.value.load(Ordering::Acquire))
    }

    /// Store `value` and wake watchers.
    pub fn set(&self, value: T) {
        let bits = value.to_usize();
        // Publish to the atomic first (lock-free reads see it immediately), then
        // signal. `send` is a no-op when there are no watchers, so an idle value
        // pays only the atomic store.
        self.value.store(bits, Ordering::Release);
        // `send` errors only when there are no receivers, that's the idle case we
        // intentionally treat as a no-op.
        let _unused = self.signal.send(bits);
    }

    /// Subscribe to changes. Hold the returned [`Changed`] and loop
    /// [`Changed::changed`] to observe every change, its `watch` cursor is
    /// persistent, so no edge is missed (unlike re-subscribing per await).
    #[must_use]
    pub fn watch(&self) -> Changed<T> {
        Changed {
            rx: self.signal.subscribe(),
            _repr: PhantomData,
        }
    }
}

impl<T: ReactiveRepr + Default> Default for Reactive<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// Change subscription handed out by [`Reactive::watch`].
///
/// Holds a persistent `watch` cursor, so looping [`Changed::changed`] observes
/// every change (coalescing to the latest value) without missing edges.
#[derive(Debug, Clone)]
pub struct Changed<T> {
    rx: watch::Receiver<usize>,
    _repr: PhantomData<fn() -> T>,
}

impl<T: ReactiveRepr> Changed<T> {
    /// Wait for the next change and return the new value. Returns `None` once the
    /// source [`Reactive`] is gone (all references dropped), so a forwarding loop
    /// can terminate.
    pub async fn changed(&mut self) -> Option<T> {
        self.rx.changed().await.ok()?;
        Some(T::from_usize(*self.rx.borrow_and_update()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn get_set_roundtrip() {
        let r = Reactive::<usize>::new(3);
        assert_eq!(r.get(), 3);
        r.set(7);
        assert_eq!(r.get(), 7);
    }

    #[tokio::test]
    async fn changed_yields_the_new_value() {
        let r = Arc::new(Reactive::<usize>::new(0));
        let mut w = r.watch();

        let handle = tokio::spawn(async move { w.changed().await });

        // give the watcher a chance to park, then change the value
        tokio::task::yield_now().await;
        r.set(42);

        assert_eq!(handle.await.unwrap(), Some(42));
    }

    #[tokio::test]
    async fn changed_returns_none_once_source_dropped() {
        let r = Reactive::<usize>::new(0);
        let mut w = r.watch();
        drop(r);
        assert_eq!(
            w.changed().await,
            None,
            "no source left: should report closed"
        );
    }

    #[tokio::test]
    async fn set_without_watchers_is_a_noop_send() {
        // No watcher subscribed: `set` must still update the value (via the
        // atomic) without erroring or blocking.
        let r = Reactive::<usize>::new(1);
        r.set(2);
        assert_eq!(r.get(), 2);
        // A watcher subscribing afterwards sees the current value and future changes.
        let mut w = r.watch();
        r.set(3);
        assert_eq!(w.changed().await, Some(3));
    }
}
