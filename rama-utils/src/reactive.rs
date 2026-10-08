//! A lock-free-read value paired with a race-free change signal.

use smallvec::SmallVec;
use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::{Notify, watch};

#[cfg(not(all(loom, test)))]
use {
    parking_lot::Mutex,
    std::sync::atomic::{AtomicBool, fence},
};

#[cfg(all(loom, test))]
use loom::sync::atomic::{AtomicBool, fence};

#[cfg(all(loom, test))]
struct Mutex<T>(loom::sync::Mutex<T>);

#[cfg(all(loom, test))]
impl<T> Mutex<T> {
    fn new(value: T) -> Self {
        Self(loom::sync::Mutex::new(value))
    }

    fn lock(&self) -> loom::sync::MutexGuard<'_, T> {
        self.0.lock().unwrap()
    }
}

/// Woken, without a value, after a source it subscribed to changed.
///
/// The source calls it synchronously from whatever changed it, possibly under
/// the source's own locks: only wake, never block or call into the source.
pub trait ChangeListener: Send + Sync {
    /// The source changed.
    fn changed(&self);
}

/// Wakes the tasks waiting at this moment, as [`Notify::notify_waiters`].
impl ChangeListener for Notify {
    fn changed(&self) {
        self.notify_waiters();
    }
}

/// The listeners of one source, woken on every change.
///
/// Listeners are held weakly: subscribing never keeps a listener alive, and
/// dropped ones are pruned. Waking allocates nothing for up to four live
/// listeners, and a source without listeners pays a fence and an atomic load.
pub struct ChangeSignal {
    listening: AtomicBool,
    listeners: Mutex<SmallVec<[Weak<dyn ChangeListener>; 2]>>,
}

impl Default for ChangeSignal {
    fn default() -> Self {
        Self {
            listening: AtomicBool::new(false),
            listeners: Mutex::new(SmallVec::new()),
        }
    }
}

impl ChangeSignal {
    /// Create a signal without listeners.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wake `listener` after every later change, until it is dropped.
    ///
    /// A change made before this returns is seen by a check of the source
    /// after it, or wakes `listener`.
    pub fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
        {
            let mut listeners = self.listeners.lock();
            // Prune before growing, so repeated subscribers never pile up.
            if listeners.len() == listeners.capacity() {
                listeners.retain(|listener| listener.strong_count() > 0);
            }
            listeners.push(listener);
            self.listening.store(true, Ordering::Relaxed);
        }
        // Pairs with the fence in `notify`: of a change and a subscription
        // racing, one sees the other.
        fence(Ordering::SeqCst);
    }

    /// Wake every live listener. Call after changing the source.
    pub fn notify(&self) {
        // See `subscribe`.
        fence(Ordering::SeqCst);
        if !self.listening.load(Ordering::Relaxed) {
            return;
        }
        let mut live: SmallVec<[Arc<dyn ChangeListener>; 4]> = SmallVec::new();
        {
            let mut listeners = self.listeners.lock();
            listeners.retain(|listener| match listener.upgrade() {
                Some(listener) => {
                    live.push(listener);
                    true
                }
                None => false,
            });
            self.listening
                .store(!listeners.is_empty(), Ordering::Relaxed);
        }
        // Outside the lock: a listener may subscribe again while woken.
        for listener in live {
            listener.changed();
        }
    }
}

/// A source going away is its last change: listeners wake to see it.
impl Drop for ChangeSignal {
    fn drop(&mut self) {
        self.notify();
    }
}

impl fmt::Debug for ChangeSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangeSignal")
            .field("listeners", &self.listeners.lock().len())
            .finish()
    }
}

/// A [`ChangeListener`] that one task awaits: see [`Self::wait`].
#[derive(Debug, Default)]
pub struct ChangeWaiter {
    notify: Notify,
}

impl ChangeWaiter {
    /// Create a waiter to subscribe before checking the state it waits for.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// The waiter as a listener to subscribe.
    #[must_use]
    pub fn listener(self: &Arc<Self>) -> Weak<dyn ChangeListener> {
        let weak: Weak<Self> = Arc::downgrade(self);
        weak
    }

    /// Wait for a change since this waiter subscribed, or since the last wait.
    pub async fn wait(&self) {
        self.notify.notified().await;
    }
}

impl ChangeListener for ChangeWaiter {
    fn changed(&self) {
        // A stored permit: a change before the wait starts is not lost.
        self.notify.notify_one();
    }
}

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
    changes: ChangeSignal,
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
            changes: ChangeSignal::new(),
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
        self.changes.notify();
    }

    /// Wake `listener` after every later [`Self::set`], without a task or an
    /// allocation per change: see [`ChangeSignal`].
    pub fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
        self.changes.subscribe(listener);
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

#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;
    use loom::{sync::atomic::AtomicUsize, thread};

    struct Flag(AtomicBool);

    impl ChangeListener for Flag {
        fn changed(&self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Subscribe-then-check: a change racing the first subscription is
    /// either seen by the check or wakes the listener.
    #[test]
    fn a_first_subscriber_never_misses_a_concurrent_change() {
        loom::model(|| {
            let signal = Arc::new(ChangeSignal::new());
            let source = Arc::new(AtomicUsize::new(0));
            let listener = Arc::new(Flag(AtomicBool::new(false)));
            let producer = {
                let (signal, source) = (signal.clone(), source.clone());
                thread::spawn(move || {
                    source.store(1, Ordering::Release);
                    signal.notify();
                })
            };
            signal.subscribe(Arc::downgrade(&listener) as Weak<dyn ChangeListener>);
            let seen = source.load(Ordering::Acquire);
            producer.join().unwrap();
            assert!(
                seen == 1 || listener.0.load(Ordering::SeqCst),
                "the change was neither seen nor signalled"
            );
        });
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

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

    /// A subscription observes a `set` made after `watch()` but before the
    /// first `changed()` poll. Waiters that subscribe-then-check rely on this
    /// (e.g. the multiplex connection pool's `MaxConcurrency` watch): with it,
    /// a change is either seen by the check or wakes the watcher — never lost.
    #[tokio::test]
    async fn set_after_subscribe_is_seen_at_first_poll() {
        let r = Reactive::<usize>::new(1);
        let mut w = r.watch();
        r.set(2);
        assert_eq!(w.changed().await, Some(2));
    }

    #[derive(Default)]
    struct Count(AtomicUsize);

    impl ChangeListener for Count {
        fn changed(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn subscribed_listeners_are_woken_until_dropped() {
        let r = Reactive::<usize>::new(0);
        let first = Arc::new(Count::default());
        let second = Arc::new(Count::default());
        r.subscribe(Arc::downgrade(&first) as Weak<dyn ChangeListener>);
        r.subscribe(Arc::downgrade(&second) as Weak<dyn ChangeListener>);
        r.set(1);
        drop(second);
        r.set(2);
        assert_eq!(first.0.load(Ordering::Relaxed), 2);
        assert_eq!(
            r.changes.listeners.lock().len(),
            1,
            "dropped listeners are pruned"
        );
    }

    #[test]
    fn repeated_subscriptions_do_not_pile_up() {
        let signal = ChangeSignal::new();
        let kept = Arc::new(Count::default());
        signal.subscribe(Arc::downgrade(&kept) as Weak<dyn ChangeListener>);
        for _ in 0..1000 {
            let waiter = ChangeWaiter::new();
            signal.subscribe(waiter.listener());
        }
        assert!(signal.listeners.lock().len() <= 2);
        signal.notify();
        assert_eq!(kept.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_listener_may_subscribe_again_while_woken() {
        struct Resubscribe(Arc<ChangeSignal>, Weak<Self>, AtomicUsize);

        impl ChangeListener for Resubscribe {
            fn changed(&self) {
                self.2.fetch_add(1, Ordering::Relaxed);
                self.0.subscribe(self.1.clone() as Weak<dyn ChangeListener>);
            }
        }

        let signal = Arc::new(ChangeSignal::new());
        let listener =
            Arc::new_cyclic(|weak| Resubscribe(signal.clone(), weak.clone(), AtomicUsize::new(0)));
        signal.subscribe(Arc::downgrade(&listener) as Weak<dyn ChangeListener>);
        signal.notify();
        signal.notify();
        assert!(listener.2.load(Ordering::Relaxed) >= 2);
    }

    #[tokio::test]
    async fn a_notify_listener_wakes_every_waiting_task() {
        let notify = Arc::new(Notify::new());
        let signal = ChangeSignal::new();
        signal.subscribe(Arc::downgrade(&notify) as Weak<dyn ChangeListener>);
        let mut first = Box::pin(notify.notified());
        let mut second = Box::pin(notify.notified());
        first.as_mut().enable();
        second.as_mut().enable();
        signal.notify();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            first.await;
            second.await;
        })
        .await
        .expect("a change wakes every task that waits");
    }

    #[test]
    fn dropping_the_source_wakes_its_listeners() {
        let r = Reactive::<usize>::new(0);
        let listener = Arc::new(Count::default());
        r.subscribe(Arc::downgrade(&listener) as Weak<dyn ChangeListener>);
        drop(r);
        assert_eq!(listener.0.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_change_before_the_wait_is_not_lost() {
        let r = Reactive::<usize>::new(0);
        let waiter = ChangeWaiter::new();
        r.subscribe(waiter.listener());
        r.set(1);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter.wait())
            .await
            .expect("the change woke the waiter");
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
