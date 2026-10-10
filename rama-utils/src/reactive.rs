//! A lock-free-read value paired with a race-free change signal.

use smallvec::SmallVec;
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use tokio::sync::{Notify, watch};

#[cfg(not(all(loom, test)))]
use {
    atomic_waker::AtomicWaker,
    parking_lot::Mutex,
    std::sync::atomic::{AtomicBool, AtomicUsize, fence},
};

#[cfg(all(loom, test))]
use loom::sync::atomic::{AtomicBool, AtomicUsize, fence};

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

#[cfg(all(loom, test))]
impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// A waker slot loom can model, in place of the lock-free one.
#[cfg(all(loom, test))]
struct AtomicWaker(Mutex<Option<std::task::Waker>>);

#[cfg(all(loom, test))]
impl AtomicWaker {
    fn new() -> Self {
        Self(Mutex::new(None))
    }

    fn register(&self, waker: &std::task::Waker) {
        *self.0.lock() = Some(waker.clone());
    }

    fn wake(&self) {
        let waker = self.0.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// Woken, without a value, after a source it subscribed to changed.
///
/// The source calls it synchronously from whatever changed it, possibly under
/// the source's own locks: only wake, never block or call into the source.
pub trait ChangeListener: Send + Sync {
    /// The source changed.
    fn changed(&self, change: Change);
}

/// What changed at a source, so a listener wakes as many waiters as can use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// One unit of what the source counts came free, such as a stream slot.
    Freed,
    /// Anything else, by an amount the source does not count: a limit, a
    /// state, the source going away.
    Other,
}

/// Wakes the tasks waiting at this moment, as [`Notify::notify_waiters`].
impl ChangeListener for Notify {
    fn changed(&self, _: Change) {
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

    /// Wake every live listener with `change`. Call after changing the source.
    pub fn notify(&self, change: Change) {
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
            listener.changed(change);
        }
    }
}

/// A source going away is its last change: listeners wake to see it.
impl Drop for ChangeSignal {
    fn drop(&mut self) {
        self.notify(Change::Other);
    }
}

impl fmt::Debug for ChangeSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangeSignal")
            .field("listeners", &self.listeners.lock().len())
            .finish()
    }
}

/// Parties waiting, in arrival order, for capacity that others free.
///
/// A [`Party`] queues a [`Waiter`] with [`Self::push`] before it checks the
/// capacity it waits for; whoever frees capacity calls [`Self::wake_one`] for one
/// unit, or [`Self::wake_all`] for a change of unknown size, after freeing it.
/// Both sides fence, so of a waiter queuing and capacity freeing at once, one
/// sees the other. Every unit reaches a waiter, which spends it on a look or, as
/// it leaves, passes it on in this queue. A leaf lock: nothing else is taken
/// while it is held.
///
/// Capacity several queues contend for goes to the oldest of their fronts: a
/// party leaving it to an older waiter of another queue [gives way](Self::give_way)
/// to it.
pub struct WaitQueue {
    queue: Mutex<Queued>,
    len: AtomicUsize,
}

#[derive(Default)]
struct Queued {
    waiters: VecDeque<Waiter>,
    /// Parties that gave way to a waiter here, and their queues.
    gave_way: Vec<GaveWay>,
}

/// A party gave way, with its place `giver`, to the waiter of order `to`.
struct GaveWay {
    to: u64,
    giver: WeakWaiter,
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self {
            queue: Mutex::new(Queued::default()),
            len: AtomicUsize::new(0),
        }
    }
}

impl WaitQueue {
    /// Create an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue `waiter` behind the older parties. Check the capacity it waits for
    /// after.
    pub fn push(&self, waiter: &Waiter) {
        {
            let mut queue = self.queue.lock();
            let waiters = &mut queue.waiters;
            // Mostly the back: a party queuing late goes ahead of younger ones.
            let at = waiters
                .iter()
                .rposition(|queued| queued.party.order <= waiter.party.order)
                .map_or(0, |at| at + 1);
            waiters.insert(at, waiter.clone());
            self.len.store(waiters.len(), Ordering::Relaxed);
        }
        // Pairs with the fence in `wake_*`: see the type's docs.
        fence(Ordering::SeqCst);
    }

    /// Leave the queue, returning the wakes it sent the waiter that are not
    /// spent: capacity they stand for and the waiter does not use is left to
    /// the others, so pass it on. Queues whose parties gave way to the waiter
    /// get a wake.
    ///
    /// A party freeing capacity meets the leave under the queue's lock: it
    /// wakes the waiter before, or reports nobody waiting after.
    pub fn remove(&self, waiter: &Waiter) -> usize {
        let (held, gave_way) = {
            let mut queue = self.queue.lock();
            // Mostly the front: served waiters leave in arrival order.
            let Some(at) = queue.waiters.iter().position(|queued| queued.is(waiter)) else {
                return 0;
            };
            queue.waiters.remove(at);
            self.len.store(queue.waiters.len(), Ordering::Relaxed);
            let order = waiter.party.order;
            let gave_way: SmallVec<[WeakWaiter; 2]> = queue
                .gave_way
                .extract_if(.., |gave| gave.to == order)
                .map(|gave| gave.giver)
                .collect();
            // Under the lock: no wake of this queue reaches the waiter after.
            // Leaving before those it gave way to, its turn is its queue's: a
            // wake to pass on, read with its wakes, so a turn handed back
            // meanwhile is one or the other.
            (waiter.leave(), gave_way)
        };
        // Outside the lock, which is a leaf: each party that gave way and
        // still waits looks again, its turn handed back.
        for giver in gave_way.iter().filter_map(WeakWaiter::upgrade) {
            giver.hand_back_turn();
        }
        held
    }

    /// Whether a waiter older than `than` waits here, for capacity the party of
    /// `giver`, its place in another queue, contends for too: that party gives
    /// way to it. The waiter is woken to look, if it holds no wake, and `giver`
    /// once it leaves, if its party still waits: atomic with the leave, so that
    /// wake is not lost.
    pub fn give_way(&self, than: u64, giver: &Waiter) -> bool {
        if self.is_empty() {
            return false;
        }
        let mut queued = self.queue.lock();
        let Some(front) = queued
            .waiters
            .front()
            .filter(|front| front.party.order < than)
            .cloned()
        else {
            return false;
        };
        let to = front.party.order;
        let gave_way = &mut queued.gave_way;
        if !gave_way
            .iter()
            .any(|gave| gave.to == to && gave.giver.is(giver))
        {
            // Parties that left are not woken: forget them before growing.
            if gave_way.len() == gave_way.capacity() {
                gave_way.retain(|gave| gave.giver.party.strong_count() > 0);
            }
            gave_way.push(GaveWay {
                to,
                giver: WeakWaiter::new(giver),
            });
            let mut turns = giver.counters().turns.lock();
            *turns = turns.saturating_add(1);
        }
        // What it was left is worth a look, also if its current look began
        // before the capacity was there.
        front.wake();
        true
    }

    /// How many wait.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    /// Whether nobody waits.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len.load(Ordering::Relaxed) == 0
    }

    /// The [`Party::order`] of the first waiter, if any waits.
    #[must_use]
    pub fn front_order(&self) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        self.queue
            .lock()
            .waiters
            .front()
            .map(|front| front.party.order)
    }

    /// The wakes this queue sent its waiters that they did not spend.
    #[must_use]
    pub fn unspent(&self) -> usize {
        self.queue
            .lock()
            .waiters
            .iter()
            .map(|waiter| waiter.held())
            .sum()
    }

    /// Whether a party may take capacity now: nobody waits ahead of it, or it
    /// holds a wake of this queue. `None` is a party that does not wait here.
    #[must_use]
    pub fn admits(&self, waiter: Option<&Waiter>) -> bool {
        if self.is_empty() {
            return true;
        }
        let Some(waiter) = waiter else {
            return false;
        };
        waiter.is_woken()
            || self
                .queue
                .lock()
                .waiters
                .front()
                .is_some_and(|front| front.is(waiter))
    }

    /// One unit of capacity: wake the first waiter without a wake of this queue
    /// or, if all of them hold one, the first again, since its look may have
    /// begun before the unit. False if nobody waits: the capacity is nobody's.
    pub fn wake_one(&self) -> bool {
        fence(Ordering::SeqCst);
        if self.is_empty() {
            return false;
        }
        let queue = self.queue.lock();
        let Some(front) = queue.waiters.front() else {
            return false;
        };
        queue
            .waiters
            .iter()
            .find(|waiter| !waiter.is_woken())
            .unwrap_or(front)
            .wake();
        true
    }

    /// `n` units of capacity at once: as [`Self::wake_one`] `n` times, in one
    /// pass over the queue. False if nobody waits.
    pub fn wake_many(&self, n: usize) -> bool {
        fence(Ordering::SeqCst);
        if n == 0 || self.is_empty() {
            return false;
        }
        let queue = self.queue.lock();
        let Some(front) = queue.waiters.front() else {
            return false;
        };
        let mut left = n;
        for waiter in queue.waiters.iter().filter(|waiter| !waiter.is_woken()) {
            if left == 0 {
                return true;
            }
            waiter.wake();
            left -= 1;
        }
        if left > 0 {
            front.wake_by(left);
        }
        true
    }

    /// A change of unknown size: wake every waiter. False if nobody waits.
    pub fn wake_all(&self) -> bool {
        fence(Ordering::SeqCst);
        if self.is_empty() {
            return false;
        }
        let queue = self.queue.lock();
        for waiter in &queue.waiters {
            waiter.wake();
        }
        !queue.waiters.is_empty()
    }
}

impl fmt::Debug for WaitQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitQueue")
            .field("len", &self.len.load(Ordering::Relaxed))
            .finish()
    }
}

/// One waiting task. It queues a [`Waiter`] in each [`WaitQueue`] it waits in,
/// and any of them wakes it: see [`Self::woken`].
pub struct Party {
    order: u64,
    /// How often its waiters were woken.
    wakes: AtomicUsize,
    waker: AtomicWaker,
    /// The counters of its first places, in the same allocation.
    places: [Place; INLINE_PLACES],
    /// Inline places handed out so far.
    placed: AtomicUsize,
}

/// Places a [`Party`] keeps inline: a lane, a keyed lane and the slot queue.
const INLINE_PLACES: usize = 3;

/// Wakes a place holds at most: far more than any waiter spends, with room for
/// the turn its departure adds.
const MAX_HELD: usize = usize::MAX / 2;

/// The wakes one queue sent a party, how many of them it spent, and the turns
/// it gave way with that are not handed back yet.
#[derive(Default)]
struct Place {
    wakes: AtomicUsize,
    /// Only the waiting party writes it.
    spent: AtomicUsize,
    /// Under it, a turn handed back becomes a wake, and a departure takes the
    /// turns and reads the wakes: each in one step. A leaf lock.
    turns: Mutex<usize>,
}

impl Place {
    /// Add `n` wakes, as many as fit below [`MAX_HELD`].
    fn add_wakes(&self, n: usize) {
        let spent = self.spent.load(Ordering::Relaxed);
        let mut wakes = self.wakes.load(Ordering::Acquire);
        loop {
            let room = MAX_HELD.saturating_sub(wakes.wrapping_sub(spent));
            match self.wakes.compare_exchange_weak(
                wakes,
                wakes.wrapping_add(n.min(room)),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(seen) => wakes = seen,
            }
        }
    }
}

impl Party {
    /// Create a party, `order` being its arrival among its owner's parties:
    /// lower is older.
    #[must_use]
    pub fn new(order: u64) -> Arc<Self> {
        Arc::new(Self {
            order,
            wakes: AtomicUsize::new(0),
            waker: AtomicWaker::new(),
            places: Default::default(),
            placed: AtomicUsize::new(0),
        })
    }

    /// Its arrival among its owner's parties: lower is older.
    #[must_use]
    pub fn order(&self) -> u64 {
        self.order
    }

    /// A place for the party in one more queue, to [`WaitQueue::push`].
    #[must_use]
    pub fn waiter(self: &Arc<Self>) -> Waiter {
        let index = self.placed.fetch_add(1, Ordering::Relaxed);
        Waiter {
            party: self.clone(),
            place: if index < INLINE_PLACES {
                PlaceRef::Inline(index)
            } else {
                PlaceRef::Extra(Arc::default())
            },
        }
    }

    /// How often its waiters were woken so far: read before a look.
    #[must_use]
    pub fn wakes(&self) -> usize {
        self.wakes.load(Ordering::Acquire)
    }

    /// Completes once any of its waiters is woken after `seen`, the count of
    /// [`Self::wakes`] read before the look: no wake between the look and the
    /// wait is lost.
    pub fn woken(&self, seen: usize) -> Woken<'_> {
        Woken { party: self, seen }
    }
}

impl fmt::Debug for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Party")
            .field("order", &self.order)
            .field("wakes", &self.wakes.load(Ordering::Relaxed))
            .finish()
    }
}

/// A [`Party`]'s place in one [`WaitQueue`], holding the wakes that queue sent
/// it and the party did not spend: each a unit of capacity, or a change, to
/// look at. Cloning it shares the place.
#[derive(Clone)]
pub struct Waiter {
    party: Arc<Party>,
    place: PlaceRef,
}

#[derive(Clone)]
enum PlaceRef {
    Inline(usize),
    Extra(Arc<Place>),
}

/// The wakes a [`Waiter`] had received when a look at its capacity began.
#[derive(Debug, Clone, Copy)]
pub struct Wakes {
    wakes: usize,
    spent: usize,
}

impl Wakes {
    /// Whether the look began with a wake held: one it spends if it takes
    /// capacity.
    #[must_use]
    pub fn held(self) -> bool {
        self.wakes != self.spent
    }
}

impl Waiter {
    /// The party it is a place of.
    #[must_use]
    pub fn party(&self) -> &Arc<Party> {
        &self.party
    }

    fn counters(&self) -> &Place {
        match &self.place {
            PlaceRef::Inline(index) => &self.party.places[*index],
            PlaceRef::Extra(place) => place,
        }
    }

    /// Whether `other` is this same place.
    fn is(&self, other: &Self) -> bool {
        std::ptr::eq(self.counters(), other.counters())
    }

    /// Whether the waiter holds a wake it has not spent.
    #[must_use]
    pub fn is_woken(&self) -> bool {
        self.held() != 0
    }

    /// The wakes the waiter holds and has not spent.
    #[must_use]
    pub fn held(&self) -> usize {
        let place = self.counters();
        place
            .wakes
            .load(Ordering::Acquire)
            .wrapping_sub(place.spent.load(Ordering::Relaxed))
    }

    /// It leaves its queue: the wakes it holds, and one more if a turn it gave
    /// way with is not handed back.
    fn leave(&self) -> usize {
        let mut turns = self.counters().turns.lock();
        let turn = std::mem::take(&mut *turns) > 0;
        self.held().saturating_add(usize::from(turn))
    }

    /// The wakes so far: read before a look at the capacity waited for.
    #[must_use]
    pub fn wakes(&self) -> Wakes {
        let place = self.counters();
        Wakes {
            wakes: place.wakes.load(Ordering::Acquire),
            spent: place.spent.load(Ordering::Relaxed),
        }
    }

    /// The look begun at `seen` found nothing: the wakes it answered are
    /// spent, a wake since keeps the waiter woken.
    pub fn spend(&self, seen: Wakes) {
        self.counters().spent.store(seen.wakes, Ordering::Relaxed);
    }

    fn wake(&self) {
        self.wake_by(1);
    }

    /// One of the turns it gave way with is handed back, as a wake in the same
    /// step: none left, it passed its turn on as it left.
    fn hand_back_turn(&self) {
        let place = self.counters();
        {
            let mut turns = place.turns.lock();
            let Some(left) = turns.checked_sub(1) else {
                return;
            };
            *turns = left;
            place.add_wakes(1);
        }
        // Outside the leaf lock: a waker may run anything.
        self.wake_party();
    }

    fn wake_by(&self, n: usize) {
        self.counters().add_wakes(n);
        self.wake_party();
    }

    /// One more wake of the party, however many its place took: a look waits
    /// for any, and a count of calls cannot wrap back to one it saw.
    fn wake_party(&self) {
        self.party.wakes.fetch_add(1, Ordering::AcqRel);
        self.party.waker.wake();
    }
}

/// A [`Waiter`] that does not keep its party alive.
struct WeakWaiter {
    party: Weak<Party>,
    place: PlaceRef,
}

impl WeakWaiter {
    fn new(waiter: &Waiter) -> Self {
        Self {
            party: Arc::downgrade(&waiter.party),
            place: waiter.place.clone(),
        }
    }

    fn upgrade(&self) -> Option<Waiter> {
        Some(Waiter {
            party: self.party.upgrade()?,
            place: self.place.clone(),
        })
    }

    /// Whether `waiter` is this same place.
    fn is(&self, waiter: &Waiter) -> bool {
        std::ptr::eq(self.party.as_ptr(), Arc::as_ptr(&waiter.party))
            && match (&self.place, &waiter.place) {
                (PlaceRef::Inline(ours), PlaceRef::Inline(theirs)) => ours == theirs,
                (PlaceRef::Extra(ours), PlaceRef::Extra(theirs)) => Arc::ptr_eq(ours, theirs),
                _ => false,
            }
    }
}

impl fmt::Debug for Waiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Waiter")
            .field("party", &self.party.order)
            .field("held", &self.held())
            .finish()
    }
}

/// Completes once its [`Party`] is woken after a count: see [`Party::woken`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Woken<'a> {
    party: &'a Party,
    seen: usize,
}

impl Future for Woken<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.party.wakes.load(Ordering::Acquire) != self.seen {
            return Poll::Ready(());
        }
        self.party.waker.register(cx.waker());
        // A wake before the registration found no waker to wake.
        if self.party.wakes.load(Ordering::Acquire) == self.seen {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
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
    fn changed(&self, _: Change) {
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

    /// Store `value` and wake watchers; listeners learn of a [`Change::Other`].
    pub fn set(&self, value: T) {
        self.set_change(value, Change::Other);
    }

    /// Store `value` and wake watchers; listeners learn of `change`.
    pub fn set_change(&self, value: T, change: Change) {
        let bits = value.to_usize();
        // Publish to the atomic first (lock-free reads see it immediately), then
        // signal. `send` is a no-op when there are no watchers, so an idle value
        // pays only the atomic store.
        self.value.store(bits, Ordering::Release);
        // `send` errors only when there are no receivers, that's the idle case we
        // intentionally treat as a no-op.
        let _unused = self.signal.send(bits);
        self.changes.notify(change);
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
    use loom::thread;

    struct Flag(AtomicBool);

    impl ChangeListener for Flag {
        fn changed(&self, _: Change) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Queue-then-check: capacity freed while a waiter queues is either seen
    /// by its check or wakes it.
    #[test]
    fn a_queuing_waiter_never_misses_freed_capacity() {
        loom::model(|| {
            let queue = Arc::new(WaitQueue::new());
            let capacity = Arc::new(AtomicUsize::new(0));
            let releaser = {
                let (queue, capacity) = (queue.clone(), capacity.clone());
                thread::spawn(move || {
                    capacity.store(1, Ordering::Release);
                    queue.wake_one();
                })
            };
            let waiter = Party::new(0).waiter();
            queue.push(&waiter);
            let seen = capacity.load(Ordering::Acquire);
            releaser.join().unwrap();
            assert!(
                seen == 1 || waiter.is_woken(),
                "the freed capacity was neither seen nor signalled"
            );
        });
    }

    /// A look that began before a unit was freed and found nothing does
    /// not spend the wake that unit sent: the waiter looks again.
    #[test]
    fn a_woken_waiter_never_spends_a_unit_freed_during_its_look() {
        loom::model(|| {
            let queue = Arc::new(WaitQueue::new());
            let capacity = Arc::new(AtomicUsize::new(0));
            let waiter = Party::new(0).waiter();
            queue.push(&waiter);
            assert!(queue.wake_all());
            let releaser = {
                let (queue, capacity) = (queue.clone(), capacity.clone());
                thread::spawn(move || {
                    capacity.store(1, Ordering::Release);
                    queue.wake_one();
                })
            };
            let seen = waiter.wakes();
            let found = capacity.load(Ordering::Acquire);
            if found == 0 {
                waiter.spend(seen);
            }
            releaser.join().unwrap();
            assert!(
                found == 1 || waiter.is_woken(),
                "the freed unit was spent by a look that missed it"
            );
        });
    }

    /// A change of unknown size during a woken waiter's look is not spent by
    /// that look either.
    #[test]
    fn a_change_during_a_woken_look_is_not_spent() {
        loom::model(|| {
            let queue = Arc::new(WaitQueue::new());
            let capacity = Arc::new(AtomicUsize::new(0));
            let waiter = Party::new(0).waiter();
            queue.push(&waiter);
            assert!(queue.wake_one());
            let changer = {
                let (queue, capacity) = (queue.clone(), capacity.clone());
                thread::spawn(move || {
                    capacity.store(1, Ordering::Release);
                    queue.wake_all();
                })
            };
            let seen = waiter.wakes();
            let found = capacity.load(Ordering::Acquire);
            if found == 0 {
                waiter.spend(seen);
            }
            changer.join().unwrap();
            assert!(
                found == 1 || waiter.is_woken(),
                "the change was spent by a look that missed it"
            );
        });
    }

    /// Queue-then-check against a change: a change made while a waiter
    /// queues is either seen by its check or wakes it.
    #[test]
    fn a_queuing_waiter_never_misses_a_change() {
        loom::model(|| {
            let queue = Arc::new(WaitQueue::new());
            let capacity = Arc::new(AtomicUsize::new(0));
            let changer = {
                let (queue, capacity) = (queue.clone(), capacity.clone());
                thread::spawn(move || {
                    capacity.store(1, Ordering::Release);
                    queue.wake_all();
                })
            };
            let waiter = Party::new(0).waiter();
            queue.push(&waiter);
            let seen = capacity.load(Ordering::Acquire);
            changer.join().unwrap();
            assert!(
                seen == 1 || waiter.is_woken(),
                "the change was neither seen nor signalled"
            );
        });
    }

    /// Check-register-check: a wake racing the waiter's registration still
    /// ends its wait.
    #[test]
    fn a_wake_racing_the_registration_ends_the_wait() {
        loom::model(|| {
            let queue = Arc::new(WaitQueue::new());
            let party = Party::new(0);
            let waiter = party.waiter();
            queue.push(&waiter);
            let seen = party.wakes();
            let releaser = {
                let queue = queue.clone();
                thread::spawn(move || {
                    queue.wake_one();
                })
            };
            loom::future::block_on(party.woken(seen));
            releaser.join().unwrap();
        });
    }

    /// Of the last waiter leaving and capacity freed for the queue at once,
    /// one announces the capacity as nobody's.
    #[test]
    fn capacity_freed_as_the_last_waiter_leaves_is_announced() {
        loom::model(|| {
            let queue = Arc::new(WaitQueue::new());
            let freed = Arc::new(AtomicBool::new(false));
            let waiter = Party::new(0).waiter();
            queue.push(&waiter);
            let releaser = {
                let (queue, freed) = (queue.clone(), freed.clone());
                thread::spawn(move || {
                    freed.store(true, Ordering::Relaxed);
                    !queue.wake_one()
                })
            };
            queue.remove(&waiter);
            let seen = queue.is_empty() && freed.load(Ordering::Relaxed);
            let announced = releaser.join().unwrap();
            assert!(
                announced || seen,
                "the freed capacity was announced by nobody"
            );
        });
    }

    /// Of a party giving way to a waiter and that waiter leaving, one sees the
    /// other: the party does not give way, or its queue is woken.
    #[test]
    fn a_party_giving_way_is_woken_once_the_waiter_leaves() {
        loom::model(|| {
            let [theirs, ours] = [Arc::new(WaitQueue::new()), Arc::new(WaitQueue::new())];
            let ahead = Party::new(0).waiter();
            theirs.push(&ahead);
            let waiter = Party::new(1).waiter();
            ours.push(&waiter);
            let leaver = {
                let theirs = theirs.clone();
                thread::spawn(move || theirs.remove(&ahead))
            };
            let gave_way = theirs.give_way(1, &waiter);
            leaver.join().unwrap();
            assert!(
                !gave_way || waiter.is_woken(),
                "it gave way to a waiter that left without telling it"
            );
        });
    }

    /// Of a party that gave way leaving and the waiter it gave way to leaving,
    /// whichever comes first, the turn it gave away is passed on.
    #[test]
    fn a_turn_given_away_is_passed_on_whoever_leaves_first() {
        loom::model(|| {
            let [theirs, ours] = [Arc::new(WaitQueue::new()), Arc::new(WaitQueue::new())];
            let ahead = Party::new(0).waiter();
            theirs.push(&ahead);
            let giver = Party::new(1).waiter();
            ours.push(&giver);
            assert!(theirs.give_way(1, &giver));
            let leaver = {
                let theirs = theirs.clone();
                thread::spawn(move || theirs.remove(&ahead))
            };
            let passed = ours.remove(&giver);
            leaver.join().unwrap();
            assert_eq!(passed, 1, "the turn it gave away, passed on once");
        });
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
                    signal.notify(Change::Other);
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
        fn changed(&self, _: Change) {
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
        signal.notify(Change::Other);
        assert_eq!(kept.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_listener_may_subscribe_again_while_woken() {
        struct Resubscribe(Arc<ChangeSignal>, Weak<Self>, AtomicUsize);

        impl ChangeListener for Resubscribe {
            fn changed(&self, _: Change) {
                self.2.fetch_add(1, Ordering::Relaxed);
                self.0.subscribe(self.1.clone() as Weak<dyn ChangeListener>);
            }
        }

        let signal = Arc::new(ChangeSignal::new());
        let listener =
            Arc::new_cyclic(|weak| Resubscribe(signal.clone(), weak.clone(), AtomicUsize::new(0)));
        signal.subscribe(Arc::downgrade(&listener) as Weak<dyn ChangeListener>);
        signal.notify(Change::Other);
        signal.notify(Change::Other);
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
        signal.notify(Change::Other);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            first.await;
            second.await;
        })
        .await
        .expect("a change wakes every task that waits");
    }

    #[test]
    fn a_wait_queue_wakes_in_arrival_order_once_per_unit() {
        let queue = WaitQueue::new();
        let [first, second] = [Party::new(0).waiter(), Party::new(1).waiter()];
        queue.push(&first);
        queue.push(&second);
        assert!(!queue.admits(None));
        assert_eq!(queue.front_order(), Some(0));
        assert!(queue.admits(Some(&first)) && !queue.admits(Some(&second)));
        queue.wake_one();
        assert!(first.is_woken() && !second.is_woken());
        queue.wake_one();
        assert!(second.is_woken() && queue.admits(Some(&second)));
        first.spend(first.wakes());
        second.spend(second.wakes());
        assert!(queue.wake_all());
        assert!(first.is_woken() && second.is_woken());
        // Both hold a wake: the next unit goes to the first, whose look may
        // have begun before it.
        let seen = first.wakes();
        assert!(queue.wake_one());
        first.spend(seen);
        assert!(first.is_woken(), "a wake during a look is not spent by it");
        assert_eq!(queue.remove(&first), 1);
        assert_eq!(queue.remove(&second), 1);
        assert!(queue.is_empty() && queue.admits(None) && !queue.wake_one());
        assert_eq!(queue.front_order(), None);
    }

    #[test]
    fn a_cancellation_wave_across_queues_passes_each_wake_once() {
        let queues = [WaitQueue::new(), WaitQueue::new()];
        let waiters: Vec<_> = (0..32)
            .map(|order| {
                let party = Party::new(order);
                queues.each_ref().map(|queue| {
                    let waiter = party.waiter();
                    queue.push(&waiter);
                    waiter
                })
            })
            .collect();
        assert!(queues[0].wake_one());
        // Each leaves without a look, passing on what each queue sent it.
        for places in &waiters[..31] {
            for (queue, waiter) in queues.iter().zip(places) {
                for _ in 0..queue.remove(waiter) {
                    queue.wake_one();
                }
            }
        }
        let last = &waiters[31];
        assert_eq!(
            last[0].held() + last[1].held(),
            1,
            "one wake, passed on along its queue"
        );
        assert_eq!(last[0].party().wakes(), 1);
    }

    #[test]
    fn a_wake_of_one_queue_admits_only_there() {
        let [ours, theirs] = [WaitQueue::new(), WaitQueue::new()];
        let ahead = Party::new(0).waiter();
        ours.push(&ahead);
        let party = Party::new(1);
        let [here, there] = [party.waiter(), party.waiter()];
        ours.push(&here);
        theirs.push(&there);
        assert!(theirs.wake_one());
        assert!(theirs.admits(Some(&there)));
        assert!(
            !ours.admits(Some(&here)),
            "its wake came from another queue"
        );
        assert_eq!(
            ours.remove(&here),
            0,
            "nothing to pass on where nothing was sent"
        );
        assert_eq!(theirs.remove(&there), 1);
    }

    #[test]
    fn waking_many_wakes_as_waking_one_as_often() {
        let [many, one] = [WaitQueue::new(), WaitQueue::new()];
        let waiters = |queue: &WaitQueue| {
            let waiters = [0, 1, 2].map(|order| Party::new(order).waiter());
            for waiter in &waiters {
                queue.push(waiter);
            }
            waiters
        };
        let [by_many, by_one] = [waiters(&many), waiters(&one)];
        by_many[1].wake();
        by_one[1].wake();
        assert!(many.wake_many(4));
        for _ in 0..4 {
            assert!(one.wake_one());
        }
        let held = |waiters: &[Waiter; 3]| waiters.each_ref().map(Waiter::held);
        assert_eq!(held(&by_many), held(&by_one));
        assert_eq!(held(&by_many), [3, 1, 1], "the rest goes to the front");
        assert!(!WaitQueue::new().wake_many(1) && !many.wake_many(0));
    }

    #[test]
    fn a_party_queuing_late_goes_ahead_of_younger_ones() {
        let queue = WaitQueue::new();
        let [old, young, late] = [0, 2, 1].map(|order| Party::new(order).waiter());
        queue.push(&old);
        queue.push(&young);
        queue.push(&late);
        assert!(queue.remove(&old) == 0 && queue.front_order() == Some(1));
        assert!(queue.wake_one());
        assert!(late.is_woken() && !young.is_woken(), "the older one first");
    }

    #[test]
    fn a_party_that_gave_way_is_woken_when_that_waiter_leaves() {
        let theirs = WaitQueue::new();
        let ours = WaitQueue::new();
        let [ahead, behind] = [0, 3].map(|order| Party::new(order).waiter());
        theirs.push(&ahead);
        theirs.push(&behind);
        let [first, second] = [1, 2].map(|order| Party::new(order).waiter());
        ours.push(&first);
        ours.push(&second);
        assert!(!theirs.give_way(0, &first), "nobody older than the oldest");
        assert!(theirs.give_way(1, &first) && theirs.give_way(1, &first));
        assert!(theirs.give_way(2, &second));
        assert!(ahead.held() >= 1, "woken to look at what it was left");
        assert_eq!(theirs.remove(&behind), 0);
        assert!(!first.is_woken(), "they gave way to another one");
        assert_eq!(theirs.remove(&ahead), 3, "woken by each look that gave way");
        assert_eq!(
            (first.held(), second.held()),
            (1, 1),
            "one wake per party that gave way, however often"
        );
        assert!(!theirs.give_way(1, &first) && theirs.is_empty());
    }

    #[test]
    fn a_party_that_gave_way_and_leaves_first_passes_its_turn_on() {
        let [theirs, ours] = [WaitQueue::new(), WaitQueue::new()];
        let older = Party::new(0).waiter();
        theirs.push(&older);
        let [giver, behind] = [1, 2].map(|order| Party::new(order).waiter());
        ours.push(&giver);
        ours.push(&behind);
        assert!(theirs.give_way(1, &giver));
        assert_eq!(ours.remove(&giver), 1, "its turn, to pass on");
        assert_eq!(theirs.remove(&older), 1, "its own look's wake");
        assert!(!behind.is_woken(), "the leaver passes the turn on, once");
        assert_eq!(
            giver.held(),
            0,
            "its turn went with it: nothing handed back"
        );
    }

    #[test]
    fn however_many_wakes_a_place_got_its_departure_invents_no_turn() {
        let queue = WaitQueue::new();
        let waiter = Party::new(0).waiter();
        queue.push(&waiter);
        for _ in 0..3 {
            assert!(queue.wake_many(usize::MAX));
            waiter.spend(waiter.wakes());
        }
        assert_eq!(queue.remove(&waiter), 0, "nothing held, no turn given");
    }

    #[test]
    fn however_many_turns_a_place_gave_its_departure_passes_one_on() {
        let ours = WaitQueue::new();
        let giver = Party::new(u64::MAX).waiter();
        ours.push(&giver);
        // As many as a 16-bit count of turns wraps to none.
        let rivals: Vec<_> = (0..65_536)
            .map(|order| {
                let queue = WaitQueue::new();
                let older = Party::new(order).waiter();
                queue.push(&older);
                assert!(queue.give_way(u64::MAX, &giver));
                (queue, older)
            })
            .collect();
        assert_eq!(ours.remove(&giver), 1, "its turn, once");
        drop(rivals);
    }

    #[test]
    fn a_place_holding_all_the_wakes_it_can_leaves_with_its_turn() {
        let [theirs, ours] = [WaitQueue::new(), WaitQueue::new()];
        let older = Party::new(0).waiter();
        theirs.push(&older);
        let giver = Party::new(1).waiter();
        ours.push(&giver);
        assert!(ours.wake_many(usize::MAX));
        assert!(theirs.give_way(1, &giver));
        assert_eq!(
            ours.remove(&giver),
            giver.held() + 1,
            "its wakes, and its turn"
        );
    }

    #[test]
    fn a_turn_handed_back_to_a_place_holding_all_it_can_keeps_it_woken() {
        let [theirs, ours] = [WaitQueue::new(), WaitQueue::new()];
        let older = Party::new(0).waiter();
        theirs.push(&older);
        let giver = Party::new(1).waiter();
        ours.push(&giver);
        assert!(ours.wake_many(usize::MAX));
        assert!(theirs.give_way(1, &giver));
        theirs.remove(&older);
        assert!(giver.is_woken(), "no wake it holds is lost");
    }

    #[test]
    fn a_party_woken_by_a_full_batch_and_one_more_is_woken() {
        let queue = WaitQueue::new();
        let waiter = Party::new(0).waiter();
        queue.push(&waiter);
        let seen = waiter.party().wakes();
        assert!(queue.wake_many(usize::MAX));
        assert!(queue.wake_one());
        assert_ne!(
            waiter.party().wakes(),
            seen,
            "no count wraps back to the one it saw"
        );
        assert!(waiter.is_woken());
    }

    #[test]
    fn a_turn_handed_back_is_passed_on_once() {
        let [theirs, ours] = [WaitQueue::new(), WaitQueue::new()];
        let older = Party::new(0).waiter();
        theirs.push(&older);
        let giver = Party::new(1).waiter();
        ours.push(&giver);
        assert!(theirs.give_way(1, &giver));
        let party_wakes = giver.party().wakes();
        theirs.remove(&older);
        assert_eq!(giver.held(), 1, "handed back");
        assert!(giver.party().wakes() > party_wakes, "its party looks again");
        assert_eq!(ours.remove(&giver), 1, "that wake, not one more");
    }

    #[test]
    fn giving_way_during_the_fronts_look_keeps_it_woken() {
        let [theirs, ours] = [WaitQueue::new(), WaitQueue::new()];
        let front = Party::new(0).waiter();
        theirs.push(&front);
        let giver = Party::new(1).waiter();
        ours.push(&giver);
        assert!(theirs.wake_one(), "a unit before its look");
        let seen = front.wakes();
        assert!(theirs.give_way(1, &giver), "during its look");
        front.spend(seen);
        assert!(front.is_woken(), "it looks again at what it was left");
    }

    #[test]
    fn parties_that_gave_way_and_left_are_forgotten() {
        let [theirs, ours] = [WaitQueue::new(), WaitQueue::new()];
        let ahead = Party::new(0).waiter();
        theirs.push(&ahead);
        for order in 1..10_000 {
            let giver = Party::new(order).waiter();
            ours.push(&giver);
            assert!(theirs.give_way(order, &giver));
            ours.remove(&giver);
        }
        assert!(
            theirs.queue.lock().gave_way.len() < 64,
            "records of parties that left do not pile up"
        );
        let tail = Party::new(10_000).waiter();
        ours.push(&tail);
        theirs.remove(&ahead);
        assert_eq!(
            tail.held(),
            0,
            "nobody that left is woken, nor anyone for them"
        );
    }

    #[test]
    fn a_listener_learns_what_changed() {
        #[derive(Default)]
        struct Last(Mutex<Option<Change>>);

        impl ChangeListener for Last {
            fn changed(&self, change: Change) {
                *self.0.lock() = Some(change);
            }
        }

        let signal = ChangeSignal::new();
        let listener = Arc::new(Last::default());
        signal.subscribe(Arc::downgrade(&listener) as Weak<dyn ChangeListener>);
        signal.notify(Change::Freed);
        assert_eq!(*listener.0.lock(), Some(Change::Freed));
        drop(signal);
        assert_eq!(
            *listener.0.lock(),
            Some(Change::Other),
            "going away is no unit"
        );
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
