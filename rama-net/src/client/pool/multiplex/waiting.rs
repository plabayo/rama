//! A waiting checkout's places in the queues it can be served from.

use super::*;

/// Who looks at a bucket's lanes.
pub(super) enum Look<'a> {
    /// A checkout that does not wait: lanes with waiters are closed to it.
    New,
    /// A waiting checkout, queuing in the lanes it looks at.
    Register(&'a mut Waiting),
    /// A waiting checkout, looking again.
    Waiting(&'a Waiting),
}

impl Look<'_> {
    pub(super) fn waiting(&self) -> Option<&Waiting> {
        match self {
            Self::New => None,
            Self::Register(waiting) => Some(waiting),
            Self::Waiting(waiting) => Some(waiting),
        }
    }

    /// A sweep of the look found an idle connection expiring `at`.
    pub(super) fn note_expiry(&mut self, at: u64) {
        if let Self::Register(waiting) = self {
            waiting.next_expiry = waiting.next_expiry.min(at);
        }
    }
}

/// Why a look found neither a connection nor a create permit.
#[derive(Debug, Clone, Copy)]
pub(super) enum Blocked {
    /// The id is at its connection limit: wait for one of its slots.
    Id,
    /// The pool is at its total connection limit: wait for a total slot.
    Total,
    /// Enough connects are in flight for the request's lanes: wait for them.
    Connecting,
    /// The connects it waited for failed.
    Failed(Failure),
}

/// A queued acquisition of a pool or id slot, kept across wakes so the
/// checkout keeps its place in the semaphore's FIFO.
pub(super) type SlotWait =
    Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send>>;

/// The output of `future` if there is one, else never.
pub(super) async fn maybe<F: Future + Unpin>(future: &mut Option<F>) -> F::Output {
    match future {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

/// As [`maybe`], for a future pinned in place.
pub(super) async fn maybe_pinned<F: Future>(future: Pin<&mut Option<F>>) -> F::Output {
    match future.as_pin_mut() {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

/// An acquisition of an id's slot, kept across wakes like [`SlotWait`].
pub(super) type IdSlotWait = Pin<Box<dyn Future<Output = Result<IdPermit, AcquireError>> + Send>>;

/// A waiting checkout's place in the queues it can be served from, and in the
/// pool's count of waiting checkouts. Dropped when the checkout ends: each
/// queue gets back the wakes it sent and the checkout did not use.
pub(super) struct Waiting {
    pub(super) party: Arc<Party>,
    pub(super) places: SmallVec<[Place; 2]>,
    /// The queue that served the checkout, if filed: the lane of its
    /// connection, or the queue of the eviction chance it took.
    pub(super) served: Option<Arc<WaitQueue>>,
    /// Whether serving it spent a wake of that queue.
    pub(super) spent: bool,
    /// When the first idle connection the current look's sweeps kept expires.
    pub(super) next_expiry: u64,
    /// The connects it waits for, and their failures when it started waiting.
    pub(super) connects_seen: Option<(Weak<Connects>, u64)>,
    pub(super) waiting: Arc<AtomicUsize>,
    pub(super) slot_waiters: Arc<WaitQueue>,
    /// The checkouts at its id's limit that may replace one of the id's idle
    /// connections, if the pool limits connections per id.
    pub(super) id_evictors: Option<Arc<WaitQueue>>,
}

/// A waiting checkout's place in one queue.
pub(super) struct Place {
    pub(super) queue: Arc<WaitQueue>,
    pub(super) waiter: Waiter,
    /// Its wakes when the current look began, if it was queued by then.
    pub(super) seen: Option<Wakes>,
    /// Whether the current look queued in it: a look leaves the queues its
    /// request no longer uses.
    pub(super) looked: bool,
    /// A queue of eviction chances, not of units of capacity: a chance is
    /// worth one more look, however many reached the checkout.
    pub(super) chances: bool,
}

impl Waiting {
    pub(super) fn new(
        waiting: &Arc<AtomicUsize>,
        slot_waiters: &Arc<WaitQueue>,
        id_evictors: Option<Arc<WaitQueue>>,
        order: u64,
    ) -> Self {
        waiting.fetch_add(1, Ordering::Relaxed);
        // Pairs with the fence of a release: for a checkout that queues in no
        // lane, this is what orders its count before its look.
        fence(Ordering::SeqCst);
        Self {
            party: Party::new(order),
            places: SmallVec::new(),
            served: None,
            spent: false,
            next_expiry: u64::MAX,
            connects_seen: None,
            waiting: waiting.clone(),
            slot_waiters: slot_waiters.clone(),
            id_evictors,
        }
    }

    /// Start a look: returns the party's wakes to wait past if it finds nothing.
    pub(super) fn begin_look(&mut self) -> usize {
        let seen = self.party.wakes();
        self.next_expiry = u64::MAX;
        for place in &mut self.places {
            place.seen = Some(place.waiter.wakes());
            place.looked = false;
        }
        seen
    }

    /// Queue in the lane `queue`, once. Call with the storage lock held, before
    /// the look at the lane's capacity: see [`StoredConnection::freed`].
    pub(super) fn register(&mut self, queue: &Arc<WaitQueue>) {
        self.register_in(queue, false);
    }

    /// Queue for the eviction chances of `queue`, once, before looking for an
    /// idle connection to evict.
    pub(super) fn register_for_chances(&mut self, queue: &Arc<WaitQueue>) {
        self.register_in(queue, true);
    }

    fn register_in(&mut self, queue: &Arc<WaitQueue>, chances: bool) {
        if let Some(place) = self
            .places
            .iter_mut()
            .find(|place| Arc::ptr_eq(&place.queue, queue))
        {
            place.looked = true;
            return;
        }
        let waiter = self.party.waiter();
        queue.push(&waiter);
        self.places.push(Place {
            queue: queue.clone(),
            waiter,
            seen: None,
            looked: true,
            chances,
        });
    }

    /// Wait for the connects of `connects`, once: their failures from now on
    /// are its own.
    pub(super) fn wait_for_connects(&mut self, connects: &Arc<Connects>) -> u64 {
        self.register_in(&connects.waiters, true);
        match &self.connects_seen {
            Some((of, seen)) if std::ptr::eq(of.as_ptr(), Arc::as_ptr(connects)) => *seen,
            _ => {
                let seen = connects.failures();
                self.connects_seen = Some((Arc::downgrade(connects), seen));
                seen
            }
        }
    }

    /// The checkout's place in `queue`, if it queues there.
    pub(super) fn waiter_in(&self, queue: &Arc<WaitQueue>) -> Option<&Waiter> {
        self.places
            .iter()
            .find(|place| Arc::ptr_eq(&place.queue, queue))
            .map(|place| &place.waiter)
    }

    /// Leave the lanes the current look did not queue in: the request no
    /// longer uses them. Call once the look queued in the request's lanes.
    pub(super) fn leave_other_lanes(&mut self) {
        let emptied = self.leave_where(|place| !place.looked && !place.chances);
        self.announce(emptied, self.others_wait());
    }

    /// A look found nothing: it spent the wakes it answered, and the checkout
    /// leaves the chance queues the look no longer queued in. The lanes it no
    /// longer uses it left during the look.
    pub(super) fn end_fruitless_look(&mut self) {
        for place in &self.places {
            if let Some(seen) = place.seen {
                place.waiter.spend(seen);
            }
        }
        let emptied = self.leave_where(|place| !place.looked);
        debug_assert!(!emptied, "the look left the lanes it no longer uses");
    }

    /// Whether other checkouts wait in the pool.
    fn others_wait(&self) -> bool {
        self.waiting.load(Ordering::Relaxed) > 1
    }

    /// Leave the queues `leave` picks; whether a lane was left empty.
    fn leave_where(&mut self, mut leave: impl FnMut(&Place) -> bool) -> bool {
        let mut emptied = false;
        self.places.retain(|place| {
            if !leave(place) {
                return true;
            }
            emptied |= Self::leave(place, false);
            false
        });
        emptied
    }

    /// Leave `place`'s queue, passing on the wakes it sent that the checkout
    /// did not use, minus one it spent there; whether a lane was left empty.
    fn leave(place: &Place, spent_there: bool) -> bool {
        let mut held = place.queue.remove(&place.waiter);
        if spent_there {
            held = held.saturating_sub(1);
        }
        if place.chances {
            held = held.min(1);
        }
        // The capacity these wakes stand for is there for the others.
        for _ in 0..held {
            place.queue.wake_one();
        }
        !place.chances && place.queue.is_empty()
    }

    /// Lanes left empty while others wait: their idle connections can be
    /// evicted now.
    fn announce(&self, emptied: bool, others: bool) {
        if emptied && others {
            self.slot_waiters.wake_one();
            if let Some(id_evictors) = &self.id_evictors {
                id_evictors.wake_one();
            }
        }
    }

    /// The checkout was served through `queue`: the lane of its connection, if
    /// filed, or the chance queue of the idle connection it evicted.
    pub(super) fn served(&mut self, queue: Option<Arc<WaitQueue>>) {
        self.served = queue;
        self.spent = self.served.as_ref().is_some_and(|served| {
            self.places.iter().any(|place| {
                Arc::ptr_eq(&place.queue, served) && place.seen.is_some_and(Wakes::held)
            })
        });
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut emptied = false;
        for place in &self.places {
            let spent_there = self.spent
                && self
                    .served
                    .as_ref()
                    .is_some_and(|served| Arc::ptr_eq(served, &place.queue));
            emptied |= Self::leave(place, spent_there);
        }
        let others = self.waiting.fetch_sub(1, Ordering::Relaxed) > 1;
        self.announce(emptied, others);
    }
}
