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
}

/// Why a look found neither a connection nor a create permit.
#[derive(Debug, Clone, Copy)]
pub(super) enum Blocked {
    /// The id is at its connection limit: wait for one of its slots.
    Id,
    /// The pool is at its total connection limit: wait for a total slot.
    Total,
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

/// A waiting checkout's place in the lanes it can be served from, and in the
/// pool's count of waiting checkouts. Dropped when the checkout ends: each
/// lane gets back the wakes it sent and the checkout did not use.
pub(super) struct Waiting {
    pub(super) party: Arc<Party>,
    pub(super) places: SmallVec<[Place; 2]>,
    /// The lane of the connection that served the checkout, if filed.
    pub(super) served: Option<Arc<WaitQueue>>,
    /// Whether serving it spent a wake of that lane.
    pub(super) spent: bool,
    pub(super) waiting: Arc<AtomicUsize>,
    pub(super) slot_waiters: Arc<WaitQueue>,
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
}

impl Waiting {
    pub(super) fn new(
        waiting: &Arc<AtomicUsize>,
        slot_waiters: &Arc<WaitQueue>,
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
            waiting: waiting.clone(),
            slot_waiters: slot_waiters.clone(),
        }
    }

    /// Start a look: returns the party's wakes to wait past if it finds nothing.
    pub(super) fn begin_look(&mut self) -> usize {
        let seen = self.party.wakes();
        for place in &mut self.places {
            place.seen = Some(place.waiter.wakes());
            place.looked = false;
        }
        seen
    }

    /// Queue in `queue`, once. Call with the storage lock held, before the
    /// look at the lane's capacity: see [`StoredConnection::freed`].
    pub(super) fn register(&mut self, queue: &Arc<WaitQueue>) {
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
        });
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
        let slot_waiters = self.slot_waiters.clone();
        self.leave_where(|place| !place.looked && !Arc::ptr_eq(&place.queue, &slot_waiters));
    }

    /// A look found nothing: it spent the wakes it answered, and the checkout
    /// leaves the slot waiters unless the look queued there.
    pub(super) fn end_fruitless_look(&mut self) {
        for place in &self.places {
            if let Some(seen) = place.seen {
                place.waiter.spend(seen);
            }
        }
        self.leave_where(|place| !place.looked);
    }

    /// Leave the queues `leave` picks, passing on the wakes each sent.
    pub(super) fn leave_where(&mut self, mut leave: impl FnMut(&Place) -> bool) {
        self.places.retain(|place| {
            if !leave(place) {
                return true;
            }
            for _ in 0..place.queue.remove(&place.waiter) {
                place.queue.wake_one();
            }
            false
        });
    }

    /// The checkout was served by a connection of `lane`, if filed.
    pub(super) fn served(&mut self, lane: Option<Arc<WaitQueue>>) {
        self.served = lane;
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
            let mut held = place.queue.remove(&place.waiter);
            if self.spent
                && self
                    .served
                    .as_ref()
                    .is_some_and(|served| Arc::ptr_eq(served, &place.queue))
            {
                held = held.saturating_sub(1);
            }
            // The capacity these wakes stand for is there for the others.
            for _ in 0..held {
                place.queue.wake_one();
            }
            emptied |= place.queue.is_empty();
        }
        if self.waiting.fetch_sub(1, Ordering::Relaxed) > 1 && emptied {
            // Idle connections of a lane nobody waits in can be evicted now.
            self.slot_waiters.wake_one();
        }
    }
}
