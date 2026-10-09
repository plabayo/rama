//! Connects in flight, and the checkouts waiting for them instead of dialing
//! their own: a burst on a multiplexed lane opens the connections it needs, not
//! one each.

use super::*;
use rama_core::error::BoxErrorExt as _;

/// Connects a cold lane makes before one lands and shows its real capacity.
const COLD_CONNECTS: usize = 2;

/// Which checkouts a connect may serve: those of its id with the same keys.
pub(super) type ConnectKey = SmallVec<[Option<ReuseKey>; 1]>;

/// The connects in flight for one id and keys, and the checkouts waiting for
/// them.
#[derive(Debug, Default)]
pub(super) struct Connects {
    in_flight: AtomicUsize,
    /// A connect is worth a look to as many as it brings streams for.
    pub(super) waiters: Arc<WaitQueue>,
    /// Bumped as the last connect in flight fails: its waiters fail with it.
    failures: AtomicU64,
    failure: Mutex<Option<Failure>>,
}

/// How the last connect failed: its waiters fail the same way.
#[derive(Debug, Clone, Copy)]
pub(super) struct Failure {
    domain: ConnectionErrorDomain,
    kind: ConnectionErrorKind,
    scope: ConnectionPolicyScope,
}

impl Failure {
    pub(super) fn into_error(self) -> BoxError {
        ConnectionError::new(
            BoxError::from_static_str("the connection this checkout waited for failed"),
            self.domain,
            self.kind,
        )
        .with_policy_scope(self.scope)
        .into_box_error()
    }
}

/// What a checkout that found no stream does about the connects of its lane.
pub(super) enum Coalesce {
    /// Dial, counted in flight if the lane multiplexes.
    Dial(Option<Connect>),
    /// Enough connects are in flight: wait for them.
    Wait,
    /// The connects it waited for failed.
    Failed(Failure),
}

impl Connects {
    /// Whether nothing is in flight or waits, so it can be forgotten.
    pub(super) fn is_unused(self: &Arc<Self>) -> bool {
        Arc::strong_count(self) == 1 && self.waiters.is_empty()
    }

    /// The failures so far: a waiter fails once they grow.
    pub(super) fn failures(&self) -> u64 {
        self.failures.load(Ordering::Acquire)
    }

    /// Dial, or wait for the connects in flight: a connection brings `streams`,
    /// one of them for its own checkout, and `cold` says that is a guess.
    /// `impatient` dials whatever is in flight. Queue in `waiters` first.
    pub(super) fn coalesce(
        self: &Arc<Self>,
        streams: usize,
        cold: bool,
        impatient: bool,
    ) -> Coalesce {
        let waiting = self.waiters.len().max(1);
        let mut needed = waiting.div_ceil(streams.saturating_sub(1).max(1));
        if cold {
            needed = needed.min(COLD_CONNECTS);
        }
        let mut in_flight = self.in_flight.load(Ordering::Acquire);
        loop {
            if in_flight >= needed && !impatient {
                return Coalesce::Wait;
            }
            match self.in_flight.compare_exchange_weak(
                in_flight,
                in_flight + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Coalesce::Dial(Some(Connect(Some(self.clone())))),
                Err(now) => in_flight = now,
            }
        }
    }

    /// How the last connect failed, once failures grew past `seen`.
    pub(super) fn failed_since(&self, seen: u64) -> Option<Failure> {
        (self.failures() > seen)
            .then(|| *self.failure.lock())
            .flatten()
    }
}

/// A connect counted in flight: it [lands](Self::landed) or [fails](Self::failed);
/// dropped otherwise, as when the dial is cancelled, a waiter may dial instead.
#[derive(Debug)]
pub(super) struct Connect(Option<Arc<Connects>>);

impl Connect {
    /// The connection is stored and takes `streams`, one for its own checkout:
    /// its lane's waiters take the others. One more looks if what is still in
    /// flight leaves waiters out, such as when it takes fewer than guessed: it
    /// dials, and passes its wake on to the next one left out.
    pub(super) fn landed(self, streams: usize) {
        let Some(connects) = self.end() else {
            return;
        };
        // Pairs with the fence of a waiter queuing: it is woken, or sees the
        // connect ended.
        fence(Ordering::SeqCst);
        let spare = streams.saturating_sub(1);
        let in_flight = connects.in_flight.load(Ordering::Acquire);
        if connects.waiters.len() > spare.saturating_add(in_flight.saturating_mul(spare)) {
            connects.waiters.wake_one();
        }
    }

    /// The dial failed with `error`: with nothing else in flight, its waiters
    /// fail too; else one of them looks.
    pub(super) fn failed(self, error: &ConnectionError) {
        let Some(connects) = self.end() else {
            return;
        };
        if connects.in_flight.load(Ordering::Acquire) != 0 {
            connects.waiters.wake_one();
            return;
        }
        *connects.failure.lock() = Some(Failure {
            domain: error.domain(),
            kind: error.kind(),
            scope: error.policy_scope(),
        });
        connects.failures.fetch_add(1, Ordering::AcqRel);
        connects.waiters.wake_all();
    }

    /// No longer in flight, without the wake of a drop.
    fn end(mut self) -> Option<Arc<Connects>> {
        let connects = self.0.take()?;
        connects.in_flight.fetch_sub(1, Ordering::AcqRel);
        Some(connects)
    }
}

impl Drop for Connect {
    fn drop(&mut self) {
        if let Some(connects) = self.0.take() {
            connects.in_flight.fetch_sub(1, Ordering::AcqRel);
            // One of the waiters may dial instead.
            connects.waiters.wake_one();
        }
    }
}
