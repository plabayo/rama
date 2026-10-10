//! Connects in flight, and the checkouts waiting for them instead of dialing
//! their own: a burst on a multiplexed lane opens the connections it needs, not
//! one each.

use super::*;
use rama_core::error::{BoxErrorExt as _, ErrorExt as _};

/// Connects a cold lane makes before one lands and shows its real capacity.
const COLD_CONNECTS: usize = 2;

/// Which checkouts a connect may serve: those of its id able to use the same
/// keyed lanes, each a classifier and the key a request derives in it.
pub(super) type ConnectKey = SmallVec<[(ReuseKey, ReuseKey); 1]>;

/// The keyed lanes of `lanes`.
pub(super) fn connect_key(lanes: &RequestLanes) -> ConnectKey {
    lanes
        .classes
        .iter()
        .flat_map(|classes| classes.iter())
        .zip(&lanes.keys)
        .filter_map(|(class, key)| Some((class.classifier().clone(), key.clone()?)))
        .collect()
}

/// The connects in flight for one id and keyed lanes, and the checkouts
/// waiting for them.
#[derive(Debug)]
pub(super) struct Connects {
    key: ConnectKey,
    in_flight: AtomicUsize,
    /// A connect is worth a look to as many as it brings streams for.
    pub(super) waiters: Arc<WaitQueue>,
    /// Bumped as a connect lands: the endpoint is up.
    landings: AtomicU64,
    /// Bumped as a connect fails: a waiter that saw none land since it began
    /// waiting fails with it.
    failures: AtomicU64,
    failure: Mutex<Failures>,
    /// Whether its last landing reached none of its waiters (kept by none, or
    /// filed for other keys): its waiters dial their own.
    lands_unusable: AtomicBool,
}

/// The last failure of a group's connects, and the last one its waiters would
/// share, with the failures counted by then.
#[derive(Debug, Default)]
struct Failures {
    last: Option<Failure>,
    shared: Option<(u64, Failure)>,
}

/// The landings and failures of its connects a waiter saw as it began waiting.
#[derive(Debug, Clone, Copy)]
pub(super) struct Seen {
    landings: u64,
    failures: u64,
}

/// How the last connect failed.
#[derive(Debug, Clone)]
pub(super) struct Failure {
    domain: ConnectionErrorDomain,
    kind: ConnectionErrorKind,
    scope: ConnectionPolicyScope,
    cause: Arc<str>,
}

impl Failure {
    fn of(error: &ConnectionError) -> Self {
        Self {
            domain: error.domain(),
            kind: error.kind(),
            scope: error.policy_scope(),
            cause: error.to_string().into(),
        }
    }

    /// Whether its waiters would fail alike: the endpoint failed, or the
    /// connector's own policy. A request's own policy failing says nothing
    /// about theirs: they dial their own.
    pub(super) fn is_shared(&self) -> bool {
        self.scope != ConnectionPolicyScope::Request
            && (self.domain == ConnectionErrorDomain::Transport
                || self.scope == ConnectionPolicyScope::Connector)
    }

    pub(super) fn into_error(self) -> BoxError {
        ConnectionError::new(
            BoxError::from_static_str("the connection this checkout waited for failed")
                .context_str_field("cause", &*self.cause),
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
    pub(super) fn new(key: ConnectKey) -> Self {
        Self {
            key,
            in_flight: AtomicUsize::new(0),
            waiters: Arc::default(),
            landings: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            failure: Mutex::new(Failures::default()),
            lands_unusable: AtomicBool::new(false),
        }
    }

    pub(super) fn is_for(&self, key: &ConnectKey) -> bool {
        self.key == *key
    }

    /// Whether a connection filed in `lane` serves its checkouts.
    pub(super) fn serves(&self, lane: &LaneKey) -> bool {
        match lane {
            LaneKey::Unrestricted => true,
            LaneKey::Keyed(keyed) => self.key.iter().any(|(classifier, key)| {
                classifier == keyed.class.classifier() && *key == keyed.key
            }),
        }
    }

    /// Whether nothing is in flight or waits, so it can be forgotten.
    pub(super) fn is_unused(self: &Arc<Self>) -> bool {
        Arc::strong_count(self) == 1 && self.waiters.is_empty()
    }

    /// What a waiter beginning to wait now sees.
    pub(super) fn seen(&self) -> Seen {
        Seen {
            landings: self.landings.load(Ordering::Acquire),
            failures: self.failures.load(Ordering::Acquire),
        }
    }

    /// Dial, or wait for the connects in flight: a connection brings `streams`,
    /// one of them for its own checkout, and `cold` says that is a guess.
    /// `impatient` dials whatever is in flight, but never past `cap`. Queue in
    /// `waiters` first.
    pub(super) fn coalesce(
        self: &Arc<Self>,
        streams: usize,
        cold: bool,
        impatient: bool,
        cap: Option<NonZeroUsize>,
    ) -> Coalesce {
        let cap = cap.map_or(usize::MAX, NonZeroUsize::get);
        let waiting = self.waiters.len().max(1);
        let mut needed = waiting.div_ceil(streams.saturating_sub(1).max(1));
        if cold {
            needed = needed.min(COLD_CONNECTS);
        }
        let mut in_flight = self.in_flight.load(Ordering::Acquire);
        loop {
            if in_flight >= cap || (in_flight >= needed && !impatient) {
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

    /// How the last connect failed, if one failed since `seen` and none landed:
    /// the endpoint is down for all that waited since.
    pub(super) fn failed_since(&self, seen: Seen) -> Option<Failure> {
        // Failures first: a landing between both reads keeps the waiter going.
        let failures = self.failures.load(Ordering::Acquire);
        if failures == seen.failures || self.landings.load(Ordering::Acquire) != seen.landings {
            return None;
        }
        let known = self.failure.lock();
        known
            .shared
            .as_ref()
            // After the waiter's view, as a serial number: the count wraps.
            .filter(|(at, _)| {
                let after = at.wrapping_sub(seen.failures);
                after != 0 && after <= u64::MAX / 2
            })
            .map(|(_, failure)| failure.clone())
            .or_else(|| known.last.clone())
    }

    /// Whether a connect failed after one landed since `seen`: the endpoint
    /// was up, it may no longer be.
    pub(super) fn failed_after_landing(&self, seen: Seen) -> bool {
        self.failures.load(Ordering::Acquire) != seen.failures
            && self.landings.load(Ordering::Acquire) != seen.landings
    }

    /// Whether its last landing reached none of its waiters.
    pub(super) fn lands_unusable(&self) -> bool {
        self.lands_unusable.load(Ordering::Acquire)
    }

    /// A connection its waiters can use landed, through a claim or not.
    pub(super) fn lands_usable(&self) {
        self.lands_unusable.store(false, Ordering::Release);
    }
}

/// A connect counted in flight: it [lands](Self::landed) or [fails](Self::failed);
/// dropped otherwise, as when the dial is cancelled, a waiter may dial instead.
#[derive(Debug)]
pub(super) struct Connect(Option<Arc<Connects>>);

impl Connect {
    /// Whether it is counted in `connects`.
    pub(super) fn is_in(&self, connects: &Arc<Connects>) -> bool {
        self.0
            .as_ref()
            .is_some_and(|counted| Arc::ptr_eq(counted, connects))
    }

    /// Whether a connection filed in `lane` serves the checkouts waiting for it.
    pub(super) fn serves(&self, lane: &LaneKey) -> bool {
        self.0
            .as_ref()
            .is_some_and(|connects| connects.serves(lane))
    }

    /// The connection takes `streams`, one for its own checkout; `reached`
    /// says whether the others are woken for its waiters, through its lane or
    /// a lane it opens, and `usable` whether they can use it. One more looks
    /// if they are not, or if what is still in flight leaves waiters out, such
    /// as when it takes fewer than guessed: it dials, and passes its wake on to
    /// the next one left out.
    pub(super) fn landed(self, streams: usize, reached: bool, usable: bool) {
        let Some(connects) = self.end() else {
            return;
        };
        connects.lands_unusable.store(!usable, Ordering::Release);
        connects.landings.fetch_add(1, Ordering::AcqRel);
        // Pairs with the fence of a waiter queuing: it is woken, or sees the
        // connect ended.
        fence(Ordering::SeqCst);
        let spare = streams.saturating_sub(1);
        let in_flight = connects.in_flight.load(Ordering::Acquire);
        if !reached
            || connects.waiters.len() > spare.saturating_add(in_flight.saturating_mul(spare))
        {
            connects.waiters.wake_one();
        }
    }

    /// The dial failed with `error`: every waiter looks, and those that saw no
    /// connect land since they began waiting fail with it if it is shared, else
    /// dial their own. None of them waits for another dial to fail.
    pub(super) fn failed(self, error: &ConnectionError) {
        let Some(connects) = self.end() else {
            return;
        };
        let failure = Failure::of(error);
        {
            let mut known = connects.failure.lock();
            let at = connects
                .failures
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1);
            if failure.is_shared() {
                known.shared = Some((at, failure.clone()));
            }
            known.last = Some(failure);
        }
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
