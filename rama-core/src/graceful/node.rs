//! One node of the scope tree: phase state, causes, signals, waiters and the strong count.

use std::{
    future::Future,
    mem::ManuallyDrop,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    ptr::NonNull,
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use rama_utils::collections::smallvec::SmallVec;
use slab::Slab;
use tokio::time::Instant;

use super::{
    cause::Cause,
    sync::{
        Arc, AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Mutex, Ordering, Sleep, fence,
        sleep_until, thread_local,
    },
};

const CANCELLED: u8 = 1 << 0;
const ABORTED: u8 = 1 << 1;
// A deadline or hard deadline is set: a phase is reached by the clock alone.
const TIMED: u8 = 1 << 2;
const SIGNALS: u8 = 1 << 3;
// A grace is set. It counts from a cancel, so it schedules nothing while no
// level is cancelled or timed, and such a chain stays on the quick path.
const GRACE: u8 = 1 << 4;

/// Offset value for "not set".
const UNSET: u64 = u64::MAX;

/// Set in the strong word once the node is drained for good; upgrades fail from then on.
const CLOSED: usize = 1 << (usize::BITS - 1);
const COUNT: usize = !CLOSED;

#[cfg(all(test, rama_loom))]
pub(super) const COUNT_CLOSED: (usize, usize) = (COUNT, CLOSED);

/// Drive rounds before handing a self-waking signal back to the woken waiters.
const DRIVE_ROUNDS: usize = 4;

pub(super) type Signal = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

// Laid out as declared. The count every hold writes comes first, next to the counts of the
// allocation; what a poll or a walk up the chain reads follows past the rarely read fields,
// away from those writes and within reach of a single load.
#[repr(C)]
pub(super) struct Node {
    // Handles on this node plus live children (each holds one), plus the `CLOSED` bit.
    strong: AtomicUsize,
    // Shared by the whole tree, so instants inherited from an ancestor are stored exactly.
    base: Instant,
    // Offsets in nanoseconds since `base`, `UNSET` when absent.
    cancelled_at: AtomicU64,
    aborted_at: AtomicU64,
    // Nanoseconds, `UNSET` when absent.
    grace: AtomicU64,
    parent: Option<Arc<Self>>,
    flags: AtomicU8,
    // Set once the wakes of every ancestor are forwarded to `waiters`, see `Relay`.
    relayed: AtomicBool,
    // Shared with the waiters of the children, which register it on those of this node to
    // have its wakes forwarded, and with this node's signals as their waker.
    waiters: std::sync::Arc<Waiters>,
    // Offsets as for `cancelled_at`.
    deadline: AtomicU64,
    hard_deadline: AtomicU64,
    causes: Mutex<Causes>,
    // Polled only by the driver holding this lock.
    signals: Mutex<Driven>,
    // Added here, moved into `signals` by the driver, so a signal can add signals while polled.
    incoming: Mutex<Signals>,
}

#[derive(Default)]
struct Causes {
    cancel: Option<Cause>,
    abort: Option<Cause>,
}

#[derive(Default)]
struct Signals {
    graceful: Vec<Signal>,
    hard: Vec<Signal>,
}

/// The signals a driver polls, and what it polls them with.
#[derive(Default)]
struct Driven {
    signals: Signals,
    // The waker of the signals of a node below a parent, made by its first drive.
    waker: Option<Waker>,
}

/// Scheduled phase instants of a node, as offsets (`UNSET` without one); they may lie in
/// the future.
#[derive(Debug, Clone, Copy)]
struct Times {
    graceful: u64,
    hard: u64,
    // Reached without consulting the clock.
    cancelled: bool,
    aborted: bool,
}

/// How far a node got: the hard phase comes with the graceful one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Stage {
    Open,
    Graceful,
    Hard,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Phase {
    pub(super) stage: Stage,
    /// The next instant at which the phase changes by time alone.
    pub(super) next: Option<Instant>,
}

impl Phase {
    const HARD: Self = Self {
        stage: Stage::Hard,
        next: None,
    };

    /// The phase of a node only cancelled, or not even that, by its own flags.
    const fn settled(cancelled: bool) -> Self {
        Self {
            stage: if cancelled {
                Stage::Graceful
            } else {
                Stage::Open
            },
            next: None,
        }
    }

    /// The phase of a node [settled](is_settled) by its flags `own`.
    #[inline]
    const fn settled_by(own: u8) -> Self {
        if own & ABORTED != 0 {
            Self::HARD
        } else {
            Self::settled(own & CANCELLED != 0)
        }
    }

    pub(super) fn graceful(self) -> bool {
        self.stage >= Stage::Graceful
    }

    pub(super) fn hard(self) -> bool {
        self.stage == Stage::Hard
    }

    pub(super) fn reached(self, hard: bool) -> bool {
        if hard { self.hard() } else { self.graceful() }
    }
}

/// Graceful or hard phase candidate, ordered by instant and then local-first rank.
#[derive(Debug, Clone)]
struct Candidate {
    at: Instant,
    rank: u8,
    cause: Cause,
}

const RANK_TRIGGER: u8 = 0;
const RANK_SIGNAL: u8 = 1;
const RANK_DEADLINE: u8 = 2;
const RANK_GRACE: u8 = 3;
const RANK_PARENT: u8 = 4;

impl Node {
    /// Creates a node with one holder; `parent` must be held by the caller.
    pub(super) fn new_held(parent: Option<Arc<Self>>) -> Self {
        let base = match &parent {
            Some(parent) => {
                parent.retain_held();
                parent.base
            }
            None => Instant::now(),
        };
        let root = parent.is_none();
        let relayed = AtomicBool::new(root);
        Self {
            parent,
            base,
            flags: AtomicU8::new(0),
            cancelled_at: AtomicU64::new(UNSET),
            aborted_at: AtomicU64::new(UNSET),
            deadline: AtomicU64::new(UNSET),
            hard_deadline: AtomicU64::new(UNSET),
            grace: AtomicU64::new(UNSET),
            strong: AtomicUsize::new(1),
            causes: Mutex::new(Causes::default()),
            signals: Mutex::new(Driven::default()),
            incoming: Mutex::new(Signals::default()),
            waiters: std::sync::Arc::new(Waiters::new(root)),
            relayed,
        }
    }

    /// Makes sure every wake of an ancestor's waiters reaches this node's waiters.
    #[inline]
    fn ensure_relayed(&self) {
        // Acquire: pairs with the store in `install_relay`, so the relay chain is in place.
        if !self.relayed.load(Ordering::Acquire) {
            self.install_relays();
        }
    }

    /// Relays this node and every ancestor that is not yet; once per node, off the poll path.
    #[cold]
    #[inline(never)]
    fn install_relays(&self) {
        // Installed from the relayed end down, without recursion: a deep tree costs no stack.
        let mut missing: SmallVec<[&Self; 8]> = SmallVec::new();
        let mut node = Some(self);
        while let Some(current) = node {
            if current.relayed.load(Ordering::Acquire) {
                break;
            }
            missing.push(current);
            node = current.parent();
        }
        for node in missing.iter().rev() {
            node.install_relay();
        }
    }

    /// Has the wakes of its parent's waiters forwarded to those of this node; its parent
    /// must be relayed already.
    fn install_relay(&self) {
        let Some(parent) = self.parent() else {
            return;
        };
        self.waiters.relay_from(&parent.waiters);
        self.relayed.store(true, Ordering::Release);
    }

    pub(super) fn parent(&self) -> Option<&Self> {
        self.parent.as_deref()
    }

    /// This node and its ancestors, nearest first. Every walk over them is a loop, so a
    /// deep tree costs no stack.
    fn chain(&self) -> SmallVec<[&Self; 8]> {
        let mut chain = SmallVec::new();
        let mut node = Some(self);
        while let Some(current) = node {
            chain.push(current);
            node = current.parent();
        }
        #[cfg(all(test, not(rama_loom)))]
        walk_steps::add(chain.len());
        chain
    }

    #[cfg(all(test, not(rama_loom)))]
    pub(super) fn waiters(&self) -> &Waiters {
        &self.waiters
    }

    fn offset(&self, at: Instant) -> u64 {
        let nanos = at.saturating_duration_since(self.base).as_nanos();
        u64::try_from(nanos).unwrap_or(UNSET - 1).min(UNSET - 1)
    }

    fn instant(&self, field: &AtomicU64) -> Option<Instant> {
        match field.load(Ordering::Acquire) {
            UNSET => None,
            offset => Some(self.base + Duration::from_nanos(offset)),
        }
    }

    pub(super) fn cancel(&self, cause: Cause) {
        let at = Instant::now();
        self.publish(
            CANCELLED,
            Some(Candidate {
                at,
                rank: rank_of(&cause),
                cause,
            }),
        );
    }

    pub(super) fn abort(&self, cause: Cause) {
        let at = Instant::now();
        self.publish(
            ABORTED,
            Some(Candidate {
                at,
                rank: rank_of(&cause),
                cause,
            }),
        );
    }

    /// Publishes a phase once: picks the earliest reached candidate (plus `extra`) and fixes
    /// its instant and cause; later candidates never change a published phase.
    fn publish(&self, flag: u8, extra: Option<Candidate>) {
        // Ancestors publish first, so a cause taken from them stays theirs.
        let parent = match self.parent() {
            Some(parent) => {
                let _phase = parent.phase();
                parent.candidates()
            }
            None => (None, None),
        };
        let _own = self.publish_with(flag, extra, as_parent(parent), false, true);
    }

    /// Publishes `flag` (or nothing for `0`) given the candidates of the parent, and returns
    /// whether it published, plus the candidates of this node for its children if `children`.
    /// Wakes its waiters if `wake`.
    fn publish_with(
        &self,
        flag: u8,
        extra: Option<Candidate>,
        parent: Candidates,
        children: bool,
        wake: bool,
    ) -> (Candidates, bool) {
        // `extra` is only cloned below: a caller's cause may run code when dropped, so its
        // last reference goes after every lock is released.
        let mut published = false;
        let mut own = (None, None);
        {
            let mut causes = self.causes.lock();
            // A candidate reached after `extra` would lose to it, so its instant serves as now.
            let now = extra.as_ref().map_or_else(Instant::now, |extra| extra.at);
            if flag == ABORTED && causes.abort.is_none() {
                let (_, hard) = self.own_candidates(&causes, parent.clone());
                if let Some(best) = pick(hard.filter(|c| c.at <= now), extra.clone()) {
                    self.aborted_at
                        .store(self.offset(best.at), Ordering::Relaxed);
                    causes.abort = Some(best.cause);
                    // Release: readers that see the flag also see the instant stored above.
                    self.flags.fetch_or(ABORTED, Ordering::Release);
                    published = true;
                }
            }
            if flag != 0 && causes.cancel.is_none() && (flag == CANCELLED || causes.abort.is_some())
            {
                let (graceful, _) = self.own_candidates(&causes, parent.clone());
                let extra = if flag == CANCELLED {
                    extra.clone()
                } else {
                    None
                };
                if let Some(best) = pick(graceful.filter(|c| c.at <= now), extra) {
                    self.cancelled_at
                        .store(self.offset(best.at), Ordering::Relaxed);
                    causes.cancel = Some(best.cause);
                    self.flags.fetch_or(CANCELLED, Ordering::Release);
                    published = true;
                }
            }
            if children {
                own = self.own_candidates(&causes, parent);
            }
        }
        if published {
            self.drop_settled_signals();
        }
        if wake && flag != 0 {
            self.waiters.wake_all();
        }
        drop(extra);
        (own, published)
    }

    /// Drops the signals of every reached phase, so what they capture is not held until the
    /// node itself goes away.
    fn drop_settled_signals(&self) {
        let flags = self.flags.load(Ordering::Acquire);
        if flags & SIGNALS == 0 {
            return;
        }
        let Some(mut driven) = self.signals.try_lock() else {
            // Release: the driver holding the lock sees this and clears them next round.
            self.waiters.signalled.store(true, Ordering::Release);
            return;
        };
        let signals = &mut driven.signals;
        let mut settled = Signals::default();
        {
            let mut incoming = self.incoming.lock();
            if flags & (CANCELLED | ABORTED) != 0 {
                settled.graceful.append(&mut signals.graceful);
                settled.graceful.append(&mut incoming.graceful);
            }
            if flags & ABORTED != 0 {
                settled.hard.append(&mut signals.hard);
                settled.hard.append(&mut incoming.hard);
            }
        }
        drop(driven);
        // Dropped outside the locks: a signal's drop may re-enter the tree.
        drop(settled);
    }

    /// Moves a deadline earlier, never before the moment it is attached.
    pub(super) fn tighten_deadline(&self, hard: bool, at: Instant) {
        self.tighten_coming_deadline(hard, at.max(Instant::now()));
    }

    /// Moves a deadline earlier, to an instant the caller knows is not before the moment it
    /// is attached: the clock is not read for it.
    pub(super) fn tighten_coming_deadline(&self, hard: bool, at: Instant) {
        let field = if hard {
            &self.hard_deadline
        } else {
            &self.deadline
        };
        field.fetch_min(self.offset(at), Ordering::Release);
        self.flags.fetch_or(TIMED, Ordering::Release);
        self.waiters.wake_all();
    }

    pub(super) fn tighten_grace(&self, grace: Duration) {
        let nanos = u64::try_from(grace.as_nanos())
            .unwrap_or(UNSET - 1)
            .min(UNSET - 1);
        self.grace.fetch_min(nanos, Ordering::Release);
        self.flags.fetch_or(GRACE, Ordering::Release);
        self.waiters.wake_all();
    }

    pub(super) fn add_signal(&self, hard: bool, signal: Signal) {
        {
            let mut incoming = self.incoming.lock();
            if hard {
                incoming.hard.push(signal);
            } else {
                incoming.graceful.push(signal);
            }
        }
        self.flags.fetch_or(SIGNALS, Ordering::Release);
        self.waiters.signal();
    }

    /// Polls this node's signals with the node-owned fan-out waker.
    ///
    /// One driver at a time; a driver that finds the lock taken returns, and the holder
    /// repeats after unlocking when a wake arrived meanwhile. Returns whether it polled: a
    /// polled signal may change any phase, also without completing.
    #[cold]
    #[inline(never)]
    fn drive_signals(&self) -> bool {
        let mut polled = false;
        for _round in 0..DRIVE_ROUNDS {
            // A signal only progresses after its waker fired or after it was added.
            if self.flags.load(Ordering::Acquire) & SIGNALS == 0
                || !self.waiters.signalled.load(Ordering::Acquire)
            {
                return polled;
            }
            // Declared before the lock guard: on unwind the lock is released first.
            let rearm = RearmOnPanic(self);
            let Some(mut driven) = self.signals.try_lock() else {
                return polled;
            };
            let Driven { signals, waker } = &mut *driven;
            self.waiters.signalled.store(false, Ordering::Relaxed);
            polled = true;
            {
                let mut incoming = self.incoming.lock();
                signals.graceful.append(&mut incoming.graceful);
                signals.hard.append(&mut incoming.hard);
            }

            let flags = self.flags.load(Ordering::Acquire);
            if flags & (CANCELLED | ABORTED) != 0 {
                signals.graceful.clear();
            }
            if flags & ABORTED != 0 {
                signals.hard.clear();
            }

            let waker = self.waiters.signal_waker(waker);
            let mut cx = Context::from_waker(&waker);
            let graceful = poll_any(&mut signals.graceful, &mut cx);
            let hard = poll_any(&mut signals.hard, &mut cx);
            if signals.graceful.is_empty() && signals.hard.is_empty() {
                let incoming = self.incoming.lock();
                // Cleared under the incoming lock: a racing `add_signal` sets it again after.
                if incoming.graceful.is_empty() && incoming.hard.is_empty() {
                    self.flags.fetch_and(!SIGNALS, Ordering::Relaxed);
                }
            }
            drop(rearm);
            drop(driven);

            if hard {
                self.abort(Cause::Signal);
            }
            if graceful {
                self.cancel(Cause::Signal);
            }
            // Acquire: pairs with the store in `Waiters::signal`, made before a skipped driver's attempt.
            if !self.waiters.signalled.load(Ordering::Acquire) {
                return polled;
            }
        }
        // A signal keeps waking itself: leave the next round to the woken waiters.
        self.waiters.wake_all();
        polled
    }

    /// Drives the signals of this node and every ancestor, then returns the phase.
    ///
    /// One walk when no signal is polled and no level has a phase to publish; the flags read
    /// on the way stay valid, as a later change wakes the waiter registered before.
    pub(super) fn driven_phase(&self) -> Phase {
        self.driven_phase_by(Instant::now)
    }

    /// As [`Self::driven_phase`], with `now` in place of a read of the clock where an open
    /// chain is judged by its deadlines: a reading the caller took for this poll.
    pub(super) fn driven_phase_at(&self, now: Instant) -> Phase {
        self.driven_phase_by(|| now)
    }

    /// [`Self::driven_phase`], an open chain judged at the instant `now` gives.
    #[inline(always)]
    fn driven_phase_by(&self, now: impl FnOnce() -> Instant) -> Phase {
        let own = self.flags.load(Ordering::Acquire);
        let mut seen = own;
        let mut earliest = UNSET;
        let mut polled = false;
        let mut flags = own;
        let mut node = self;
        loop {
            if flags & (SIGNALS | TIMED | GRACE) != 0 {
                // The pending flag is read here too: an idle signal costs no call.
                if flags & SIGNALS != 0
                    && node.waiters.signalled.load(Ordering::Acquire)
                    && node.drive_signals()
                {
                    polled = true;
                }
                earliest = node.earliest_deadline(flags, earliest);
            }
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
            flags = node.flags.load(Ordering::Acquire);
            seen |= flags;
        }
        if polled {
            // A polled signal may have changed any level.
            self.phase()
        } else if is_settled(own, seen) {
            Phase::settled_by(own)
        } else if seen & (CANCELLED | ABORTED) != 0 {
            self.phase_slow()
        } else {
            match self.open_until_by(earliest, now) {
                Some(phase) => phase,
                None => self.phase_slow(),
            }
        }
    }

    /// The earlier of `earliest` and the deadlines of this node, whose flags are `flags`.
    #[inline]
    fn earliest_deadline(&self, flags: u8, earliest: u64) -> u64 {
        // The levels whose deadlines count, as for `Self::own_times`.
        if flags & (TIMED | GRACE) == 0 {
            return earliest;
        }
        earliest
            .min(self.deadline.load(Ordering::Acquire))
            .min(self.hard_deadline.load(Ordering::Acquire))
    }

    /// The phase of a chain without a cancelled level, whose earliest deadline is at the
    /// offset `earliest`: every level is open until then, as a grace only counts from a
    /// cancel. `None` without a deadline, or once it is reached.
    fn open_until(&self, earliest: u64) -> Option<Phase> {
        self.open_until_by(earliest, Instant::now)
    }

    /// [`Self::open_until`], judged at the instant `now` gives.
    #[inline(always)]
    fn open_until_by(&self, earliest: u64, now: impl FnOnce() -> Instant) -> Option<Phase> {
        if earliest == UNSET {
            return None;
        }
        let at = self.base + Duration::from_nanos(earliest);
        (now() < at).then_some(Phase {
            stage: Stage::Open,
            next: Some(at),
        })
    }

    /// The own flags, when the phase follows from them alone and no signal of this node or
    /// an ancestor waits to be driven: what [`Self::driven_phase`] then returns without a call.
    #[inline]
    fn settled_flags(&self) -> Option<u8> {
        let own = self.flags.load(Ordering::Acquire);
        let mut seen = own;
        let mut flags = own;
        let mut node = self;
        loop {
            if flags & SIGNALS != 0 && node.waiters.signalled.load(Ordering::Acquire) {
                return None;
            }
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
            flags = node.flags.load(Ordering::Acquire);
            seen |= flags;
        }
        is_settled(own, seen).then_some(own)
    }

    /// The times of this node, given those of its parent, and the flags they were read with.
    #[inline]
    fn own_times(&self, parent: Times) -> (Times, u8) {
        let flags = self.flags.load(Ordering::Acquire);
        let timed = flags & (TIMED | GRACE) != 0;
        let mut times = parent;

        // A published phase is fixed; otherwise it is the earliest scheduled candidate.
        if flags & CANCELLED != 0 {
            times.cancelled = true;
            times.graceful = self.cancelled_at.load(Ordering::Acquire);
        } else if timed {
            times.graceful = times.graceful.min(self.deadline.load(Ordering::Acquire));
        }
        if flags & ABORTED != 0 {
            times.aborted = true;
            times.hard = self.aborted_at.load(Ordering::Acquire);
        } else if timed {
            times.hard = times.hard.min(self.hard_deadline.load(Ordering::Acquire));
            let grace = self.grace.load(Ordering::Acquire);
            let start = times.graceful.min(times.hard);
            if grace != UNSET && start != UNSET {
                times.hard = times.hard.min(start.saturating_add(grace).min(UNSET - 1));
            }
        }
        if flags & CANCELLED == 0 {
            times.graceful = times.graceful.min(times.hard);
            times.cancelled |= times.aborted;
        }
        (times, flags)
    }

    fn grace(&self) -> Option<Duration> {
        match self.grace.load(Ordering::Acquire) {
            UNSET => None,
            nanos => Some(Duration::from_nanos(nanos)),
        }
    }

    /// Current phase; publishes a phase reached by time or through an ancestor.
    #[inline]
    pub(super) fn phase(&self) -> Phase {
        let own = self.flags.load(Ordering::Acquire);
        if own & ABORTED != 0 {
            return Phase::HARD;
        }
        let seen = self.seen_flags(own);
        if is_settled(own, seen) {
            Phase::settled_by(own)
        } else {
            self.unsettled_phase(seen)
        }
    }

    /// As [`Self::phase`], and whether the walk up published every phase reached on the way.
    #[inline]
    pub(super) fn phase_walked(&self) -> (Phase, bool) {
        let own = self.flags.load(Ordering::Acquire);
        if own & ABORTED != 0 {
            return (Phase::HARD, false);
        }
        let seen = self.seen_flags(own);
        if is_settled(own, seen) {
            return (Phase::settled_by(own), false);
        }
        self.unsettled_phase_walked(seen)
    }

    /// As [`Self::unsettled_phase`], and whether it walked up to publish.
    #[inline(never)]
    fn unsettled_phase_walked(&self, seen: u8) -> (Phase, bool) {
        match self.timed_phase(seen) {
            Some(phase) => (phase, false),
            None => (self.phase_slow(), true),
        }
    }

    /// The flags of every level of the chain of this node, whose own are `own`.
    #[inline]
    fn seen_flags(&self, own: u8) -> u8 {
        let mut seen = own;
        let mut node = self.parent();
        while let Some(current) = node {
            #[cfg(all(test, not(rama_loom)))]
            walk_steps::add(1);
            seen |= current.flags.load(Ordering::Acquire);
            node = current.parent();
        }
        seen
    }

    /// The phase of a chain that is not settled by its flags, which were `seen`.
    #[inline(never)]
    fn unsettled_phase(&self, seen: u8) -> Phase {
        if seen & (CANCELLED | ABORTED) != 0 {
            return self.phase_slow();
        }
        match self.timed_phase(seen) {
            Some(phase) => phase,
            None => self.phase_slow(),
        }
    }

    /// The phase when a clock or an ancestor is involved; kept out of the quick path.
    #[cold]
    #[inline(never)]
    fn phase_slow(&self) -> Phase {
        // A chain of a few levels is walked from a buffer on the stack.
        let mut levels = [self; 8];
        let mut len = 0;
        let mut node = Some(self);
        while let Some(current) = node {
            let Some(level) = levels.get_mut(len) else {
                return self.chain_phase(&self.chain());
            };
            *level = current;
            len += 1;
            node = current.parent();
        }
        #[cfg(all(test, not(rama_loom)))]
        walk_steps::add(len);
        self.chain_phase(levels.get(..len).unwrap_or_default())
    }

    /// The phase of this node, whose chain is `chain`, publishing what is reached on it.
    #[inline]
    fn chain_phase(&self, chain: &[&Self]) -> Phase {
        let mut times = Times::NONE;
        // Whether a level is in a phase it has yet to publish, and the earliest offset at
        // which a level gets to a phase by time.
        let mut unpublished = false;
        let mut pending = UNSET;
        // Root first: the times of a level follow from those above it.
        for node in chain.iter().rev() {
            let flags;
            (times, flags) = node.own_times(times);
            if times.aborted {
                unpublished |= flags & (CANCELLED | ABORTED) != CANCELLED | ABORTED;
                continue;
            }
            pending = pending.min(times.hard);
            if times.cancelled {
                unpublished |= flags & CANCELLED == 0;
            } else {
                pending = pending.min(times.graceful);
            }
        }
        let (stage, next) = if times.aborted {
            (Stage::Hard, UNSET)
        } else if times.cancelled {
            (Stage::Graceful, times.hard)
        } else {
            (Stage::Open, times.graceful)
        };
        // One conversion in the common case: what is pending is what this node waits for.
        let next_at = self.instant_at(next);
        let pending_at = if pending == next {
            next_at
        } else {
            self.instant_at(pending)
        };
        if unpublished || pending_at.is_some_and(|at| at <= Instant::now()) {
            return self.publish_reached(chain);
        }
        Phase {
            stage,
            next: next_at,
        }
    }

    /// The instant at `offset`, if it is one.
    fn instant_at(&self, offset: u64) -> Option<Instant> {
        match offset {
            UNSET => None,
            offset => Some(self.base + Duration::from_nanos(offset)),
        }
    }

    /// The flag of the phase that this node has not published, though it got to `stage`.
    #[inline]
    fn unpublished(&self, stage: Stage) -> u8 {
        let flags = self.flags.load(Ordering::Acquire);
        if stage == Stage::Hard && flags & ABORTED == 0 {
            ABORTED
        } else if stage >= Stage::Graceful && flags & CANCELLED == 0 {
            CANCELLED
        } else {
            0
        }
    }

    /// Publishes every phase reached on `chain`, which is that of this node, and returns the
    /// phase of this node, all at one instant.
    #[cold]
    #[inline(never)]
    fn publish_reached(&self, chain: &[&Self]) -> Phase {
        let now = self.offset(Instant::now());
        let mut times = Times::NONE;
        let mut stage = Stage::Open;
        let mut candidates = (None, None);
        let mut topmost = None;
        // Root first: an ancestor publishes before its children, so a cause taken from it
        // stays its own.
        for (depth, node) in chain.iter().rev().enumerate() {
            (times, _) = node.own_times(times);
            stage = times.stage(now);
            let flag = node.unpublished(stage);
            let children = depth + 1 < chain.len();
            if flag == 0 && !children {
                break;
            }
            let (own, published) = node.publish_with(flag, None, candidates, children, false);
            candidates = as_parent(own);
            if published && topmost.is_none() {
                topmost = Some(*node);
            }
        }
        // Once, at the topmost level that changed: every waiter below has relays up to
        // it, so a wake per level would reach the same waiters once per ancestor.
        if let Some(node) = topmost {
            node.waiters.wake_all();
        }
        Phase {
            stage,
            next: self.instant_at(times.next(stage)),
        }
    }

    /// The phase of a chain that, by the flags `seen` on it, has a deadline and no cancelled
    /// level, when that still holds and the deadline is not reached.
    #[inline]
    fn timed_phase(&self, seen: u8) -> Option<Phase> {
        if seen & (CANCELLED | ABORTED) != 0 {
            return None;
        }
        // Read by a walk of its own, so the chains that have none pay nothing for it.
        let mut earliest = UNSET;
        let mut node = Some(self);
        while let Some(current) = node {
            let flags = current.flags.load(Ordering::Acquire);
            if flags & (CANCELLED | ABORTED) != 0 {
                return None;
            }
            earliest = current.earliest_deadline(flags, earliest);
            node = current.parent();
        }
        self.open_until(earliest)
    }

    /// Published graceful and hard causes.
    pub(super) fn causes(&self) -> (Option<Cause>, Option<Cause>) {
        let _phase = self.phase();
        let causes = self.causes.lock();
        (causes.cancel.clone(), causes.abort.clone())
    }

    /// Publishes every phase reached on the way up, even when this node's own flags would end
    /// the walk of [`Self::phase`] early.
    pub(super) fn publish_up_the_chain(&self) {
        let _phase = self.phase_slow();
    }

    /// Instant of the published graceful (or `hard`) phase, without publishing one reached by
    /// time or through an ancestor first. A published phase never changes, so its cause can be
    /// read later with [`Self::published_so_far`].
    pub(super) fn published_at(&self, hard: bool) -> Option<Instant> {
        let flag = if hard { ABORTED } else { CANCELLED };
        // Acquire: pairs with the publication's Release, after it stored the instant.
        if self.flags.load(Ordering::Acquire) & flag == 0 {
            return None;
        }
        self.instant(if hard {
            &self.aborted_at
        } else {
            &self.cancelled_at
        })
    }

    /// Instants of the published graceful and hard phases, read together, without publishing
    /// one reached by time or through an ancestor first. An abort publishes the cancel it
    /// implies under the same lock, so a read between the two waits for that lock.
    pub(super) fn published_both_at(&self) -> (Option<Instant>, Option<Instant>) {
        let mut flags = self.flags.load(Ordering::Acquire);
        if flags & ABORTED != 0 && flags & CANCELLED == 0 {
            drop(self.causes.lock());
            flags = self.flags.load(Ordering::Acquire);
        }
        let at = |flag: u8, field: &AtomicU64| {
            if flags & flag == 0 {
                None
            } else {
                self.instant(field)
            }
        };
        (
            at(CANCELLED, &self.cancelled_at),
            at(ABORTED, &self.aborted_at),
        )
    }

    /// Instant and cause of the published graceful (or `hard`) phase, without publishing one
    /// reached by time or through an ancestor first.
    pub(super) fn published_so_far(&self, hard: bool) -> Option<(Instant, Cause)> {
        let causes = self.causes.lock();
        let (cause, at) = if hard {
            (&causes.abort, &self.aborted_at)
        } else {
            (&causes.cancel, &self.cancelled_at)
        };
        Some((self.instant(at)?, cause.clone()?))
    }

    /// Graceful and hard candidates of this node, from the root down.
    fn candidates(&self) -> Candidates {
        let mut candidates = (None, None);
        for node in self.chain().iter().rev() {
            let causes = node.causes.lock();
            candidates = node.own_candidates(&causes, as_parent(candidates));
        }
        candidates
    }

    /// Scheduled graceful and hard candidates, given the parent's as parent candidates; a
    /// published phase is its only candidate.
    fn own_candidates(&self, causes: &Causes, parent: Candidates) -> Candidates {
        let (parent_graceful, parent_hard) = parent;
        let flags = self.flags.load(Ordering::Acquire);
        let timed = flags & (TIMED | GRACE) != 0;

        let published_graceful = match (&causes.cancel, self.instant(&self.cancelled_at)) {
            (Some(cause), Some(at)) if flags & CANCELLED != 0 => Some(Candidate {
                at,
                rank: rank_of(cause),
                cause: cause.clone(),
            }),
            _ => None,
        };
        let published_hard = match (&causes.abort, self.instant(&self.aborted_at)) {
            (Some(cause), Some(at)) if flags & ABORTED != 0 => Some(Candidate {
                at,
                rank: rank_of(cause),
                cause: cause.clone(),
            }),
            _ => None,
        };

        let mut graceful = if let Some(published) = published_graceful.clone() {
            Some(published)
        } else {
            let mut graceful = parent_graceful;
            if timed && let Some(at) = self.instant(&self.deadline) {
                graceful = better(graceful, deadline_candidate(at));
            }
            graceful
        };
        let hard = if let Some(published) = published_hard {
            Some(published)
        } else {
            let mut hard = parent_hard;
            if timed {
                if let Some(at) = self.instant(&self.hard_deadline) {
                    hard = better(hard, deadline_candidate(at));
                }
                if let Some(grace) = self.grace() {
                    let start = match (&graceful, &hard) {
                        (Some(g), Some(h)) => Some(g.at.min(h.at)),
                        (Some(g), None) => Some(g.at),
                        (None, Some(h)) => Some(h.at),
                        (None, None) => None,
                    };
                    if let Some(start) = start {
                        hard = better(
                            hard,
                            Candidate {
                                at: start + grace,
                                rank: RANK_GRACE,
                                cause: Cause::GraceElapsed,
                            },
                        );
                    }
                }
            }
            hard
        };
        if published_graceful.is_none()
            && let Some(h) = hard.clone()
        {
            graceful = better(graceful, h);
        }
        (graceful, hard)
    }

    #[cfg(all(test, rama_loom))]
    pub(super) fn strong_word(&self) -> usize {
        self.strong.load(Ordering::Acquire)
    }

    pub(super) fn strong_count(&self) -> usize {
        self.strong.load(Ordering::Acquire) & COUNT
    }

    /// Adds a holder to a node the caller already holds, so it cannot be closed.
    #[inline]
    pub(super) fn retain_held(&self) {
        self.strong.fetch_add(1, Ordering::Relaxed);
    }

    /// Removes a holder; the last one wakes drain observers and lets go of the parent.
    #[inline]
    pub(super) fn release(&self) {
        if self.strong.fetch_sub(1, Ordering::Release) & COUNT != 1 {
            return;
        }
        self.release_drained();
    }

    /// The rest of a release that drained this node: up the chain, then one wake.
    fn release_drained(&self) {
        let mut topmost = self;
        while let Some(parent) = topmost.parent() {
            if parent.strong.fetch_sub(1, Ordering::Release) & COUNT != 1 {
                break;
            }
            topmost = parent;
        }
        // Acquire: the drain observers woken below see everything the released holders did.
        fence(Ordering::Acquire);
        // Once, at the topmost level that drained: every observer below has relays up to it,
        // so a wake per level would reach the same observers once per ancestor.
        topmost.waiters.wake_all();
    }

    /// Adds a holder unless the node is closed, or drained and cancelled (which closes it).
    ///
    /// Reviving a drained node takes its parent first, so a level never counts a live child
    /// without that child holding it.
    #[inline]
    pub(super) fn try_retain(&self) -> bool {
        // A held node takes one more holder at once: neither its phase nor its parent matters.
        let word = self.strong.load(Ordering::Acquire);
        if word != 0
            && word & CLOSED == 0
            && self
                .strong
                .compare_exchange(word, word + 1, Ordering::Relaxed, Ordering::Acquire)
                .is_ok()
        {
            return true;
        }
        self.try_retain_slow()
    }

    #[inline(never)]
    fn try_retain_slow(&self) -> bool {
        // Publishes every phase reached along the chain once, so each level below only
        // checks its own flags.
        let _phase = self.phase();
        // Levels waiting for their parent to be held, nearest last: revival walks up and
        // then down without recursion, so a deep tree costs no stack.
        let mut waiting: SmallVec<[&Self; 8]> = SmallVec::new();
        let mut node = self;
        loop {
            let mut held = loop {
                match node.retain_step() {
                    Retain::Done(held) => break held,
                    Retain::NeedsParent(parent) => {
                        waiting.push(node);
                        node = parent;
                    }
                }
            };
            // Each waiting level now has its parent held, or none will be revived.
            let mut restart = None;
            while let Some(child) = waiting.pop() {
                if !held {
                    return false;
                }
                if child
                    .strong
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    held = true;
                    continue;
                }
                // Its count moved meanwhile: let go of the parent and decide again.
                if let Some(parent) = child.parent() {
                    parent.release();
                }
                restart = Some(child);
                break;
            }
            match restart {
                Some(child) => node = child,
                None => return held,
            }
        }
    }

    /// One revival decision for this level alone: held, refused, or needing its parent.
    fn retain_step(&self) -> Retain<'_> {
        let mut word = self.strong.load(Ordering::Acquire);
        loop {
            if word & CLOSED != 0 {
                return Retain::Done(false);
            }
            if word != 0 {
                match self.strong.compare_exchange_weak(
                    word,
                    word + 1,
                    Ordering::Relaxed,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Retain::Done(true),
                    Err(current) => word = current,
                }
                continue;
            }
            if self.flags.load(Ordering::Acquire) & (CANCELLED | ABORTED) != 0 {
                match self
                    .strong
                    .compare_exchange(0, CLOSED, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => return Retain::Done(false),
                    Err(current) => word = current,
                }
                continue;
            }
            match self.parent() {
                // Reviving takes the parent first, so a level never counts a live child
                // without that child holding it.
                Some(parent) => return Retain::NeedsParent(parent),
                None => {
                    match self
                        .strong
                        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    {
                        Ok(_) => return Retain::Done(true),
                        Err(current) => word = current,
                    }
                }
            }
        }
    }

    /// Marks the node closed if no holder is left; linearized against `try_retain`.
    pub(super) fn close_if_drained(&self) -> bool {
        self.strong
            .compare_exchange(0, CLOSED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            || self.strong.load(Ordering::Acquire) == CLOSED
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // Acquire: pairs with the store in `install_relay`, made once it registered.
        // Iterative destruction below takes an ancestor's parent before dropping it.
        // The relay still owns its registration and must be closed in that case too.
        if self.relayed.load(Ordering::Acquire) && !self.waiters.root {
            self.waiters.close_relay();
        }
        // Ancestors this was the last reference to go one by one, not as nested drops.
        #[cfg(not(all(rama_loom, test)))]
        {
            let mut parent = self.parent.take();
            while let Some(node) = parent {
                parent = Arc::into_inner(node).and_then(|mut node| node.parent.take());
            }
        }
    }
}

/// Whether the phase of a node with flags `own` follows from them alone, given the flags
/// `seen` on its whole chain: it is aborted, or no level has a deadline, a phase the node has
/// yet to publish as its own, or a grace that counts.
#[inline]
const fn is_settled(own: u8, seen: u8) -> bool {
    own & ABORTED != 0
        || (seen & (TIMED | ABORTED) == 0
            && (seen & CANCELLED == 0 || own & CANCELLED != 0)
            && !grace_counts(own, seen))
}

/// Whether a grace somewhere in a chain (`seen`: the flags of every level) may schedule the
/// hard phase of the node with flags `own`: only once that node is cancelled. The callers
/// leave the quick path before this for a cancel above a node that is not.
#[inline]
const fn grace_counts(own: u8, seen: u8) -> bool {
    own & CANCELLED != 0 && seen & GRACE != 0
}

/// Graceful and hard candidates of a node.
type Candidates = (Option<Candidate>, Option<Candidate>);

/// Candidates of a parent, as its children see them.
fn as_parent((graceful, hard): Candidates) -> Candidates {
    let as_parent = |candidate: Candidate| Candidate {
        rank: RANK_PARENT,
        ..candidate
    };
    (graceful.map(as_parent), hard.map(as_parent))
}

/// One revival step of [`Node::try_retain`].
enum Retain<'a> {
    Done(bool),
    NeedsParent(&'a Node),
}

impl Times {
    const NONE: Self = Self {
        graceful: UNSET,
        hard: UNSET,
        cancelled: false,
        aborted: false,
    };

    /// How far a node with these times got at the offset `now`.
    fn stage(&self, now: u64) -> Stage {
        // No offset of the clock gets to `UNSET`, so a time that is not there is not reached.
        if self.aborted || self.hard <= now {
            Stage::Hard
        } else if self.cancelled || self.graceful <= now {
            Stage::Graceful
        } else {
            Stage::Open
        }
    }

    /// The offset at which a node with these times leaves `stage` by time alone, if it does.
    #[inline]
    fn next(&self, stage: Stage) -> u64 {
        match stage {
            _ if self.aborted => UNSET,
            Stage::Open => self.graceful,
            Stage::Graceful => self.hard,
            Stage::Hard => UNSET,
        }
    }
}

fn better(current: Option<Candidate>, candidate: Candidate) -> Option<Candidate> {
    match current {
        Some(current) if (current.at, current.rank) <= (candidate.at, candidate.rank) => {
            Some(current)
        }
        _ => Some(candidate),
    }
}

fn pick(reached: Option<Candidate>, extra: Option<Candidate>) -> Option<Candidate> {
    match (reached, extra) {
        (Some(reached), Some(extra)) => better(Some(reached), extra),
        (reached, None) => reached,
        (None, extra) => extra,
    }
}

fn deadline_candidate(at: Instant) -> Candidate {
    Candidate {
        at,
        rank: RANK_DEADLINE,
        cause: Cause::Deadline,
    }
}

fn rank_of(cause: &Cause) -> u8 {
    match cause {
        Cause::Signal => RANK_SIGNAL,
        _ => RANK_TRIGGER,
    }
}

/// Polls until one signal completes; a signal that panics is dropped, never polled again.
fn poll_any(signals: &mut Vec<Signal>, cx: &mut Context<'_>) -> bool {
    let mut index = 0;
    while index < signals.len() {
        let guard = DropOnPanic { signals, index };
        let ready = guard
            .signals
            .get_mut(index)
            .is_some_and(|signal| signal.as_mut().poll(cx).is_ready());
        drop(guard);
        if ready {
            signals.clear();
            return true;
        }
        index += 1;
    }
    false
}

/// When a signal panics mid-drive: marks the signals as needing a drive again and wakes the
/// waiters, as the panicking driver will not run another round.
struct RearmOnPanic<'a>(&'a Node);

impl Drop for RearmOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.waiters.signal();
        }
    }
}

struct DropOnPanic<'a> {
    signals: &'a mut Vec<Signal>,
    index: usize,
}

impl Drop for DropOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() && self.index < self.signals.len() {
            drop(self.signals.remove(self.index));
        }
    }
}

/// How the wakes of a parent's waiters reach those of a child, so a waiter registers on its
/// own node only, at any depth: the child's waiters are themselves a waker on the parent's,
/// and wake every waiter of the child.
///
/// They register again before forwarding: a parent wake from then on reaches them, and one
/// that drained them before sees the child woken after its own changes.
#[derive(Default)]
struct Relay {
    // The waiters of the parent, from the first waiter of the child until the child is gone.
    parent: Option<std::sync::Arc<Waiters>>,
    registration: Option<Registration>,
}

/// Waiters still to wake by the relay forwarding on this thread, if one is.
type Forwarded = std::cell::RefCell<Option<Vec<std::sync::Arc<Waiters>>>>;

#[cfg(not(all(rama_loom, test)))]
thread_local! {
    static FORWARDING: Forwarded = const { std::cell::RefCell::new(None) };
}

// Loom's macro takes no `const` initializer.
#[cfg(all(rama_loom, test))]
thread_local! {
    static FORWARDING: Forwarded = std::cell::RefCell::new(None);
}

/// Marks this thread as forwarding until dropped, also on unwind.
struct Forwarding;

impl Forwarding {
    fn start() -> Self {
        FORWARDING.with(|forwarding| *forwarding.borrow_mut() = Some(Vec::new()));
        Self
    }
}

impl Drop for Forwarding {
    fn drop(&mut self) {
        // On unwind from a panicking waker, the waiters still queued are not woken.
        FORWARDING.with(|forwarding| *forwarding.borrow_mut() = None);
    }
}

/// Wakers of futures waiting on a node.
///
/// `wake_all` empties the list and bumps the generation, so a waiter whose generation is
/// current knows its waker is still registered without taking the lock.
// Laid out as declared: the lock every registration takes comes first, where taking it
// needs no address computed.
#[repr(C)]
pub(super) struct Waiters {
    slots: Mutex<Slab<Waker>>,
    // Starts at one, so a registration's generation is never zero and fits its niche.
    generation: AtomicU64,
    // Set once a signal of the node asked for a poll, until a driver takes it up.
    signalled: AtomicBool,
    relay: Mutex<Relay>,
    // Whether the node has no parent: its waiters are never a relay, and so are free to be
    // the waker of its signals.
    root: bool,
}

/// The waker of the signals of a node below a parent, whose waiters are a relay when woken.
struct SignalWake(std::sync::Arc<Waiters>);

impl Wake for SignalWake {
    fn wake(self: std::sync::Arc<Self>) {
        self.0.signal();
    }

    fn wake_by_ref(self: &std::sync::Arc<Self>) {
        self.0.signal();
    }
}

/// Below a parent, the [`Relay`] of the parent's wakes. Those of a root, which has nothing
/// to relay, are the waker handed to its signals: marks a drive as needed and wakes every
/// waiter.
impl Wake for Waiters {
    fn wake(self: std::sync::Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &std::sync::Arc<Self>) {
        if self.root {
            self.signal();
        } else {
            self.forward();
        }
    }
}

/// A waiter's registration on one node.
#[derive(Debug, Clone, Copy)]
pub(super) struct Registration {
    index: usize,
    generation: NonZeroU64,
}

impl Waiters {
    fn new(root: bool) -> Self {
        Self {
            slots: Mutex::default(),
            generation: AtomicU64::new(1),
            signalled: AtomicBool::new(false),
            relay: Mutex::default(),
            root,
        }
    }

    /// The waker to poll the signals of the node with; `made` keeps the one of a node below
    /// a parent, which is made once.
    fn signal_waker(self: &std::sync::Arc<Self>, made: &mut Option<Waker>) -> Waker {
        if self.root {
            return Waker::from(self.clone());
        }
        made.get_or_insert_with(|| Waker::from(std::sync::Arc::new(SignalWake(self.clone()))))
            .clone()
    }

    /// Starts forwarding the wakes of `parent`, the waiters of the parent node, unless it
    /// does already.
    fn relay_from(self: &std::sync::Arc<Self>, parent: &std::sync::Arc<Self>) {
        let mut relay = self.relay.lock();
        if relay.parent.is_none() {
            let waker = Waker::from(self.clone());
            parent.register(&mut relay.registration, &waker, true);
            relay.parent = Some(parent.clone());
        }
    }

    /// Registers on the parent's waiters again, unless the child node is gone.
    fn relay_again(self: &std::sync::Arc<Self>) -> bool {
        let mut relay = self.relay.lock();
        let Relay {
            parent: Some(parent),
            registration,
        } = &mut *relay
        else {
            return false;
        };
        let waker = Waker::from(self.clone());
        parent.register(registration, &waker, true);
        true
    }

    /// Ends the forwarding, as the child node goes away.
    fn close_relay(&self) {
        let (parent, registration) = {
            let mut relay = self.relay.lock();
            (relay.parent.take(), relay.registration.take())
        };
        if let Some((parent, registration)) = parent.zip(registration) {
            parent.deregister(registration);
        }
    }

    /// Wakes every waiter, as a wake of the parent's waiters.
    fn forward(self: &std::sync::Arc<Self>) {
        if !self.relay_again() {
            return;
        }
        // A wake reaching a deeper relay while this thread forwards is queued, not nested:
        // a deep tree costs no stack. Each relay registers again before it is queued.
        let queued = FORWARDING.with(|forwarding| match forwarding.borrow_mut().as_mut() {
            Some(queue) => {
                queue.push(self.clone());
                true
            }
            None => false,
        });
        if queued {
            return;
        }
        let _forwarding = Forwarding::start();
        let mut next = Some(self.clone());
        while let Some(waiters) = next {
            waiters.wake_all();
            next =
                FORWARDING.with(|forwarding| forwarding.borrow_mut().as_mut().and_then(Vec::pop));
        }
    }

    /// Registers `waker`; `same_waker` says it will wake the waker registered before. Returns
    /// the identity of the clone it keeps, `None` if it kept the one it had.
    ///
    /// Wakers are cloned and dropped outside the lock: their code may call back into the tree.
    fn register(
        &self,
        registration: &mut Option<Registration>,
        waker: &Waker,
        same_waker: bool,
    ) -> Option<WakerKey> {
        if same_waker && registration.is_some_and(|r| self.is_current(r)) {
            return None;
        }
        let new = waker.clone();
        // A clone need not share the input's address: the identity is the clone's own.
        let key = WakerKey::of(&new);
        let replaced = {
            let mut slots = self.slots.lock();
            let generation = self.generation.load(Ordering::Relaxed);
            match registration {
                Some(current) if current.generation.get() == generation => slots
                    .get_mut(current.index)
                    .map(|slot| std::mem::replace(slot, new)),
                _ => {
                    *registration = Some(Registration {
                        index: slots.insert(new),
                        generation: NonZeroU64::new(generation).unwrap_or(NonZeroU64::MIN),
                    });
                    None
                }
            }
        };
        drop(replaced);
        Some(key)
    }

    /// Whether `registration` was not consumed by a wake yet.
    fn is_current(&self, registration: Registration) -> bool {
        // Acquire: pairs with the bump in `wake_all`.
        registration.generation.get() == self.generation.load(Ordering::Acquire)
    }

    pub(super) fn deregister(&self, registration: Registration) {
        if registration.generation.get() != self.generation.load(Ordering::Acquire) {
            return;
        }
        let removed = {
            let mut slots = self.slots.lock();
            if registration.generation.get() == self.generation.load(Ordering::Relaxed) {
                slots.try_remove(registration.index)
            } else {
                None
            }
        };
        drop(removed);
    }

    /// Marks the signals of the node as needing a drive and wakes every waiter.
    fn signal(&self) {
        self.signalled.store(true, Ordering::Release);
        self.wake_all();
    }

    pub(super) fn wake_all(&self) {
        let mut wakers = {
            let mut slots = self.slots.lock();
            if slots.is_empty() {
                return;
            }
            // Release: a waiter that sees the new generation also sees the state change
            // published before this wake.
            self.generation.fetch_add(1, Ordering::Release);
            std::mem::take(&mut *slots)
        };
        for waker in wakers.drain() {
            waker.wake();
        }
    }

    #[cfg(all(test, not(rama_loom)))]
    pub(super) fn len(&self) -> usize {
        self.slots.lock().len()
    }
}

/// The data and vtable addresses of a waker, as compared by [`Waker::will_wake`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WakerKey(usize, NonZeroUsize);

impl WakerKey {
    fn of(waker: &Waker) -> Self {
        Self(waker.data().addr(), NonNull::from(waker.vtable()).addr())
    }
}

/// What a [`Wait`] waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Target {
    Graceful,
    Hard,
    Drained,
}

/// Cancel-safe wait on one node; ancestor wakes reach it through the [`Relay`] of each level.
pub(super) struct Wait {
    node: Option<Arc<Node>>,
    state: WaitState,
}

struct WaitState {
    target: Target,
    registration: Option<Registration>,
    // Identity of the clone the waiters keep, not of the waker it was cloned from. Only
    // compared while its registration is current, and that clone keeps its data alive until
    // then, so its address cannot be reused.
    waker: Option<WakerKey>,
    // Released by `WaitState::clear_timer`, so a wait without a timer never calls into its drop.
    timer: ManuallyDrop<Option<Pin<Box<Timer>>>>,
    done: bool,
}

pin_project_lite::pin_project! {
    /// The timer of a wait. Once polled again it is polled with a waker of its own, so that
    /// the wait can tell whether the timer asked for a poll, and leaves it alone until it does.
    struct Timer {
        #[pin]
        sleep: Sleep,
        own: Option<TimerWaker>,
        // Whether the last poll of `sleep` with `own` left it pending.
        pending: bool,
    }
}

/// The waker a wait polls its timer with.
struct TimerWaker {
    // Made from `wake`.
    waker: Waker,
    wake: std::sync::Arc<TimerWake>,
}

impl TimerWaker {
    /// A timer waker that wakes the task of `task`.
    fn of(task: &Waker) -> Self {
        let wake = std::sync::Arc::new(TimerWake {
            asked: AtomicBool::new(false),
            task: task.clone(),
        });
        Self {
            waker: Waker::from(wake.clone()),
            wake,
        }
    }
}

/// Notes that the timer asked for a poll, then wakes the task.
struct TimerWake {
    asked: AtomicBool,
    task: Waker,
}

impl Wake for TimerWake {
    fn wake(self: std::sync::Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &std::sync::Arc<Self>) {
        // Set before the task is woken: the poll that wake leads to sees it. Release: pairs
        // with the load in `WaitState::poll_timer`.
        self.asked.store(true, Ordering::Release);
        self.task.wake_by_ref();
    }
}

impl Wait {
    #[inline]
    pub(super) fn new(node: Option<Arc<Node>>, target: Target) -> Self {
        Self {
            node,
            state: WaitState {
                target,
                registration: None,
                waker: None,
                timer: ManuallyDrop::new(None),
                done: false,
            },
        }
    }
}

impl WaitState {
    /// Whether the wait is over, else the instant at which the phase changes by time.
    ///
    /// Computing the phase publishes a reached one, which drops its settled signals: they
    /// may hold the drain.
    fn check(&self, node: &Node, phase: Phase) -> Result<(), Option<Instant>> {
        let done = match self.target {
            Target::Drained => node.strong_count() == 0,
            Target::Graceful => phase.graceful(),
            Target::Hard => phase.hard(),
        };
        if done { Ok(()) } else { Err(phase.next) }
    }

    /// As [`Self::check`] of [`Node::driven_phase`], without a call when the flags say it all.
    #[inline]
    fn check_driven(&self, node: &Node, now: Option<Instant>) -> Result<(), Option<Instant>> {
        match node.settled_flags() {
            Some(own) if self.reached(node, own) => Ok(()),
            Some(_) => Err(None),
            None => self.check(
                node,
                match now {
                    Some(now) => node.driven_phase_at(now),
                    None => node.driven_phase(),
                },
            ),
        }
    }

    fn published(&self, node: &Node) -> bool {
        let flags = node.flags.load(Ordering::Acquire);
        match self.target {
            Target::Graceful => flags & (CANCELLED | ABORTED) != 0,
            Target::Hard => flags & ABORTED != 0,
            Target::Drained => false,
        }
    }

    fn register(&mut self, node: &Node, waker: &Waker) {
        let same_waker = self.waker == Some(WakerKey::of(waker));
        node.ensure_relayed();
        if let Some(key) = node
            .waiters
            .register(&mut self.registration, waker, same_waker)
        {
            self.waker = Some(key);
        }
    }

    #[inline]
    fn clear_timer(&mut self) {
        if self.timer.is_some() {
            self.drop_timer();
        }
    }

    fn drop_timer(&mut self) {
        drop(self.timer.take());
    }

    #[inline]
    fn deregister(&mut self, node: &Node) {
        if let Some(registration) = self.registration.take() {
            node.waiters.deregister(registration);
        }
    }

    /// Whether this wait is registered on `node` with a waker that wakes the same task as
    /// `waker`, so that only the state is left to check.
    #[inline]
    fn is_registered(&self, node: &Node, waker: &Waker) -> bool {
        self.waker == Some(WakerKey::of(waker))
            && self
                .registration
                .is_some_and(|registration| node.waiters.is_current(registration))
    }

    /// Whether a node settled by its flags `own` is where this wait ends.
    #[inline]
    fn reached(&self, node: &Node, own: u8) -> bool {
        match self.target {
            Target::Drained => node.strong_count() == 0,
            Target::Graceful => own & (CANCELLED | ABORTED) != 0,
            Target::Hard => own & ABORTED != 0,
        }
    }

    fn poll_node(&mut self, node: &Node, cx: &mut Context<'_>) -> Poll<()> {
        if !self.is_registered(node, cx.waker()) {
            return self.poll_unregistered(node, cx);
        }
        // No signal to drive and no timer to look after: the flags say it all.
        if self.timer.is_none()
            && let Some(own) = node.settled_flags()
            && !self.reached(node, own)
        {
            return Poll::Pending;
        }
        self.poll_registered(node, cx)
    }

    /// As [`Self::poll_node`], with `now` as its first reading of the clock: one the caller
    /// took for this poll.
    fn poll_node_at(&mut self, node: &Node, cx: &mut Context<'_>, now: Instant) -> Poll<()> {
        if !self.is_registered(node, cx.waker()) {
            return self.poll_unregistered_at(node, cx, now);
        }
        if self.timer.is_none()
            && let Some(own) = node.settled_flags()
            && !self.reached(node, own)
        {
            return Poll::Pending;
        }
        self.poll_registered_at(node, cx, now)
    }

    /// The poll of a registered wait that ends, or has signals or a timer to look after.
    #[inline(never)]
    fn poll_registered(&mut self, node: &Node, cx: &mut Context<'_>) -> Poll<()> {
        self.poll_in_phase(node, cx, node.driven_phase())
    }

    /// As [`Self::poll_registered`], the clock read as `now`.
    #[inline(never)]
    fn poll_registered_at(&mut self, node: &Node, cx: &mut Context<'_>, now: Instant) -> Poll<()> {
        self.poll_in_phase(node, cx, node.driven_phase_at(now))
    }

    /// The poll of a registered wait whose node is in `phase`.
    #[inline(always)]
    fn poll_in_phase(&mut self, node: &Node, cx: &mut Context<'_>, phase: Phase) -> Poll<()> {
        // Nothing to register, and the relays are in place since it registered.
        match self.check(node, phase) {
            Ok(()) => return self.finish(node),
            Err(None) => {
                self.clear_timer();
                return Poll::Pending;
            }
            Err(Some(at)) => {
                if self.poll_timer(at, cx).is_pending() {
                    return Poll::Pending;
                }
            }
        }
        self.poll_elapsed(node, cx)
    }

    /// The poll of a wait whose timer elapsed: around again, as a wait that registers does.
    #[cold]
    #[inline(never)]
    fn poll_elapsed(&mut self, node: &Node, cx: &mut Context<'_>) -> Poll<()> {
        self.poll_registering(node, cx, None)
    }

    /// The poll of a wait that is not registered, or not with this waker.
    #[inline(never)]
    fn poll_unregistered(&mut self, node: &Node, cx: &mut Context<'_>) -> Poll<()> {
        self.poll_unregistered_by(node, cx, None)
    }

    /// As [`Self::poll_unregistered`], the clock first read as `now`.
    #[inline(never)]
    fn poll_unregistered_at(
        &mut self,
        node: &Node,
        cx: &mut Context<'_>,
        now: Instant,
    ) -> Poll<()> {
        self.poll_unregistered_by(node, cx, Some(now))
    }

    /// [`Self::poll_unregistered`], with `now` as the first reading of the clock, if any.
    #[inline(always)]
    fn poll_unregistered_by(
        &mut self,
        node: &Node,
        cx: &mut Context<'_>,
        now: Option<Instant>,
    ) -> Poll<()> {
        // Checked before registering: a woken waiter completes without touching any lock. A
        // first poll only looks at the published flags.
        let ready = match self.registration {
            None => self.published(node),
            Some(_) => self.check(node, node.phase()).is_ok(),
        };
        if ready {
            return self.finish(node);
        }
        self.poll_registering(node, cx, now)
    }

    /// Registers, checks and arms the timer, until the wait is over or left pending. The
    /// first check takes `now` for the clock, if given: a timer that elapsed is newer.
    #[inline(always)]
    fn poll_registering(
        &mut self,
        node: &Node,
        cx: &mut Context<'_>,
        mut now: Option<Instant>,
    ) -> Poll<()> {
        loop {
            // Registered before driving: a signal that completes later wakes this waiter.
            self.register(node, cx.waker());
            let next = match self.check_driven(node, now.take()) {
                Ok(()) => return self.finish(node),
                Err(next) => next,
            };
            let Some(at) = next else {
                self.clear_timer();
                return Poll::Pending;
            };
            if self.poll_timer(at, cx).is_pending() {
                return Poll::Pending;
            }
        }
    }

    /// Polls the timer for `at`, the instant the phase changes at by time alone, unless it is
    /// set for `at` and did not ask for a poll since it was left pending.
    fn poll_timer(&mut self, at: Instant, cx: &mut Context<'_>) -> Poll<()> {
        let Some(timer) = &mut *self.timer else {
            // Polled as the task itself: a wait polled once makes no waker for its timer.
            let timer = self.timer.insert(Box::pin(Timer {
                sleep: sleep_until(at),
                own: None,
                pending: false,
            }));
            return timer.as_mut().project().sleep.poll(cx);
        };
        let mut this = timer.as_mut().project();
        match this.own {
            Some(own) if own.wake.task.will_wake(cx.waker()) => {
                // Acquire: pairs with the store in `TimerWake::wake_by_ref`.
                if *this.pending
                    && this.sleep.deadline() == at
                    && !own.wake.asked.load(Ordering::Acquire)
                {
                    return Poll::Pending;
                }
            }
            _ => {
                let own = TimerWaker::of(cx.waker());
                *this.pending = false;
                let replaced = this.own.replace(own);
                // Dropped once the timer holds the new one: a waker's drop may panic.
                drop(replaced);
            }
        }
        if this.sleep.deadline() != at {
            this.sleep.as_mut().reset(at);
        }
        let Some(own) = this.own else {
            return this.sleep.poll(cx);
        };
        // Cleared before the poll: a timer that asked before is answered by this poll, one
        // that asks from here on sets it again.
        own.wake.asked.store(false, Ordering::Release);
        // Not left pending by a poll that panics.
        *this.pending = false;
        let poll = this.sleep.poll(&mut Context::from_waker(&own.waker));
        *this.pending = poll.is_pending();
        poll
    }

    /// Ends a wait that completed.
    #[inline(always)]
    fn finish(&mut self, node: &Node) -> Poll<()> {
        self.deregister(node);
        self.waker = None;
        self.clear_timer();
        self.done = true;
        Poll::Ready(())
    }
}

impl Wait {
    /// Lets go of the waker and the timer, as dropping the wait does.
    #[inline]
    fn end(&mut self) {
        if let Some(node) = self.node.as_deref() {
            self.state.deregister(node);
        }
        self.state.clear_timer();
    }

    /// Polls as the future does, with `now` as its first reading of the clock: one the caller
    /// took for this poll, so that a poll judged by more than this wait reads it once.
    #[inline]
    pub(super) fn poll_at(&mut self, cx: &mut Context<'_>, now: Instant) -> Poll<()> {
        let Self { node, state } = self;
        if state.done {
            return Poll::Ready(());
        }
        let Some(node) = node.as_deref() else {
            return match state.target {
                Target::Drained => Poll::Ready(()),
                Target::Graceful | Target::Hard => Poll::Pending,
            };
        };
        state.poll_node_at(node, cx, now)
    }
}

impl Future for Wait {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let Self { node, state } = self.get_mut();
        if state.done {
            return Poll::Ready(());
        }
        let Some(node) = node.as_deref() else {
            // A detached scope tracks no holders, so it is drained, and never cancelled or aborted.
            return match state.target {
                Target::Drained => Poll::Ready(()),
                Target::Graceful | Target::Hard => Poll::Pending,
            };
        };
        state.poll_node(node, cx)
    }
}

impl Drop for Wait {
    #[inline]
    fn drop(&mut self) {
        self.end();
    }
}

/// Ancestors visited by the walks of this thread, so tests can bound how a walk scales.
#[cfg(all(test, not(rama_loom)))]
pub(super) mod walk_steps {
    use std::cell::Cell;

    std::thread_local! {
        static STEPS: Cell<usize> = const { Cell::new(0) };
    }

    pub(in super::super) fn add(steps: usize) {
        STEPS.with(|count| count.set(count.get() + steps));
    }

    /// The steps since the last call.
    pub(in super::super) fn take() -> usize {
        STEPS.with(|count| count.replace(0))
    }
}
