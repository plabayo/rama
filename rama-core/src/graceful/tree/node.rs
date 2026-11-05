//! One node of the scope tree: phase state, causes, signals, waiters and the strong count.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use slab::Slab;
use tokio::time::Instant;

use super::{
    cause::Cause,
    sync::{Arc, AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Mutex, Ordering, fence},
};

const CANCELLED: u8 = 1 << 0;
const ABORTED: u8 = 1 << 1;
const TIMED: u8 = 1 << 2;
const SIGNALS: u8 = 1 << 3;

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

pub(super) struct Node {
    parent: Option<Arc<Self>>,
    // Shared by the whole tree, so instants inherited from an ancestor are stored exactly.
    base: Instant,
    flags: AtomicU8,
    // Offsets in nanoseconds since `base`, `UNSET` when absent.
    cancelled_at: AtomicU64,
    aborted_at: AtomicU64,
    deadline: AtomicU64,
    hard_deadline: AtomicU64,
    // Nanoseconds, `UNSET` when absent.
    grace: AtomicU64,
    // Handles on this node plus live children (each holds one), plus the `CLOSED` bit.
    strong: AtomicUsize,
    causes: Mutex<Causes>,
    // Polled only by the driver holding this lock.
    signals: Mutex<Signals>,
    // Added here, moved into `signals` by the driver, so a signal can add signals while polled.
    incoming: Mutex<Signals>,
    waiters: std::sync::Arc<Waiters>,
    notify: std::sync::Arc<SignalNotify>,
    // Forwards the parent's wakes to `waiters`; made by the first waiter, see `Relay`.
    relay: Mutex<Option<std::sync::Arc<Relay>>>,
    // Set once this node and every ancestor forward their parent's wakes.
    relayed: AtomicBool,
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

/// Scheduled phase instants of a node; they may lie in the future.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Times {
    graceful: Option<Instant>,
    hard: Option<Instant>,
    // Reached without consulting the clock.
    cancelled: bool,
    aborted: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Phase {
    pub(super) graceful: bool,
    pub(super) hard: bool,
    /// The next instant at which the phase changes by time alone.
    pub(super) next: Option<Instant>,
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
        let waiters = std::sync::Arc::new(Waiters::default());
        let relayed = AtomicBool::new(parent.is_none());
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
            signals: Mutex::new(Signals::default()),
            incoming: Mutex::new(Signals::default()),
            waiters: waiters.clone(),
            notify: std::sync::Arc::new(SignalNotify {
                pending: AtomicBool::new(false),
                waiters,
            }),
            relay: Mutex::new(None),
            relayed,
        }
    }

    /// Makes sure every wake of an ancestor's waiters reaches this node's waiters.
    fn ensure_relayed(&self) {
        // Acquire: pairs with the store below, so the relay chain is in place.
        if self.relayed.load(Ordering::Acquire) {
            return;
        }
        let Some(parent) = self.parent() else {
            return;
        };
        parent.ensure_relayed();
        let mut relay = self.relay.lock();
        if relay.is_none() {
            let new = std::sync::Arc::new(Relay {
                parent: parent.waiters.clone(),
                child: self.waiters.clone(),
                state: Mutex::new(RelayState::default()),
            });
            new.register();
            *relay = Some(new);
            self.relayed.store(true, Ordering::Release);
        }
    }

    pub(super) fn parent(&self) -> Option<&Self> {
        self.parent.as_deref()
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
        // `extra` is only cloned below: a caller's cause may run code when dropped, so its
        // last reference goes after every lock is released.
        // Ancestors publish first, so a cause taken from them stays theirs.
        if let Some(parent) = self.parent() {
            let _phase = parent.phase();
        }
        let mut published = false;
        {
            let mut causes = self.causes.lock();
            // A candidate reached after `extra` would lose to it, so its instant serves as now.
            let now = extra.as_ref().map_or_else(Instant::now, |extra| extra.at);
            if flag == ABORTED && causes.abort.is_none() {
                let (_, hard) = self.candidates_locked(&causes);
                if let Some(best) = pick(hard.filter(|c| c.at <= now), extra.clone()) {
                    self.aborted_at
                        .store(self.offset(best.at), Ordering::Relaxed);
                    causes.abort = Some(best.cause);
                    // Release: readers that see the flag also see the instant stored above.
                    self.flags.fetch_or(ABORTED, Ordering::Release);
                    published = true;
                }
            }
            if causes.cancel.is_none() && (flag == CANCELLED || causes.abort.is_some()) {
                let (graceful, _) = self.candidates_locked(&causes);
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
        }
        if published {
            self.drop_settled_signals();
        }
        self.waiters.wake_all();
        drop(extra);
    }

    /// Drops the signals of every reached phase, so what they capture is not held until the
    /// node itself goes away.
    fn drop_settled_signals(&self) {
        let flags = self.flags.load(Ordering::Acquire);
        if flags & SIGNALS == 0 {
            return;
        }
        let Some(mut signals) = self.signals.try_lock() else {
            // Release: the driver holding the lock sees this and clears them next round.
            self.notify.pending.store(true, Ordering::Release);
            return;
        };
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
        drop(signals);
        // Dropped outside the locks: a signal's drop may re-enter the tree.
        drop(settled);
    }

    /// Moves a deadline earlier, never before the moment it is attached.
    pub(super) fn tighten_deadline(&self, hard: bool, at: Instant) {
        let field = if hard {
            &self.hard_deadline
        } else {
            &self.deadline
        };
        field.fetch_min(self.offset(at.max(Instant::now())), Ordering::Release);
        self.flags.fetch_or(TIMED, Ordering::Release);
        self.waiters.wake_all();
    }

    pub(super) fn tighten_grace(&self, grace: Duration) {
        let nanos = u64::try_from(grace.as_nanos())
            .unwrap_or(UNSET - 1)
            .min(UNSET - 1);
        self.grace.fetch_min(nanos, Ordering::Release);
        self.flags.fetch_or(TIMED, Ordering::Release);
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
        self.notify.notify();
    }

    /// Polls this node's signals with the node-owned fan-out waker.
    ///
    /// One driver at a time; a driver that finds the lock taken returns, and the holder
    /// repeats after unlocking when a wake arrived meanwhile. Returns whether it polled: a
    /// polled signal may change any phase, also without completing.
    fn drive_signals(&self) -> bool {
        let mut polled = false;
        for _round in 0..DRIVE_ROUNDS {
            // A signal only progresses after its waker fired or after it was added.
            if self.flags.load(Ordering::Acquire) & SIGNALS == 0
                || !self.notify.pending.load(Ordering::Acquire)
            {
                return polled;
            }
            // Declared before the lock guard: on unwind the lock is released first.
            let rearm = RearmOnPanic(self);
            let Some(mut signals) = self.signals.try_lock() else {
                return polled;
            };
            self.notify.pending.store(false, Ordering::Relaxed);
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

            let waker = Waker::from(self.notify.clone());
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
            drop(signals);

            if hard {
                self.abort(Cause::Signal);
            }
            if graceful {
                self.cancel(Cause::Signal);
            }
            // Acquire: pairs with the store in `SignalNotify::notify`, made before a skipped driver's attempt.
            if !self.notify.pending.load(Ordering::Acquire) {
                return polled;
            }
        }
        // A signal keeps waking itself: leave the next round to the woken waiters.
        self.waiters.wake_all();
        polled
    }

    /// Drives the signals of this node and every ancestor, then returns the phase.
    ///
    /// One walk when no level is timed or past the own phase and no signal is polled; the flags
    /// read on the way stay valid, as a later change wakes the waiter registered before.
    pub(super) fn driven_phase(&self) -> Phase {
        let own = self.flags.load(Ordering::Acquire);
        let mut quick = own & (TIMED | ABORTED) == 0;
        let mut flags = own;
        let mut node = self;
        loop {
            // The pending flag is read here too: an idle signal costs no call.
            if flags & SIGNALS != 0
                && node.notify.pending.load(Ordering::Acquire)
                && node.drive_signals()
            {
                quick = false;
            }
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
            flags = node.flags.load(Ordering::Acquire);
            if flags & (TIMED | ABORTED) != 0 || (flags & CANCELLED != 0 && own & CANCELLED == 0) {
                quick = false;
            }
        }
        if quick {
            Phase {
                graceful: own & CANCELLED != 0,
                hard: false,
                next: None,
            }
        } else {
            self.phase()
        }
    }

    pub(super) fn times(&self) -> Times {
        let parent = self.parent().map(Self::times).unwrap_or_default();
        let flags = self.flags.load(Ordering::Acquire);
        let timed = flags & TIMED != 0;
        let mut times = Times::default();

        // A published phase is fixed; otherwise it is the earliest scheduled candidate.
        if flags & CANCELLED != 0 {
            times.cancelled = true;
            times.graceful = self.instant(&self.cancelled_at);
        } else {
            times.cancelled = parent.cancelled;
            times.graceful = parent.graceful;
            if timed {
                times.graceful = earliest(times.graceful, self.instant(&self.deadline));
            }
        }
        if flags & ABORTED != 0 {
            times.aborted = true;
            times.hard = self.instant(&self.aborted_at);
        } else {
            times.aborted = parent.aborted;
            times.hard = parent.hard;
            if timed {
                times.hard = earliest(times.hard, self.instant(&self.hard_deadline));
                if let Some(grace) = self.grace() {
                    let start = earliest(times.graceful, times.hard);
                    times.hard = earliest(times.hard, start.map(|at| at + grace));
                }
            }
        }
        if flags & CANCELLED == 0 {
            times.graceful = earliest(times.graceful, times.hard);
            times.cancelled |= times.aborted;
        }
        times
    }

    fn grace(&self) -> Option<Duration> {
        match self.grace.load(Ordering::Acquire) {
            UNSET => None,
            nanos => Some(Duration::from_nanos(nanos)),
        }
    }

    /// Current phase; publishes a phase reached by time or through an ancestor.
    pub(super) fn phase(&self) -> Phase {
        let flags = self.flags.load(Ordering::Acquire);
        if let Some(phase) = self.quick_phase(flags) {
            return phase;
        }
        let phase = self.times().phase();
        let flags = self.flags.load(Ordering::Acquire);
        if phase.hard && flags & ABORTED == 0 {
            self.publish(ABORTED, None);
        } else if phase.graceful && flags & CANCELLED == 0 {
            self.publish(CANCELLED, None);
        }
        phase
    }

    /// Phase from flags alone, when no clock is involved and nothing needs publishing.
    fn quick_phase(&self, own: u8) -> Option<Phase> {
        if own & ABORTED != 0 {
            return Some(Phase {
                graceful: true,
                hard: true,
                next: None,
            });
        }
        if own & TIMED != 0 {
            return None;
        }
        let mut node = self.parent();
        while let Some(current) = node {
            let flags = current.flags.load(Ordering::Acquire);
            if flags & (TIMED | ABORTED) != 0 || (flags & CANCELLED != 0 && own & CANCELLED == 0) {
                return None;
            }
            node = current.parent();
        }
        Some(Phase {
            graceful: own & CANCELLED != 0,
            hard: false,
            next: None,
        })
    }

    /// Published graceful and hard causes.
    pub(super) fn causes(&self) -> (Option<Cause>, Option<Cause>) {
        let _phase = self.phase();
        let causes = self.causes.lock();
        (causes.cancel.clone(), causes.abort.clone())
    }

    fn candidates(&self) -> (Option<Candidate>, Option<Candidate>) {
        let causes = self.causes.lock();
        self.candidates_locked(&causes)
    }

    /// Scheduled graceful and hard candidates; a published phase is its only candidate.
    fn candidates_locked(&self, causes: &Causes) -> (Option<Candidate>, Option<Candidate>) {
        let (parent_graceful, parent_hard) = match self.parent() {
            Some(parent) => {
                let (graceful, hard) = parent.candidates();
                let as_parent = |c: Candidate| Candidate {
                    rank: RANK_PARENT,
                    ..c
                };
                (graceful.map(as_parent), hard.map(as_parent))
            }
            None => (None, None),
        };
        let flags = self.flags.load(Ordering::Acquire);
        let timed = flags & TIMED != 0;

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
    pub(super) fn retain_held(&self) {
        self.strong.fetch_add(1, Ordering::Relaxed);
    }

    /// Removes a holder; the last one wakes drain observers and lets go of the parent.
    pub(super) fn release(&self) {
        let mut node = Some(self);
        while let Some(current) = node {
            if current.strong.fetch_sub(1, Ordering::Release) & COUNT != 1 {
                return;
            }
            // Acquire: the drain observer woken below sees everything the released holders did.
            fence(Ordering::Acquire);
            current.waiters.wake_all();
            node = current.parent();
        }
    }

    /// Adds a holder unless the node is closed, or drained and cancelled (which closes it).
    ///
    /// Reviving a drained node takes its parent first, so a level never counts a live child
    /// without that child holding it.
    pub(super) fn try_retain(&self) -> bool {
        let mut word = self.strong.load(Ordering::Acquire);
        loop {
            if word & CLOSED != 0 {
                return false;
            }
            if word != 0 {
                match self.strong.compare_exchange_weak(
                    word,
                    word + 1,
                    Ordering::Relaxed,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return true,
                    Err(current) => word = current,
                }
                continue;
            }
            if self.phase().graceful {
                match self
                    .strong
                    .compare_exchange(0, CLOSED, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => return false,
                    Err(current) => word = current,
                }
                continue;
            }
            if let Some(parent) = self.parent()
                && !parent.try_retain()
            {
                return false;
            }
            match self
                .strong
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(current) => {
                    if let Some(parent) = self.parent() {
                        parent.release();
                    }
                    word = current;
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
        let relay = self.relay.lock().take();
        if let Some(relay) = relay {
            relay.close();
        }
    }
}

impl Times {
    pub(super) fn phase(&self) -> Phase {
        if self.aborted {
            return Phase {
                graceful: true,
                hard: true,
                next: None,
            };
        }
        let needs_clock = (!self.cancelled && self.graceful.is_some()) || self.hard.is_some();
        if !needs_clock {
            return Phase {
                graceful: self.cancelled,
                hard: false,
                next: None,
            };
        }
        let now = Instant::now();
        let hard = self.hard.is_some_and(|at| at <= now);
        let graceful = hard || self.cancelled || self.graceful.is_some_and(|at| at <= now);
        let next = if !graceful {
            self.graceful
        } else if !hard {
            self.hard
        } else {
            None
        };
        Phase {
            graceful,
            hard,
            next,
        }
    }
}

fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
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
            self.0.notify.notify();
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

/// Waker handed to a node's signals: marks a drive as needed and wakes every waiter.
pub(super) struct SignalNotify {
    pending: AtomicBool,
    waiters: std::sync::Arc<Waiters>,
}

impl SignalNotify {
    fn notify(&self) {
        self.pending.store(true, Ordering::Release);
        self.waiters.wake_all();
    }
}

impl Wake for SignalNotify {
    fn wake(self: std::sync::Arc<Self>) {
        self.notify();
    }

    fn wake_by_ref(self: &std::sync::Arc<Self>) {
        self.notify();
    }
}

/// A waker on a parent's waiters that wakes the child's waiters, so a waiter registers on
/// its own node only, at any depth.
///
/// It registers itself again before forwarding: a parent wake from then on reaches it, and
/// one that drained it before sees the child woken after its own changes.
struct Relay {
    parent: std::sync::Arc<Waiters>,
    child: std::sync::Arc<Waiters>,
    state: Mutex<RelayState>,
}

#[derive(Default)]
struct RelayState {
    registration: Option<Registration>,
    // Set once the child node is gone.
    closed: bool,
}

impl Relay {
    /// Registers on the parent's waiters, unless the child is gone.
    fn register(self: &std::sync::Arc<Self>) -> bool {
        let mut state = self.state.lock();
        if state.closed {
            return false;
        }
        let waker = Waker::from(self.clone());
        self.parent.register(&mut state.registration, &waker, true);
        true
    }

    fn close(&self) {
        let registration = {
            let mut state = self.state.lock();
            state.closed = true;
            state.registration.take()
        };
        if let Some(registration) = registration {
            self.parent.deregister(registration);
        }
    }

    fn forward(self: &std::sync::Arc<Self>) {
        if self.register() {
            self.child.wake_all();
        }
    }
}

impl Wake for Relay {
    fn wake(self: std::sync::Arc<Self>) {
        self.forward();
    }

    fn wake_by_ref(self: &std::sync::Arc<Self>) {
        self.forward();
    }
}

/// Wakers of futures waiting on a node.
///
/// `wake_all` empties the list and bumps the generation, so a waiter whose generation is
/// current knows its waker is still registered without taking the lock.
#[derive(Default)]
pub(super) struct Waiters {
    slots: Mutex<Slab<Waker>>,
    generation: AtomicU64,
}

/// A waiter's registration on one node.
#[derive(Debug, Clone, Copy)]
pub(super) struct Registration {
    index: usize,
    generation: u64,
}

impl Waiters {
    /// Registers `waker`; `same_waker` says it will wake the waker registered before.
    ///
    /// Wakers are cloned and dropped outside the lock: their code may call back into the tree.
    pub(super) fn register(
        &self,
        registration: &mut Option<Registration>,
        waker: &Waker,
        same_waker: bool,
    ) {
        if same_waker && registration.is_some_and(|r| self.is_current(r)) {
            return;
        }
        let new = waker.clone();
        let replaced = {
            let mut slots = self.slots.lock();
            let generation = self.generation.load(Ordering::Relaxed);
            match registration {
                Some(current) if current.generation == generation => slots
                    .get_mut(current.index)
                    .map(|slot| std::mem::replace(slot, new)),
                _ => {
                    *registration = Some(Registration {
                        index: slots.insert(new),
                        generation,
                    });
                    None
                }
            }
        };
        drop(replaced);
    }

    /// Whether `registration` was not consumed by a wake yet.
    fn is_current(&self, registration: Registration) -> bool {
        // Acquire: pairs with the bump in `wake_all`.
        registration.generation == self.generation.load(Ordering::Acquire)
    }

    pub(super) fn deregister(&self, registration: Registration) {
        if registration.generation != self.generation.load(Ordering::Acquire) {
            return;
        }
        let removed = {
            let mut slots = self.slots.lock();
            if registration.generation == self.generation.load(Ordering::Relaxed) {
                slots.try_remove(registration.index)
            } else {
                None
            }
        };
        drop(removed);
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
struct WakerKey(usize, usize);

impl WakerKey {
    fn of(waker: &Waker) -> Self {
        Self(
            waker.data().addr(),
            std::ptr::from_ref(waker.vtable()).addr(),
        )
    }
}

/// What a [`Wait`] waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Target {
    Graceful,
    Hard,
    Drained,
}

/// Cancel-safe wait on one node; ancestor wakes reach it through the node's [`Relay`].
pub(super) struct Wait {
    node: Option<Arc<Node>>,
    state: WaitState,
}

struct WaitState {
    target: Target,
    registration: Option<Registration>,
    // Identity of the registered waker. Only compared while its registration is current, and
    // the registered clone keeps the waker's data alive until then, so it cannot be reused.
    waker: Option<WakerKey>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    done: bool,
}

impl Wait {
    pub(super) fn new(node: Option<Arc<Node>>, target: Target) -> Self {
        Self {
            node,
            state: WaitState {
                target,
                registration: None,
                waker: None,
                sleep: None,
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
            Target::Graceful => phase.graceful,
            Target::Hard => phase.hard,
        };
        if done { Ok(()) } else { Err(phase.next) }
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
        let key = WakerKey::of(waker);
        let same_waker = self.waker == Some(key);
        if !same_waker {
            self.waker = Some(key);
        }
        node.ensure_relayed();
        node.waiters
            .register(&mut self.registration, waker, same_waker);
    }

    fn deregister(&mut self, node: &Node) {
        if let Some(registration) = self.registration.take() {
            node.waiters.deregister(registration);
        }
    }

    fn poll_node(&mut self, node: &Node, cx: &mut Context<'_>) -> Poll<()> {
        // Checked before registering: a woken waiter completes without touching any lock. A
        // first poll only looks at the published flags, and a waiter still registered with
        // this waker leaves it to the check after registering, which is complete.
        let ready = match self.registration {
            None => self.published(node),
            Some(registration)
                if self.waker == Some(WakerKey::of(cx.waker()))
                    && node.waiters.is_current(registration) =>
            {
                false
            }
            Some(_) => self.check(node, node.phase()).is_ok(),
        };
        if ready {
            return Poll::Ready(());
        }
        loop {
            // Registered before driving: a signal that completes later wakes this waiter.
            self.register(node, cx.waker());
            let next = match self.check(node, node.driven_phase()) {
                Ok(()) => return Poll::Ready(()),
                Err(next) => next,
            };
            let Some(at) = next else {
                self.sleep = None;
                return Poll::Pending;
            };
            let sleep = match &mut self.sleep {
                Some(sleep) => {
                    if sleep.deadline() != at {
                        sleep.as_mut().reset(at);
                    }
                    sleep
                }
                None => self.sleep.insert(Box::pin(tokio::time::sleep_until(at))),
            };
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
    }
}

impl Future for Wait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let Self { node, state } = self.get_mut();
        if state.done {
            return Poll::Ready(());
        }
        let Some(node) = node.as_deref() else {
            // A never scope tracks no holders, so it is drained, and never cancelled or aborted.
            return match state.target {
                Target::Drained => Poll::Ready(()),
                Target::Graceful | Target::Hard => Poll::Pending,
            };
        };
        if state.poll_node(node, cx).is_pending() {
            return Poll::Pending;
        }
        state.deregister(node);
        state.waker = None;
        state.sleep = None;
        state.done = true;
        Poll::Ready(())
    }
}

impl Drop for Wait {
    fn drop(&mut self) {
        if let Some(node) = self.node.as_deref() {
            self.state.deregister(node);
        }
    }
}
