use std::{
    collections::{BTreeMap, btree_map::Entry},
    future::{Future, poll_fn},
    ops::Bound,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};

use atomic_waker::AtomicWaker;
use rama_core::{bytes::Bytes, graceful::ShutdownGuard};
use rama_utils::octets::{kib, mib};

use super::UdpDemandSink;

pub const MAX_UDP_DATAGRAM_PAYLOAD_SIZE: usize = u16::MAX as usize;
pub const DEFAULT_UDP_INGRESS_PER_FLOW_MAX_BYTES: usize = kib(256);
pub const DEFAULT_UDP_INGRESS_GLOBAL_MAX_BYTES: usize = mib(16);
pub const DEFAULT_UDP_INGRESS_PROBE_LEASE: Duration = Duration::from_millis(10);
pub const MAX_UDP_INGRESS_PROBE_LEASE: Duration = Duration::from_mins(1);

const INGRESS_OPEN: u8 = 0;
const INGRESS_PAUSED_COUNT: u8 = 1;
const INGRESS_PAUSED_FLOW_BYTES: u8 = 2;
const INGRESS_PAUSED_GLOBAL_BYTES: u8 = 3;
const INGRESS_CLOSED: u8 = 4;
const NO_GLOBAL_WAITER: u64 = u64::MAX;
const NO_RELEASE_WAITER: u64 = u64::MAX;

/// Maximum number of globally blocked flows allowed to issue a new read in
/// one coordinator turn. Admission still happens through the exact global
/// byte counter; this only bounds speculative read fanout when capacity is
/// released.
const GLOBAL_WAKE_BATCH: usize = 4;
/// Bound flow-byte recovery callbacks separately from global lease fanout.
const FLOW_RELEASE_WAKE_BATCH: usize = 4;
/// Bound cold-path FIFO rotation work independently from callback fanout.
/// At 8,192 waiters this caps a full no-fit pass at 256 paced turns while
/// keeping the coordinator mutex hold to a small constant.
const GLOBAL_SCAN_BATCH: usize = 32;
/// Pace bounded coordinator turns independently of ACK/release signals. This
/// limits both callback fanout and finite no-fit queue scans to one turn per
/// millisecond.
const GLOBAL_WAKE_RETRY: Duration = Duration::from_millis(1);
/// A selected Apple read which never completes cannot pin provisional global
/// capacity forever. This is the liveness backstop for a lost/stuck framework
/// callback which never ACKs.
/// Apple ACKs after staging a completed read but before the flow-queue hop
/// which delivers that staged payload to Rust. Keep the exact admission credit
/// alive across that bounded handoff; a broken client still cannot pin it
/// forever.
const GLOBAL_ACKED_PROBE_DELIVERY_GRACE: Duration = Duration::from_millis(250);

struct UdpIngressProbeLease {
    bytes: usize,
    expires_at: tokio::time::Instant,
    read_completed: bool,
    flow: Weak<UdpIngressFlowControl>,
}

/// Sequence-ordered AVL index with the smallest requested size cached below
/// each node. This finds the oldest fitting waiter in O(log N), independently
/// of the number of nonfitting predecessors or distinct datagram sizes.
/// Insertions, removals and rotations also take O(log N); no payload or flow
/// reference is owned here. The FIFO waiter map remains authoritative.
#[derive(Default)]
struct UdpIngressFittingIndex {
    root: Option<Box<UdpIngressFittingNode>>,
}

struct UdpIngressFittingNode {
    sequence: u64,
    needed_bytes: usize,
    minimum_bytes: usize,
    height: u8,
    left: Option<Box<Self>>,
    right: Option<Box<Self>>,
}

impl UdpIngressFittingNode {
    fn height(node: Option<&Self>) -> u8 {
        node.map_or(0, |node| node.height)
    }

    fn minimum(node: Option<&Self>) -> usize {
        node.map_or(usize::MAX, |node| node.minimum_bytes)
    }

    fn refresh(&mut self) {
        self.height =
            1 + Self::height(self.left.as_deref()).max(Self::height(self.right.as_deref()));
        self.minimum_bytes = self
            .needed_bytes
            .min(Self::minimum(self.left.as_deref()))
            .min(Self::minimum(self.right.as_deref()));
    }

    fn rotate_left(mut node: Box<Self>) -> Box<Self> {
        let Some(mut pivot) = node.right.take() else {
            return node;
        };
        node.right = pivot.left.take();
        node.refresh();
        pivot.left = Some(node);
        pivot.refresh();
        pivot
    }

    fn rotate_right(mut node: Box<Self>) -> Box<Self> {
        let Some(mut pivot) = node.left.take() else {
            return node;
        };
        node.left = pivot.right.take();
        node.refresh();
        pivot.right = Some(node);
        pivot.refresh();
        pivot
    }

    fn balance(mut node: Box<Self>) -> Box<Self> {
        node.refresh();
        if Self::height(node.left.as_deref()) > Self::height(node.right.as_deref()) + 1 {
            if let Some(left) = node.left.as_ref()
                && Self::height(left.right.as_deref()) > Self::height(left.left.as_deref())
            {
                node.left = node.left.take().map(Self::rotate_left);
            }
            Self::rotate_right(node)
        } else if Self::height(node.right.as_deref()) > Self::height(node.left.as_deref()) + 1 {
            if let Some(right) = node.right.as_ref()
                && Self::height(right.left.as_deref()) > Self::height(right.right.as_deref())
            {
                node.right = node.right.take().map(Self::rotate_right);
            }
            Self::rotate_left(node)
        } else {
            node
        }
    }

    fn insert(node: Option<Box<Self>>, sequence: u64, needed_bytes: usize) -> Box<Self> {
        let Some(mut node) = node else {
            return Box::new(Self {
                sequence,
                needed_bytes,
                minimum_bytes: needed_bytes,
                height: 1,
                left: None,
                right: None,
            });
        };
        match sequence.cmp(&node.sequence) {
            std::cmp::Ordering::Less => {
                node.left = Some(Self::insert(node.left.take(), sequence, needed_bytes));
            }
            std::cmp::Ordering::Greater => {
                node.right = Some(Self::insert(node.right.take(), sequence, needed_bytes));
            }
            std::cmp::Ordering::Equal => node.needed_bytes = needed_bytes,
        }
        Self::balance(node)
    }

    fn take_first(mut node: Box<Self>) -> (Option<Box<Self>>, Box<Self>) {
        let Some(left) = node.left.take() else {
            return (node.right.take(), node);
        };
        let (left, first) = Self::take_first(left);
        node.left = left;
        (Some(Self::balance(node)), first)
    }

    fn remove(node: Option<Box<Self>>, sequence: u64) -> Option<Box<Self>> {
        let mut node = node?;
        match sequence.cmp(&node.sequence) {
            std::cmp::Ordering::Less => node.left = Self::remove(node.left.take(), sequence),
            std::cmp::Ordering::Greater => node.right = Self::remove(node.right.take(), sequence),
            std::cmp::Ordering::Equal => {
                let Some(left) = node.left.take() else {
                    return node.right.take();
                };
                let Some(right) = node.right.take() else {
                    return Some(left);
                };
                let (right, mut successor) = Self::take_first(right);
                successor.left = Some(left);
                successor.right = right;
                node = successor;
            }
        }
        Some(Self::balance(node))
    }
}

impl UdpIngressFittingIndex {
    fn insert(&mut self, sequence: u64, needed_bytes: usize) {
        self.root = Some(UdpIngressFittingNode::insert(
            self.root.take(),
            sequence,
            needed_bytes,
        ));
    }

    fn remove(&mut self, sequence: u64) {
        self.root = UdpIngressFittingNode::remove(self.root.take(), sequence);
    }

    fn oldest_fitting(&self, available: usize) -> Option<(u64, usize)> {
        let mut node = self.root.as_deref()?;
        if node.minimum_bytes > available {
            return None;
        }
        loop {
            if let Some(left) = node.left.as_deref()
                && left.minimum_bytes <= available
            {
                node = left;
            } else if node.needed_bytes <= available {
                return Some((node.sequence, node.needed_bytes));
            } else {
                node = node.right.as_deref()?;
            }
        }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.root.is_none()
    }
}

#[derive(Default)]
struct UdpIngressCoordinatorState {
    waiters: BTreeMap<(u64, usize), Weak<UdpIngressFlowControl>>,
    /// Derived index of unleased waiters. During discovery it finds the oldest
    /// fitting retry without rescanning the cohort or prioritizing tiny packets.
    fitting_waiters: UdpIngressFittingIndex,
    /// Only flows paused on their own bytes enter this cold-path queue.
    /// Sequence-first keys preserve FIFO order; the pointer keeps identities
    /// distinct even if the sequence wraps during an engine lifetime.
    released_flows: BTreeMap<(u64, usize), Weak<UdpIngressFlowControl>>,
    flow_releases_closed: bool,
    next_release_sequence: u64,
    release_wake_not_before: Option<tokio::time::Instant>,
    leases: BTreeMap<u64, UdpIngressProbeLease>,
    provisional_bytes: usize,
    /// A constant-size cache of the oldest nonfitting waiters encountered in
    /// the exact-fit pass. It starts discovery without revisiting tree nodes
    /// already inspected in that turn; the cursor then covers the remainder.
    discovery_candidates: Vec<((u64, usize), Weak<UdpIngressFlowControl>)>,
    /// After the initial finite exact-fit pass, continue discovery through
    /// this frozen FIFO frontier. A cursor uses the existing tree rather than
    /// retaining an unbounded candidate list or rescanning the population for
    /// each completed small-packet probe.
    discovery_frontier: Option<u64>,
    discovery_cursor: Option<(u64, usize)>,
    /// Alternate useful fitting traffic with discovery when either can spend
    /// the last free byte. Neither lane may monopolize successive grants.
    discovery_prefers_fitting: bool,
    /// Global probe issue pacing. ACK/close signals may free lease slots
    /// immediately, but cannot cause another coordinator issue turn before
    /// this instant.
    wake_not_before: Option<tokio::time::Instant>,
    /// Remaining waiters in the current bounded rotation pass. Real capacity
    /// opportunities restart a quiescent pass, but cannot discard an ongoing
    /// pass or its pending discovery. Continuous fitting releases must still
    /// let stale large-size hints discover a later small QUIC/control packet.
    scan_remaining: usize,
    /// Pending passes can include arrivals until their first inspection.
    /// After that point their finite inspection budget must not be extended.
    scan_started: bool,
    /// Arrivals and releases during either phase receive one later pass;
    /// they cannot reset or extend unfinished discovery.
    scan_needs_followup: bool,
    observed_opportunity_epoch: u64,
}

struct UdpIngressCoordinatorSignal {
    pending: AtomicBool,
    waker: AtomicWaker,
}

impl UdpIngressCoordinatorSignal {
    fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    /// Coalesce any number of release/registration edges into one task wake.
    /// This is the only coordinator operation on an unpaused payload release.
    fn kick(&self) {
        if !self.pending.swap(true, Ordering::Release) {
            self.waker.wake();
        }
    }

    async fn wait(&self) {
        poll_fn(|cx| {
            if self.pending.swap(false, Ordering::AcqRel) {
                return Poll::Ready(());
            }

            self.waker.register(cx.waker());
            if self.pending.swap(false, Ordering::AcqRel) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Kicks received during the retry cooldown are represented by the
    /// capacity re-evaluation that follows it. Clear them before that probe;
    /// a racing later kick remains pending for the next outer turn.
    fn coalesce_before_probe(&self) {
        // Acquire any release that published retained-byte capacity before
        // its kick. A plain store could erase that kick without synchronizing
        // the capacity probe that is meant to replace it.
        _ = self.pending.swap(false, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpIngressDropReason {
    Count,
    FlowBytes,
    GlobalBytes,
}

#[derive(Clone, Copy)]
pub(super) enum UdpIngressBytePressure {
    Flow,
    Global,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct UdpIngressSnapshot {
    pub(super) retained_bytes: usize,
    pub(super) charged_bytes: usize,
    pub(super) peak_retained_bytes: usize,
    pub(super) accepted_datagrams: u64,
    pub(super) accepted_bytes: u64,
    pub(super) dropped_count_full: u64,
    pub(super) dropped_flow_bytes_full: u64,
    pub(super) dropped_global_bytes_full: u64,
    pub(super) resumed_count_full: u64,
    pub(super) resumed_flow_bytes_full: u64,
    pub(super) resumed_global_bytes_full: u64,
    pub(super) paused_transitions: u64,
    pub(super) resumed_transitions: u64,
    pub(super) global_waiters: usize,
    pub(super) provisional_probe_bytes: usize,
    pub(super) provisional_probe_count: usize,
    pub(super) coordinator_waiter_inspections: u64,
}

/// One immutable, engine-generation-scoped UDP ingress budget.
///
/// Successful datagrams charge this budget before allocating their retained
/// payload. The charge lives in that payload's `Bytes` owner, so slices and
/// clones remain charged until the last reference to the allocation is gone.
pub(super) struct UdpIngressBudget {
    max_retained_bytes: usize,
    probe_lease: Duration,
    /// Authoritative global admission counter. It charges both retained
    /// payloads and active probe leases, so lock-free unleased admissions
    /// cannot consume capacity promised to a selected flow.
    charged_bytes: AtomicUsize,
    retained_bytes: AtomicUsize,
    #[cfg(test)]
    peak_retained_bytes: AtomicUsize,
    /// Sequence-first ordering provides FIFO opportunity. A bounded turn
    /// rotates nonfitting heads to the tail, so mixed sizes make progress
    /// without an O(waiter-count) scan or permanent head-of-line starvation.
    coordinator: parking_lot::Mutex<UdpIngressCoordinatorState>,
    next_waiter_sequence: AtomicU64,
    next_probe_id: AtomicU64,
    opportunity_epoch: AtomicU64,
    waiter_count: AtomicUsize,
    coordinator_signal: Arc<UdpIngressCoordinatorSignal>,
    #[cfg(test)]
    accepted_datagrams: AtomicU64,
    #[cfg(test)]
    accepted_bytes: AtomicU64,
    dropped_count_full: AtomicU64,
    dropped_flow_bytes_full: AtomicU64,
    dropped_global_bytes_full: AtomicU64,
    resumed_count_full: AtomicU64,
    resumed_flow_bytes_full: AtomicU64,
    resumed_global_bytes_full: AtomicU64,
    #[cfg(test)]
    paused_transitions: AtomicU64,
    #[cfg(test)]
    resumed_transitions: AtomicU64,
    #[cfg(test)]
    coordinator_waiter_inspections: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeLeaseConsumption {
    NoLease,
    AwaitingAck,
    Consumed,
    Insufficient,
}

impl UdpIngressBudget {
    #[cfg(test)]
    pub(super) fn new(max_retained_bytes: usize) -> Self {
        Self::new_with_probe_lease(max_retained_bytes, DEFAULT_UDP_INGRESS_PROBE_LEASE)
    }

    pub(super) fn new_with_probe_lease(max_retained_bytes: usize, probe_lease: Duration) -> Self {
        debug_assert!(!probe_lease.is_zero());
        debug_assert!(probe_lease <= MAX_UDP_INGRESS_PROBE_LEASE);
        Self {
            max_retained_bytes,
            probe_lease,
            charged_bytes: AtomicUsize::new(0),
            retained_bytes: AtomicUsize::new(0),
            #[cfg(test)]
            peak_retained_bytes: AtomicUsize::new(0),
            coordinator: parking_lot::Mutex::new(UdpIngressCoordinatorState::default()),
            next_waiter_sequence: AtomicU64::new(0),
            next_probe_id: AtomicU64::new(1),
            opportunity_epoch: AtomicU64::new(1),
            waiter_count: AtomicUsize::new(0),
            coordinator_signal: Arc::new(UdpIngressCoordinatorSignal::new()),
            #[cfg(test)]
            accepted_datagrams: AtomicU64::new(0),
            #[cfg(test)]
            accepted_bytes: AtomicU64::new(0),
            dropped_count_full: AtomicU64::new(0),
            dropped_flow_bytes_full: AtomicU64::new(0),
            dropped_global_bytes_full: AtomicU64::new(0),
            resumed_count_full: AtomicU64::new(0),
            resumed_flow_bytes_full: AtomicU64::new(0),
            resumed_global_bytes_full: AtomicU64::new(0),
            #[cfg(test)]
            paused_transitions: AtomicU64::new(0),
            #[cfg(test)]
            resumed_transitions: AtomicU64::new(0),
            #[cfg(test)]
            coordinator_waiter_inspections: AtomicU64::new(0),
        }
    }

    pub(super) fn max_retained_bytes(&self) -> usize {
        self.max_retained_bytes
    }

    pub(super) fn probe_lease(&self) -> Duration {
        self.probe_lease
    }

    fn try_charge(&self, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        self.charged_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(len)
                    .filter(|next| *next <= self.max_retained_bytes)
            })
            .is_ok()
    }

    #[inline]
    fn try_charge_without_barging(&self, len: usize) -> bool {
        self.try_charge_without_barging_after(len, || {})
    }

    /// Charge unleased capacity only if the reservation can linearize before
    /// global waiter publication. The second check closes the race where a
    /// waiter publishes after the first check but before the charge. Its
    /// rollback is itself a capacity opportunity and must kick the waiter.
    #[inline]
    fn try_charge_without_barging_after(&self, len: usize, after_charge: impl FnOnce()) -> bool {
        if len == 0 {
            return true;
        }
        if self.waiter_count.load(Ordering::SeqCst) != 0 || !self.try_charge(len) {
            return false;
        }
        after_charge();
        if self.waiter_count.load(Ordering::SeqCst) == 0 {
            return true;
        }

        self.release_charge(len);
        self.opportunity_epoch.fetch_add(1, Ordering::Release);
        self.coordinator_signal.kick();
        false
    }

    fn release_charge(&self, len: usize) {
        if len == 0 {
            return;
        }
        let previous = self.charged_bytes.fetch_sub(len, Ordering::AcqRel);
        debug_assert!(previous >= len, "UDP global charged byte underflow");
    }

    fn record_retained_reservation(&self, len: usize) {
        if len == 0 {
            return;
        }
        let _previous = self.retained_bytes.fetch_add(len, Ordering::AcqRel);
        #[cfg(test)]
        self.peak_retained_bytes
            .fetch_max(_previous + len, Ordering::Relaxed);
    }

    fn try_reserve(&self, len: usize) -> bool {
        if !self.try_charge_without_barging(len) {
            return false;
        }
        self.record_retained_reservation(len);
        true
    }

    fn release(&self, len: usize) {
        if len == 0 {
            return;
        }
        let previous = self.retained_bytes.fetch_sub(len, Ordering::AcqRel);
        debug_assert!(previous >= len, "UDP global byte reservation underflow");
        self.release_charge(len);
        if self.waiter_count.load(Ordering::Acquire) != 0 {
            self.opportunity_epoch.fetch_add(1, Ordering::Release);
            self.coordinator_signal.kick();
        }
    }

    pub(super) fn start_coordinator(
        self: &Arc<Self>,
        rt: &super::TransparentProxyAsyncRuntime,
        shutdown: ShutdownGuard,
    ) {
        let budget = Arc::downgrade(self);
        let signal = self.coordinator_signal.clone();
        _ = rt.spawn(run_udp_ingress_coordinator(budget, signal, async move {
            shutdown.cancelled().await;
        }));
    }

    fn restart_scan_locked(coordinator: &mut UdpIngressCoordinatorState) {
        coordinator.scan_remaining = coordinator.waiters.len();
        coordinator.scan_started = false;
        coordinator.scan_needs_followup = false;
        coordinator.discovery_candidates.clear();
        coordinator.discovery_frontier = None;
        coordinator.discovery_cursor = None;
        coordinator.discovery_prefers_fitting = false;
    }

    fn schedule_flow_release(&self, flow: &Arc<UdpIngressFlowControl>) {
        let mut coordinator = self.coordinator.lock();
        if coordinator.flow_releases_closed
            || flow.state.load(Ordering::Acquire) != INGRESS_PAUSED_FLOW_BYTES
            || flow.release_waiter_sequence.load(Ordering::Relaxed) != NO_RELEASE_WAITER
        {
            return;
        }
        let sequence = coordinator.next_release_sequence;
        coordinator.next_release_sequence = if sequence == NO_RELEASE_WAITER - 1 {
            0
        } else {
            sequence + 1
        };
        flow.release_waiter_sequence
            .store(sequence, Ordering::Release);
        let replaced = coordinator
            .released_flows
            .insert((sequence, Arc::as_ptr(flow) as usize), Arc::downgrade(flow));
        debug_assert!(replaced.is_none(), "UDP release waiter key collision");
        drop(coordinator);
        self.coordinator_signal.kick();
    }

    fn remove_flow_release(&self, flow: &UdpIngressFlowControl) {
        // Always acquire the cold-path lock: a release may already have
        // observed PAUSED but not yet published its key when close runs.
        let mut coordinator = self.coordinator.lock();
        let sequence = flow
            .release_waiter_sequence
            .swap(NO_RELEASE_WAITER, Ordering::AcqRel);
        if sequence != NO_RELEASE_WAITER {
            _ = coordinator
                .released_flows
                .remove(&(sequence, flow as *const _ as usize));
        }
    }

    fn wake_released_flow_batch(&self, now: tokio::time::Instant) -> usize {
        let selected = {
            let mut coordinator = self.coordinator.lock();
            if coordinator.released_flows.is_empty()
                || coordinator
                    .release_wake_not_before
                    .is_some_and(|not_before| now < not_before)
            {
                return 0;
            }
            let mut selected = Vec::with_capacity(FLOW_RELEASE_WAKE_BATCH);
            let mut inspected = 0;
            while inspected < FLOW_RELEASE_WAKE_BATCH {
                let Some((_, candidate)) = coordinator.released_flows.pop_first() else {
                    break;
                };
                inspected += 1;
                if let Some(flow) = candidate.upgrade() {
                    flow.release_waiter_sequence
                        .store(NO_RELEASE_WAITER, Ordering::Release);
                    selected.push(flow);
                }
            }
            if inspected != 0 {
                coordinator.release_wake_not_before = Some(now + GLOBAL_WAKE_RETRY);
            }
            selected
        };
        // A payload may be dropped while either callback gate is held. Never
        // call user demand on its destructor's stack or under the queue lock.
        for flow in &selected {
            flow.resume_flow_bytes_if_capacity();
        }
        selected.len()
    }

    pub(super) fn close_flow_releases(&self) {
        let released_flows = {
            let mut coordinator = self.coordinator.lock();
            coordinator.flow_releases_closed = true;
            std::mem::take(&mut coordinator.released_flows)
        };
        for candidate in released_flows.into_values() {
            if let Some(flow) = candidate.upgrade() {
                flow.release_waiter_sequence
                    .store(NO_RELEASE_WAITER, Ordering::Release);
            }
        }
    }

    fn restart_quiescent_scan_locked(coordinator: &mut UdpIngressCoordinatorState) {
        if !coordinator.scan_started
            || (coordinator.scan_remaining == 0
                && coordinator.discovery_candidates.is_empty()
                && coordinator.discovery_frontier.is_none())
        {
            Self::restart_scan_locked(coordinator);
        } else {
            coordinator.scan_needs_followup = true;
        }
    }

    fn register_waiter(&self, flow: &Arc<UdpIngressFlowControl>) {
        let mut coordinator = self.coordinator.lock();
        if flow.state.load(Ordering::Acquire) != INGRESS_PAUSED_GLOBAL_BYTES
            || flow.global_waiter_sequence.load(Ordering::Relaxed) != NO_GLOBAL_WAITER
        {
            return;
        }
        let Ok(sequence) =
            self.next_waiter_sequence
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
        else {
            // Exhaustion requires 2^64 registrations in one engine lifetime.
            // Fail live instead of leaving the flow permanently paused.
            drop(coordinator);
            _ = flow.resume(INGRESS_PAUSED_GLOBAL_BYTES, 0);
            return;
        };
        let needed_bytes = flow.blocked_bytes.load(Ordering::Acquire);
        flow.global_waiter_sequence
            .store(sequence, Ordering::Release);
        let replaced = coordinator
            .waiters
            .insert((sequence, needed_bytes), Arc::downgrade(flow));
        debug_assert!(replaced.is_none(), "UDP global waiter key collision");
        Self::index_unleased_waiter_locked(&mut coordinator, flow);
        // This SeqCst increment is the waiter-publication linearization point
        // paired with the two SeqCst admission checks above.
        self.waiter_count.fetch_add(1, Ordering::SeqCst);
        // Do not restart an in-progress bounded pass for every newcomer. If no
        // pass has started, include all current waiters; otherwise this tail
        // insertion will be covered by the next real capacity opportunity.
        // This keeps sustained arrivals from starving partial discovery.
        Self::restart_quiescent_scan_locked(&mut coordinator);
        drop(coordinator);

        // Close the classic missed-wakeup store-buffering race without a
        // lock or sequentially-consistent fence on normal release.
        // Registration publishes `waiter_count` before this retained-counter
        // marker. If release precedes the marker, the marker observes capacity
        // and kicks. If the marker precedes release, release observes the
        // publication and kicks.
        let charged = self.charged_bytes.fetch_add(0, Ordering::AcqRel);
        // Exact-fit retries and the one-shot partial discovery path both need
        // a coordinator turn. An active lease charges the available headroom,
        // so a repeated nonfitting delivery cannot use registration to spin.
        if charged < self.max_retained_bytes {
            self.coordinator_signal.kick();
        }
    }

    fn remove_waiter(&self, flow: &UdpIngressFlowControl) {
        let mut coordinator = self.coordinator.lock();
        let sequence = flow
            .global_waiter_sequence
            .swap(NO_GLOBAL_WAITER, Ordering::AcqRel);
        if sequence == NO_GLOBAL_WAITER {
            return;
        }
        let needed_bytes = flow.blocked_bytes.load(Ordering::Acquire);
        let removed = coordinator.waiters.remove(&(sequence, needed_bytes));
        coordinator.fitting_waiters.remove(sequence);
        debug_assert_eq!(
            removed.as_ref().map(Weak::as_ptr),
            Some(flow as *const _),
            "UDP global waiter registry mismatch"
        );
        if removed.is_some() {
            self.waiter_count.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn rotate_waiter_locked(
        &self,
        coordinator: &mut UdpIngressCoordinatorState,
        key: (u64, usize),
        flow: &Arc<UdpIngressFlowControl>,
    ) -> Option<(u64, usize)> {
        let waiter = coordinator.waiters.remove(&key)?;
        coordinator.fitting_waiters.remove(key.0);
        let Ok(new_sequence) =
            self.next_waiter_sequence
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
        else {
            // Sequence exhaustion is unreachable in practice. Retain the
            // waiter and quiesce instead of dropping its only registration.
            coordinator.waiters.insert(key, waiter);
            Self::index_unleased_waiter_locked(coordinator, flow);
            coordinator.scan_remaining = 0;
            return None;
        };
        let new_key = (new_sequence, key.1);
        flow.global_waiter_sequence
            .store(new_sequence, Ordering::Release);
        let replaced = coordinator.waiters.insert(new_key, waiter);
        debug_assert!(replaced.is_none(), "UDP rotated waiter key collision");
        Self::index_unleased_waiter_locked(coordinator, flow);
        Some(new_key)
    }

    fn index_unleased_waiter_locked(
        coordinator: &mut UdpIngressCoordinatorState,
        flow: &UdpIngressFlowControl,
    ) {
        let sequence = flow.global_waiter_sequence.load(Ordering::Acquire);
        let needed_bytes = flow.blocked_bytes.load(Ordering::Acquire);
        if flow.global_probe_id.load(Ordering::Acquire) == 0
            && coordinator.waiters.contains_key(&(sequence, needed_bytes))
        {
            coordinator.fitting_waiters.insert(sequence, needed_bytes);
        }
    }

    fn issue_probe_lease_locked(
        &self,
        coordinator: &mut UdpIngressCoordinatorState,
        key: (u64, usize),
        flow: &Arc<UdpIngressFlowControl>,
        lease_bytes: usize,
        now: tokio::time::Instant,
    ) -> Option<u64> {
        debug_assert_ne!(lease_bytes, 0);
        let Ok(probe_id) =
            self.next_probe_id
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
        else {
            // Never reuse an ID or issue an unaccounted callback. Exhaustion
            // requires 2^64 probes in one engine generation.
            coordinator.scan_remaining = 0;
            return None;
        };
        if !self.try_charge(lease_bytes) {
            return None;
        }
        let Some(_) = coordinator.waiters.remove(&key) else {
            self.release_charge(lease_bytes);
            return None;
        };
        coordinator.fitting_waiters.remove(key.0);
        self.waiter_count.fetch_sub(1, Ordering::SeqCst);
        coordinator.provisional_bytes += lease_bytes;
        let previous = flow.global_probe_id.swap(probe_id, Ordering::AcqRel);
        debug_assert_eq!(previous, 0, "UDP flow received overlapping probe leases");
        let replaced = coordinator.leases.insert(
            probe_id,
            UdpIngressProbeLease {
                bytes: lease_bytes,
                expires_at: now + self.probe_lease,
                read_completed: false,
                flow: Arc::downgrade(flow),
            },
        );
        debug_assert!(replaced.is_none(), "UDP probe ID collision");
        flow.global_waiter_sequence
            .store(NO_GLOBAL_WAITER, Ordering::Release);
        Some(probe_id)
    }

    /// Give at most [`GLOBAL_WAKE_BATCH`] flows one charged retry lease.
    /// After every flow in a finite FIFO pass has an exact-fit opportunity,
    /// discover later smaller datagrams through that cohort in bounded turns.
    /// Real releases cannot restart either phase before its remaining flows
    /// receive their opportunity.
    fn wake_fitting_batch(&self, now: tokio::time::Instant) -> usize {
        let selected = {
            let mut coordinator = self.coordinator.lock();
            self.expire_probe_leases_locked(&mut coordinator, now);
            let opportunity_epoch = self.opportunity_epoch.load(Ordering::Acquire);
            if coordinator.observed_opportunity_epoch != opportunity_epoch {
                coordinator.observed_opportunity_epoch = opportunity_epoch;
                Self::restart_quiescent_scan_locked(&mut coordinator);
            }
            if coordinator
                .wake_not_before
                .is_some_and(|not_before| now < not_before)
            {
                return 0;
            }
            coordinator.wake_not_before = None;
            let available_probe_slots = GLOBAL_WAKE_BATCH.saturating_sub(coordinator.leases.len());
            let mut selected = Vec::with_capacity(available_probe_slots);
            let mut inspected = 0;

            // Inspect at most `GLOBAL_SCAN_BATCH` FIFO heads while issuing at
            // most `GLOBAL_WAKE_BATCH` callbacks. A nonfitting or
            // already-leased flow rotates to the tail, providing eventual
            // opportunity for mixed sizes without an O(waiter-count) fitting
            // scan.
            while selected.len() < available_probe_slots
                && inspected < GLOBAL_SCAN_BATCH
                && coordinator.scan_remaining > 0
            {
                let Some((key, candidate)) = coordinator
                    .waiters
                    .first_key_value()
                    .map(|(&key, candidate)| (key, candidate.clone()))
                else {
                    break;
                };
                inspected += 1;
                coordinator.scan_started = true;
                coordinator.scan_remaining -= 1;
                #[cfg(test)]
                self.coordinator_waiter_inspections
                    .fetch_add(1, Ordering::Relaxed);
                let Some(flow) = candidate.upgrade() else {
                    _ = coordinator.waiters.remove(&key);
                    coordinator.fitting_waiters.remove(key.0);
                    self.waiter_count.fetch_sub(1, Ordering::SeqCst);
                    continue;
                };
                let needed_bytes = key.1;
                let available = self
                    .max_retained_bytes
                    .saturating_sub(self.charged_bytes.load(Ordering::Acquire));
                let already_leased = flow.global_probe_id.load(Ordering::Acquire) != 0;
                if needed_bytes > available || already_leased {
                    let Some(new_key) = self.rotate_waiter_locked(&mut coordinator, key, &flow)
                    else {
                        break;
                    };
                    if !already_leased && coordinator.discovery_candidates.len() < GLOBAL_WAKE_BATCH
                    {
                        coordinator
                            .discovery_candidates
                            .push((new_key, Arc::downgrade(&flow)));
                    }
                    continue;
                }
                if let Some(probe_id) =
                    self.issue_probe_lease_locked(&mut coordinator, key, &flow, needed_bytes, now)
                {
                    selected.push((flow, probe_id));
                } else {
                    // A lock-free admission raced our headroom snapshot. Keep
                    // this waiter live and let the next real opportunity start
                    // a fresh pass.
                    let _ = self.rotate_waiter_locked(&mut coordinator, key, &flow);
                }
            }

            if coordinator.scan_remaining == 0
                && coordinator.discovery_frontier.is_none()
                && !coordinator.discovery_candidates.is_empty()
            {
                coordinator.discovery_frontier =
                    coordinator.waiters.last_key_value().map(|(key, _)| key.0);
            }

            // A fitting flow can re-park beyond the frozen discovery frontier
            // after every successful delivery. Give it one bounded opportunity
            // between discovery grants, without restarting either FIFO pass.
            // The augmented index avoids O(cohort size) work per retry; active
            // insufficient leases are absent until their capacity is refunded.
            while coordinator.scan_remaining == 0
                && coordinator.discovery_frontier.is_some()
                && coordinator.discovery_prefers_fitting
                && selected.len() < available_probe_slots
                && inspected < GLOBAL_SCAN_BATCH
            {
                let available = self
                    .max_retained_bytes
                    .saturating_sub(self.charged_bytes.load(Ordering::Acquire));
                let Some((sequence, needed_bytes)) =
                    coordinator.fitting_waiters.oldest_fitting(available)
                else {
                    break;
                };
                let key = (sequence, needed_bytes);
                inspected += 1;
                #[cfg(test)]
                self.coordinator_waiter_inspections
                    .fetch_add(1, Ordering::Relaxed);
                let flow = coordinator.waiters.get(&key).and_then(Weak::upgrade);
                let Some(flow) = flow else {
                    coordinator.fitting_waiters.remove(sequence);
                    if coordinator.waiters.remove(&key).is_some() {
                        self.waiter_count.fetch_sub(1, Ordering::SeqCst);
                    }
                    continue;
                };
                if let Some(probe_id) =
                    self.issue_probe_lease_locked(&mut coordinator, key, &flow, needed_bytes, now)
                {
                    selected.push((flow, probe_id));
                    coordinator.discovery_prefers_fitting = false;
                }
                break;
            }

            while coordinator.scan_remaining == 0
                && selected.len() < available_probe_slots
                && let Some(frontier) = coordinator.discovery_frontier
            {
                let available = self
                    .max_retained_bytes
                    .saturating_sub(self.charged_bytes.load(Ordering::Acquire));
                if available == 0 {
                    // Exact fitting traffic can temporarily consume every
                    // byte. Neither its release nor its re-registration may
                    // erase this completed pass's owed FIFO discovery.
                    break;
                }
                let sampled = !coordinator.discovery_candidates.is_empty();
                let candidate = if sampled {
                    coordinator.discovery_candidates.first().cloned()
                } else {
                    if inspected == GLOBAL_SCAN_BATCH {
                        break;
                    }
                    match coordinator.discovery_cursor {
                        Some(cursor) if cursor.0 > frontier => None,
                        cursor => coordinator
                            .waiters
                            .range((
                                cursor.map_or(Bound::Unbounded, Bound::Excluded),
                                Bound::Included((frontier, usize::MAX)),
                            ))
                            .next()
                            .map(|(&key, candidate)| (key, candidate.clone())),
                    }
                };
                let Some((key, candidate)) = candidate else {
                    coordinator.discovery_frontier = None;
                    coordinator.discovery_cursor = None;
                    break;
                };
                if !sampled {
                    inspected += 1;
                    #[cfg(test)]
                    self.coordinator_waiter_inspections
                        .fetch_add(1, Ordering::Relaxed);
                }
                let flow = candidate.upgrade();
                let eligible = flow.as_ref().filter(|flow| {
                    coordinator.waiters.contains_key(&key)
                        && flow.global_probe_id.load(Ordering::Acquire) == 0
                });
                let issued = if let Some(flow) = eligible {
                    let Some(probe_id) = self.issue_probe_lease_locked(
                        &mut coordinator,
                        key,
                        flow,
                        key.1.min(available),
                        now,
                    ) else {
                        // An admission which began before waiter publication
                        // raced the headroom snapshot. Preserve this cursor.
                        break;
                    };
                    Some((flow.clone(), probe_id))
                } else {
                    if flow.is_none() && coordinator.waiters.remove(&key).is_some() {
                        coordinator.fitting_waiters.remove(key.0);
                        self.waiter_count.fetch_sub(1, Ordering::SeqCst);
                    }
                    None
                };
                if sampled {
                    coordinator.discovery_candidates.remove(0);
                }
                coordinator.discovery_cursor = Some(
                    coordinator
                        .discovery_cursor
                        .map_or(key, |cursor| cursor.max(key)),
                );
                if let Some(issued) = issued {
                    selected.push(issued);
                    coordinator.discovery_prefers_fitting = true;
                    // At most one discovery per paced turn. Keep the cursor
                    // and the remaining constant-size sample for later real
                    // capacity opportunities, without another population scan.
                    break;
                }
            }
            if coordinator.waiters.is_empty()
                || (coordinator.scan_remaining == 0
                    && coordinator.discovery_frontier.is_none()
                    && coordinator.discovery_candidates.is_empty()
                    && coordinator.scan_needs_followup)
            {
                Self::restart_scan_locked(&mut coordinator);
            }
            if inspected != 0 || !selected.is_empty() {
                coordinator.wake_not_before = Some(now + GLOBAL_WAKE_RETRY);
            }
            selected
        };

        let selected_count = selected.len();
        for (flow, probe_id) in selected {
            if !flow.resume(INGRESS_PAUSED_GLOBAL_BYTES, probe_id) && probe_id != 0 {
                self.release_probe_lease(&flow, probe_id);
            }
        }
        selected_count
    }

    fn expire_probe_leases_locked(
        &self,
        coordinator: &mut UdpIngressCoordinatorState,
        now: tokio::time::Instant,
    ) {
        let expired: Vec<_> = coordinator
            .leases
            .iter()
            .filter_map(|(&id, lease)| (lease.expires_at <= now).then_some(id))
            .collect();
        let released_any = !expired.is_empty();
        for id in expired {
            let Some(lease) = coordinator.leases.remove(&id) else {
                continue;
            };
            debug_assert!(
                coordinator.provisional_bytes >= lease.bytes,
                "UDP provisional byte reservation underflow"
            );
            coordinator.provisional_bytes =
                coordinator.provisional_bytes.saturating_sub(lease.bytes);
            self.release_charge(lease.bytes);
            if let Some(flow) = lease.flow.upgrade() {
                _ = flow.global_probe_id.compare_exchange(
                    id,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                Self::index_unleased_waiter_locked(coordinator, &flow);
            }
        }
        if released_any && self.waiter_count.load(Ordering::Acquire) != 0 {
            self.opportunity_epoch.fetch_add(1, Ordering::Release);
        }
    }

    fn acknowledge_probe_lease(
        &self,
        flow: &UdpIngressFlowControl,
        probe_id: u64,
        now: tokio::time::Instant,
    ) -> bool {
        if probe_id == 0 {
            return false;
        }
        let released_bytes = {
            let mut coordinator = self.coordinator.lock();
            let Some(lease) = coordinator.leases.get(&probe_id) else {
                return false;
            };
            if !lease
                .flow
                .upgrade()
                .is_some_and(|owner| std::ptr::eq(Arc::as_ptr(&owner), flow))
            {
                return false;
            }
            if lease.expires_at <= now {
                let Some(lease) = coordinator.leases.remove(&probe_id) else {
                    debug_assert!(false, "validated UDP probe lease disappeared under lock");
                    return false;
                };
                debug_assert!(
                    coordinator.provisional_bytes >= lease.bytes,
                    "UDP provisional byte reservation underflow"
                );
                coordinator.provisional_bytes =
                    coordinator.provisional_bytes.saturating_sub(lease.bytes);
                _ = flow.global_probe_id.compare_exchange(
                    probe_id,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                Self::index_unleased_waiter_locked(&mut coordinator, flow);
                lease.bytes
            } else {
                let Some(lease) = coordinator.leases.get_mut(&probe_id) else {
                    debug_assert!(false, "validated UDP probe lease disappeared under lock");
                    return false;
                };
                if lease.read_completed {
                    return false;
                }
                lease.read_completed = true;
                lease.expires_at = now + self.probe_lease.max(GLOBAL_ACKED_PROBE_DELIVERY_GRACE);
                return true;
            }
        };

        self.release_charge(released_bytes);
        if self.waiter_count.load(Ordering::Acquire) != 0 {
            self.opportunity_epoch.fetch_add(1, Ordering::Release);
            self.coordinator_signal.kick();
        }
        false
    }

    fn try_consume_probe_lease(
        &self,
        flow: &UdpIngressFlowControl,
        probe_id: u64,
        len: usize,
    ) -> ProbeLeaseConsumption {
        if probe_id == 0 {
            return ProbeLeaseConsumption::NoLease;
        }

        let now = tokio::time::Instant::now();
        let (consumption, released_bytes) = {
            let mut coordinator = self.coordinator.lock();
            let Some(lease) = coordinator.leases.get(&probe_id) else {
                return ProbeLeaseConsumption::NoLease;
            };
            if !lease
                .flow
                .upgrade()
                .is_some_and(|owner| std::ptr::eq(Arc::as_ptr(&owner), flow))
            {
                return ProbeLeaseConsumption::NoLease;
            }

            let lease_bytes = lease.bytes;
            if lease.expires_at <= now {
                let Some(lease) = coordinator.leases.remove(&probe_id) else {
                    debug_assert!(false, "validated UDP probe lease disappeared under lock");
                    return ProbeLeaseConsumption::NoLease;
                };
                debug_assert!(
                    coordinator.provisional_bytes >= lease.bytes,
                    "UDP provisional byte reservation underflow"
                );
                coordinator.provisional_bytes =
                    coordinator.provisional_bytes.saturating_sub(lease.bytes);
                _ = flow.global_probe_id.compare_exchange(
                    probe_id,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                Self::index_unleased_waiter_locked(&mut coordinator, flow);
                // Release and wake only after dropping the coordinator lock.
                // The caller then takes the ordinary no-barge admission path.
                (ProbeLeaseConsumption::NoLease, lease.bytes)
            } else if !lease.read_completed {
                return ProbeLeaseConsumption::AwaitingAck;
            } else if len > lease_bytes && !self.try_charge_without_barging(len - lease_bytes) {
                // The discovered packet is larger than the charged partial
                // credit. Keep that credit active briefly while the caller
                // re-parks: otherwise releasing and immediately registering
                // would turn the same unchanged headroom into a 1ms hot read
                // loop. Use the delivery grace as the minimum retry interval:
                // with four global slots this strictly bounds permanently
                // nonfitting discovery even at the default 10ms lease.
                let retry_at = now + self.probe_lease.max(GLOBAL_ACKED_PROBE_DELIVERY_GRACE);
                let Some(lease) = coordinator.leases.get_mut(&probe_id) else {
                    debug_assert!(false, "validated UDP probe lease disappeared under lock");
                    return ProbeLeaseConsumption::NoLease;
                };
                lease.expires_at = lease.expires_at.min(retry_at);
                (ProbeLeaseConsumption::Insufficient, 0)
            } else {
                let Some(lease) = coordinator.leases.remove(&probe_id) else {
                    debug_assert!(false, "validated UDP probe lease disappeared under lock");
                    if len > lease_bytes {
                        self.release_charge(len - lease_bytes);
                    }
                    return ProbeLeaseConsumption::NoLease;
                };
                debug_assert_eq!(lease.bytes, lease_bytes);
                debug_assert!(
                    coordinator.provisional_bytes >= lease_bytes,
                    "UDP provisional byte reservation underflow"
                );
                coordinator.provisional_bytes =
                    coordinator.provisional_bytes.saturating_sub(lease_bytes);
                self.record_retained_reservation(len);
                _ = flow.global_probe_id.compare_exchange(
                    probe_id,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                (
                    ProbeLeaseConsumption::Consumed,
                    lease_bytes.saturating_sub(len),
                )
            }
        };

        if released_bytes != 0 {
            self.release_charge(released_bytes);
            if self.waiter_count.load(Ordering::Acquire) != 0 {
                self.opportunity_epoch.fetch_add(1, Ordering::Release);
                self.coordinator_signal.kick();
            }
        }
        consumption
    }

    fn release_probe_lease(&self, flow: &UdpIngressFlowControl, probe_id: u64) -> bool {
        if probe_id == 0 {
            return false;
        }
        let released = {
            let mut coordinator = self.coordinator.lock();
            match coordinator.leases.entry(probe_id) {
                Entry::Vacant(_) => false,
                Entry::Occupied(entry) => {
                    let matches = entry
                        .get()
                        .flow
                        .upgrade()
                        .is_some_and(|owner| std::ptr::eq(Arc::as_ptr(&owner), flow));
                    if !matches {
                        false
                    } else {
                        let lease = entry.remove();
                        debug_assert!(
                            coordinator.provisional_bytes >= lease.bytes,
                            "UDP provisional byte reservation underflow"
                        );
                        coordinator.provisional_bytes =
                            coordinator.provisional_bytes.saturating_sub(lease.bytes);
                        self.release_charge(lease.bytes);
                        _ = flow.global_probe_id.compare_exchange(
                            probe_id,
                            0,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                        Self::index_unleased_waiter_locked(&mut coordinator, flow);
                        true
                    }
                }
            }
        };
        if released && self.waiter_count.load(Ordering::Acquire) != 0 {
            self.opportunity_epoch.fetch_add(1, Ordering::Release);
            self.coordinator_signal.kick();
        }
        released
    }

    fn next_coordinator_deadline(&self, now: tokio::time::Instant) -> Option<tokio::time::Instant> {
        let mut coordinator = self.coordinator.lock();
        let opportunity_epoch = self.opportunity_epoch.load(Ordering::Acquire);
        if coordinator.observed_opportunity_epoch != opportunity_epoch {
            coordinator.observed_opportunity_epoch = opportunity_epoch;
            Self::restart_quiescent_scan_locked(&mut coordinator);
        }
        let lease_deadline = coordinator
            .leases
            .values()
            .map(|lease| lease.expires_at)
            .min();
        let release_deadline = (!coordinator.released_flows.is_empty()).then(|| {
            coordinator
                .release_wake_not_before
                .filter(|not_before| *not_before > now)
                .unwrap_or(now + GLOBAL_WAKE_RETRY)
        });
        let has_unleased_capacity =
            self.charged_bytes.load(Ordering::Acquire) < self.max_retained_bytes;
        let waiter_deadline = (coordinator.leases.len() < GLOBAL_WAKE_BATCH
            && has_unleased_capacity
            && (coordinator.scan_remaining != 0
                || !coordinator.discovery_candidates.is_empty()
                || coordinator.discovery_frontier.is_some())
            && !coordinator.waiters.is_empty())
        .then(|| {
            coordinator
                .wake_not_before
                .filter(|not_before| *not_before > now)
                .unwrap_or(now + GLOBAL_WAKE_RETRY)
        });
        [release_deadline, waiter_deadline, lease_deadline]
            .into_iter()
            .flatten()
            .min()
    }

    #[cfg(test)]
    fn record_accepted(&self, len: usize) {
        self.accepted_datagrams.fetch_add(1, Ordering::Relaxed);
        self.accepted_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }

    fn record_drop(&self, flow_id: u64, reason: UdpIngressDropReason) {
        let (counter, pressure) = match reason {
            UdpIngressDropReason::Count => (&self.dropped_count_full, "channel_count"),
            UdpIngressDropReason::FlowBytes => (&self.dropped_flow_bytes_full, "flow_bytes"),
            UdpIngressDropReason::GlobalBytes => (&self.dropped_global_bytes_full, "global_bytes"),
        };
        let total = saturating_increment(counter);
        if telemetry_sample(total) {
            let retained = self.retained_bytes.load(Ordering::Relaxed);
            tracing::warn!(
                flow_id,
                pressure,
                cumulative_drops = total,
                global_retained_bytes = retained,
                global_max_retained_bytes = self.max_retained_bytes,
                "UDP ingress pressure dropped datagram flow_id={} pressure=\"{}\" cumulative_drops={} global_retained_bytes={} global_max_retained_bytes={}",
                flow_id,
                pressure,
                total,
                retained,
                self.max_retained_bytes,
            );
        }
    }

    fn record_recovery(&self, flow_id: u64, previous_state: u8) {
        let (counter, pressure) = match previous_state {
            INGRESS_PAUSED_COUNT => (&self.resumed_count_full, "channel_count"),
            INGRESS_PAUSED_FLOW_BYTES => (&self.resumed_flow_bytes_full, "flow_bytes"),
            INGRESS_PAUSED_GLOBAL_BYTES => (&self.resumed_global_bytes_full, "global_bytes"),
            _ => return,
        };
        let total = saturating_increment(counter);
        if telemetry_sample(total) {
            let retained = self.retained_bytes.load(Ordering::Relaxed);
            tracing::info!(
                flow_id,
                pressure,
                cumulative_resumptions = total,
                global_retained_bytes = retained,
                global_max_retained_bytes = self.max_retained_bytes,
                "UDP ingress pressure resumed flow flow_id={} pressure=\"{}\" cumulative_resumptions={} global_retained_bytes={} global_max_retained_bytes={}",
                flow_id,
                pressure,
                total,
                retained,
                self.max_retained_bytes,
            );
        }
    }

    #[cfg(test)]
    pub(super) fn snapshot(&self) -> UdpIngressSnapshot {
        let coordinator = self.coordinator.lock();
        UdpIngressSnapshot {
            retained_bytes: self.retained_bytes.load(Ordering::Acquire),
            charged_bytes: self.charged_bytes.load(Ordering::Acquire),
            peak_retained_bytes: self.peak_retained_bytes.load(Ordering::Relaxed),
            accepted_datagrams: self.accepted_datagrams.load(Ordering::Relaxed),
            accepted_bytes: self.accepted_bytes.load(Ordering::Relaxed),
            dropped_count_full: self.dropped_count_full.load(Ordering::Relaxed),
            dropped_flow_bytes_full: self.dropped_flow_bytes_full.load(Ordering::Relaxed),
            dropped_global_bytes_full: self.dropped_global_bytes_full.load(Ordering::Relaxed),
            resumed_count_full: self.resumed_count_full.load(Ordering::Relaxed),
            resumed_flow_bytes_full: self.resumed_flow_bytes_full.load(Ordering::Relaxed),
            resumed_global_bytes_full: self.resumed_global_bytes_full.load(Ordering::Relaxed),
            paused_transitions: self.paused_transitions.load(Ordering::Relaxed),
            resumed_transitions: self.resumed_transitions.load(Ordering::Relaxed),
            global_waiters: self.waiter_count.load(Ordering::Acquire),
            provisional_probe_bytes: coordinator.provisional_bytes,
            provisional_probe_count: coordinator.leases.len(),
            coordinator_waiter_inspections: self
                .coordinator_waiter_inspections
                .load(Ordering::Relaxed),
        }
    }
}

fn telemetry_sample(total: u64) -> bool {
    total.is_power_of_two()
}

fn saturating_increment(counter: &AtomicU64) -> u64 {
    match counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(1))
    }) {
        Ok(previous) => previous.saturating_add(1),
        // The closure always returns `Some`; retain a total function if that
        // implementation detail is ever refactored.
        Err(current) => current,
    }
}

async fn run_udp_ingress_coordinator<F>(
    budget: Weak<UdpIngressBudget>,
    signal: Arc<UdpIngressCoordinatorSignal>,
    shutdown: F,
) where
    F: Future<Output = ()>,
{
    tokio::pin!(shutdown);
    let mut deadline = None;
    'coordinator: loop {
        if let Some(at) = deadline {
            tokio::select! {
                biased;
                () = &mut shutdown => break 'coordinator,
                () = signal.wait() => {}
                () = tokio::time::sleep_until(at) => {
                    signal.coalesce_before_probe();
                }
            }
        } else {
            tokio::select! {
                biased;
                () = &mut shutdown => break 'coordinator,
                () = signal.wait() => {}
            }
        }

        let Some(budget) = budget.upgrade() else {
            break 'coordinator;
        };
        let now = tokio::time::Instant::now();
        _ = budget.wake_released_flow_batch(now);
        _ = budget.wake_fitting_batch(now);
        deadline = budget.next_coordinator_deadline(now);
    }

    // `AtomicWaker::wake` normally consumes its stored waker. Shutdown can
    // win the select without a coordinator kick, so clear that final task
    // reference explicitly before retained payloads outlive the engine.
    if let Some(budget) = budget.upgrade() {
        budget.close_flow_releases();
    }
    _ = signal.waker.take();
}

pub(super) struct UdpIngressFlowControl {
    /// Stable process-local identity shared with decision and Dial9 records.
    flow_id: u64,
    max_retained_bytes: usize,
    retained_bytes: AtomicUsize,
    /// Changes only when this flow releases retained payload capacity. A
    /// nonfitting datagram may spend each epoch on at most one partial-size
    /// discovery read, preventing a hot retry loop.
    flow_capacity_epoch: AtomicU64,
    last_partial_probe_epoch: AtomicU64,
    state: AtomicU8,
    blocked_bytes: AtomicUsize,
    global_waiter_sequence: AtomicU64,
    release_waiter_sequence: AtomicU64,
    global_probe_id: AtomicU64,
    /// Joins admitted copy/count/publish transactions before terminal receiver
    /// destruction. Foreign demand callbacks must run after this gate drops.
    submission_gate: parking_lot::Mutex<()>,
    #[cfg(test)]
    pub(super) submission_close_started: AtomicBool,
    demand_gate: parking_lot::Mutex<()>,
    demand: UdpDemandSink,
    global: Arc<UdpIngressBudget>,
}

impl UdpIngressFlowControl {
    #[cfg(test)]
    pub(super) fn new(
        max_retained_bytes: usize,
        global: Arc<UdpIngressBudget>,
        demand: UdpDemandSink,
    ) -> Arc<Self> {
        Self::new_with_flow_id(max_retained_bytes, global, demand, 0)
    }

    pub(super) fn new_with_flow_id(
        max_retained_bytes: usize,
        global: Arc<UdpIngressBudget>,
        demand: UdpDemandSink,
        flow_id: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            flow_id,
            max_retained_bytes,
            retained_bytes: AtomicUsize::new(0),
            flow_capacity_epoch: AtomicU64::new(1),
            last_partial_probe_epoch: AtomicU64::new(0),
            state: AtomicU8::new(INGRESS_OPEN),
            blocked_bytes: AtomicUsize::new(0),
            global_waiter_sequence: AtomicU64::new(NO_GLOBAL_WAITER),
            release_waiter_sequence: AtomicU64::new(NO_RELEASE_WAITER),
            global_probe_id: AtomicU64::new(0),
            submission_gate: parking_lot::Mutex::new(()),
            #[cfg(test)]
            submission_close_started: AtomicBool::new(false),
            demand_gate: parking_lot::Mutex::new(()),
            demand,
            global,
        })
    }

    pub(super) fn request_read(&self) {
        self.dispatch_demand_if_open(0);
    }

    pub(super) fn acknowledge_probe(&self, probe_id: u64) {
        _ = self
            .global
            .acknowledge_probe_lease(self, probe_id, tokio::time::Instant::now());
    }

    pub(super) fn on_channel_capacity_released(&self) {
        self.resume(INGRESS_PAUSED_COUNT, 0);
    }

    pub(super) fn close(self: &Arc<Self>) {
        #[cfg(test)]
        self.submission_close_started.store(true, Ordering::Release);
        let old_state = {
            // An OPEN check or reserved channel permit alone cannot join a
            // concurrent receiver drop: outstanding permits can still publish
            // after Tokio drains the receiver. Close admission and wait for
            // every admitted copy/count/publish transaction first.
            let _submission = self.submission_gate.lock();
            self.state.swap(INGRESS_CLOSED, Ordering::AcqRel)
        };
        // Join demand only after releasing submission. A foreign ingress call
        // can hold its session-entry lock while waiting for submission; an
        // in-flight demand callback may need that same foreign lock to ACK.
        // Holding both Rust gates here would invert those locks. CLOSED now
        // rejects every new submission/demand, and this separate join waits
        // for a demand that observed OPEN before the terminal transition.
        drop(self.demand_gate.lock());
        if old_state == INGRESS_PAUSED_GLOBAL_BYTES {
            self.global.remove_waiter(self);
        }
        self.global.remove_flow_release(self);
        let probe_id = self.global_probe_id.load(Ordering::Acquire);
        if probe_id != 0 {
            _ = self.global.release_probe_lease(self, probe_id);
        }
    }

    pub(super) fn begin_submission(&self) -> Option<parking_lot::MutexGuard<'_, ()>> {
        let submission = self.submission_gate.lock();
        (self.state.load(Ordering::Acquire) != INGRESS_CLOSED).then_some(submission)
    }

    pub(super) fn drop_while_paused(&self) -> bool {
        let state = self.state.load(Ordering::Acquire);
        if state == INGRESS_CLOSED {
            return true;
        }
        if let Some(reason) = match state {
            INGRESS_PAUSED_COUNT => Some(UdpIngressDropReason::Count),
            INGRESS_PAUSED_FLOW_BYTES => Some(UdpIngressDropReason::FlowBytes),
            INGRESS_PAUSED_GLOBAL_BYTES => Some(UdpIngressDropReason::GlobalBytes),
            _ => None,
        } {
            self.global.record_drop(self.flow_id, reason);
        }
        matches!(
            state,
            INGRESS_PAUSED_COUNT | INGRESS_PAUSED_FLOW_BYTES | INGRESS_PAUSED_GLOBAL_BYTES
        )
    }

    pub(super) fn reject_count_full(
        self: &Arc<Self>,
        channel_capacity_probe: impl FnOnce() -> bool,
    ) {
        self.global
            .record_drop(self.flow_id, UdpIngressDropReason::Count);
        if self.pause(INGRESS_PAUSED_COUNT, 0) && channel_capacity_probe() {
            // The receiver won the race between `try_reserve(Full)` and pause
            // publication. The production probe performs a real semaphore
            // reservation and immediately drops it, rather than trusting a
            // potentially stale capacity snapshot. Re-open immediately instead
            // of stranding an empty flow after its only release edge.
            self.resume(INGRESS_PAUSED_COUNT, 0);
        }
    }

    /// Reserve and copy without invoking demand callbacks. The caller holds
    /// its submission guard through counter publication and channel send, and
    /// applies any returned pressure only after releasing that guard.
    pub(super) fn try_copy_payload_without_demand(
        self: &Arc<Self>,
        bytes: &[u8],
    ) -> Result<Bytes, UdpIngressBytePressure> {
        let len = bytes.len();
        if len == 0 && self.global_probe_id.load(Ordering::Acquire) == 0 {
            return Ok(Bytes::new());
        }
        let Ok(_) =
            self.retained_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(len)
                        .filter(|next| *next <= self.max_retained_bytes)
                })
        else {
            return Err(UdpIngressBytePressure::Flow);
        };

        let probe_id = self.global_probe_id.load(Ordering::Acquire);
        let global_reserved = match self.global.try_consume_probe_lease(self, probe_id, len) {
            ProbeLeaseConsumption::Consumed => true,
            ProbeLeaseConsumption::NoLease => self.global.try_reserve(len),
            // A zero-length UDP datagram consumes no byte capacity. Before the
            // exact ACK it may pass without consuming or releasing the lease;
            // after ACK the `Consumed` arm above refunds the full credit.
            ProbeLeaseConsumption::AwaitingAck if len == 0 => true,
            ProbeLeaseConsumption::AwaitingAck | ProbeLeaseConsumption::Insufficient => false,
        };
        if !global_reserved {
            let flow_previous = self.retained_bytes.fetch_sub(len, Ordering::AcqRel);
            debug_assert!(flow_previous >= len, "UDP flow byte reservation underflow");
            return Err(UdpIngressBytePressure::Global);
        }

        if len == 0 {
            return Ok(Bytes::new());
        }

        Ok(Bytes::from_owner(RetainedUdpPayload {
            bytes: Box::<[u8]>::from(bytes),
            flow: self.clone(),
        }))
    }

    pub(super) fn reject_byte_pressure(
        self: &Arc<Self>,
        reason: UdpIngressBytePressure,
        len: usize,
    ) {
        match reason {
            UdpIngressBytePressure::Flow => {
                self.global
                    .record_drop(self.flow_id, UdpIngressDropReason::FlowBytes);
                if self.pause(INGRESS_PAUSED_FLOW_BYTES, len) {
                    self.resume_flow_bytes_if_capacity();
                }
            }
            UdpIngressBytePressure::Global => {
                self.global
                    .record_drop(self.flow_id, UdpIngressDropReason::GlobalBytes);
                if self.pause(INGRESS_PAUSED_GLOBAL_BYTES, len) {
                    self.global.register_waiter(self);
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn try_copy_payload(self: &Arc<Self>, bytes: &[u8]) -> Option<Bytes> {
        let result = {
            let _submission = self.begin_submission()?;
            self.try_copy_payload_without_demand(bytes)
        };
        match result {
            Ok(payload) => Some(payload),
            Err(reason) => {
                self.reject_byte_pressure(reason, bytes.len());
                None
            }
        }
    }

    #[cfg(test)]
    pub(super) fn record_accepted(&self, len: usize) {
        self.global.record_accepted(len);
    }

    #[cfg(test)]
    pub(super) fn retained_bytes(&self) -> usize {
        self.retained_bytes.load(Ordering::Acquire)
    }

    fn pause(&self, state: u8, blocked_bytes: usize) -> bool {
        self.blocked_bytes.store(blocked_bytes, Ordering::Release);
        if self
            .state
            .compare_exchange(INGRESS_OPEN, state, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        #[cfg(test)]
        self.global
            .paused_transitions
            .fetch_add(1, Ordering::Relaxed);
        true
    }

    fn resume(&self, expected_state: u8, probe_id: u64) -> bool {
        if self
            .state
            .compare_exchange(
                expected_state,
                INGRESS_OPEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        // Do not clear `blocked_bytes` here. After the PAUSED→OPEN CAS, a new
        // datagram can concurrently publish a fresh blocked size and PAUSED
        // state; a trailing zero store would then corrupt its waiter key. The
        // value is ignored while open/closed and every pause overwrites it
        // before publishing the new state.
        #[cfg(test)]
        self.global
            .resumed_transitions
            .fetch_add(1, Ordering::Relaxed);
        self.global.record_recovery(self.flow_id, expected_state);
        self.dispatch_demand_if_open(probe_id);
        true
    }

    fn dispatch_demand_if_open(&self, probe_id: u64) {
        let _gate = self.demand_gate.lock();
        if self.state.load(Ordering::Acquire) == INGRESS_OPEN {
            (self.demand)(probe_id);
        }
    }

    fn release_retained_bytes(self: &Arc<Self>, len: usize) {
        let previous = self.retained_bytes.fetch_sub(len, Ordering::AcqRel);
        debug_assert!(previous >= len, "UDP flow byte reservation underflow");
        self.global.release(len);
        _ = self
            .flow_capacity_epoch
            .try_update(Ordering::Release, Ordering::Relaxed, |current| {
                current.checked_add(1)
            });
        if self.state.load(Ordering::Acquire) == INGRESS_PAUSED_FLOW_BYTES {
            self.global.schedule_flow_release(self);
        }
    }

    fn resume_flow_bytes_if_capacity(&self) {
        if self.state.load(Ordering::Acquire) != INGRESS_PAUSED_FLOW_BYTES {
            return;
        }
        let needed = self.blocked_bytes.load(Ordering::Acquire);
        // Cold-path handshake matching the global waiter publication. If this
        // marker precedes a payload release RMW, that release observes the
        // PAUSED publication and schedules us. If the release precedes this
        // marker, the returned counter observes its newly available capacity.
        let retained = self.retained_bytes.fetch_add(0, Ordering::AcqRel);
        let fits = retained
            .checked_add(needed)
            .is_some_and(|next| next <= self.max_retained_bytes);
        if fits {
            self.resume(INGRESS_PAUSED_FLOW_BYTES, 0);
            return;
        }

        // The rejected datagram has already been discarded, so its size is
        // only a hint: a later QUIC ACK/control packet may fit in the partial
        // headroom. Spend at most one discovery read per real capacity-release
        // epoch. A second nonfitting packet in the same epoch remains paused,
        // eliminating an immediate demand/drop loop.
        if retained < self.max_retained_bytes {
            let epoch = self.flow_capacity_epoch.load(Ordering::Acquire);
            let discovered = self
                .last_partial_probe_epoch
                .try_update(Ordering::AcqRel, Ordering::Acquire, |last| {
                    (last != epoch).then_some(epoch)
                })
                .is_ok();
            if discovered {
                self.resume(INGRESS_PAUSED_FLOW_BYTES, 0);
            }
        }
    }
}

/// Private owner behind `Bytes`. `Bytes` clones share this owner, so both the
/// per-flow and engine reservations remain live until the final clone drops.
struct RetainedUdpPayload {
    bytes: Box<[u8]>,
    flow: Arc<UdpIngressFlowControl>,
}

impl AsRef<[u8]> for RetainedUdpPayload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for RetainedUdpPayload {
    fn drop(&mut self) {
        let bytes = std::mem::take(&mut self.bytes);
        let len = bytes.len();
        // Refunded capacity may be admitted immediately on another thread.
        // Destroy the allocation before publishing either budget's refund.
        drop(bytes);
        self.flow.release_retained_bytes(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn terminal_close_releases_submission_before_joining_demand() {
        let foreign_session = Arc::new(parking_lot::Mutex::new(()));
        let callback_session = foreign_session.clone();
        let (demand_started_tx, demand_started_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let (callback_result_tx, callback_result_rx) = std::sync::mpsc::channel();
        let flow = UdpIngressFlowControl::new(
            100,
            Arc::new(UdpIngressBudget::new(100)),
            Arc::new(move |_| {
                demand_started_tx.send(()).expect("demand entered");
                // Model an ACK waiting for the session-entry lock held by
                // ingress. Every mock lock wait is bounded even on failure.
                let session = callback_session.try_lock_for(Duration::from_secs(3));
                callback_result_tx
                    .send(session.is_some())
                    .expect("record ACK lock availability");
            }),
        );
        let ingress_flow = flow.clone();
        let (ingress_started_tx, ingress_started_rx) = std::sync::mpsc::channel();
        let ingress = std::thread::spawn(move || {
            let _session = foreign_session.lock();
            ingress_started_tx
                .send(())
                .expect("ingress owns session lock");
            let resumed = continue_rx.recv_timeout(Duration::from_secs(3)).is_ok();
            let submission = ingress_flow
                .submission_gate
                .try_lock_for(Duration::from_secs(1));
            (
                resumed,
                submission.is_some(),
                ingress_flow.state.load(Ordering::Acquire) == INGRESS_CLOSED,
            )
        });
        ingress_started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("ingress entry active");
        let demand_flow = flow.clone();
        let demand = std::thread::spawn(move || demand_flow.request_read());
        demand_started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("demand active");
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let closers: Vec<_> = (0..2)
            .map(|_| {
                let closing_flow = flow.clone();
                let closed_tx = closed_tx.clone();
                std::thread::spawn(move || {
                    closing_flow.close();
                    _ = closed_tx.send(());
                })
            })
            .collect();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while flow.state.load(Ordering::Acquire) != INGRESS_CLOSED
            && std::time::Instant::now() < deadline
        {
            std::thread::yield_now();
        }
        let closed_before_demand_join = flow.state.load(Ordering::Acquire) == INGRESS_CLOSED;
        let returned_before_demand_join = closed_rx.try_recv().is_ok();
        continue_tx
            .send(())
            .expect("let ingress observe closed admission");
        let ingress_result = ingress.join().expect("ingress returned");
        let ack_completed = callback_result_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("callback completed");
        demand.join().expect("demand returned");
        for closer in closers {
            closer.join().expect("close returned");
        }
        assert!(
            closed_before_demand_join,
            "close must seal submission before joining demand"
        );
        assert!(
            !returned_before_demand_join,
            "each close must still join the active demand"
        );
        assert_eq!(
            ingress_result,
            (true, true, true),
            "ingress must acquire submission and observe CLOSED"
        );
        assert!(
            ack_completed,
            "ACK must finish once closed ingress releases the foreign lock"
        );
        assert!(flow.begin_submission().is_none());
    }

    #[test]
    fn byte_pressure_demand_runs_after_submission_guard_is_released() {
        for global_pressure in [false, true] {
            let global = Arc::new(UdpIngressBudget::new(100));
            let owner = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
            let held = owner
                .try_copy_payload(&[0; 90])
                .expect("retained occupancy");
            let flow_slot = Arc::new(std::sync::OnceLock::<Weak<UdpIngressFlowControl>>::new());
            let callback_flow = flow_slot.clone();
            let callbacks = Arc::new(AtomicUsize::new(0));
            let callback_count = callbacks.clone();
            let flow = UdpIngressFlowControl::new(
                if global_pressure { 100 } else { 10 },
                global.clone(),
                Arc::new(move |_| {
                    let flow = callback_flow
                        .get()
                        .expect("installed flow")
                        .upgrade()
                        .expect("live flow");
                    assert!(
                        flow.submission_gate.try_lock().is_some(),
                        "demand held submission gate"
                    );
                    callback_count.fetch_add(1, Ordering::Relaxed);
                }),
            );
            flow_slot
                .set(Arc::downgrade(&flow))
                .expect("install flow once");
            assert!(flow.try_copy_payload(&[0; 20]).is_none());
            if global_pressure {
                // The partial discovery lease calls demand from the paced
                // coordinator after failed ingress admission has returned.
                global.wake_fitting_batch(tokio::time::Instant::now());
            }
            assert_eq!(callbacks.load(Ordering::Relaxed), 1);
            flow.close();
            assert!(flow.begin_submission().is_none());
            assert!(flow.try_copy_payload(&[0]).is_none());
            drop(held);
            assert_eq!(global.snapshot().charged_bytes, 0);
        }
    }

    #[test]
    fn concurrent_global_reservations_never_cross_the_cap() {
        const WORKERS: usize = 16;
        const GLOBAL_SLOTS: usize = 4;
        let global = Arc::new(UdpIngressBudget::new(
            MAX_UDP_DATAGRAM_PAYLOAD_SIZE * GLOBAL_SLOTS,
        ));
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut workers = Vec::with_capacity(WORKERS);

        for _ in 0..WORKERS {
            let global = global.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                let control = UdpIngressFlowControl::new(
                    MAX_UDP_DATAGRAM_PAYLOAD_SIZE,
                    global,
                    Arc::new(|_| {}),
                );
                let bytes = vec![0xA5; MAX_UDP_DATAGRAM_PAYLOAD_SIZE];
                barrier.wait();
                let payload = control.try_copy_payload(&bytes);
                (control, payload)
            }));
        }

        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("reservation worker"))
            .collect();
        let accepted = results
            .iter()
            .filter(|(_, payload)| payload.is_some())
            .count();
        assert_eq!(accepted, GLOBAL_SLOTS);
        let snapshot = global.snapshot();
        assert_eq!(
            snapshot.retained_bytes,
            MAX_UDP_DATAGRAM_PAYLOAD_SIZE * GLOBAL_SLOTS
        );
        assert_eq!(snapshot.peak_retained_bytes, snapshot.retained_bytes);

        for (control, _) in &results {
            control.close();
        }
        drop(results);
        let snapshot = global.snapshot();
        assert_eq!(snapshot.retained_bytes, 0);
        assert_eq!(snapshot.global_waiters, 0);
    }

    #[test]
    fn count_full_release_before_pause_publication_resumes_once() {
        let demand_count = Arc::new(AtomicUsize::new(0));
        let demand_count_for_sink = demand_count.clone();
        let global = Arc::new(UdpIngressBudget::new(DEFAULT_UDP_INGRESS_GLOBAL_MAX_BYTES));
        let control = UdpIngressFlowControl::new(
            DEFAULT_UDP_INGRESS_PER_FLOW_MAX_BYTES,
            global.clone(),
            Arc::new(move |_| {
                demand_count_for_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );

        // The capacity probe must run only after pause publication. `true`
        // models the receiver freeing the slot in the former
        // snapshot-to-publication race window.
        control.reject_count_full(|| {
            assert_eq!(control.state.load(Ordering::Acquire), INGRESS_PAUSED_COUNT);
            true
        });
        assert_eq!(demand_count.load(Ordering::Relaxed), 1);
        assert_eq!(global.snapshot().paused_transitions, 1);
        assert_eq!(global.snapshot().resumed_transitions, 1);
        control.close();
    }

    #[test]
    fn coordinator_wakes_a_fitting_waiter_not_the_newest_waiter() {
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let held_small = holder.try_copy_payload(&[0; 10]).expect("reserve 10");
        let held_large = holder.try_copy_payload(&[0; 90]).expect("reserve 90");

        let small_demands = Arc::new(AtomicUsize::new(0));
        let small_demands_sink = small_demands.clone();
        let small = UdpIngressFlowControl::new(
            100,
            global.clone(),
            Arc::new(move |_| {
                small_demands_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        let large_demands = Arc::new(AtomicUsize::new(0));
        let large_demands_sink = large_demands.clone();
        let large = UdpIngressFlowControl::new(
            100,
            global.clone(),
            Arc::new(move |_| {
                large_demands_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );

        assert!(small.try_copy_payload(&[0; 10]).is_none());
        assert!(large.try_copy_payload(&[0; 80]).is_none());
        assert_eq!(global.snapshot().global_waiters, 2);

        drop(held_small);
        assert_eq!(
            small_demands.load(Ordering::Relaxed),
            0,
            "payload drop must not synchronously dispatch demand"
        );
        assert_eq!(global.wake_fitting_batch(tokio::time::Instant::now()), 1);
        assert_eq!(small_demands.load(Ordering::Relaxed), 1);
        assert_eq!(large_demands.load(Ordering::Relaxed), 0);
        assert_eq!(global.snapshot().global_waiters, 1);

        small.close();
        large.close();
        holder.close();
        drop(held_large);
        assert_eq!(global.snapshot().retained_bytes, 0);
    }

    #[test]
    fn coordinator_never_over_wakes_and_acked_delivery_advances_fifo() {
        let global = Arc::new(UdpIngressBudget::new(20));
        let holder = UdpIngressFlowControl::new(20, global.clone(), Arc::new(|_| {}));
        let released = holder
            .try_copy_payload(&[0; 10])
            .expect("reserve first half");
        let retained = holder
            .try_copy_payload(&[0; 10])
            .expect("reserve second half");
        let order = Arc::new(parking_lot::Mutex::new(Vec::new()));

        let mut flows = Vec::new();
        for index in 0..GLOBAL_WAKE_BATCH + 2 {
            let order = order.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |probe_id| order.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&[0; 10]).is_none());
            flows.push(flow);
        }

        drop(released);
        assert!(order.lock().is_empty(), "release must only atomically kick");
        let mut now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 1);
        assert_eq!(order.lock().len(), 1);
        assert_eq!(global.snapshot().provisional_probe_bytes, 10);
        assert_eq!(global.snapshot().provisional_probe_count, 1);
        assert_eq!(global.snapshot().charged_bytes, 20);

        // The same 10 bytes of headroom cannot provision another 10-byte
        // callback until the exact first lease is acknowledged and consumed
        // by its owner's delivered payload.
        assert_eq!(global.wake_fitting_batch(now), 0);
        for expected_index in 0..GLOBAL_WAKE_BATCH + 2 {
            let (index, probe_id) = order.lock()[expected_index];
            assert_eq!(index, expected_index);
            assert_ne!(probe_id, 0);
            assert!(global.acknowledge_probe_lease(&flows[index], probe_id, now));
            assert_eq!(global.snapshot().charged_bytes, 20);
            let delivered = flows[index]
                .try_copy_payload(&[0; 10])
                .expect("ACKed owner consumes its exact lease");
            assert_eq!(global.snapshot().provisional_probe_count, 0);
            assert_eq!(global.snapshot().retained_bytes, 20);
            assert_eq!(global.snapshot().charged_bytes, 20);
            drop(delivered);
            assert_eq!(global.snapshot().retained_bytes, 10);
            assert_eq!(global.snapshot().charged_bytes, 10);
            if expected_index + 1 < GLOBAL_WAKE_BATCH + 2 {
                assert_eq!(global.wake_fitting_batch(now), 0);
                now += GLOBAL_WAKE_RETRY;
                assert_eq!(global.wake_fitting_batch(now), 1);
            }
        }
        assert_eq!(global.snapshot().global_waiters, 0);
        assert_eq!(global.snapshot().provisional_probe_bytes, 0);
        assert_eq!(global.snapshot().charged_bytes, 10);

        for flow in flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().retained_bytes, 0);
    }

    #[test]
    fn partial_discovery_lease_admits_small_datagram_after_large_drop() {
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("reserve 90");
        let demands = Arc::new(AtomicUsize::new(0));
        let demands_sink = demands.clone();
        let waiter = UdpIngressFlowControl::new(
            100,
            global.clone(),
            Arc::new(move |_| {
                demands_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        assert!(waiter.try_copy_payload(&[0; 80]).is_none());
        assert!(
            global.coordinator_signal.pending.load(Ordering::Acquire),
            "partial headroom at registration must schedule discovery"
        );

        let now = tokio::time::Instant::now();
        assert_eq!(demands.load(Ordering::Relaxed), 0);
        assert_eq!(global.wake_fitting_batch(now), 1);
        assert_eq!(demands.load(Ordering::Relaxed), 1);
        assert_eq!(global.snapshot().global_waiters, 0);
        assert_eq!(global.snapshot().provisional_probe_bytes, 10);
        assert_eq!(global.snapshot().charged_bytes, 100);

        let probe_id = waiter.global_probe_id.load(Ordering::Acquire);
        assert_ne!(probe_id, 0);
        assert_eq!(
            global.try_consume_probe_lease(&waiter, probe_id, 5),
            ProbeLeaseConsumption::AwaitingAck,
            "delivery cannot consume a lease before its exact read-complete ACK"
        );
        assert!(global.acknowledge_probe_lease(&waiter, probe_id, now));
        let small = waiter
            .try_copy_payload(&[0; 5])
            .expect("a smaller next datagram consumes and refunds the discovery credit");
        let snapshot = global.snapshot();
        assert_eq!(snapshot.provisional_probe_count, 0);
        assert_eq!(snapshot.retained_bytes, 95);
        assert_eq!(snapshot.charged_bytes, 95);
        drop(small);

        waiter.close();
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().retained_bytes, 0);
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[test]
    fn repeated_large_global_discovery_is_lease_paced_without_spin() {
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain 90");
        let demands = Arc::new(AtomicUsize::new(0));
        let demands_sink = demands.clone();
        let waiter = UdpIngressFlowControl::new(
            100,
            global.clone(),
            Arc::new(move |_| {
                demands_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        assert!(waiter.try_copy_payload(&[0; 80]).is_none());

        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 1);
        let probe_id = waiter.global_probe_id.load(Ordering::Acquire);
        assert!(global.acknowledge_probe_lease(&waiter, probe_id, now));
        assert!(waiter.try_copy_payload(&[0; 80]).is_none());
        assert_eq!(demands.load(Ordering::Relaxed), 1);
        assert_eq!(global.snapshot().provisional_probe_bytes, 10);
        assert_eq!(global.snapshot().charged_bytes, 100);
        assert_eq!(global.snapshot().global_waiters, 1);

        assert_eq!(
            global.wake_fitting_batch(now + GLOBAL_WAKE_RETRY),
            0,
            "same unchanged headroom cannot trigger a millisecond retry loop"
        );
        assert_eq!(demands.load(Ordering::Relaxed), 1);
        assert_eq!(
            global.wake_fitting_batch(
                now + DEFAULT_UDP_INGRESS_PROBE_LEASE + Duration::from_millis(1)
            ),
            0,
            "default lease expiry cannot create a 100Hz nonfitting read loop"
        );
        assert_eq!(demands.load(Ordering::Relaxed), 1);
        assert_eq!(
            global.wake_fitting_batch(
                now + GLOBAL_ACKED_PROBE_DELIVERY_GRACE + Duration::from_millis(1)
            ),
            1,
            "the delivery grace provides the bounded next discovery"
        );
        assert_eq!(demands.load(Ordering::Relaxed), 2);
        assert_eq!(global.snapshot().provisional_probe_count, 1);
        assert_eq!(global.snapshot().charged_bytes, 100);

        waiter.close();
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn already_leased_waiters_quiesce_until_earliest_lease_expiry() {
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let released = holder
            .try_copy_payload(&[0; 90])
            .expect("reserve released capacity");
        let retained = holder.try_copy_payload(&[0; 10]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut flows = Vec::with_capacity(GLOBAL_WAKE_BATCH);
        for index in 0..GLOBAL_WAKE_BATCH {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                30,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&[0; 20]).is_none());
            flows.push(flow);
        }

        drop(released);
        let issued_at = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(issued_at), GLOBAL_WAKE_BATCH);
        let initial = observed.lock().clone();
        assert_eq!(initial.len(), GLOBAL_WAKE_BATCH);
        for &(index, probe_id) in &initial {
            assert!(global.acknowledge_probe_lease(&flows[index], probe_id, issued_at));
        }

        let owner_payload = flows[0]
            .try_copy_payload(&[0; 30])
            .expect("first owner grows into final headroom");
        for flow in flows.iter().skip(1) {
            assert!(flow.try_copy_payload(&[0; 30]).is_none());
        }
        let snapshot = global.snapshot();
        assert_eq!(snapshot.global_waiters, GLOBAL_WAKE_BATCH - 1);
        assert_eq!(snapshot.provisional_probe_count, GLOBAL_WAKE_BATCH - 1);
        assert_eq!(snapshot.provisional_probe_bytes, 60);
        assert_eq!(snapshot.charged_bytes, 100);

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_udp_ingress_coordinator(
            Arc::downgrade(&global),
            global.coordinator_signal.clone(),
            async move {
                _ = stop_rx.await;
            },
        ));
        let before_release = snapshot.coordinator_waiter_inspections;
        drop(owner_payload);
        tokio::time::advance(GLOBAL_WAKE_RETRY).await;
        tokio::task::yield_now().await;
        let after_quiescing_scan = global.snapshot().coordinator_waiter_inspections;
        assert_eq!(
            after_quiescing_scan - before_release,
            (GLOBAL_WAKE_BATCH - 1) as u64
        );
        assert_eq!(observed.lock().len(), GLOBAL_WAKE_BATCH);
        assert_eq!(
            global.next_coordinator_deadline(tokio::time::Instant::now()),
            Some(issued_at + GLOBAL_ACKED_PROBE_DELIVERY_GRACE)
        );

        const QUIET_MILLISECOND_TURNS: u64 = 64;
        for _ in 0..QUIET_MILLISECOND_TURNS {
            tokio::time::advance(GLOBAL_WAKE_RETRY).await;
            tokio::task::yield_now().await;
            assert_eq!(
                global.snapshot().coordinator_waiter_inspections,
                after_quiescing_scan,
                "active insufficient leases must not trigger per-millisecond rescans"
            );
        }
        let remaining_before_expiry = GLOBAL_ACKED_PROBE_DELIVERY_GRACE
            .checked_sub(GLOBAL_WAKE_RETRY + Duration::from_millis(QUIET_MILLISECOND_TURNS + 1))
            .expect("delivery grace exceeds the paced quiet test window");
        tokio::time::advance(remaining_before_expiry).await;
        tokio::task::yield_now().await;
        assert_eq!(
            global.snapshot().coordinator_waiter_inspections,
            after_quiescing_scan,
            "active insufficient leases must not trigger per-millisecond rescans"
        );
        assert_eq!(observed.lock().len(), GLOBAL_WAKE_BATCH);

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(observed.lock().len(), GLOBAL_WAKE_BATCH * 2 - 1);
        assert_eq!(
            global.snapshot().coordinator_waiter_inspections,
            after_quiescing_scan + (GLOBAL_WAKE_BATCH - 1) as u64,
            "lease expiry must start one bounded progress pass"
        );
        let snapshot = global.snapshot();
        assert_eq!(snapshot.global_waiters, 0);
        assert_eq!(snapshot.provisional_probe_count, GLOBAL_WAKE_BATCH - 1);
        assert_eq!(snapshot.provisional_probe_bytes, 90);
        assert_eq!(snapshot.charged_bytes, 100);

        for flow in &flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        _ = stop_tx.send(());
        task.await.expect("coordinator task");
        let snapshot = global.snapshot();
        assert_eq!(snapshot.provisional_probe_count, 0);
        assert_eq!(snapshot.charged_bytes, 0);
        assert_eq!(snapshot.global_waiters, 0);
    }

    #[test]
    fn active_lease_blocks_barging_until_exact_acked_owner_consumes_it() {
        let global = Arc::new(UdpIngressBudget::new(10));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let waiter = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let thief_demands = Arc::new(AtomicUsize::new(0));
        let thief_demands_sink = thief_demands.clone();
        let thief = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |_| {
                thief_demands_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        assert!(waiter.try_copy_payload(&[0; 10]).is_none());

        drop(retained);
        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 1);
        let probe_id = waiter.global_probe_id.load(Ordering::Acquire);
        assert_ne!(probe_id, 0);
        assert_eq!(global.snapshot().charged_bytes, 10);
        assert!(
            thief.try_copy_payload(&[0; 10]).is_none(),
            "unleased flow must not steal capacity charged to the selected owner"
        );
        assert_eq!(global.snapshot().retained_bytes, 0);
        assert_eq!(global.snapshot().charged_bytes, 10);
        assert_eq!(global.snapshot().global_waiters, 1);
        assert!(!global.acknowledge_probe_lease(&thief, probe_id, now));
        assert_eq!(
            global.try_consume_probe_lease(&waiter, probe_id, 10),
            ProbeLeaseConsumption::AwaitingAck
        );

        assert!(global.acknowledge_probe_lease(&waiter, probe_id, now));
        let delivered = waiter
            .try_copy_payload(&[0; 10])
            .expect("exact ACKed owner consumes promised capacity");
        assert!(!global.acknowledge_probe_lease(&waiter, probe_id, now));
        let snapshot = global.snapshot();
        assert_eq!(snapshot.retained_bytes, 10);
        assert_eq!(snapshot.charged_bytes, 10);
        assert_eq!(snapshot.provisional_probe_count, 0);

        drop(delivered);
        assert_eq!(global.snapshot().charged_bytes, 0);
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(
            global.wake_fitting_batch(now + GLOBAL_WAKE_RETRY),
            1,
            "the barred flow receives the next paced opportunity"
        );
        assert_eq!(thief_demands.load(Ordering::Relaxed), 1);

        waiter.close();
        thief.close();
        holder.close();
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[test]
    fn queued_oldest_blocks_continuous_newcomers_before_lease_selection() {
        let global = Arc::new(UdpIngressBudget::new(10));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let order = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let oldest_order = order.clone();
        let oldest = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |_| oldest_order.lock().push("oldest")),
        );
        assert!(oldest.try_copy_payload(&[0; 10]).is_none());
        drop(retained);

        for attempt in 0..128 {
            assert!(
                !global.try_reserve(10),
                "unleased newcomer {attempt} stole released capacity before selection"
            );
        }
        assert_eq!(global.snapshot().charged_bytes, 0);

        let newcomer_order = order.clone();
        let newcomer = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |_| newcomer_order.lock().push("newcomer")),
        );
        assert!(newcomer.try_copy_payload(&[0; 10]).is_none());
        assert_eq!(global.snapshot().global_waiters, 2);

        assert_eq!(global.wake_fitting_batch(tokio::time::Instant::now()), 1);
        assert_eq!(&*order.lock(), &["oldest"]);
        assert_eq!(global.snapshot().charged_bytes, 10);

        oldest.close();
        newcomer.close();
        holder.close();
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[test]
    fn waiter_publication_racing_after_charge_rolls_back_and_kicks() {
        let global = Arc::new(UdpIngressBudget::new(10));
        let demands = Arc::new(AtomicUsize::new(0));
        let demands_sink = demands.clone();
        let waiter = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |_| {
                demands_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        assert!(waiter.pause(INGRESS_PAUSED_GLOBAL_BYTES, 10));

        assert!(
            !global.try_charge_without_barging_after(10, || {
                global.register_waiter(&waiter);
            }),
            "reservation charged before publication must roll back after publication wins"
        );
        let snapshot = global.snapshot();
        assert_eq!(snapshot.charged_bytes, 0);
        assert_eq!(snapshot.global_waiters, 1);
        assert!(
            global.coordinator_signal.pending.load(Ordering::Acquire),
            "rollback must publish the newly available capacity"
        );

        assert_eq!(global.wake_fitting_batch(tokio::time::Instant::now()), 1);
        assert_eq!(demands.load(Ordering::Relaxed), 1);
        assert_eq!(global.snapshot().charged_bytes, 10);

        waiter.close();
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[test]
    fn acked_owner_can_grow_lease_into_unclaimed_headroom() {
        let global = Arc::new(UdpIngressBudget::new(20));
        let holder = UdpIngressFlowControl::new(20, global.clone(), Arc::new(|_| {}));
        let released = holder.try_copy_payload(&[0; 15]).expect("reserve 15");
        let retained = holder.try_copy_payload(&[0; 5]).expect("reserve 5");
        let waiter = UdpIngressFlowControl::new(20, global.clone(), Arc::new(|_| {}));
        assert!(waiter.try_copy_payload(&[0; 10]).is_none());

        drop(released);
        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 1);
        let probe_id = waiter.global_probe_id.load(Ordering::Acquire);
        assert!(global.acknowledge_probe_lease(&waiter, probe_id, now));
        assert_eq!(global.snapshot().charged_bytes, 15);
        let delivered = waiter
            .try_copy_payload(&[0; 15])
            .expect("owner atomically charges only the five-byte lease delta");
        let snapshot = global.snapshot();
        assert_eq!(snapshot.provisional_probe_count, 0);
        assert_eq!(snapshot.retained_bytes, 20);
        assert_eq!(snapshot.charged_bytes, 20);

        drop(delivered);
        waiter.close();
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[test]
    fn zero_length_delivery_only_consumes_an_acked_lease() {
        let global = Arc::new(UdpIngressBudget::new(10));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let waiter = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        assert!(waiter.try_copy_payload(&[0; 10]).is_none());
        drop(retained);

        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 1);
        let probe_id = waiter.global_probe_id.load(Ordering::Acquire);
        assert!(waiter.try_copy_payload(&[]).is_some());
        assert_eq!(global.snapshot().provisional_probe_bytes, 10);
        assert_eq!(global.snapshot().charged_bytes, 10);

        assert!(global.acknowledge_probe_lease(&waiter, probe_id, now));
        assert!(waiter.try_copy_payload(&[]).is_some());
        assert_eq!(global.snapshot().provisional_probe_count, 0);
        assert_eq!(global.snapshot().retained_bytes, 0);
        assert_eq!(global.snapshot().charged_bytes, 0);

        waiter.close();
        holder.close();
    }

    #[test]
    fn republished_waiter_kicks_after_release_in_pop_gap() {
        let global = Arc::new(UdpIngressBudget::new(10));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let demands = Arc::new(AtomicUsize::new(0));
        let demands_for_sink = demands.clone();
        let waiter = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |_| {
                demands_for_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        assert!(waiter.try_copy_payload(&[0; 10]).is_none());

        {
            let mut coordinator = global.coordinator.lock();
            let ((sequence, _needed), candidate) =
                coordinator.waiters.pop_first().expect("registered waiter");
            coordinator.fitting_waiters.remove(sequence);
            let selected = candidate.upgrade().expect("live waiter");
            assert!(Arc::ptr_eq(&selected, &waiter));
            waiter
                .global_waiter_sequence
                .store(NO_GLOBAL_WAITER, Ordering::Release);
            global.waiter_count.fetch_sub(1, Ordering::SeqCst);
        }

        // Model the release landing after selection but before re-publication.
        // With no registered waiter this edge cannot issue demand itself.
        drop(retained);
        assert_eq!(demands.load(Ordering::Relaxed), 0);
        global.register_waiter(&waiter);
        assert!(global.coordinator_signal.pending.load(Ordering::Acquire));
        assert_eq!(global.wake_fitting_batch(tokio::time::Instant::now()), 1);
        assert_eq!(demands.load(Ordering::Relaxed), 1);
        assert_eq!(global.snapshot().global_waiters, 0);

        waiter.close();
        holder.close();
    }

    #[test]
    fn resume_never_clobbers_a_new_waiter_blocked_size() {
        let global = Arc::new(UdpIngressBudget::new(10));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let waiter = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        assert!(waiter.try_copy_payload(&[0; 7]).is_none());
        assert_eq!(waiter.blocked_bytes.load(Ordering::Acquire), 7);

        global.remove_waiter(&waiter);
        assert!(waiter.resume(INGRESS_PAUSED_GLOBAL_BYTES, 0));
        assert_eq!(
            waiter.blocked_bytes.load(Ordering::Acquire),
            7,
            "open state must not clear a concurrently publishable waiter key"
        );

        assert!(waiter.pause(INGRESS_PAUSED_GLOBAL_BYTES, 9));
        global.register_waiter(&waiter);
        assert_eq!(waiter.blocked_bytes.load(Ordering::Acquire), 9);
        waiter.close();
        assert_eq!(global.snapshot().global_waiters, 0);

        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().retained_bytes, 0);
    }

    #[test]
    fn flow_byte_pause_self_resumes_after_release_before_publication() {
        let demands = Arc::new(AtomicUsize::new(0));
        let demands_for_sink = demands.clone();
        let global = Arc::new(UdpIngressBudget::new(100));
        let control = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |_| {
                demands_for_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        let retained = control
            .try_copy_payload(&[0; 10])
            .expect("fill flow budget");

        // Model the payload release winning after a failed reservation but
        // before PAUSED_FLOW_BYTES is published. The release sees OPEN and
        // cannot wake; the post-publication marker must observe its capacity.
        drop(retained);
        assert_eq!(demands.load(Ordering::Relaxed), 0);
        assert!(control.pause(INGRESS_PAUSED_FLOW_BYTES, 7));
        control.resume_flow_bytes_if_capacity();
        assert_eq!(demands.load(Ordering::Relaxed), 1);
        assert_eq!(control.state.load(Ordering::Acquire), INGRESS_OPEN);

        control.close();
        assert_eq!(global.snapshot().retained_bytes, 0);
    }

    #[test]
    fn flow_release_wakes_are_deduplicated_fifo_bounded_and_unlinked_on_close() {
        const FLOW_COUNT: usize = FLOW_RELEASE_WAKE_BATCH * 3 + 1;
        let global = Arc::new(UdpIngressBudget::new(FLOW_COUNT * 2));
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut controls = Vec::new();
        for id in 0..FLOW_COUNT {
            let observed = observed.clone();
            let control = UdpIngressFlowControl::new(
                2,
                global.clone(),
                Arc::new(move |_| observed.lock().push(id)),
            );
            let first = control.try_copy_payload(&[1]).expect("first retained byte");
            let second = control
                .try_copy_payload(&[2])
                .expect("second retained byte");
            assert!(control.try_copy_payload(&[3]).is_none());
            drop(first);
            drop(second);
            controls.push(control);
        }
        assert!(
            observed.lock().is_empty(),
            "release must never dispatch inline"
        );
        assert_eq!(global.coordinator.lock().released_flows.len(), FLOW_COUNT);

        // Cancellation unlinks the entry without waiting for a coordinator
        // turn, and repeated close cannot refund or dispatch it a second time.
        controls[1].close();
        controls[1].close();
        assert_eq!(
            global.coordinator.lock().released_flows.len(),
            FLOW_COUNT - 1
        );
        let expected: Vec<_> = (0..FLOW_COUNT).filter(|id| *id != 1).collect();
        let mut now = tokio::time::Instant::now();
        for completed in (FLOW_RELEASE_WAKE_BATCH..FLOW_COUNT).step_by(FLOW_RELEASE_WAKE_BATCH) {
            assert_eq!(
                global.wake_released_flow_batch(now),
                FLOW_RELEASE_WAKE_BATCH
            );
            assert_eq!(*observed.lock(), expected[..completed]);
            assert_eq!(global.wake_released_flow_batch(now), 0);
            if completed < expected.len() {
                assert_eq!(
                    global.next_coordinator_deadline(now),
                    Some(now + GLOBAL_WAKE_RETRY)
                );
            }
            now += GLOBAL_WAKE_RETRY;
        }
        assert!(global.coordinator.lock().released_flows.is_empty());
        assert_eq!(global.next_coordinator_deadline(now), None);
        for control in controls {
            control.close();
        }
        assert_eq!(global.snapshot().retained_bytes, 0);
    }

    #[tokio::test]
    async fn shutdown_discards_pending_flow_releases_and_rejects_late_releases() {
        let global = Arc::new(UdpIngressBudget::new(4));
        let demands = Arc::new(AtomicUsize::new(0));
        let demands_for_sink = demands.clone();
        let control = UdpIngressFlowControl::new(
            2,
            global.clone(),
            Arc::new(move |_| {
                demands_for_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        let first = control.try_copy_payload(&[1]).expect("first retained byte");
        let last = control.try_copy_payload(&[2]).expect("last retained byte");
        assert!(control.try_copy_payload(&[3]).is_none());
        drop(first);
        assert_eq!(global.coordinator.lock().released_flows.len(), 1);
        run_udp_ingress_coordinator(
            Arc::downgrade(&global),
            global.coordinator_signal.clone(),
            std::future::ready(()),
        )
        .await;
        assert!(global.coordinator.lock().released_flows.is_empty());
        assert_eq!(
            control.release_waiter_sequence.load(Ordering::Acquire),
            NO_RELEASE_WAITER
        );

        drop(last);
        assert!(global.coordinator.lock().released_flows.is_empty());
        assert_eq!(
            global.wake_released_flow_batch(tokio::time::Instant::now()),
            0
        );
        assert_eq!(demands.load(Ordering::Relaxed), 0);
        assert_eq!(global.snapshot().retained_bytes, 0);
        control.close();
    }

    #[test]
    fn flow_byte_partial_discovery_is_once_per_release_epoch_and_admits_next_small() {
        let demands = Arc::new(AtomicUsize::new(0));
        let demands_for_sink = demands.clone();
        let global = Arc::new(UdpIngressBudget::new(1_000));
        let control = UdpIngressFlowControl::new(
            100,
            global.clone(),
            Arc::new(move |_| {
                demands_for_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        let retained_large = control
            .try_copy_payload(&[0; 80])
            .expect("retain 80 flow bytes");
        let retained_small = control
            .try_copy_payload(&[0; 10])
            .expect("retain another 10 flow bytes");

        assert!(control.try_copy_payload(&[0; 80]).is_none());
        assert_eq!(
            demands.load(Ordering::Relaxed),
            1,
            "initial partial headroom grants one discovery"
        );
        assert_eq!(control.state.load(Ordering::Acquire), INGRESS_OPEN);

        assert!(control.try_copy_payload(&[0; 80]).is_none());
        assert_eq!(
            demands.load(Ordering::Relaxed),
            1,
            "same capacity epoch cannot create a demand/drop loop"
        );
        assert_eq!(
            control.state.load(Ordering::Acquire),
            INGRESS_PAUSED_FLOW_BYTES
        );

        drop(retained_small);
        assert_eq!(demands.load(Ordering::Relaxed), 1);
        assert_eq!(
            global.wake_released_flow_batch(tokio::time::Instant::now()),
            1
        );
        assert_eq!(demands.load(Ordering::Relaxed), 2);
        assert_eq!(control.state.load(Ordering::Acquire), INGRESS_OPEN);
        let next_small = control
            .try_copy_payload(&[0; 5])
            .expect("small control packet fits after the paced discovery");

        drop(next_small);
        drop(retained_large);
        control.close();
        assert_eq!(global.snapshot().retained_bytes, 0);
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[test]
    fn closed_global_waiter_is_removed_and_never_receives_late_demand() {
        let demand_count = Arc::new(AtomicUsize::new(0));
        let demand_count_for_sink = demand_count.clone();
        let global = Arc::new(UdpIngressBudget::new(MAX_UDP_DATAGRAM_PAYLOAD_SIZE));
        let retaining_control = UdpIngressFlowControl::new(
            MAX_UDP_DATAGRAM_PAYLOAD_SIZE,
            global.clone(),
            Arc::new(|_| {}),
        );
        let waiting_control = UdpIngressFlowControl::new(
            MAX_UDP_DATAGRAM_PAYLOAD_SIZE,
            global.clone(),
            Arc::new(move |_| {
                demand_count_for_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        let bytes = vec![0xA5; MAX_UDP_DATAGRAM_PAYLOAD_SIZE];

        let retained = retaining_control
            .try_copy_payload(&bytes)
            .expect("first flow reserves the global budget");
        assert!(waiting_control.try_copy_payload(&bytes).is_none());
        assert_eq!(global.snapshot().global_waiters, 1);

        waiting_control.close();
        assert_eq!(global.snapshot().global_waiters, 0);
        drop(retained);
        assert_eq!(demand_count.load(Ordering::Relaxed), 0);
        assert_eq!(global.snapshot().retained_bytes, 0);
        retaining_control.close();
    }

    #[test]
    fn stale_probe_ack_cannot_release_a_newer_lease() {
        let global = Arc::new(UdpIngressBudget::new(10));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let first_id = Arc::new(AtomicU64::new(0));
        let first_id_sink = first_id.clone();
        let first = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |id| first_id_sink.store(id, Ordering::Release)),
        );
        let second_id = Arc::new(AtomicU64::new(0));
        let second_id_sink = second_id.clone();
        let second = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |id| second_id_sink.store(id, Ordering::Release)),
        );
        assert!(first.try_copy_payload(&[0; 10]).is_none());
        assert!(second.try_copy_payload(&[0; 10]).is_none());
        drop(retained);
        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 1);
        let old_id = first_id.load(Ordering::Acquire);
        assert_ne!(old_id, 0);
        assert!(global.acknowledge_probe_lease(&first, old_id, now));
        let first_payload = first
            .try_copy_payload(&[0; 10])
            .expect("first ACKed owner consumes lease");
        drop(first_payload);
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(global.wake_fitting_batch(now + GLOBAL_WAKE_RETRY), 1);
        let new_id = second_id.load(Ordering::Acquire);
        assert_ne!(new_id, 0);
        assert_ne!(new_id, old_id);

        assert!(!global.acknowledge_probe_lease(&first, old_id, now + GLOBAL_WAKE_RETRY));
        assert!(!global.acknowledge_probe_lease(&first, new_id, now + GLOBAL_WAKE_RETRY));
        assert_eq!(global.snapshot().provisional_probe_count, 1);
        assert_eq!(global.snapshot().provisional_probe_bytes, 10);
        assert_eq!(global.snapshot().charged_bytes, 10);
        assert!(global.acknowledge_probe_lease(&second, new_id, now + GLOBAL_WAKE_RETRY));
        let second_payload = second
            .try_copy_payload(&[0; 10])
            .expect("new exact owner still consumes after wrong and stale ACKs");
        assert_eq!(global.snapshot().provisional_probe_count, 0);
        assert_eq!(global.snapshot().charged_bytes, 10);
        drop(second_payload);

        first.close();
        second.close();
        holder.close();
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[test]
    fn close_releases_an_active_probe_once_and_advances_fifo() {
        let global = Arc::new(UdpIngressBudget::new(10));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let first = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let second_demands = Arc::new(AtomicUsize::new(0));
        let second_demands_sink = second_demands.clone();
        let second = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |_| {
                second_demands_sink.fetch_add(1, Ordering::Relaxed);
            }),
        );
        assert!(first.try_copy_payload(&[0; 10]).is_none());
        assert!(second.try_copy_payload(&[0; 10]).is_none());
        drop(retained);
        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 1);
        assert_eq!(global.snapshot().provisional_probe_count, 1);
        assert_eq!(global.snapshot().charged_bytes, 10);

        first.close();
        first.close();
        assert_eq!(global.snapshot().provisional_probe_count, 0);
        assert_eq!(global.snapshot().charged_bytes, 0);
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(global.wake_fitting_batch(now + GLOBAL_WAKE_RETRY), 1);
        assert_eq!(second_demands.load(Ordering::Relaxed), 1);

        second.close();
        assert_eq!(global.snapshot().provisional_probe_count, 0);
        assert_eq!(global.snapshot().charged_bytes, 0);
        holder.close();
    }

    #[test]
    fn close_racing_expiry_removes_once_and_advances_one_waiter() {
        for _ in 0..64 {
            let global = Arc::new(UdpIngressBudget::new(10));
            let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
            let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
            let owner = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
            let next_demands = Arc::new(AtomicUsize::new(0));
            let next_demands_sink = next_demands.clone();
            let next = UdpIngressFlowControl::new(
                10,
                global.clone(),
                Arc::new(move |_| {
                    next_demands_sink.fetch_add(1, Ordering::Relaxed);
                }),
            );
            assert!(owner.try_copy_payload(&[0; 10]).is_none());
            assert!(next.try_copy_payload(&[0; 10]).is_none());
            drop(retained);

            let issued_at = tokio::time::Instant::now();
            assert_eq!(global.wake_fitting_batch(issued_at), 1);
            let stale_id = owner.global_probe_id.load(Ordering::Acquire);
            assert!(global.acknowledge_probe_lease(&owner, stale_id, issued_at));
            let expires_at = issued_at + GLOBAL_ACKED_PROBE_DELIVERY_GRACE;

            let barrier = Arc::new(Barrier::new(3));
            let close_barrier = barrier.clone();
            let close_owner = owner.clone();
            let close_thread = std::thread::spawn(move || {
                close_barrier.wait();
                close_owner.close();
            });
            let expiry_barrier = barrier.clone();
            let expiry_global = global.clone();
            let expiry_thread = std::thread::spawn(move || {
                expiry_barrier.wait();
                expiry_global.wake_fitting_batch(expires_at)
            });
            barrier.wait();
            close_thread.join().expect("close race thread");
            _ = expiry_thread.join().expect("expiry race thread");

            assert_eq!(next_demands.load(Ordering::Relaxed), 1);
            assert_eq!(
                global.try_consume_probe_lease(&owner, stale_id, 10),
                ProbeLeaseConsumption::NoLease
            );
            let snapshot = global.snapshot();
            assert_eq!(snapshot.provisional_probe_count, 1);
            assert_eq!(snapshot.provisional_probe_bytes, 10);
            assert_eq!(snapshot.charged_bytes, 10);
            assert_eq!(snapshot.global_waiters, 0);

            owner.close();
            next.close();
            holder.close();
            let snapshot = global.snapshot();
            assert_eq!(snapshot.provisional_probe_count, 0);
            assert_eq!(snapshot.charged_bytes, 0);
            assert_eq!(snapshot.global_waiters, 0);
        }
    }

    #[test]
    fn acked_undelivered_lease_expires_once_after_delivery_grace() {
        let probe_lease = Duration::from_millis(20);
        let global = Arc::new(UdpIngressBudget::new_with_probe_lease(10, probe_lease));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let waiter = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        assert!(waiter.try_copy_payload(&[0; 10]).is_none());
        drop(retained);

        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 1);
        let probe_id = waiter.global_probe_id.load(Ordering::Acquire);
        assert!(global.acknowledge_probe_lease(&waiter, probe_id, now));
        assert!(
            !global.acknowledge_probe_lease(&waiter, probe_id, now + Duration::from_millis(100)),
            "duplicate ACK must not extend the delivery deadline"
        );
        assert_eq!(
            global.wake_fitting_batch(
                now + GLOBAL_ACKED_PROBE_DELIVERY_GRACE - Duration::from_millis(1)
            ),
            0
        );
        assert_eq!(global.snapshot().charged_bytes, 10);
        assert_eq!(
            global.wake_fitting_batch(now + GLOBAL_ACKED_PROBE_DELIVERY_GRACE),
            0
        );
        assert_eq!(global.snapshot().provisional_probe_count, 0);
        assert_eq!(global.snapshot().charged_bytes, 0);
        assert!(!global.acknowledge_probe_lease(
            &waiter,
            probe_id,
            now + GLOBAL_ACKED_PROBE_DELIVERY_GRACE
        ));

        waiter.close();
        waiter.close();
        holder.close();
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn late_empty_read_ack_retires_expired_lease_and_wakes_next_waiter() {
        let global = Arc::new(UdpIngressBudget::new(10));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let first_id = Arc::new(AtomicU64::new(0));
        let first_id_sink = first_id.clone();
        let first = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |probe_id| first_id_sink.store(probe_id, Ordering::Release)),
        );
        let second_id = Arc::new(AtomicU64::new(0));
        let second_id_sink = second_id.clone();
        let second = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |probe_id| second_id_sink.store(probe_id, Ordering::Release)),
        );
        assert!(first.try_copy_payload(&[0; 10]).is_none());
        assert!(second.try_copy_payload(&[0; 10]).is_none());
        drop(retained);

        let issued_at = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(issued_at), 1);
        let expired_id = first_id.load(Ordering::Acquire);
        assert_ne!(expired_id, 0);
        global.coordinator_signal.coalesce_before_probe();
        assert!(!global.coordinator_signal.pending.load(Ordering::Acquire));

        tokio::time::advance(DEFAULT_UDP_INGRESS_PROBE_LEASE + Duration::from_millis(1)).await;
        assert!(
            !global.acknowledge_probe_lease(&first, expired_id, tokio::time::Instant::now()),
            "an empty read completed after expiry must not ACK stale credit"
        );
        let snapshot = global.snapshot();
        assert_eq!(snapshot.provisional_probe_count, 0);
        assert_eq!(snapshot.charged_bytes, 0);
        assert_eq!(snapshot.global_waiters, 1);
        assert_eq!(first.global_probe_id.load(Ordering::Acquire), 0);
        assert!(
            global.coordinator_signal.pending.load(Ordering::Acquire),
            "late exact-owner ACK must signal the newly released opportunity"
        );

        // Start the coordinator only after the late ACK. The next waiter must
        // advance from that release signal; no lease-expiry timer existed.
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_udp_ingress_coordinator(
            Arc::downgrade(&global),
            global.coordinator_signal.clone(),
            async move {
                _ = stop_rx.await;
            },
        ));
        tokio::task::yield_now().await;
        assert_ne!(second_id.load(Ordering::Acquire), 0);
        let snapshot = global.snapshot();
        assert_eq!(snapshot.provisional_probe_count, 1);
        assert_eq!(snapshot.charged_bytes, 10);
        assert_eq!(snapshot.global_waiters, 0);

        first.close();
        second.close();
        holder.close();
        _ = stop_tx.send(());
        task.await.expect("coordinator task");
        let snapshot = global.snapshot();
        assert_eq!(snapshot.provisional_probe_count, 0);
        assert_eq!(snapshot.charged_bytes, 0);
        assert_eq!(snapshot.global_waiters, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn late_owner_payload_cannot_consume_expired_lease_without_coordinator_tick() {
        let global = Arc::new(UdpIngressBudget::new(10));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let first_id = Arc::new(AtomicU64::new(0));
        let first_id_sink = first_id.clone();
        let first = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |probe_id| first_id_sink.store(probe_id, Ordering::Release)),
        );
        let second_id = Arc::new(AtomicU64::new(0));
        let second_id_sink = second_id.clone();
        let second = UdpIngressFlowControl::new(
            10,
            global.clone(),
            Arc::new(move |probe_id| second_id_sink.store(probe_id, Ordering::Release)),
        );
        assert!(first.try_copy_payload(&[0; 10]).is_none());
        assert!(second.try_copy_payload(&[0; 10]).is_none());
        drop(retained);

        let issued_at = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(issued_at), 1);
        let expired_id = first_id.load(Ordering::Acquire);
        assert_ne!(expired_id, 0);
        assert!(global.acknowledge_probe_lease(&first, expired_id, issued_at));

        tokio::time::advance(GLOBAL_ACKED_PROBE_DELIVERY_GRACE + Duration::from_millis(1)).await;
        assert!(
            first.try_copy_payload(&[0; 10]).is_none(),
            "late owner must not consume credit after its bounded grace"
        );
        let snapshot = global.snapshot();
        assert_eq!(snapshot.provisional_probe_count, 0);
        assert_eq!(snapshot.charged_bytes, 0);
        assert_eq!(snapshot.global_waiters, 2);
        assert_eq!(first.global_probe_id.load(Ordering::Acquire), 0);

        assert_eq!(global.wake_fitting_batch(tokio::time::Instant::now()), 1);
        assert_ne!(second_id.load(Ordering::Acquire), 0);
        assert_eq!(first_id.load(Ordering::Acquire), expired_id);

        first.close();
        second.close();
        holder.close();
        let snapshot = global.snapshot();
        assert_eq!(snapshot.provisional_probe_count, 0);
        assert_eq!(snapshot.charged_bytes, 0);
        assert_eq!(snapshot.global_waiters, 0);
    }

    #[test]
    fn configured_long_probe_lease_is_the_minimum_acked_delivery_grace() {
        let probe_lease = Duration::from_millis(500);
        let global = Arc::new(UdpIngressBudget::new_with_probe_lease(10, probe_lease));
        let holder = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 10]).expect("fill budget");
        let waiter = UdpIngressFlowControl::new(10, global.clone(), Arc::new(|_| {}));
        assert!(waiter.try_copy_payload(&[0; 10]).is_none());
        drop(retained);

        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 1);
        let probe_id = waiter.global_probe_id.load(Ordering::Acquire);
        assert!(global.acknowledge_probe_lease(&waiter, probe_id, now));
        assert_eq!(
            global.wake_fitting_batch(now + probe_lease - Duration::from_millis(1)),
            0
        );
        assert_eq!(global.snapshot().charged_bytes, 10);
        assert_eq!(global.wake_fitting_batch(now + probe_lease), 0);
        assert_eq!(global.snapshot().charged_bytes, 0);

        waiter.close();
        holder.close();
    }

    #[tokio::test(start_paused = true)]
    async fn coordinator_eventually_visits_500_quiet_waiters_at_bounded_rate() {
        const FLOW_COUNT: usize = 500;
        let global = Arc::new(UdpIngressBudget::new(50));
        let holder = UdpIngressFlowControl::new(50, global.clone(), Arc::new(|_| {}));
        let released = holder
            .try_copy_payload(&[0; 40])
            .expect("reserve released headroom");
        let retained = holder
            .try_copy_payload(&[0; 10])
            .expect("reserve retained half");
        let order = Arc::new(parking_lot::Mutex::new(Vec::with_capacity(FLOW_COUNT)));
        let mut flows = Vec::with_capacity(FLOW_COUNT);

        for index in 0..FLOW_COUNT {
            let order = order.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |_| order.lock().push(index)),
            );
            assert!(flow.try_copy_payload(&[0; 10]).is_none());
            flows.push(flow);
        }
        assert_eq!(global.snapshot().global_waiters, FLOW_COUNT);

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_udp_ingress_coordinator(
            Arc::downgrade(&global),
            global.coordinator_signal.clone(),
            async move {
                _ = stop_rx.await;
            },
        ));

        drop(released);
        assert!(
            order.lock().is_empty(),
            "normal payload drop must not run callbacks"
        );
        tokio::task::yield_now().await;
        assert_eq!(order.lock().len(), GLOBAL_WAKE_BATCH);
        assert_eq!(global.snapshot().provisional_probe_count, GLOBAL_WAKE_BATCH);

        let Some(before_probe_expiry) =
            DEFAULT_UDP_INGRESS_PROBE_LEASE.checked_sub(Duration::from_millis(1))
        else {
            panic!("UDP probe lease must exceed one millisecond");
        };
        tokio::time::advance(before_probe_expiry).await;
        tokio::task::yield_now().await;
        assert_eq!(
            order.lock().len(),
            GLOBAL_WAKE_BATCH,
            "quiet callbacks must not accumulate beyond the engine-wide lease cap"
        );

        let turns = FLOW_COUNT.div_ceil(GLOBAL_WAKE_BATCH);
        for completed_turns in 1..turns {
            let before = order.lock().len();
            let advance = if completed_turns == 1 {
                Duration::from_millis(1)
            } else {
                DEFAULT_UDP_INGRESS_PROBE_LEASE
            };
            tokio::time::advance(advance).await;
            tokio::task::yield_now().await;
            let after = order.lock().len();
            assert!(
                after - before <= GLOBAL_WAKE_BATCH,
                "turn {completed_turns} resumed {} flows, above batch {GLOBAL_WAKE_BATCH}",
                after - before
            );
            assert!(global.snapshot().provisional_probe_count <= GLOBAL_WAKE_BATCH);
        }

        let observed = order.lock().clone();
        assert_eq!(observed.len(), FLOW_COUNT);
        assert_eq!(observed, (0..FLOW_COUNT).collect::<Vec<_>>());
        assert_eq!(global.snapshot().global_waiters, 0);
        assert_eq!(
            global.snapshot().resumed_global_bytes_full,
            FLOW_COUNT as u64
        );

        _ = stop_tx.send(());
        task.await.expect("coordinator task");
        for flow in flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().retained_bytes, 0);
    }

    #[test]
    fn coordinator_8192_waiters_are_fifo_constant_inspection_and_four_per_millisecond() {
        const FLOW_COUNT: usize = 8_192;
        let global = Arc::new(UdpIngressBudget::new(GLOBAL_WAKE_BATCH));
        let holder =
            UdpIngressFlowControl::new(GLOBAL_WAKE_BATCH, global.clone(), Arc::new(|_| {}));
        let retained = holder
            .try_copy_payload(&[0; GLOBAL_WAKE_BATCH])
            .expect("fill global budget");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::with_capacity(FLOW_COUNT)));
        let mut flows = Vec::with_capacity(FLOW_COUNT);

        for index in 0..FLOW_COUNT {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                1,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&[0]).is_none());
            flows.push(flow);
        }
        drop(retained);

        let mut now = tokio::time::Instant::now();
        for turn in 0..FLOW_COUNT.div_ceil(GLOBAL_WAKE_BATCH) {
            let before_len = observed.lock().len();
            let before_inspections = global.snapshot().coordinator_waiter_inspections;
            assert_eq!(global.wake_fitting_batch(now), GLOBAL_WAKE_BATCH);
            let after_inspections = global.snapshot().coordinator_waiter_inspections;
            assert_eq!(
                after_inspections - before_inspections,
                GLOBAL_WAKE_BATCH as u64,
                "turn {turn} inspected more waiters than it could issue"
            );
            let issued = observed.lock()[before_len..].to_vec();
            assert_eq!(issued.len(), GLOBAL_WAKE_BATCH);
            for (expected, (index, probe_id)) in ((turn * GLOBAL_WAKE_BATCH)..).zip(issued) {
                assert_eq!(index, expected);
                assert!(global.acknowledge_probe_lease(&flows[index], probe_id, now));
                let delivered = flows[index]
                    .try_copy_payload(&[0])
                    .expect("ACKed owner consumes one-byte lease");
                drop(delivered);
            }
            assert_eq!(
                global.wake_fitting_batch(now),
                0,
                "immediate ACKs bypassed the coordinator cooldown"
            );
            now += GLOBAL_WAKE_RETRY;
        }

        assert_eq!(observed.lock().len(), FLOW_COUNT);
        let snapshot = global.snapshot();
        assert_eq!(snapshot.global_waiters, 0);
        assert_eq!(snapshot.provisional_probe_count, 0);
        assert_eq!(snapshot.charged_bytes, 0);
        assert_eq!(
            snapshot.coordinator_waiter_inspections, FLOW_COUNT as u64,
            "strict FIFO selection must inspect each waiter exactly once"
        );
        for flow in flows {
            flow.close();
        }
        holder.close();
    }

    #[test]
    fn mixed_size_releases_preserve_bounded_partial_discovery() {
        const FLOW_COUNT: usize = 64;
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut flows = Vec::with_capacity(FLOW_COUNT);
        for index in 0..FLOW_COUNT {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            let blocked_size = if index % 2 == 0 { 20 } else { 1 };
            assert!(flow.try_copy_payload(&vec![0; blocked_size]).is_none());
            flows.push(flow);
        }

        let mut now = tokio::time::Instant::now();
        let mut large_hint_probed = [false; FLOW_COUNT / 2];
        // Far more than a full FIFO rotation. Small flows keep releasing real
        // capacity and immediately need another read. A discarded large
        // packet is only a size hint: its next packet can be a small QUIC ACK.
        for _ in 0..FLOW_COUNT * 8 {
            let before = global.snapshot().coordinator_waiter_inspections;
            global.wake_fitting_batch(now);
            assert!(
                global.snapshot().coordinator_waiter_inspections - before
                    <= GLOBAL_SCAN_BATCH as u64
            );
            let issued = std::mem::take(&mut *observed.lock());
            for (index, probe_id) in issued {
                assert!(global.acknowledge_probe_lease(&flows[index], probe_id, now));
                let payload = flows[index]
                    .try_copy_payload(&[0])
                    .expect("the next small datagram fits the acknowledged probe");
                drop(payload);
                if index % 2 == 0 {
                    large_hint_probed[index / 2] = true;
                    flows[index].close();
                } else {
                    assert!(flows[index].try_copy_payload(&[0]).is_none());
                }
            }
            if large_hint_probed.iter().all(|probed| *probed) {
                break;
            }
            now += GLOBAL_WAKE_RETRY;
        }

        for flow in &flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().charged_bytes, 0);
        assert!(
            large_hint_probed.iter().all(|probed| *probed),
            "continuous fitting releases must not indefinitely restart the nonfit discovery pass; probed {} of {} large-hint flows",
            large_hint_probed.iter().filter(|probed| **probed).count(),
            large_hint_probed.len(),
        );
    }

    #[test]
    fn exact_capacity_fitting_retries_do_not_starve_partial_discovery() {
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let large = {
            let observed = observed.clone();
            UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((0, probe_id))),
            )
        };
        let fitting = {
            let observed = observed.clone();
            UdpIngressFlowControl::new(
                10,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((1, probe_id))),
            )
        };
        assert!(large.try_copy_payload(&[0; 20]).is_none());
        assert!(fitting.try_copy_payload(&[0; 10]).is_none());

        let mut now = tokio::time::Instant::now();
        let mut discovered_large_hint = false;
        for _ in 0..16 {
            let before = global.snapshot().coordinator_waiter_inspections;
            _ = global.wake_fitting_batch(now);
            assert!(
                global.snapshot().coordinator_waiter_inspections - before
                    <= GLOBAL_SCAN_BATCH as u64
            );
            for (index, probe_id) in std::mem::take(&mut *observed.lock()) {
                if index == 0 {
                    assert!(global.acknowledge_probe_lease(&large, probe_id, now));
                    let payload = large
                        .try_copy_payload(&[0])
                        .expect("the next small packet consumes the discovery lease");
                    drop(payload);
                    discovered_large_hint = true;
                } else {
                    assert!(global.acknowledge_probe_lease(&fitting, probe_id, now));
                    let payload = fitting
                        .try_copy_payload(&[0; 10])
                        .expect("the fitting flow consumes all free capacity");
                    assert_eq!(
                        global.next_coordinator_deadline(now),
                        None,
                        "owed discovery must not schedule turns while all capacity is retained"
                    );
                    drop(payload);
                    assert!(fitting.try_copy_payload(&[0; 10]).is_none());
                }
            }
            if discovered_large_hint {
                break;
            }
            now += GLOBAL_WAKE_RETRY;
        }

        large.close();
        fitting.close();
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().charged_bytes, 0);
        assert!(
            discovered_large_hint,
            "a fitting flow repeatedly consuming the last free byte must not erase owed discovery"
        );
    }

    #[test]
    fn exhausted_capacity_discovery_survives_fitter_expiry_and_oldest_cancellation() {
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut flows = Vec::new();
        for (index, size) in [20, 20, 10].into_iter().enumerate() {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                size,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&vec![0; size]).is_none());
            flows.push(flow);
        }

        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 1);
        assert_eq!(
            observed.lock()[0].0,
            2,
            "the exact fit gets the first grant"
        );
        flows[0].close();
        assert_eq!(
            global.next_coordinator_deadline(now),
            Some(now + DEFAULT_UDP_INGRESS_PROBE_LEASE),
            "full capacity must wait for the existing lease, not a scan timer"
        );

        let expired_at = now + DEFAULT_UDP_INGRESS_PROBE_LEASE;
        assert_eq!(global.wake_fitting_batch(expired_at), 1);
        let (index, probe_id) = observed.lock()[1];
        assert_eq!(
            index, 1,
            "cancellation must preserve the next owed discovery"
        );
        assert!(global.acknowledge_probe_lease(&flows[index], probe_id, expired_at));
        let payload = flows[index]
            .try_copy_payload(&[0])
            .expect("smaller packet consumes the credit released by expiry");
        drop(payload);
        assert_eq!(global.wake_fitting_batch(expired_at), 0);
        for flow in flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[test]
    fn partial_discovery_total_work_is_linear_across_released_small_packets() {
        for flow_count in [128, 256, 8_192] {
            assert_partial_discovery_total_work_is_linear(flow_count, true);
        }
    }

    #[test]
    fn partial_discovery_total_work_is_linear_across_nonfitting_reparks() {
        for flow_count in [128, 256, 8_192] {
            assert_partial_discovery_total_work_is_linear(flow_count, false);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fitting_retries_progress_during_256_nonfitting_discoveries() {
        assert_fitting_retries_progress_during_discovery(256).await;
    }

    #[tokio::test(start_paused = true)]
    async fn fitting_retries_progress_during_8192_nonfitting_discoveries() {
        assert_fitting_retries_progress_during_discovery(8_192).await;
    }

    #[tokio::test(start_paused = true)]
    async fn older_medium_fitter_precedes_recurring_tiny_fitter_during_128_discoveries() {
        assert_older_medium_fitter_progresses_during_discovery(128).await;
    }

    #[tokio::test(start_paused = true)]
    async fn older_medium_fitter_precedes_recurring_tiny_fitter_during_8192_discoveries() {
        assert_older_medium_fitter_progresses_during_discovery(8_192).await;
    }

    async fn assert_older_medium_fitter_progresses_during_discovery(flow_count: usize) {
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut flows = Vec::with_capacity(flow_count + 2);
        for index in 0..flow_count {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&[0; 20]).is_none());
            flows.push(flow);
        }
        for _ in 0..flow_count.div_ceil(GLOBAL_SCAN_BATCH) + 1 {
            let now = tokio::time::Instant::now();
            _ = global.wake_fitting_batch(now);
            if !observed.lock().is_empty() {
                break;
            }
            tokio::time::advance(GLOBAL_WAKE_RETRY).await;
        }
        let (index, probe_id) = observed.lock().remove(0);
        assert_eq!(index, 0);
        assert!(global.acknowledge_probe_lease(
            &flows[index],
            probe_id,
            tokio::time::Instant::now()
        ));
        assert!(flows[index].try_copy_payload(&[0; 20]).is_none());

        // Both fitting flows arrive after the finite discovery frontier. The
        // older medium packet fits the ten bytes refunded by the first lease;
        // a newer one-byte retry must not repeatedly take those opportunities.
        for (index, size) in [(flow_count, 10), (flow_count + 1, 1)] {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&vec![0; size]).is_none());
            flows.push(flow);
        }
        let mut medium_served = false;
        let mut tiny_grants = 0;
        for _ in 0..8 {
            let now = tokio::time::Instant::now();
            let deadline = global
                .next_coordinator_deadline(now)
                .expect("lease or paced retry");
            tokio::time::advance(deadline.saturating_duration_since(now)).await;
            let now = tokio::time::Instant::now();
            let before = global.snapshot().coordinator_waiter_inspections;
            _ = global.wake_fitting_batch(now);
            assert!(
                global.snapshot().coordinator_waiter_inspections - before
                    <= GLOBAL_SCAN_BATCH as u64
            );
            for (index, probe_id) in std::mem::take(&mut *observed.lock()) {
                assert!(global.acknowledge_probe_lease(&flows[index], probe_id, now));
                if index == flow_count {
                    drop(
                        flows[index]
                            .try_copy_payload(&[0; 10])
                            .expect("older medium fits"),
                    );
                    medium_served = true;
                } else if index == flow_count + 1 {
                    drop(
                        flows[index]
                            .try_copy_payload(&[0])
                            .expect("tiny packet fits"),
                    );
                    assert!(flows[index].try_copy_payload(&[0]).is_none());
                    tiny_grants += 1;
                    assert!(
                        tiny_grants <= 1,
                        "{flow_count} stale hints let recurring tiny traffic starve the older medium fitter"
                    );
                } else {
                    assert!(flows[index].try_copy_payload(&[0; 20]).is_none());
                }
                assert!(global.snapshot().charged_bytes <= 100);
            }
            if medium_served {
                break;
            }
        }
        assert!(
            medium_served,
            "older fitting traffic must not wait for the cohort to end"
        );
        assert_eq!(
            tiny_grants, 0,
            "the oldest currently fitting waiter receives the opportunity"
        );
        assert!(
            global.snapshot().coordinator_waiter_inspections
                <= (flow_count + GLOBAL_SCAN_BATCH) as u64
        );
        for flow in flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().charged_bytes, 0);
        assert!(global.coordinator.lock().fitting_waiters.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn oldest_fitting_index_survives_mixed_waiter_lifecycles() {
        const FLOW_COUNT: usize = 128;
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let make_flow = |index, size| {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                100,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&vec![0; size]).is_none());
            flow
        };
        let mut sizes: Vec<_> = (0..FLOW_COUNT).map(|index| 11 + index * 37 % 90).collect();
        let mut flows: Vec<_> = sizes
            .iter()
            .enumerate()
            .map(|(index, &size)| make_flow(index, size))
            .collect();

        // Exercise deletion through the coordinator's real cancellation path
        // while the indexed node has two children, then register its replacement.
        let sequence = {
            let coordinator = global.coordinator.lock();
            let root = coordinator
                .fitting_waiters
                .root
                .as_ref()
                .expect("populated index");
            assert!(root.left.is_some() && root.right.is_some());
            root.sequence
        };
        let index = flows
            .iter()
            .position(|flow| flow.global_waiter_sequence.load(Ordering::Acquire) == sequence)
            .expect("root's live waiter");
        flows[index].close();
        flows[index] = make_flow(index, sizes[index]);
        assert_fitting_index_matches_waiters(&global);

        for turn in 0..512 {
            let index = (turn * 73 + 19) % FLOW_COUNT;
            if turn % 4 == 0 {
                flows[index].close();
                sizes[index] = 11 + (turn * 43) % 90;
                flows[index] = make_flow(index, sizes[index]);
            } else if flows[index].state.load(Ordering::Acquire) == INGRESS_OPEN {
                // A callback deliberately left unacknowledged below can expire
                // before the next read arrives and re-registers a fresh waiter.
                assert!(
                    flows[index]
                        .try_copy_payload(&vec![0; sizes[index]])
                        .is_none()
                );
            }
            let now = tokio::time::Instant::now();
            let deadline = global
                .next_coordinator_deadline(now)
                .unwrap_or(now + GLOBAL_WAKE_RETRY);
            tokio::time::advance(deadline.saturating_duration_since(now)).await;
            let now = tokio::time::Instant::now();
            let before = global.snapshot().coordinator_waiter_inspections;
            _ = global.wake_fitting_batch(now);
            assert!(
                global.snapshot().coordinator_waiter_inspections - before
                    <= GLOBAL_SCAN_BATCH as u64
            );
            for (index, probe_id) in std::mem::take(&mut *observed.lock()) {
                if index % 3 == 0 {
                    continue;
                }
                assert!(global.acknowledge_probe_lease(&flows[index], probe_id, now));
                if index % 3 == 2 {
                    // An empty completion consumes/refunds its exact lease;
                    // the later nonfit re-registers without an active lease.
                    drop(
                        flows[index]
                            .try_copy_payload(&[])
                            .expect("empty ACKed delivery"),
                    );
                }
                // Otherwise this insufficient delivery re-parks with a lease,
                // and expiry must restore its eligibility in the derived index.
                assert!(
                    flows[index]
                        .try_copy_payload(&vec![0; sizes[index]])
                        .is_none()
                );
            }
            assert_fitting_index_matches_waiters(&global);
            assert!(global.snapshot().charged_bytes <= 100);
        }

        let oldest = {
            let coordinator = global.coordinator.lock();
            coordinator
                .waiters
                .iter()
                .find_map(|(_, candidate)| {
                    let flow = candidate.upgrade()?;
                    (flow.global_probe_id.load(Ordering::Acquire) == 0).then_some(flow)
                })
                .expect("an unleased waiter remains after churn")
        };
        let oldest_index = flows
            .iter()
            .position(|flow| Arc::ptr_eq(flow, &oldest))
            .expect("oldest flow slot");
        for flow in &flows {
            if !Arc::ptr_eq(flow, &oldest) {
                flow.close();
            }
        }
        drop(retained);
        for _ in 0..GLOBAL_SCAN_BATCH {
            tokio::time::advance(GLOBAL_WAKE_RETRY).await;
            _ = global.wake_fitting_batch(tokio::time::Instant::now());
            if !observed.lock().is_empty() {
                break;
            }
        }
        let callbacks = std::mem::take(&mut *observed.lock());
        assert_eq!(
            callbacks.len(),
            1,
            "only the oldest surviving waiter receives demand"
        );
        let (index, probe_id) = callbacks[0];
        assert_eq!(index, oldest_index);
        assert!(global.acknowledge_probe_lease(&oldest, probe_id, tokio::time::Instant::now()));
        drop(
            oldest
                .try_copy_payload(&vec![0; sizes[index]])
                .expect("oldest waiter consumes refunded capacity"),
        );
        oldest.close();
        holder.close();
        assert_fitting_index_matches_waiters(&global);
        assert_eq!(global.snapshot().charged_bytes, 0);
        assert!(global.coordinator.lock().fitting_waiters.is_empty());
        assert_eq!(
            global.next_coordinator_deadline(tokio::time::Instant::now()),
            None
        );
    }

    fn assert_fitting_index_matches_waiters(global: &UdpIngressBudget) {
        fn visit(
            node: Option<&UdpIngressFittingNode>,
            entries: &mut Vec<(u64, usize)>,
        ) -> (u8, usize) {
            let Some(node) = node else {
                return (0, usize::MAX);
            };
            let (left_height, left_minimum) = visit(node.left.as_deref(), entries);
            entries.push((node.sequence, node.needed_bytes));
            let (right_height, right_minimum) = visit(node.right.as_deref(), entries);
            assert!(
                left_height.abs_diff(right_height) <= 1,
                "index updates retain logarithmic depth"
            );
            let height = 1 + left_height.max(right_height);
            let minimum = node.needed_bytes.min(left_minimum).min(right_minimum);
            assert_eq!(node.height, height);
            assert_eq!(node.minimum_bytes, minimum);
            (height, minimum)
        }
        let coordinator = global.coordinator.lock();
        let expected: Vec<_> = coordinator
            .waiters
            .iter()
            .filter_map(|(&key, candidate)| {
                let flow = candidate.upgrade()?;
                (flow.global_probe_id.load(Ordering::Acquire) == 0).then_some(key)
            })
            .collect();
        let mut entries = Vec::new();
        _ = visit(coordinator.fitting_waiters.root.as_deref(), &mut entries);
        assert_eq!(
            entries, expected,
            "derived index agrees with every live unleased waiter"
        );
        for available in 0..=100 {
            assert_eq!(
                coordinator.fitting_waiters.oldest_fitting(available),
                expected
                    .iter()
                    .copied()
                    .find(|(_, needed)| *needed <= available),
                "oldest-fitting lookup agrees with the FIFO oracle at capacity {available}"
            );
        }
    }

    async fn assert_fitting_retries_progress_during_discovery(flow_count: usize) {
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut flows = Vec::with_capacity(flow_count + 1);
        for index in 0..=flow_count {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            let size = if index == flow_count { 10 } else { 20 };
            assert!(flow.try_copy_payload(&vec![0; size]).is_none());
            flows.push(flow);
        }

        let mut discovered = 0;
        let mut fitting_grants = 0;
        let mut discovery_since_fitting = 0;
        for _ in 0..flow_count * 4 {
            let now = tokio::time::Instant::now();
            let before = global.snapshot().coordinator_waiter_inspections;
            _ = global.wake_fitting_batch(now);
            assert!(
                global.snapshot().coordinator_waiter_inspections - before
                    <= GLOBAL_SCAN_BATCH as u64
            );
            for (index, probe_id) in std::mem::take(&mut *observed.lock()) {
                assert!(global.acknowledge_probe_lease(&flows[index], probe_id, now));
                if index == flow_count {
                    let payload = flows[index]
                        .try_copy_payload(&[0; 10])
                        .expect("the fitting retry consumes its reserved capacity");
                    drop(payload);
                    assert!(flows[index].try_copy_payload(&[0; 10]).is_none());
                    fitting_grants += 1;
                    discovery_since_fitting = 0;
                } else {
                    assert_eq!(index, discovered, "discovery retains FIFO opportunity");
                    assert!(flows[index].try_copy_payload(&[0; 20]).is_none());
                    discovered += 1;
                    discovery_since_fitting += 1;
                    assert!(
                        discovery_since_fitting <= 1,
                        "{flow_count} nonfitting flows deferred a fitting retry behind multiple discovery leases"
                    );
                }
                assert!(global.snapshot().charged_bytes <= 100);
            }
            if discovered == flow_count {
                break;
            }
            let deadline = global
                .next_coordinator_deadline(now)
                .expect("unfinished fitting and discovery work remains scheduled");
            tokio::time::advance(deadline.saturating_duration_since(now)).await;
        }
        assert_eq!(discovered, flow_count);
        assert_eq!(fitting_grants, flow_count);
        let inspections = global.snapshot().coordinator_waiter_inspections;
        assert!(
            inspections <= (flow_count * 3 + 1) as u64,
            "{flow_count} flows required {inspections} inspections; fitting progress must not restart the discovery cohort"
        );
        eprintln!(
            "{flow_count} nonfitting discoveries with {fitting_grants} fitting grants: {inspections} inspections"
        );
        for flow in flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().charged_bytes, 0);
        assert!(global.coordinator.lock().fitting_waiters.is_empty());
        assert_eq!(
            global.next_coordinator_deadline(tokio::time::Instant::now()),
            None
        );
    }

    fn assert_partial_discovery_total_work_is_linear(flow_count: usize, small_next_packet: bool) {
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut flows = Vec::with_capacity(flow_count);
        for index in 0..flow_count {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&[0; 20]).is_none());
            flows.push(flow);
        }

        let mut now = tokio::time::Instant::now();
        let mut served = 0;
        for _ in 0..flow_count * flow_count {
            let before = global.snapshot().coordinator_waiter_inspections;
            _ = global.wake_fitting_batch(now);
            assert!(
                global.snapshot().coordinator_waiter_inspections - before
                    <= GLOBAL_SCAN_BATCH as u64
            );
            for (index, probe_id) in std::mem::take(&mut *observed.lock()) {
                assert_eq!(
                    index, served,
                    "partial discovery preserves FIFO opportunity"
                );
                assert!(global.acknowledge_probe_lease(&flows[index], probe_id, now));
                if small_next_packet {
                    let payload = flows[index]
                        .try_copy_payload(&[0])
                        .expect("the next small packet fits the partial lease");
                    flows[index].close();
                    drop(payload);
                } else {
                    assert!(flows[index].try_copy_payload(&[0; 20]).is_none());
                }
                served += 1;
            }
            if served == flow_count {
                break;
            }
            now += if small_next_packet {
                GLOBAL_WAKE_RETRY
            } else {
                GLOBAL_ACKED_PROBE_DELIVERY_GRACE
            };
        }
        let inspections = global.snapshot().coordinator_waiter_inspections;
        for flow in flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().charged_bytes, 0);
        assert_eq!(served, flow_count);
        eprintln!(
            "{flow_count} flows, small_next_packet={small_next_packet}: {inspections} inspections"
        );
        assert!(
            inspections <= (flow_count * 2) as u64,
            "{flow_count} flows required {inspections} waiter inspections; one exact-fit pass plus one discovery traversal must suffice"
        );
    }

    #[test]
    fn bounded_rotation_reaches_small_waiter_behind_nonfitting_oldest() {
        let global = Arc::new(UdpIngressBudget::new(2));
        let holder = UdpIngressFlowControl::new(2, global.clone(), Arc::new(|_| {}));
        let released = holder
            .try_copy_payload(&[0])
            .expect("reserve released byte");
        let retained = holder
            .try_copy_payload(&[0])
            .expect("reserve retained byte");
        let order = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let large_order = order.clone();
        let large = UdpIngressFlowControl::new(
            2,
            global.clone(),
            Arc::new(move |_| large_order.lock().push("large")),
        );
        let small_order = order.clone();
        let small = UdpIngressFlowControl::new(
            1,
            global.clone(),
            Arc::new(move |_| small_order.lock().push("small")),
        );
        assert!(large.try_copy_payload(&[0; 2]).is_none());
        assert!(small.try_copy_payload(&[0]).is_none());
        drop(released);

        let before = global.snapshot().coordinator_waiter_inspections;
        assert_eq!(global.wake_fitting_batch(tokio::time::Instant::now()), 1);
        assert_eq!(&*order.lock(), &["small"]);
        assert_eq!(
            global.snapshot().coordinator_waiter_inspections - before,
            2,
            "one bounded turn must rotate the nonfit head then reach the fitting waiter"
        );

        large.close();
        small.close();
        holder.close();
        drop(retained);
    }

    #[test]
    fn all_nonfitting_8192_waiters_get_one_bounded_discovery_after_full_pass() {
        const FLOW_COUNT: usize = 8_192;
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut flows = Vec::with_capacity(FLOW_COUNT);
        for index in 0..FLOW_COUNT {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&[0; 20]).is_none());
            flows.push(flow);
        }

        let mut now = tokio::time::Instant::now();
        let turns = FLOW_COUNT.div_ceil(GLOBAL_SCAN_BATCH);
        for turn in 0..turns {
            let before = global.snapshot().coordinator_waiter_inspections;
            assert_eq!(
                global.wake_fitting_batch(now),
                usize::from(turn + 1 == turns),
                "discovery must wait for the complete no-fit pass"
            );
            assert!(
                global.snapshot().coordinator_waiter_inspections - before
                    <= GLOBAL_SCAN_BATCH as u64
            );
            now += GLOBAL_WAKE_RETRY;
        }
        let inspections = global.snapshot().coordinator_waiter_inspections;
        assert_eq!(inspections, FLOW_COUNT as u64);
        assert_eq!(observed.lock().len(), 1);
        assert_eq!(observed.lock()[0].0, 0, "oldest nonfit gets discovery");
        assert_ne!(observed.lock()[0].1, 0);
        assert_eq!(global.snapshot().global_waiters, FLOW_COUNT - 1);
        assert_eq!(global.snapshot().provisional_probe_count, 1);
        assert_eq!(global.snapshot().provisional_probe_bytes, 10);
        assert_eq!(global.snapshot().charged_bytes, 100);
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(
            global.snapshot().coordinator_waiter_inspections,
            inspections
        );
        assert_eq!(
            global.next_coordinator_deadline(now),
            Some(now - GLOBAL_WAKE_RETRY + DEFAULT_UDP_INGRESS_PROBE_LEASE)
        );

        for flow in flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn vanished_discovery_sample_continues_with_bounded_fifo_cursor() {
        const FLOW_COUNT: usize = GLOBAL_SCAN_BATCH * 3;
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut flows = Vec::with_capacity(FLOW_COUNT);
        for index in 0..FLOW_COUNT {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&[0; 20]).is_none());
            flows.push(flow);
        }

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_udp_ingress_coordinator(
            Arc::downgrade(&global),
            global.coordinator_signal.clone(),
            async move {
                _ = stop_rx.await;
            },
        ));
        tokio::task::yield_now().await;
        assert_eq!(
            global.snapshot().coordinator_waiter_inspections,
            GLOBAL_SCAN_BATCH as u64
        );
        assert!(observed.lock().is_empty());

        // The first turn sampled these oldest four flows. Remove every sample
        // while the remaining two turns of the original pass are pending.
        for flow in flows.iter().take(GLOBAL_WAKE_BATCH) {
            flow.close();
        }
        assert_eq!(
            global.snapshot().global_waiters,
            FLOW_COUNT - GLOBAL_WAKE_BATCH
        );

        let remaining_turns = (FLOW_COUNT - GLOBAL_SCAN_BATCH).div_ceil(GLOBAL_SCAN_BATCH) + 1;
        for _ in 0..remaining_turns {
            let before = global.snapshot().coordinator_waiter_inspections;
            tokio::time::advance(GLOBAL_WAKE_RETRY).await;
            tokio::task::yield_now().await;
            assert!(
                global.snapshot().coordinator_waiter_inspections - before
                    <= GLOBAL_SCAN_BATCH as u64,
                "candidate replenishment exceeded the bounded turn"
            );
        }

        {
            let observed = observed.lock();
            assert_eq!(observed.len(), 1);
            assert_eq!(observed[0].0, GLOBAL_WAKE_BATCH);
            assert_ne!(observed[0].1, 0);
        }
        assert!(
            global.snapshot().coordinator_waiter_inspections <= (FLOW_COUNT + 1) as u64,
            "the completed pass must continue at the next live FIFO node without rescanning"
        );
        assert_eq!(global.snapshot().provisional_probe_count, 1);

        for flow in &flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        _ = stop_tx.send(());
        task.await.expect("coordinator task");
        let snapshot = global.snapshot();
        assert_eq!(snapshot.provisional_probe_count, 0);
        assert_eq!(snapshot.charged_bytes, 0);
        assert_eq!(snapshot.global_waiters, 0);
    }

    #[test]
    fn deadline_capacity_release_preserves_in_progress_discovery() {
        const FLOW_COUNT: usize = GLOBAL_SCAN_BATCH * 2;
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let released = holder
            .try_copy_payload(&[0])
            .expect("reserve release opportunity");
        let retained = holder.try_copy_payload(&[0; 89]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut flows = Vec::with_capacity(FLOW_COUNT);
        for index in 0..FLOW_COUNT {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |probe_id| observed.lock().push((index, probe_id))),
            );
            assert!(flow.try_copy_payload(&[0; 20]).is_none());
            flows.push(flow);
        }

        let mut now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(
            global.snapshot().coordinator_waiter_inspections,
            GLOBAL_SCAN_BATCH as u64
        );

        // A real release lands after selection but before deadline
        // calculation. Preserve the original finite pass and its oldest
        // discovery candidate instead of starting over at each release.
        drop(released);
        assert_eq!(
            global.next_coordinator_deadline(now),
            Some(now + GLOBAL_WAKE_RETRY)
        );
        for _ in 0..(FLOW_COUNT - GLOBAL_SCAN_BATCH).div_ceil(GLOBAL_SCAN_BATCH) {
            now += GLOBAL_WAKE_RETRY;
            _ = global.wake_fitting_batch(now);
        }

        let observed = observed.lock();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].0, 0);
        assert_ne!(observed[0].1, 0);
        drop(observed);
        assert_eq!(
            global.snapshot().coordinator_waiter_inspections,
            FLOW_COUNT as u64,
            "capacity release must not restart an in-progress bounded pass"
        );

        for flow in &flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        let snapshot = global.snapshot();
        assert_eq!(snapshot.provisional_probe_count, 0);
        assert_eq!(snapshot.charged_bytes, 0);
        assert_eq!(snapshot.global_waiters, 0);
    }

    #[test]
    fn newcomer_registrations_do_not_restart_a_bounded_nonfit_pass() {
        const INITIAL_WAITERS: usize = GLOBAL_SCAN_BATCH * 3;
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut flows = Vec::with_capacity(INITIAL_WAITERS + 2);
        for index in 0..INITIAL_WAITERS {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |_| observed.lock().push(index)),
            );
            assert!(flow.try_copy_payload(&[0; 20]).is_none());
            flows.push(flow);
        }

        let mut now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(
            global.snapshot().coordinator_waiter_inspections,
            GLOBAL_SCAN_BATCH as u64
        );

        for newcomer_index in INITIAL_WAITERS..INITIAL_WAITERS + 2 {
            let observed = observed.clone();
            let flow = UdpIngressFlowControl::new(
                20,
                global.clone(),
                Arc::new(move |_| observed.lock().push(newcomer_index)),
            );
            assert!(flow.try_copy_payload(&[0; 20]).is_none());
            flows.push(flow);
            now += GLOBAL_WAKE_RETRY;
            assert_eq!(
                global.wake_fitting_batch(now),
                usize::from(newcomer_index + 1 == INITIAL_WAITERS + 2),
                "tail arrivals must not reset the finite pass"
            );
        }

        assert_eq!(
            global.snapshot().coordinator_waiter_inspections,
            INITIAL_WAITERS as u64,
            "the pass must finish its original bounded inspection budget"
        );
        assert_eq!(&*observed.lock(), &[0], "oldest nonfit gets discovery");
        assert_eq!(global.snapshot().provisional_probe_bytes, 10);

        for flow in flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[test]
    fn acknowledged_probe_keeps_credit_until_bounded_delivery_grace() {
        const FLOW_COUNT: usize = GLOBAL_WAKE_BATCH * 2;
        let global = Arc::new(UdpIngressBudget::new(GLOBAL_WAKE_BATCH));
        let holder =
            UdpIngressFlowControl::new(GLOBAL_WAKE_BATCH, global.clone(), Arc::new(|_| {}));
        let retained = holder
            .try_copy_payload(&[0; GLOBAL_WAKE_BATCH])
            .expect("fill budget");
        let callbacks = Arc::new(AtomicUsize::new(0));
        let mut flows = Vec::with_capacity(FLOW_COUNT);
        for _ in 0..FLOW_COUNT {
            let callbacks = callbacks.clone();
            let flow = UdpIngressFlowControl::new(
                1,
                global.clone(),
                Arc::new(move |_| {
                    callbacks.fetch_add(1, Ordering::Relaxed);
                }),
            );
            assert!(flow.try_copy_payload(&[0]).is_none());
            flows.push(flow);
        }
        drop(retained);

        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), GLOBAL_WAKE_BATCH);
        assert_eq!(callbacks.load(Ordering::Relaxed), GLOBAL_WAKE_BATCH);
        for flow in &flows {
            flow.acknowledge_probe(flow.global_probe_id.load(Ordering::Acquire));
        }
        assert_eq!(global.snapshot().provisional_probe_count, GLOBAL_WAKE_BATCH);
        assert_eq!(global.snapshot().charged_bytes, GLOBAL_WAKE_BATCH);
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(global.wake_fitting_batch(now + GLOBAL_WAKE_RETRY), 0);
        assert_eq!(callbacks.load(Ordering::Relaxed), GLOBAL_WAKE_BATCH);
        assert_eq!(
            global.wake_fitting_batch(
                now + GLOBAL_ACKED_PROBE_DELIVERY_GRACE + Duration::from_millis(1)
            ),
            GLOBAL_WAKE_BATCH
        );
        assert_eq!(callbacks.load(Ordering::Relaxed), FLOW_COUNT);
        assert_eq!(global.snapshot().provisional_probe_count, GLOBAL_WAKE_BATCH);
        assert_eq!(global.snapshot().charged_bytes, GLOBAL_WAKE_BATCH);

        for flow in flows {
            flow.close();
        }
        holder.close();
        assert_eq!(global.snapshot().provisional_probe_count, 0);
        assert_eq!(global.snapshot().charged_bytes, 0);
    }

    #[test]
    fn overload_telemetry_is_power_of_two_sampled() {
        let sampled: Vec<_> = (1..=17).filter(|total| telemetry_sample(*total)).collect();
        assert_eq!(sampled, [1, 2, 4, 8, 16]);
        assert!(!telemetry_sample(0));
        assert!(telemetry_sample(1_u64 << 63));
    }
}
