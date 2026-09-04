use std::{
    collections::{BTreeMap, btree_map::Entry},
    future::{Future, poll_fn},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};

use atomic_waker::AtomicWaker;
use rama_core::{bytes::Bytes, graceful::ShutdownGuard};

use super::UdpDemandSink;

pub const MAX_UDP_DATAGRAM_PAYLOAD_SIZE: usize = u16::MAX as usize;
pub const DEFAULT_UDP_INGRESS_PER_FLOW_MAX_BYTES: usize = 256 * 1024;
pub const DEFAULT_UDP_INGRESS_GLOBAL_MAX_BYTES: usize = 16 * 1024 * 1024;

const INGRESS_OPEN: u8 = 0;
const INGRESS_PAUSED_COUNT: u8 = 1;
const INGRESS_PAUSED_FLOW_BYTES: u8 = 2;
const INGRESS_PAUSED_GLOBAL_BYTES: u8 = 3;
const INGRESS_CLOSED: u8 = 4;
const NO_GLOBAL_WAITER: u64 = u64::MAX;

/// Maximum number of globally blocked flows allowed to issue a new read in
/// one coordinator turn. Admission still happens through the exact global
/// byte counter; this only bounds speculative read fanout when capacity is
/// released.
const GLOBAL_WAKE_BATCH: usize = 4;
/// Bound cold-path FIFO rotation work independently from callback fanout.
/// At 8,192 waiters this caps a full no-fit pass at 256 paced turns while
/// keeping the coordinator mutex hold to a small constant.
const GLOBAL_SCAN_BATCH: usize = 32;
/// Pace bounded coordinator turns independently of ACK/release signals. This
/// limits both callback fanout and finite no-fit queue scans to one turn per
/// millisecond.
const GLOBAL_WAKE_RETRY: Duration = Duration::from_millis(1);
/// A selected Apple read which never completes cannot pin provisional global
/// capacity forever. Completion normally ACKs immediately; this is only the
/// liveness backstop for a lost/stuck framework callback.
const GLOBAL_PROBE_LEASE: Duration = Duration::from_millis(10);

struct UdpIngressProbeLease {
    bytes: usize,
    expires_at: tokio::time::Instant,
    flow: Weak<UdpIngressFlowControl>,
}

#[derive(Default)]
struct UdpIngressCoordinatorState {
    waiters: BTreeMap<(u64, usize), Weak<UdpIngressFlowControl>>,
    leases: BTreeMap<u64, UdpIngressProbeLease>,
    provisional_bytes: usize,
    /// Global probe issue pacing. ACK/close signals may free lease slots
    /// immediately, but cannot cause another coordinator issue turn before
    /// this instant.
    wake_not_before: Option<tokio::time::Instant>,
    /// Remaining waiters in the current bounded rotation pass. Capacity or
    /// provisional-credit release and new registration start a fresh pass;
    /// ordinary coalesced signals do not.
    scan_remaining: usize,
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
    /// This is the only coordinator operation on normal payload release.
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct UdpIngressSnapshot {
    pub(super) retained_bytes: usize,
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

impl UdpIngressBudget {
    pub(super) fn new(max_retained_bytes: usize) -> Self {
        Self {
            max_retained_bytes,
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

    fn try_reserve(&self, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let Ok(_previous) =
            self.retained_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(len)
                        .filter(|next| *next <= self.max_retained_bytes)
                })
        else {
            return false;
        };
        #[cfg(test)]
        self.peak_retained_bytes
            .fetch_max(_previous + len, Ordering::Relaxed);
        true
    }

    fn release(&self, len: usize) {
        if len == 0 {
            return;
        }
        let previous = self.retained_bytes.fetch_sub(len, Ordering::AcqRel);
        debug_assert!(previous >= len, "UDP global byte reservation underflow");
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
        self.waiter_count.fetch_add(1, Ordering::Release);
        self.opportunity_epoch.fetch_add(1, Ordering::Release);
        let provisional = coordinator.provisional_bytes;
        drop(coordinator);

        // Close the classic missed-wakeup store-buffering race without a
        // lock or sequentially-consistent fence on normal release.
        // Registration publishes `waiter_count` before this retained-counter
        // marker. If release precedes the marker, the marker observes capacity
        // and kicks. If the marker precedes release, release observes the
        // publication and kicks.
        let retained = self.retained_bytes.fetch_add(0, Ordering::AcqRel);
        if retained
            .checked_add(provisional)
            .and_then(|used| used.checked_add(needed_bytes))
            .is_some_and(|next| next <= self.max_retained_bytes)
        {
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
        debug_assert_eq!(
            removed.as_ref().map(Weak::as_ptr),
            Some(flow as *const _),
            "UDP global waiter registry mismatch"
        );
        if removed.is_some() {
            self.waiter_count.fetch_sub(1, Ordering::Release);
        }
    }

    /// Give at most [`GLOBAL_WAKE_BATCH`] fitting flows one leased retry.
    /// Provisional bytes are scheduling credits, not payload reservations:
    /// `try_reserve` remains the authoritative admission CAS. Subtracting each
    /// issued credit makes callback fanout respect the exact byte headroom.
    fn wake_fitting_batch(&self, now: tokio::time::Instant) -> usize {
        let selected = {
            let mut coordinator = self.coordinator.lock();
            self.expire_probe_leases_locked(&mut coordinator, now);
            let opportunity_epoch = self.opportunity_epoch.load(Ordering::Acquire);
            if coordinator.observed_opportunity_epoch != opportunity_epoch {
                coordinator.observed_opportunity_epoch = opportunity_epoch;
                coordinator.scan_remaining = coordinator.waiters.len();
            }
            if coordinator
                .wake_not_before
                .is_some_and(|not_before| now < not_before)
            {
                return 0;
            }
            coordinator.wake_not_before = None;
            let mut available = self
                .max_retained_bytes
                .saturating_sub(self.retained_bytes.load(Ordering::Acquire))
                .saturating_sub(coordinator.provisional_bytes);
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
                coordinator.scan_remaining -= 1;
                #[cfg(test)]
                self.coordinator_waiter_inspections
                    .fetch_add(1, Ordering::Relaxed);
                let Some(flow) = candidate.upgrade() else {
                    _ = coordinator.waiters.remove(&key);
                    self.waiter_count.fetch_sub(1, Ordering::Release);
                    continue;
                };
                let needed_bytes = key.1;
                if needed_bytes > available || flow.global_probe_id.load(Ordering::Acquire) != 0 {
                    let Some(_) = coordinator.waiters.remove(&key) else {
                        break;
                    };
                    let Ok(new_sequence) = self.next_waiter_sequence.try_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |current| current.checked_add(1),
                    ) else {
                        // Sequence exhaustion is unreachable in practice;
                        // retain the waiter and quiesce rather than spin.
                        coordinator.waiters.insert(key, Arc::downgrade(&flow));
                        coordinator.scan_remaining = 0;
                        break;
                    };
                    flow.global_waiter_sequence
                        .store(new_sequence, Ordering::Release);
                    let replaced = coordinator
                        .waiters
                        .insert((new_sequence, needed_bytes), Arc::downgrade(&flow));
                    debug_assert!(replaced.is_none(), "UDP rotated waiter key collision");
                    continue;
                }
                let Some(_) = coordinator.waiters.remove(&key) else {
                    break;
                };
                self.waiter_count.fetch_sub(1, Ordering::Release);
                let Ok(probe_id) = self.next_probe_id.try_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |current| current.checked_add(1),
                ) else {
                    // Never reuse an ID or issue an unaccounted callback.
                    // Exhaustion requires 2^64 probes in one generation;
                    // leave this waiter registered and fail safely.
                    coordinator.waiters.insert(key, Arc::downgrade(&flow));
                    self.waiter_count.fetch_add(1, Ordering::Release);
                    break;
                };
                available -= needed_bytes;
                coordinator.provisional_bytes += needed_bytes;
                let previous = flow.global_probe_id.swap(probe_id, Ordering::AcqRel);
                debug_assert_eq!(previous, 0, "UDP flow received overlapping probe leases");
                let replaced = coordinator.leases.insert(
                    probe_id,
                    UdpIngressProbeLease {
                        bytes: needed_bytes,
                        expires_at: now + GLOBAL_PROBE_LEASE,
                        flow: Arc::downgrade(&flow),
                    },
                );
                debug_assert!(replaced.is_none(), "UDP probe ID collision");
                flow.global_waiter_sequence
                    .store(NO_GLOBAL_WAITER, Ordering::Release);
                selected.push((flow, probe_id));
            }
            if inspected != 0 {
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
            assert!(
                coordinator.provisional_bytes >= lease.bytes,
                "UDP provisional byte reservation underflow"
            );
            coordinator.provisional_bytes -= lease.bytes;
            if let Some(flow) = lease.flow.upgrade() {
                _ = flow.global_probe_id.compare_exchange(
                    id,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
        }
        if released_any && self.waiter_count.load(Ordering::Acquire) != 0 {
            self.opportunity_epoch.fetch_add(1, Ordering::Release);
        }
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
                        assert!(
                            coordinator.provisional_bytes >= lease.bytes,
                            "UDP provisional byte reservation underflow"
                        );
                        coordinator.provisional_bytes -= lease.bytes;
                        _ = flow.global_probe_id.compare_exchange(
                            probe_id,
                            0,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
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
            coordinator.scan_remaining = coordinator.waiters.len();
        }
        let lease_deadline = coordinator
            .leases
            .values()
            .map(|lease| lease.expires_at)
            .min();
        if coordinator.leases.len() >= GLOBAL_WAKE_BATCH {
            return lease_deadline;
        }
        let waiter_deadline = (coordinator.scan_remaining != 0 && !coordinator.waiters.is_empty())
            .then(|| {
                coordinator
                    .wake_not_before
                    .filter(|not_before| *not_before > now)
                    .unwrap_or(now + GLOBAL_WAKE_RETRY)
            });
        match (waiter_deadline, lease_deadline) {
            (Some(waiter), Some(lease)) => Some(waiter.min(lease)),
            (Some(waiter), None) => Some(waiter),
            (None, lease) => lease,
        }
    }

    #[cfg(test)]
    fn record_accepted(&self, len: usize) {
        self.accepted_datagrams.fetch_add(1, Ordering::Relaxed);
        self.accepted_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }

    fn record_drop(&self, reason: UdpIngressDropReason) {
        let (counter, pressure) = match reason {
            UdpIngressDropReason::Count => (&self.dropped_count_full, "channel_count"),
            UdpIngressDropReason::FlowBytes => (&self.dropped_flow_bytes_full, "flow_bytes"),
            UdpIngressDropReason::GlobalBytes => (&self.dropped_global_bytes_full, "global_bytes"),
        };
        let total = saturating_increment(counter);
        if telemetry_sample(total) {
            let retained = self.retained_bytes.load(Ordering::Relaxed);
            tracing::warn!(
                pressure,
                cumulative_drops = total,
                global_retained_bytes = retained,
                global_max_retained_bytes = self.max_retained_bytes,
                "UDP ingress pressure dropped datagram pressure=\"{}\" cumulative_drops={} global_retained_bytes={} global_max_retained_bytes={}",
                pressure,
                total,
                retained,
                self.max_retained_bytes,
            );
        }
    }

    fn record_recovery(&self, previous_state: u8) {
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
                pressure,
                cumulative_resumptions = total,
                global_retained_bytes = retained,
                global_max_retained_bytes = self.max_retained_bytes,
                "UDP ingress pressure resumed flow pressure=\"{}\" cumulative_resumptions={} global_retained_bytes={} global_max_retained_bytes={}",
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
        _ = budget.wake_fitting_batch(now);
        deadline = budget.next_coordinator_deadline(now);
    }

    // `AtomicWaker::wake` normally consumes its stored waker. Shutdown can
    // win the select without a coordinator kick, so clear that final task
    // reference explicitly before retained payloads outlive the engine.
    _ = signal.waker.take();
}

pub(super) struct UdpIngressFlowControl {
    max_retained_bytes: usize,
    retained_bytes: AtomicUsize,
    state: AtomicU8,
    blocked_bytes: AtomicUsize,
    global_waiter_sequence: AtomicU64,
    global_probe_id: AtomicU64,
    demand_gate: parking_lot::Mutex<()>,
    demand: UdpDemandSink,
    auto_ack_probe_after_demand: bool,
    global: Arc<UdpIngressBudget>,
}

impl UdpIngressFlowControl {
    #[cfg(test)]
    pub(super) fn new(
        max_retained_bytes: usize,
        global: Arc<UdpIngressBudget>,
        demand: UdpDemandSink,
    ) -> Arc<Self> {
        Self::new_with_auto_ack(max_retained_bytes, global, demand, false)
    }

    pub(super) fn new_with_auto_ack(
        max_retained_bytes: usize,
        global: Arc<UdpIngressBudget>,
        demand: UdpDemandSink,
        auto_ack_probe_after_demand: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            max_retained_bytes,
            retained_bytes: AtomicUsize::new(0),
            state: AtomicU8::new(INGRESS_OPEN),
            blocked_bytes: AtomicUsize::new(0),
            global_waiter_sequence: AtomicU64::new(NO_GLOBAL_WAITER),
            global_probe_id: AtomicU64::new(0),
            demand_gate: parking_lot::Mutex::new(()),
            demand,
            auto_ack_probe_after_demand,
            global,
        })
    }

    pub(super) fn request_read(&self) {
        self.dispatch_demand_if_open(0);
    }

    pub(super) fn acknowledge_probe(&self, probe_id: u64) {
        _ = self.global.release_probe_lease(self, probe_id);
    }

    pub(super) fn on_channel_capacity_released(&self) {
        self.resume(INGRESS_PAUSED_COUNT, 0);
    }

    pub(super) fn close(self: &Arc<Self>) {
        let old_state = {
            // Serialize the terminal transition with demand dispatch. Once
            // this method returns, no demand callback can still begin or be
            // in flight through this control.
            let _gate = self.demand_gate.lock();
            self.state.swap(INGRESS_CLOSED, Ordering::AcqRel)
        };
        if old_state == INGRESS_PAUSED_GLOBAL_BYTES {
            self.global.remove_waiter(self);
        }
        let probe_id = self.global_probe_id.load(Ordering::Acquire);
        if probe_id != 0 {
            _ = self.global.release_probe_lease(self, probe_id);
        }
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
            self.global.record_drop(reason);
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
        self.global.record_drop(UdpIngressDropReason::Count);
        if self.pause(INGRESS_PAUSED_COUNT, 0) && channel_capacity_probe() {
            // The receiver won the race between `try_reserve(Full)` and pause
            // publication. The production probe performs a real semaphore
            // reservation and immediately drops it, rather than trusting a
            // potentially stale capacity snapshot. Re-open immediately instead
            // of stranding an empty flow after its only release edge.
            self.resume(INGRESS_PAUSED_COUNT, 0);
        }
    }

    pub(super) fn try_copy_payload(self: &Arc<Self>, bytes: &[u8]) -> Option<Bytes> {
        if bytes.is_empty() {
            return Some(Bytes::new());
        }
        let len = bytes.len();
        let Ok(_) =
            self.retained_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(len)
                        .filter(|next| *next <= self.max_retained_bytes)
                })
        else {
            self.global.record_drop(UdpIngressDropReason::FlowBytes);
            if self.pause(INGRESS_PAUSED_FLOW_BYTES, len) {
                self.resume_flow_bytes_if_capacity();
            }
            return None;
        };

        if !self.global.try_reserve(len) {
            let flow_previous = self.retained_bytes.fetch_sub(len, Ordering::AcqRel);
            debug_assert!(flow_previous >= len, "UDP flow byte reservation underflow");
            self.global.record_drop(UdpIngressDropReason::GlobalBytes);
            if self.pause(INGRESS_PAUSED_GLOBAL_BYTES, len) {
                self.global.register_waiter(self);
            }
            return None;
        }

        Some(Bytes::from_owner(RetainedUdpPayload {
            bytes: Box::<[u8]>::from(bytes),
            flow: self.clone(),
        }))
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
        self.global.record_recovery(expected_state);
        self.dispatch_demand_if_open(probe_id);
        true
    }

    fn dispatch_demand_if_open(&self, probe_id: u64) {
        let _gate = self.demand_gate.lock();
        if self.state.load(Ordering::Acquire) == INGRESS_OPEN {
            (self.demand)(probe_id);
            if self.auto_ack_probe_after_demand {
                self.acknowledge_probe(probe_id);
            }
        }
    }

    fn release_retained_bytes(&self, len: usize) {
        let previous = self.retained_bytes.fetch_sub(len, Ordering::AcqRel);
        debug_assert!(previous >= len, "UDP flow byte reservation underflow");
        self.global.release(len);
        self.resume_flow_bytes_if_capacity();
    }

    fn resume_flow_bytes_if_capacity(&self) {
        if self.state.load(Ordering::Acquire) != INGRESS_PAUSED_FLOW_BYTES {
            return;
        }
        let needed = self.blocked_bytes.load(Ordering::Acquire);
        // Cold-path handshake matching the global waiter publication. If this
        // marker precedes a payload release RMW, that release observes the
        // PAUSED publication and resumes us. If the release precedes this
        // marker, the returned counter observes its newly available capacity.
        let fits = self
            .retained_bytes
            .fetch_add(0, Ordering::AcqRel)
            .checked_add(needed)
            .is_some_and(|next| next <= self.max_retained_bytes);
        if fits {
            self.resume(INGRESS_PAUSED_FLOW_BYTES, 0);
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
        self.flow.release_retained_bytes(self.bytes.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

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
    fn coordinator_never_over_wakes_byte_capacity_and_ack_advances_fifo() {
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

        // The same 10 bytes of headroom cannot provision another 10-byte
        // callback until the exact first lease is acknowledged.
        assert_eq!(global.wake_fitting_batch(now), 0);
        for expected_index in 0..GLOBAL_WAKE_BATCH + 2 {
            let (index, probe_id) = order.lock()[expected_index];
            assert_eq!(index, expected_index);
            assert_ne!(probe_id, 0);
            flows[index].acknowledge_probe(probe_id);
            if expected_index + 1 < GLOBAL_WAKE_BATCH + 2 {
                assert_eq!(global.wake_fitting_batch(now), 0);
                now += GLOBAL_WAKE_RETRY;
                assert_eq!(global.wake_fitting_batch(now), 1);
            }
        }
        assert_eq!(global.snapshot().global_waiters, 0);
        assert_eq!(global.snapshot().provisional_probe_bytes, 0);

        for flow in flows {
            flow.close();
        }
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().retained_bytes, 0);
    }

    #[test]
    fn global_release_does_not_wake_when_no_waiter_fits() {
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let released = holder.try_copy_payload(&[0; 10]).expect("reserve 10");
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

        drop(released);
        assert_eq!(demands.load(Ordering::Relaxed), 0);
        assert_eq!(global.wake_fitting_batch(tokio::time::Instant::now()), 0);
        assert_eq!(global.snapshot().global_waiters, 1);

        waiter.close();
        holder.close();
        drop(retained);
        assert_eq!(global.snapshot().retained_bytes, 0);
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
            let ((_sequence, _needed), candidate) =
                coordinator.waiters.pop_first().expect("registered waiter");
            let selected = candidate.upgrade().expect("live waiter");
            assert!(Arc::ptr_eq(&selected, &waiter));
            waiter
                .global_waiter_sequence
                .store(NO_GLOBAL_WAITER, Ordering::Release);
            global.waiter_count.fetch_sub(1, Ordering::Release);
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
        first.acknowledge_probe(old_id);
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(global.wake_fitting_batch(now + GLOBAL_WAKE_RETRY), 1);
        let new_id = second_id.load(Ordering::Acquire);
        assert_ne!(new_id, 0);
        assert_ne!(new_id, old_id);

        first.acknowledge_probe(old_id);
        assert_eq!(global.snapshot().provisional_probe_count, 1);
        assert_eq!(global.snapshot().provisional_probe_bytes, 10);
        second.acknowledge_probe(new_id);
        assert_eq!(global.snapshot().provisional_probe_count, 0);

        first.close();
        second.close();
        holder.close();
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

        first.close();
        assert_eq!(global.snapshot().provisional_probe_count, 0);
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(global.wake_fitting_batch(now + GLOBAL_WAKE_RETRY), 1);
        assert_eq!(second_demands.load(Ordering::Relaxed), 1);

        second.close();
        assert_eq!(global.snapshot().provisional_probe_count, 0);
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

        let Some(before_probe_expiry) = GLOBAL_PROBE_LEASE.checked_sub(Duration::from_millis(1))
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
                GLOBAL_PROBE_LEASE
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
                flows[index].acknowledge_probe(probe_id);
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
    fn all_nonfitting_8192_waiters_make_one_finite_pass_then_quiesce() {
        const FLOW_COUNT: usize = 8_192;
        let global = Arc::new(UdpIngressBudget::new(100));
        let holder = UdpIngressFlowControl::new(100, global.clone(), Arc::new(|_| {}));
        let retained = holder.try_copy_payload(&[0; 90]).expect("retain occupancy");
        let mut flows = Vec::with_capacity(FLOW_COUNT);
        for _ in 0..FLOW_COUNT {
            let flow = UdpIngressFlowControl::new(20, global.clone(), Arc::new(|_| {}));
            assert!(flow.try_copy_payload(&[0; 20]).is_none());
            flows.push(flow);
        }

        let mut now = tokio::time::Instant::now();
        for _ in 0..FLOW_COUNT.div_ceil(GLOBAL_SCAN_BATCH) {
            assert_eq!(global.wake_fitting_batch(now), 0);
            now += GLOBAL_WAKE_RETRY;
        }
        let inspections = global.snapshot().coordinator_waiter_inspections;
        assert_eq!(inspections, FLOW_COUNT as u64);
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(
            global.snapshot().coordinator_waiter_inspections,
            inspections
        );
        assert_eq!(global.next_coordinator_deadline(now), None);

        for flow in flows {
            flow.close();
        }
        holder.close();
        drop(retained);
    }

    #[test]
    fn legacy_no_probe_mode_auto_acks_after_callback_and_stays_paced() {
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
            let flow = UdpIngressFlowControl::new_with_auto_ack(
                1,
                global.clone(),
                Arc::new(move |_| {
                    callbacks.fetch_add(1, Ordering::Relaxed);
                }),
                true,
            );
            assert!(flow.try_copy_payload(&[0]).is_none());
            flows.push(flow);
        }
        drop(retained);

        let now = tokio::time::Instant::now();
        assert_eq!(global.wake_fitting_batch(now), GLOBAL_WAKE_BATCH);
        assert_eq!(callbacks.load(Ordering::Relaxed), GLOBAL_WAKE_BATCH);
        assert_eq!(global.snapshot().provisional_probe_count, 0);
        assert_eq!(global.wake_fitting_batch(now), 0);
        assert_eq!(
            global.wake_fitting_batch(now + GLOBAL_WAKE_RETRY),
            GLOBAL_WAKE_BATCH
        );
        assert_eq!(callbacks.load(Ordering::Relaxed), FLOW_COUNT);
        assert_eq!(global.snapshot().provisional_probe_count, 0);

        for flow in flows {
            flow.close();
        }
        holder.close();
    }

    #[test]
    fn overload_telemetry_is_power_of_two_sampled() {
        let sampled: Vec<_> = (1..=17).filter(|total| telemetry_sample(*total)).collect();
        assert_eq!(sampled, [1, 2, 4, 8, 16]);
        assert!(!telemetry_sample(0));
        assert!(telemetry_sample(1_u64 << 63));
    }
}
