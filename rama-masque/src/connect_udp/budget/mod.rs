use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use tokio::time::Instant;

use rama_http::datagram::DatagramTransport;
use rama_utils::{
    macros::generate_set_and_with,
    rate::{Acquire, Rate, RateLimiter},
};

use super::MAX_UDP_PAYLOAD;

/// A packet and a byte allowance for one direction of a tunnel.
///
/// Each datagram spends one packet and its charge in bytes; it is dropped when either
/// budget cannot pay at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramRate {
    packets: Rate,
    packet_burst: u64,
    bytes: Rate,
    byte_burst: u64,
}

impl DatagramRate {
    /// `packets` and `bytes` per period, each with a burst of one period's worth.
    #[must_use]
    pub const fn new(packets: Rate, bytes: Rate) -> Self {
        Self {
            packets,
            packet_burst: packets.units(),
            bytes,
            byte_burst: bytes.units(),
        }
    }

    generate_set_and_with! {
        /// The most packets spent at once.
        pub fn packet_burst(mut self, burst: u64) -> Self {
            self.packet_burst = burst.max(1);
            self
        }
    }

    generate_set_and_with! {
        /// The most bytes spent at once.
        pub fn byte_burst(mut self, burst: u64) -> Self {
            self.byte_burst = burst.max(1);
            self
        }
    }

    fn limiters(self) -> RateLimiters {
        RateLimiters {
            packets: RateLimiter::new(self.packets, self.packet_burst),
            bytes: RateLimiter::new(self.bytes, self.byte_burst),
        }
    }

    /// How long an emptied allowance takes to refill.
    fn refill_time(self) -> Duration {
        full_refill_time(self.packets, self.packet_burst)
            .max(full_refill_time(self.bytes, self.byte_burst))
    }
}

/// How long `rate` takes to refill `burst` units from empty.
fn full_refill_time(rate: Rate, burst: u64) -> Duration {
    let nanos = u128::from(burst)
        .saturating_mul(rate.per().as_nanos())
        .div_ceil(u128::from(rate.units()));
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

/// What each CONNECT-UDP tunnel of a proxy may move.
///
/// Every datagram is charged once, where it enters the proxy: one from the client when the
/// tunnel receives it, whatever happens to it next (empty, for an unknown context, oversized
/// or dropped later all count), one for the client when the tunnel takes it from its send queue.
/// So a relay's output is what is charged toward the client: target packets a relay consumes
/// without sending anything back are not. A datagram costs one packet and its length in bytes, at least
/// [`TunnelBudget::with_min_charge`]. Over budget, it is dropped and counted in
/// [`ConnectUdpStats`]; nothing waits.
///
/// Until the target sends anything back, at most [`TunnelBudget::with_unanswered`] packets
/// and bytes are forwarded to it, so one tunnel cannot spray a target that does not answer.
/// Every tunnel has its own allowance; a client that opens more tunnels gets more of it,
/// which the per-principal limits of a proxy bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelBudget {
    to_target: Option<DatagramRate>,
    to_client: Option<DatagramRate>,
    quota: Option<u64>,
    unanswered_packets: u64,
    unanswered_bytes: u64,
    min_charge: u64,
}

impl Default for TunnelBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelBudget {
    /// No rates or quota; 64 packets and 64 KiB to a target that has not answered; a charge
    /// of at least 64 bytes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            to_target: None,
            to_client: None,
            quota: None,
            unanswered_packets: 64,
            unanswered_bytes: 64 * 1024,
            min_charge: 64,
        }
    }

    generate_set_and_with! {
        /// The rate of datagrams from the client to the target.
        pub fn to_target(mut self, rate: Option<DatagramRate>) -> Self {
            self.to_target = rate;
            self
        }
    }

    generate_set_and_with! {
        /// The rate of datagrams from the target to the client.
        pub fn to_client(mut self, rate: Option<DatagramRate>) -> Self {
            self.to_client = rate;
            self
        }
    }

    generate_set_and_with! {
        /// The most bytes, both ways together, a tunnel is charged in its lifetime. Only what the
        /// rates admitted counts: a datagram a rate refused is not charged to the quota.
        pub fn quota(mut self, bytes: Option<u64>) -> Self {
            self.quota = bytes;
            self
        }
    }

    generate_set_and_with! {
        /// What a tunnel forwards to a target that has not sent anything back yet.
        pub fn unanswered(mut self, packets: u64, bytes: u64) -> Self {
            self.unanswered_packets = packets;
            self.unanswered_bytes = bytes;
            self
        }
    }

    generate_set_and_with! {
        /// The least a datagram is charged in bytes, so small and empty ones still cost; no
        /// datagram is charged more than one UDP payload, whatever this says.
        pub fn min_charge(mut self, bytes: u64) -> Self {
            self.min_charge = bytes;
            self
        }
    }

    /// What `len` payload bytes cost: at least the minimum, never more than one payload.
    fn cost(&self, len: u64) -> u64 {
        len.max(self.min_charge).min(MAX_CHARGE)
    }

    /// No limit of the tunnel's own: what a principal's budget charges through.
    pub(crate) fn unlimited() -> Self {
        Self::new().with_unanswered(u64::MAX, u64::MAX)
    }

    /// The account of one tunnel, charging `principal` first when it has a budget.
    pub(crate) fn account_for(self, principal: Option<Arc<PrincipalSpend>>) -> TunnelAccount {
        TunnelAccount {
            to_target: self.to_target.map(DatagramRate::limiters),
            to_client: self.to_client.map(DatagramRate::limiters),
            charged: AtomicU64::new(0),
            answered: AtomicBool::new(false),
            unanswered_packets: AtomicU64::new(0),
            unanswered_bytes: AtomicU64::new(0),
            principal,
            budget: self,
        }
    }
}

/// What all the tunnels of one principal may move together
/// ([`ConnectUdpLimits::with_principal_budget`](super::ConnectUdpLimits::with_principal_budget)).
///
/// Every datagram a tunnel is charged is charged to its principal first, at the same cost; a
/// datagram the principal's budget refuses is dropped. The principal's rates and quota outlive
/// its tunnels: a principal is only forgotten once its rates would be full again and its quota
/// window has ended, so closing and reopening tunnels never restores budget early.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrincipalBudget {
    to_target: Option<DatagramRate>,
    to_client: Option<DatagramRate>,
    quota: Option<(u64, Duration)>,
}

impl PrincipalBudget {
    /// No rates or quota.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            to_target: None,
            to_client: None,
            quota: None,
        }
    }

    generate_set_and_with! {
        /// The rate of datagrams from the principal's clients to their targets.
        pub fn to_target(mut self, rate: Option<DatagramRate>) -> Self {
            self.to_target = rate;
            self
        }
    }

    generate_set_and_with! {
        /// The rate of datagrams from the targets to the principal's clients.
        pub fn to_client(mut self, rate: Option<DatagramRate>) -> Self {
            self.to_client = rate;
            self
        }
    }

    generate_set_and_with! {
        /// The most bytes, both ways together, the principal is charged per `window`, which
        /// starts at its first charge. Only what the rates admitted counts.
        pub fn quota(mut self, bytes: u64, window: Duration) -> Self {
            self.quota = Some((bytes, window));
            self
        }
    }

    /// How long a principal without tunnels must stay tracked for its rates to be full again.
    pub(crate) fn refill_time(&self) -> Duration {
        [self.to_target, self.to_client]
            .into_iter()
            .flatten()
            .map(DatagramRate::refill_time)
            .max()
            .unwrap_or_default()
    }

    pub(crate) fn spend(self) -> PrincipalSpend {
        PrincipalSpend {
            to_target: self.to_target.map(DatagramRate::limiters),
            to_client: self.to_client.map(DatagramRate::limiters),
            quota: self.quota.map(|(bytes, window)| QuotaWindow {
                bytes,
                window,
                state: Mutex::new(None),
            }),
        }
    }
}

/// A principal's quota window, as its retention sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuotaWindowState {
    /// No window holds a charge.
    Closed,
    /// Open until this instant.
    OpenUntil(Instant),
    /// Open until past any instant this clock can represent.
    OpenBeyond,
}

/// One principal's spending against its [`PrincipalBudget`], shared by its tunnels.
pub(crate) struct PrincipalSpend {
    to_target: Option<RateLimiters>,
    to_client: Option<RateLimiters>,
    quota: Option<QuotaWindow>,
}

impl std::fmt::Debug for PrincipalSpend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrincipalSpend").finish_non_exhaustive()
    }
}

struct QuotaWindow {
    bytes: u64,
    window: Duration,
    /// When the current window started and what it charged; `None` before the first charge.
    state: Mutex<Option<(Instant, u64)>>,
}

impl PrincipalSpend {
    fn charge(&self, to_client: bool, cost: u64) -> Charge {
        let rate = if to_client {
            self.to_client.as_ref()
        } else {
            self.to_target.as_ref()
        };
        if rate.is_some_and(|rate| !rate.try_spend(cost)) {
            return Charge::RateLimited;
        }
        let Some(quota) = &self.quota else {
            return Charge::Paid;
        };
        let now = Instant::now();
        let mut state = quota.state.lock();
        let (start, charged) = match *state {
            // Elapsed time, not `start + window`: any window length is valid.
            Some((start, charged)) if now.saturating_duration_since(start) < quota.window => {
                (start, charged)
            }
            _ => (now, 0),
        };
        let total = charged.checked_add(cost);
        *state = Some((start, total.unwrap_or(u64::MAX)));
        if total.is_none_or(|total| total > quota.bytes) {
            Charge::OverQuota
        } else {
            Charge::Paid
        }
    }

    /// Whether a quota window that holds a charge is still open at `now`, and until when.
    pub(crate) fn quota_window(&self, now: Instant) -> QuotaWindowState {
        let Some(quota) = &self.quota else {
            return QuotaWindowState::Closed;
        };
        match *quota.state.lock() {
            Some((start, _charged)) if now.saturating_duration_since(start) < quota.window => start
                .checked_add(quota.window)
                .map_or(QuotaWindowState::OpenBeyond, QuotaWindowState::OpenUntil),
            _ => QuotaWindowState::Closed,
        }
    }
}

/// The most a single datagram is charged: what an oversized one declares counts no further.
const MAX_CHARGE: u64 = MAX_UDP_PAYLOAD as u64 + 1;

struct RateLimiters {
    packets: RateLimiter,
    bytes: RateLimiter,
}

impl RateLimiters {
    fn try_spend(&self, cost: u64) -> bool {
        // A packet spent on a datagram the bytes then refuse stays spent: no refunds.
        matches!(self.packets.try_acquire(1), Acquire::Granted)
            && matches!(self.bytes.try_acquire(cost), Acquire::Granted)
    }
}

/// What became of a charged datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Charge {
    Paid,
    RateLimited,
    OverQuota,
}

/// One tunnel's spending against its [`TunnelBudget`].
pub(crate) struct TunnelAccount {
    budget: TunnelBudget,
    to_target: Option<RateLimiters>,
    to_client: Option<RateLimiters>,
    charged: AtomicU64,
    answered: AtomicBool,
    unanswered_packets: AtomicU64,
    unanswered_bytes: AtomicU64,
    principal: Option<Arc<PrincipalSpend>>,
}

impl std::fmt::Debug for TunnelAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelAccount")
            .field("budget", &self.budget)
            .field("charged", &self.charged)
            .field("answered", &self.answered)
            .finish_non_exhaustive()
    }
}

impl TunnelAccount {
    /// Charge a datagram of `len` payload bytes from the client.
    pub(crate) fn charge_to_target(&self, len: u64) -> Charge {
        self.charge(false, len)
    }

    /// Charge a datagram of `len` payload bytes for the client; the target has answered.
    pub(crate) fn charge_to_client(&self, len: u64) -> Charge {
        self.answered.store(true, Ordering::Release);
        self.charge(true, len)
    }

    fn charge(&self, to_client: bool, len: u64) -> Charge {
        let cost = self.budget.cost(len);
        // The principal first: its budget is shared by every tunnel it opens.
        if let Some(principal) = &self.principal {
            let charge = principal.charge(to_client, cost);
            if charge != Charge::Paid {
                return charge;
            }
        }
        let rate = if to_client {
            self.to_client.as_ref()
        } else {
            self.to_target.as_ref()
        };
        if rate.is_some_and(|rate| !rate.try_spend(cost)) {
            return Charge::RateLimited;
        }
        let Some(quota) = self.budget.quota else {
            return Charge::Paid;
        };
        // Saturating, so a spent quota stays spent however much more is charged.
        let previous = self
            .charged
            .try_update(Ordering::AcqRel, Ordering::Acquire, |charged| {
                Some(charged.saturating_add(cost))
            })
            .unwrap_or_else(|charged| charged);
        // Past the counter's limit is past any quota, even an unbounded one.
        if previous
            .checked_add(cost)
            .is_none_or(|charged| charged > quota)
        {
            Charge::OverQuota
        } else {
            Charge::Paid
        }
    }

    /// Whether a paid datagram of `len` bytes may go to the target, which counts it
    /// against the allowance until the target has answered.
    pub(crate) fn may_reach_target(&self, len: u64) -> bool {
        if self.answered.load(Ordering::Acquire) {
            return true;
        }
        let packets = self.unanswered_packets.fetch_add(1, Ordering::AcqRel) + 1;
        let bytes = self
            .unanswered_bytes
            .fetch_add(len, Ordering::AcqRel)
            .saturating_add(len);
        packets <= self.budget.unanswered_packets && bytes <= self.budget.unanswered_bytes
    }
}

/// What a CONNECT-UDP tunnel received, forwarded and dropped, for one tunnel.
///
/// From the client: every HTTP Datagram counts in `received` and either in `forwarded` or in
/// one `dropped_*` field. From the target: every datagram the tunnel accepted to send counts,
/// once the tunnel has ended, in `returned` or in one `returned_dropped_*` field.
///
/// Byte counts are what was actually moved, never what a budget charged, and saturate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectUdpStats {
    /// HTTP Datagrams received from the client.
    pub received: u64,
    /// Of those, received as QUIC DATAGRAM frames.
    pub native: u64,
    /// Of those, received as DATAGRAM capsules.
    pub capsule: u64,
    /// UDP payloads forwarded to the target.
    pub forwarded: u64,
    /// Dropped: a context other than UDP payloads, or a truncated context ID.
    pub dropped_unknown_context: u64,
    /// Dropped: larger than the tunnel carries.
    pub dropped_oversize: u64,
    /// Dropped: over the tunnel's rate.
    pub dropped_rate_limited: u64,
    /// Dropped: over the tunnel's quota.
    pub dropped_over_quota: u64,
    /// Dropped: the target has not answered and the allowance is spent.
    pub dropped_unanswered: u64,
    /// Datagrams from the target sent on to the client.
    pub returned: u64,
    /// Datagrams from the target dropped: over the tunnel's rate.
    pub returned_dropped_rate_limited: u64,
    /// Datagrams from the target dropped: over the tunnel's quota.
    pub returned_dropped_over_quota: u64,
    /// Datagrams from the target dropped: larger than the native carrier takes now.
    pub returned_dropped_too_large: u64,
    /// Datagrams from the target dropped: the tunnel ended before the carrier took them, still
    /// queued or with their send waiting.
    pub returned_dropped_unsent: u64,
    /// Bytes after the Context ID of the HTTP Datagrams received in full, whatever their
    /// context: a truncated Context ID has none, and how an ID is encoded never counts.
    pub received_bytes: u64,
    /// What oversized DATAGRAM capsules declared after their Context ID: only their start is
    /// read, so these bytes were announced, not necessarily received.
    pub oversize_declared_bytes: u64,
    /// UDP payload bytes handed to the tunnel's reader, toward the target.
    pub forwarded_bytes: u64,
    /// UDP payload bytes the carrier took toward the client.
    pub returned_bytes: u64,
    /// UDP payload bytes from the target dropped, for any `returned_dropped_*` reason.
    pub returned_dropped_bytes: u64,
}

/// The counters behind [`ConnectUdpStats`].
#[derive(Debug, Default)]
pub(crate) struct StatsCounters {
    received: AtomicU64,
    native: AtomicU64,
    capsule: AtomicU64,
    forwarded: AtomicU64,
    dropped_unknown_context: AtomicU64,
    dropped_oversize: AtomicU64,
    dropped_rate_limited: AtomicU64,
    dropped_over_quota: AtomicU64,
    dropped_unanswered: AtomicU64,
    returned: AtomicU64,
    returned_dropped_rate_limited: AtomicU64,
    returned_dropped_over_quota: AtomicU64,
    returned_dropped_too_large: AtomicU64,
    returned_dropped_unsent: AtomicU64,
    received_bytes: AtomicU64,
    oversize_declared_bytes: AtomicU64,
    forwarded_bytes: AtomicU64,
    returned_bytes: AtomicU64,
    returned_dropped_bytes: AtomicU64,
}

/// What became of a datagram the tunnel took to send to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToClient {
    Charged(Charge),
    TooLarge,
    Unsent,
}

/// What the client sent and what became of it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum FromClient {
    /// A datagram with this many bytes after its Context ID
    /// ([`ConnectUdpStats::received_bytes`]).
    Received(Option<DatagramTransport>, u64),
    /// An oversized capsule declared this many bytes after its Context ID; counted received
    /// separately.
    DeclaredOversize(u64),
    /// A UDP payload of this many bytes handed to the reader.
    Forwarded(u64),
    UnknownContext,
    Oversize,
    Charged(Charge),
    Unanswered,
}

impl StatsCounters {
    pub(crate) fn count_from_client(&self, event: FromClient) {
        let counter = match event {
            FromClient::Received(transport, bytes) => {
                match transport {
                    Some(DatagramTransport::Native) => bump(&self.native),
                    Some(DatagramTransport::Capsule) => bump(&self.capsule),
                    None => {}
                }
                add(&self.received_bytes, bytes);
                &self.received
            }
            FromClient::DeclaredOversize(bytes) => {
                add(&self.oversize_declared_bytes, bytes);
                return;
            }
            FromClient::Forwarded(bytes) => {
                add(&self.forwarded_bytes, bytes);
                &self.forwarded
            }
            FromClient::UnknownContext => &self.dropped_unknown_context,
            FromClient::Oversize => &self.dropped_oversize,
            FromClient::Charged(Charge::RateLimited) => &self.dropped_rate_limited,
            FromClient::Charged(Charge::OverQuota) => &self.dropped_over_quota,
            FromClient::Charged(Charge::Paid) => return,
            FromClient::Unanswered => &self.dropped_unanswered,
        };
        bump(counter);
    }

    /// Count a UDP payload of `bytes` toward the client, once, by what became of it.
    pub(crate) fn count_to_client(&self, outcome: ToClient, bytes: u64) {
        let (counter, byte_counter) = match outcome {
            ToClient::Charged(Charge::Paid) => (&self.returned, &self.returned_bytes),
            ToClient::Charged(Charge::RateLimited) => (
                &self.returned_dropped_rate_limited,
                &self.returned_dropped_bytes,
            ),
            ToClient::Charged(Charge::OverQuota) => (
                &self.returned_dropped_over_quota,
                &self.returned_dropped_bytes,
            ),
            ToClient::TooLarge => (
                &self.returned_dropped_too_large,
                &self.returned_dropped_bytes,
            ),
            ToClient::Unsent => (&self.returned_dropped_unsent, &self.returned_dropped_bytes),
        };
        bump(counter);
        add(byte_counter, bytes);
    }

    pub(crate) fn snapshot(&self) -> ConnectUdpStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        ConnectUdpStats {
            received: load(&self.received),
            native: load(&self.native),
            capsule: load(&self.capsule),
            forwarded: load(&self.forwarded),
            dropped_unknown_context: load(&self.dropped_unknown_context),
            dropped_oversize: load(&self.dropped_oversize),
            dropped_rate_limited: load(&self.dropped_rate_limited),
            dropped_over_quota: load(&self.dropped_over_quota),
            dropped_unanswered: load(&self.dropped_unanswered),
            returned: load(&self.returned),
            returned_dropped_rate_limited: load(&self.returned_dropped_rate_limited),
            returned_dropped_over_quota: load(&self.returned_dropped_over_quota),
            returned_dropped_too_large: load(&self.returned_dropped_too_large),
            returned_dropped_unsent: load(&self.returned_dropped_unsent),
            received_bytes: load(&self.received_bytes),
            oversize_declared_bytes: load(&self.oversize_declared_bytes),
            forwarded_bytes: load(&self.forwarded_bytes),
            returned_bytes: load(&self.returned_bytes),
            returned_dropped_bytes: load(&self.returned_dropped_bytes),
        }
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Add `bytes`, saturating: a peer declaring huge lengths cannot wrap a total.
fn add(counter: &AtomicU64, bytes: u64) {
    _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
        Some(total.saturating_add(bytes))
    });
}

#[cfg(test)]
mod tests;
