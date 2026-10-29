use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

    pub(crate) fn account(self) -> TunnelAccount {
        TunnelAccount {
            to_target: self.to_target.map(DatagramRate::limiters),
            to_client: self.to_client.map(DatagramRate::limiters),
            charged: AtomicU64::new(0),
            answered: AtomicBool::new(false),
            unanswered_packets: AtomicU64::new(0),
            unanswered_bytes: AtomicU64::new(0),
            budget: self,
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
        self.charge(self.to_target.as_ref(), len)
    }

    /// Charge a datagram of `len` payload bytes for the client; the target has answered.
    pub(crate) fn charge_to_client(&self, len: u64) -> Charge {
        self.answered.store(true, Ordering::Release);
        self.charge(self.to_client.as_ref(), len)
    }

    fn charge(&self, rate: Option<&RateLimiters>, len: u64) -> Charge {
        let cost = self.budget.cost(len);
        if rate.is_some_and(|rate| !rate.try_spend(cost)) {
            return Charge::RateLimited;
        }
        let Some(quota) = self.budget.quota else {
            return Charge::Paid;
        };
        // Saturating, so a spent quota stays spent however much more is charged.
        let previous = self
            .charged
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |charged| {
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
/// one `dropped_*` field. From the target: every datagram the tunnel took to send counts in
/// `returned` or in one `returned_dropped_*` field.
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
}

/// What the client sent and what became of it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum FromClient {
    Received(Option<DatagramTransport>),
    Forwarded,
    UnknownContext,
    Oversize,
    Charged(Charge),
    Unanswered,
}

impl StatsCounters {
    pub(crate) fn count_from_client(&self, event: FromClient) {
        let counter = match event {
            FromClient::Received(transport) => {
                match transport {
                    Some(DatagramTransport::Native) => bump(&self.native),
                    Some(DatagramTransport::Capsule) => bump(&self.capsule),
                    None => {}
                }
                &self.received
            }
            FromClient::Forwarded => &self.forwarded,
            FromClient::UnknownContext => &self.dropped_unknown_context,
            FromClient::Oversize => &self.dropped_oversize,
            FromClient::Charged(Charge::RateLimited) => &self.dropped_rate_limited,
            FromClient::Charged(Charge::OverQuota) => &self.dropped_over_quota,
            FromClient::Charged(Charge::Paid) => return,
            FromClient::Unanswered => &self.dropped_unanswered,
        };
        bump(counter);
    }

    pub(crate) fn count_to_client(&self, charge: Charge) {
        bump(match charge {
            Charge::Paid => &self.returned,
            Charge::RateLimited => &self.returned_dropped_rate_limited,
            Charge::OverQuota => &self.returned_dropped_over_quota,
        });
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
        }
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests;
