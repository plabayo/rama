use crate::budget::{Charge, DatagramRate, PrincipalSpend};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use rama_http::datagram::DatagramTransport;
use rama_utils::macros::generate_set_and_with;

use super::MAX_UDP_PAYLOAD;

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
    traffic: crate::budget::TunnelBudget,
    unanswered_packets: u64,
    unanswered_bytes: u64,
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
            traffic: crate::budget::TunnelBudget::new(),
            unanswered_packets: 64,
            unanswered_bytes: 64 * 1024,
        }
    }

    generate_set_and_with! {
        /// The rate of datagrams from the client to the target.
        pub fn to_target(mut self, rate: Option<DatagramRate>) -> Self {
            self.traffic.maybe_set_to_target(rate);
            self
        }
    }

    generate_set_and_with! {
        /// The rate of datagrams from the target to the client.
        pub fn to_client(mut self, rate: Option<DatagramRate>) -> Self {
            self.traffic.maybe_set_to_client(rate);
            self
        }
    }

    generate_set_and_with! {
        /// The most bytes, both ways together, a tunnel is charged in its lifetime. Only what the
        /// rates admitted counts: a datagram a rate refused is not charged to the quota.
        pub fn quota(mut self, bytes: Option<u64>) -> Self {
            self.traffic.maybe_set_quota(bytes);
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
            self.traffic.set_min_charge(bytes);
            self
        }
    }

    /// No limit of the tunnel's own: what a principal's budget charges through.
    pub(crate) fn unlimited() -> Self {
        Self::new().with_unanswered(u64::MAX, u64::MAX)
    }

    /// The account of one tunnel, charging `principal` first when it has a budget.
    pub(crate) fn account_for(self, principal: Option<Arc<PrincipalSpend>>) -> TunnelAccount {
        TunnelAccount {
            traffic: self.traffic.account_for(principal, MAX_CHARGE),
            answered: AtomicBool::new(false),
            unanswered_packets: AtomicU64::new(0),
            unanswered_bytes: AtomicU64::new(0),
            budget: self,
        }
    }
}

/// The most a single datagram is charged: what an oversized one declares counts no further.
const MAX_CHARGE: u64 = MAX_UDP_PAYLOAD as u64 + 1;

/// One tunnel's spending against its [`TunnelBudget`].
pub(crate) struct TunnelAccount {
    budget: TunnelBudget,
    traffic: crate::budget::TunnelAccount,
    answered: AtomicBool,
    unanswered_packets: AtomicU64,
    unanswered_bytes: AtomicU64,
}

impl std::fmt::Debug for TunnelAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelAccount")
            .field("budget", &self.budget)
            .field("traffic", &self.traffic)
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
        self.traffic.charge(to_client, len)
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
