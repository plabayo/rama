//! Shared packet rates and principal budgets for MASQUE tunnels.
use parking_lot::Mutex;
use rama_utils::{
    macros::generate_set_and_with,
    rate::{Acquire, Rate, RateLimiter},
};
use std::{num::NonZeroU64, time::Duration};
use tokio::time::Instant;

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
        pub fn packet_burst(mut self, burst: NonZeroU64) -> Self {
            self.packet_burst = burst.get();
            self
        }
    }

    generate_set_and_with! {
        /// The most bytes spent at once.
        pub fn byte_burst(mut self, burst: NonZeroU64) -> Self {
            self.byte_burst = burst.get();
            self
        }
    }

    pub(crate) fn limiters(self) -> RateLimiters {
        RateLimiters {
            packets: RateLimiter::new(self.packets, self.packet_burst),
            bytes: RateLimiter::new(self.bytes, self.byte_burst),
        }
    }

    /// How long an emptied allowance takes to refill.
    pub(crate) fn refill_time(self) -> Duration {
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

/// What all the tunnels of one principal may move together
/// ([`TunnelLimits::with_principal_budget`](crate::limits::TunnelLimits::with_principal_budget)).
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
    lifetime_quota: Option<u64>,
}

impl PrincipalBudget {
    /// No rates or quota.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            to_target: None,
            to_client: None,
            quota: None,
            lifetime_quota: None,
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

    generate_set_and_with! {
        /// Total bytes across the principal's lifetime. The accounting record
        /// remains retained after tunnels close, so reopening cannot reset it.
        /// Once the principal map fills, new principals are refused for the
        /// service lifetime. Prefer [`Self::with_quota`] for rotating identities.
        pub fn lifetime_quota(mut self, bytes: Option<u64>) -> Self {
            self.lifetime_quota = bytes;
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
            remaining: self.lifetime_quota.map(std::sync::atomic::AtomicU64::new),
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
    remaining: Option<std::sync::atomic::AtomicU64>,
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
    pub(crate) fn charge(&self, to_client: bool, cost: u64) -> Charge {
        let rate = if to_client {
            self.to_client.as_ref()
        } else {
            self.to_target.as_ref()
        };
        if rate.is_some_and(|rate| !rate.try_spend(cost)) {
            return Charge::RateLimited;
        }
        if let Some(remaining) = &self.remaining
            && remaining
                .try_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |n| n.checked_sub(cost),
                )
                .is_err()
        {
            return Charge::OverQuota;
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
        if self.remaining.is_some() {
            return QuotaWindowState::OpenBeyond;
        }
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

#[derive(Debug, Clone)]
pub(crate) struct RateLimiters {
    packets: RateLimiter,
    bytes: RateLimiter,
}

impl RateLimiters {
    pub(crate) fn try_spend(&self, cost: u64) -> bool {
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
