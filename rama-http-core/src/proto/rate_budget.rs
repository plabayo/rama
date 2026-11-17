//! A token bucket: a burst of events tolerated at once, regained at a steady rate.

use rama_core::telemetry::tracing;
use rama_utils::rate::{Acquire, Rate, TokenBucket};
use tokio::time::Instant;

/// Where the lifetime total is first flagged when the budget gives no burst to start from.
const FALLBACK_FLAG_THRESHOLD: u64 = 1024;

/// How many events of one kind a connection tolerates before it is closed: `burst` at once,
/// regained at a [`Rate`] and never beyond `burst`.
///
/// Occasional events cost nothing lasting, a sustained flood drains the budget. A
/// [lifetime](Self::lifetime) budget regains nothing, which makes it a budget for the whole
/// life of the connection.
///
/// A rate tolerates a peer that stays below it for as long as the connection lives. Such a
/// steady drip is flagged in the logs each time its lifetime total doubles, and an optional
/// [ceiling](Self::with_ceiling) on that total ends it.
#[derive(Debug, Clone, Copy)]
pub struct RateBudget {
    burst: u32,
    rate: Option<Rate>,
    ceiling: Option<u64>,
}

impl RateBudget {
    /// A budget of `burst` events at once, regained at `rate`.
    #[must_use]
    pub const fn rated(rate: Rate, burst: u32) -> Self {
        Self {
            burst,
            rate: Some(rate),
            ceiling: None,
        }
    }

    /// A budget of `max` events over the whole life of the connection.
    #[must_use]
    pub const fn lifetime(max: u32) -> Self {
        Self {
            burst: max,
            rate: None,
            ceiling: None,
        }
    }

    /// Also close the connection once more than `ceiling` events happened over its whole
    /// life, however slowly they came.
    #[must_use]
    pub const fn with_ceiling(mut self, ceiling: u64) -> Self {
        self.ceiling = Some(ceiling);
        self
    }

    /// The events tolerated at once.
    #[must_use]
    pub const fn burst(&self) -> u32 {
        self.burst
    }

    /// The rate events are regained at, `None` for a lifetime budget.
    #[must_use]
    pub const fn rate(&self) -> Option<Rate> {
        self.rate
    }

    /// The events tolerated over the whole life of the connection, if capped.
    #[must_use]
    pub const fn ceiling(&self) -> Option<u64> {
        self.ceiling
    }
}

/// What a connection does about a stream it just refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Covered by the budget.
    Within,
    /// Covered by the budget, and the lifetime total reached a threshold worth a log line.
    Flag { total: u64 },
    /// Past the budget or its ceiling: the connection is to be closed.
    Exhausted { total: u64 },
}

/// The streams one connection refused or reset for what its peer sent, charged against a
/// [`RateBudget`] and counted for the connection's whole life.
#[derive(Debug)]
pub(crate) struct RefusedStreams {
    allowance: Option<Allowance>,
    ceiling: Option<u64>,
    total: u64,
    /// The lifetime total to flag next, doubled each time it is reached.
    flag_at: Option<u64>,
}

impl RefusedStreams {
    pub(crate) fn new(budget: Option<RateBudget>) -> Self {
        let flag_at = match budget.map(|budget| budget.burst) {
            Some(burst @ 1..) => u64::from(burst),
            Some(0) | None => FALLBACK_FLAG_THRESHOLD,
        };
        Self {
            allowance: budget.map(Allowance::new),
            ceiling: budget.and_then(|budget| budget.ceiling),
            total: 0,
            flag_at: Some(flag_at),
        }
    }

    /// Count one refused stream at `now` and tell what the connection is to do about it.
    pub(crate) fn record(&mut self, now: Instant) -> Refusal {
        self.total = self.total.saturating_add(1);
        let total = self.total;
        if let Some(allowance) = self.allowance.as_mut() {
            let over_ceiling = self.ceiling.is_some_and(|ceiling| total > ceiling);
            if over_ceiling || !allowance.try_take(now) {
                return Refusal::Exhausted { total };
            }
        }
        if self.flag_at == Some(total) {
            self.flag_at = total.checked_mul(2);
            return Refusal::Flag { total };
        }
        Refusal::Within
    }

    /// Count one refused stream now, log what it is worth, and report an exhausted budget.
    pub(crate) fn charge(
        &mut self,
        protocol: &'static str,
        role: &'static str,
    ) -> Result<(), RateBudgetExhausted> {
        match self.record(Instant::now()) {
            Refusal::Within => Ok(()),
            Refusal::Flag { total } => {
                tracing::warn!(
                    protocol,
                    role,
                    total,
                    "connection keeps refusing streams for what its peer sends",
                );
                Ok(())
            }
            Refusal::Exhausted { total } => {
                tracing::warn!(
                    protocol,
                    role,
                    total,
                    "refused streams exceeded their budget; closing the connection",
                );
                Err(RateBudgetExhausted)
            }
        }
    }

    /// The streams refused over the connection's whole life.
    #[cfg(any(test, feature = "quic", feature = "unstable"))]
    pub(crate) fn total(&self) -> u64 {
        self.total
    }
}

#[derive(Debug)]
pub(crate) struct RateBudgetExhausted;

/// The running state of a [`RateBudget`].
#[derive(Debug)]
enum Allowance {
    /// Regained at a rate, measured from the first charge.
    Rated {
        bucket: TokenBucket,
        epoch: Option<Instant>,
    },
    /// Never regained.
    Lifetime { left: u64 },
}

impl Allowance {
    fn new(budget: RateBudget) -> Self {
        match budget.rate {
            // The bucket needs a burst to hold anything; an empty one regains nothing either.
            Some(rate) if budget.burst > 0 => Self::Rated {
                bucket: TokenBucket::new(rate, u64::from(budget.burst)),
                epoch: None,
            },
            Some(_) | None => Self::Lifetime {
                left: u64::from(budget.burst),
            },
        }
    }

    /// Take one event at `now`, or report that the budget does not cover it.
    fn try_take(&mut self, now: Instant) -> bool {
        match self {
            Self::Rated { bucket, epoch } => {
                let epoch = *epoch.get_or_insert(now);
                let at = u64::try_from(now.saturating_duration_since(epoch).as_nanos())
                    .unwrap_or(u64::MAX);
                matches!(bucket.try_acquire(at, 1), Acquire::Granted)
            }
            Self::Lifetime { left } => match left.checked_sub(1) {
                Some(rest) => {
                    *left = rest;
                    true
                }
                None => false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_lifetime_budget_is_never_regained() {
        let start = Instant::now();
        let mut streams = RefusedStreams::new(Some(RateBudget::lifetime(3)));
        assert_eq!(streams.record(start), Refusal::Within);
        assert_eq!(streams.record(start), Refusal::Within);
        assert_eq!(streams.record(start), Refusal::Flag { total: 3 });
        let much_later = start + Duration::from_hours(24 * 365);
        assert_eq!(streams.record(much_later), Refusal::Exhausted { total: 4 });
    }

    #[test]
    fn an_empty_budget_covers_nothing() {
        let start = Instant::now();
        for budget in [
            RateBudget::lifetime(0),
            RateBudget::rated(Rate::per_sec(1000), 0),
        ] {
            let mut streams = RefusedStreams::new(Some(budget));
            assert_eq!(streams.record(start), Refusal::Exhausted { total: 1 });
            let later = start + Duration::from_hours(1);
            assert_eq!(streams.record(later), Refusal::Exhausted { total: 2 });
        }
    }

    /// The lifetime totals at which `count` refusals a second apart are flagged.
    fn flagged(streams: &mut RefusedStreams, count: u64) -> Vec<u64> {
        let start = Instant::now();
        (1..=count)
            .filter_map(|n| match streams.record(start + Duration::from_secs(n)) {
                Refusal::Flag { total } => Some(total),
                Refusal::Within => None,
                Refusal::Exhausted { total } => panic!("exhausted at {total}"),
            })
            .collect()
    }

    #[test]
    fn the_lifetime_total_is_flagged_each_time_it_doubles_from_the_burst() {
        let mut streams = RefusedStreams::new(Some(RateBudget::rated(Rate::per_sec(1), 5)));
        assert_eq!(flagged(&mut streams, 50), [5, 10, 20, 40]);
        assert_eq!(streams.total(), 50);
    }

    #[test]
    fn without_a_budget_nothing_is_exhausted_and_the_flag_starts_at_a_fixed_total() {
        let fallback = FALLBACK_FLAG_THRESHOLD;
        let mut streams = RefusedStreams::new(None);
        assert_eq!(
            flagged(&mut streams, 4 * fallback + 1),
            [fallback, 2 * fallback, 4 * fallback]
        );
    }

    #[test]
    fn a_spent_budget_is_reported_with_the_total_and_regained_with_time() {
        let start = Instant::now();
        let mut streams = RefusedStreams::new(Some(RateBudget::rated(Rate::per_sec(1), 3)));
        assert_eq!(streams.record(start), Refusal::Within);
        assert_eq!(streams.record(start), Refusal::Within);
        assert_eq!(streams.record(start), Refusal::Flag { total: 3 });
        assert_eq!(streams.record(start), Refusal::Exhausted { total: 4 });
        let later = start + Duration::from_secs(1);
        assert_eq!(streams.record(later), Refusal::Within);
        assert_eq!(streams.record(later), Refusal::Exhausted { total: 6 });
    }

    #[test]
    fn a_ceiling_ends_what_the_rate_would_tolerate() {
        let start = Instant::now();
        let outcomes = |budget: RateBudget| {
            let mut streams = RefusedStreams::new(Some(budget));
            (0..12)
                .map(|n| streams.record(start + Duration::from_secs(n)))
                .filter(|outcome| matches!(outcome, Refusal::Exhausted { .. }))
                .collect::<Vec<_>>()
        };
        let budget = RateBudget::rated(Rate::per_sec(1), 2);
        assert_eq!(budget.ceiling(), None);
        assert_eq!(outcomes(budget), []);
        let capped = budget.with_ceiling(10);
        assert_eq!(capped.ceiling(), Some(10));
        assert_eq!(
            outcomes(capped),
            [
                Refusal::Exhausted { total: 11 },
                Refusal::Exhausted { total: 12 }
            ]
        );
        // A ceiling of nothing covers no stream, whatever the bucket holds.
        assert_eq!(outcomes(budget.with_ceiling(0)).len(), 12);
    }

    #[test]
    fn the_lifetime_total_and_its_flag_do_not_overflow() {
        let now = Instant::now();
        let mut streams = RefusedStreams::new(None);
        streams.total = u64::MAX - 1;
        streams.flag_at = Some(u64::MAX);
        assert_eq!(streams.record(now), Refusal::Flag { total: u64::MAX });
        // Saturated, the total stays put and has no further threshold to reach.
        assert_eq!(streams.record(now), Refusal::Within);
        assert_eq!(streams.record(now), Refusal::Within);
        assert_eq!(streams.total(), u64::MAX);
    }
}
