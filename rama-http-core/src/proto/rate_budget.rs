//! A token bucket: a burst of events tolerated at once, regained at a steady rate.

use rama_core::telemetry::tracing;
use tokio::time::Instant;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Where the lifetime total is first flagged when the budget gives no burst to start from.
const FALLBACK_FLAG_THRESHOLD: u64 = 1024;

/// How many events of one kind a connection tolerates before it is closed: `burst` at once,
/// regained at `rate` per second and never beyond `burst`.
///
/// Occasional events cost nothing lasting, a sustained flood drains the budget. A rate of
/// zero regains nothing, which makes the burst a budget for the whole life of the connection.
///
/// A rate tolerates a peer that stays below it for as long as the connection lives. Such a
/// steady drip is flagged in the logs each time its lifetime total doubles, and an optional
/// [ceiling](Self::with_ceiling) on that total ends it.
#[derive(Debug, Clone, Copy)]
pub struct RateBudget {
    burst: u32,
    rate: u32,
    ceiling: Option<u64>,
}

impl RateBudget {
    /// A budget of `burst` events at once, regained at `rate` events per second.
    #[must_use]
    pub const fn new(burst: u32, rate: u32) -> Self {
        Self {
            burst,
            rate,
            ceiling: None,
        }
    }

    /// A budget of `max` events over the whole life of the connection.
    #[must_use]
    pub const fn lifetime(max: u32) -> Self {
        Self::new(max, 0)
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

    /// The events regained per second.
    #[must_use]
    pub const fn rate(&self) -> u32 {
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
    bucket: Option<TokenBucket>,
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
            bucket: budget.map(TokenBucket::new),
            total: 0,
            flag_at: Some(flag_at),
        }
    }

    /// Count one refused stream at `now` and tell what the connection is to do about it.
    pub(crate) fn record(&mut self, now: Instant) -> Refusal {
        self.total = self.total.saturating_add(1);
        let total = self.total;
        if let Some(bucket) = self.bucket.as_mut() {
            let over_ceiling = bucket.budget.ceiling.is_some_and(|ceiling| total > ceiling);
            if over_ceiling || bucket.try_take(1, now).is_err() {
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
    pub(crate) fn total(&self) -> u64 {
        self.total
    }
}

#[derive(Debug)]
pub(crate) struct RateBudgetExhausted;

/// The running state of a [`RateBudget`], brought up to date only when an event is charged.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    budget: RateBudget,
    tokens: u32,
    /// The instant `tokens` accounts for, unset while the bucket is full.
    refilled_at: Option<Instant>,
    /// What was earned up to `refilled_at` short of a whole token, in nanoseconds times rate.
    fraction: u64,
}

impl TokenBucket {
    pub(crate) fn new(budget: RateBudget) -> Self {
        Self {
            budget,
            tokens: budget.burst,
            refilled_at: None,
            fraction: 0,
        }
    }

    /// Charge `cost` tokens at `now`, or report that the budget does not cover them.
    pub(crate) fn try_take(&mut self, cost: u32, now: Instant) -> Result<(), RateBudgetExhausted> {
        self.refill(now);
        let left = self.tokens.checked_sub(cost).ok_or(RateBudgetExhausted)?;
        if self.refilled_at.is_none() {
            self.refilled_at = Some(now);
        }
        self.tokens = left;
        Ok(())
    }

    fn refill(&mut self, now: Instant) {
        let (Some(since), rate @ 1..) = (self.refilled_at, self.budget.rate) else {
            return;
        };
        // A `Duration` holds under 2^95 ns, so its product with a `u32` rate fits a `u128`.
        let earned = now.saturating_duration_since(since).as_nanos() * u128::from(rate)
            + u128::from(self.fraction);
        let gained = earned / u128::from(NANOS_PER_SEC);
        let missing = self.budget.burst - self.tokens;
        match u32::try_from(gained) {
            Ok(gained) if gained < missing => {
                self.tokens += gained;
                // The clock moves to `now` and what is short of a token is carried: no time
                // is counted twice, and none is lost.
                self.fraction = (earned % u128::from(NANOS_PER_SEC)) as u64;
                self.refilled_at = Some(self.refilled_at.map_or(now, |since| since.max(now)));
            }
            Ok(_) | Err(_) => {
                self.tokens = self.budget.burst;
                self.refilled_at = None;
                self.fraction = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn an_instant_is_never_credited_twice() {
        let mut bucket = TokenBucket::new(RateBudget::new(1000, u32::MAX));
        let start = Instant::now();
        assert!(charge(&mut bucket, 1000, start));
        // One nanosecond at this rate is worth four tokens and a fraction.
        let later = start + Duration::from_nanos(1);
        let granted = (0..16).filter(|_| take(&mut bucket, later)).count();
        assert_eq!(granted, 4);
    }

    fn charge(bucket: &mut TokenBucket, cost: u32, now: Instant) -> bool {
        bucket.try_take(cost, now).is_ok()
    }

    fn take(bucket: &mut TokenBucket, now: Instant) -> bool {
        charge(bucket, 1, now)
    }

    /// How many single tokens the bucket yields at `now`.
    fn drain(bucket: &mut TokenBucket, now: Instant) -> u32 {
        let mut taken = 0;
        while take(bucket, now) {
            taken += 1;
        }
        taken
    }

    #[test]
    fn a_burst_is_granted_at_once_and_no_more() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(RateBudget::new(5, 1));
        assert_eq!(drain(&mut bucket, now), 5);
        assert!(!take(&mut bucket, now));
    }

    #[test]
    fn tokens_return_at_the_rate() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(RateBudget::new(10, 2));
        assert_eq!(drain(&mut bucket, start), 10);
        assert_eq!(drain(&mut bucket, start + Duration::from_millis(499)), 0);
        assert_eq!(drain(&mut bucket, start + Duration::from_millis(500)), 1);
        assert_eq!(drain(&mut bucket, start + Duration::from_secs(3)), 5);
    }

    #[test]
    fn fractions_of_a_token_add_up_across_charges() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(RateBudget::new(100, 3));
        assert_eq!(drain(&mut bucket, start), 100);
        // Charged every 100 ms for 10 s, the bucket yields the 30 tokens of 10 s.
        let taken: u32 = (1..=100)
            .map(|tick| drain(&mut bucket, start + Duration::from_millis(100 * tick)))
            .sum();
        assert_eq!(taken, 30);
    }

    #[test]
    fn tokens_never_exceed_the_burst() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(RateBudget::new(4, 100));
        assert_eq!(drain(&mut bucket, start), 4);
        let later = start + Duration::from_hours(1);
        assert_eq!(drain(&mut bucket, later), 4);
        // Time spent full earns nothing ahead.
        assert!(take(&mut bucket, later + Duration::from_hours(1)));
        assert_eq!(drain(&mut bucket, later + Duration::from_hours(1)), 3);
    }

    #[test]
    fn a_zero_rate_is_a_lifetime_budget() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(RateBudget::lifetime(3));
        assert_eq!(drain(&mut bucket, start), 3);
        assert_eq!(
            drain(&mut bucket, start + Duration::from_hours(24 * 365)),
            0
        );
    }

    #[test]
    fn an_empty_burst_grants_nothing() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(RateBudget::new(0, 1000));
        assert!(!take(&mut bucket, start));
        assert!(!take(&mut bucket, start + Duration::from_hours(1)));
    }

    #[test]
    fn a_charge_larger_than_what_is_left_takes_nothing() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(RateBudget::new(5, 0));
        assert!(charge(&mut bucket, 3, now));
        assert!(!charge(&mut bucket, 3, now));
        assert_eq!(drain(&mut bucket, now), 2);
    }

    #[test]
    fn a_clock_reading_in_the_past_earns_nothing() {
        let start = Instant::now() + Duration::from_mins(1);
        let mut bucket = TokenBucket::new(RateBudget::new(2, 1000));
        assert_eq!(drain(&mut bucket, start), 2);
        assert_eq!(drain(&mut bucket, start - Duration::from_secs(30)), 0);
    }

    #[test]
    fn extreme_rates_and_waits_do_not_overflow() {
        let start = Instant::now();
        // About three centuries: as far ahead as every platform's clock can represent.
        let far = start + Duration::from_hours(24 * 365 * 300);
        for (burst, rate) in [(u32::MAX, u32::MAX), (7, u32::MAX), (u32::MAX, 1), (7, 1)] {
            let mut bucket = TokenBucket::new(RateBudget::new(burst, rate));
            assert!(charge(&mut bucket, burst, start));
            assert!(!take(&mut bucket, start));
            // One nanosecond at the highest rate already earns whole tokens.
            let soon = start + Duration::from_nanos(1);
            assert_eq!(take(&mut bucket, soon), rate == u32::MAX);
            assert!(charge(&mut bucket, burst, far));
            assert!(!take(&mut bucket, far));
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
        let mut streams = RefusedStreams::new(Some(RateBudget::new(5, 1)));
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
        let mut streams = RefusedStreams::new(Some(RateBudget::new(3, 1)));
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
        let budget = RateBudget::new(2, 1);
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
