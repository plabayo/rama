use super::{Acquire, Rate};

/// A sans-IO [token bucket]: spend units at a bounded [`Rate`] with a
/// configurable burst capacity.
///
/// The bucket never reads a clock: the caller provides `now` as
/// monotonic nanoseconds from any epoch, as long as it is consistent
/// across calls. This keeps the bucket `no_std`, deterministic to test
/// and embeddable in other sans-IO state machines.
///
/// Internally the level is stored scaled by the period (in nanoseconds),
/// so refills are exact integer arithmetic with zero drift.
///
/// [token bucket]: https://en.wikipedia.org/wiki/Token_bucket
///
/// # Examples
///
/// ```
/// use rama_utils::rate::{Acquire, Rate, TokenBucket};
///
/// let mut bucket = TokenBucket::from_rate(Rate::per_sec(2));
/// assert_eq!(bucket.try_acquire(0, 1), Acquire::Granted);
/// assert_eq!(bucket.try_acquire(0, 1), Acquire::Granted);
/// // bucket is empty: the next unit refills after half a period
/// assert_eq!(bucket.try_acquire(0, 1), Acquire::RetryAt(500_000_000));
/// assert_eq!(bucket.try_acquire(500_000_000, 1), Acquire::Granted);
/// ```
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: Rate,
    burst: u64,
    /// current level, scaled: 1 unit == `rate.per_nanos()` scaled units
    level_scaled: u128,
    last_refill: u64,
}

impl TokenBucket {
    /// Create a new [`TokenBucket`] with the given [`Rate`] and
    /// burst capacity (the maximum units spendable at once).
    ///
    /// The bucket starts full.
    ///
    /// # Panics
    ///
    /// Panics if `burst` is zero.
    #[must_use]
    pub fn new(rate: Rate, burst: u64) -> Self {
        assert!(burst > 0, "TokenBucket: burst must be non-zero");
        Self {
            rate,
            burst,
            level_scaled: Self::capacity_scaled_for(rate, burst),
            last_refill: 0,
        }
    }

    /// Create a new [`TokenBucket`] with a burst capacity of one
    /// period worth of units (`rate.units()`): a plain smooth rate.
    #[must_use]
    pub fn from_rate(rate: Rate) -> Self {
        Self::new(rate, rate.units())
    }

    /// The configured [`Rate`].
    #[must_use]
    pub const fn rate(&self) -> Rate {
        self.rate
    }

    /// The configured burst capacity.
    #[must_use]
    pub const fn burst(&self) -> u64 {
        self.burst
    }

    /// Try to spend `n` units at monotonic instant `now` (nanoseconds,
    /// caller's clock).
    ///
    /// - [`Acquire::Granted`]: the units were spent.
    /// - [`Acquire::RetryAt`]: nothing was spent; retrying with the
    ///   returned instant (and an otherwise untouched bucket) is
    ///   guaranteed to be granted.
    /// - [`Acquire::Never`]: `n` exceeds the burst capacity and can
    ///   never be granted as a single acquisition.
    ///
    /// `n == 0` is always granted. A `now` earlier than a previously
    /// provided instant is treated as no time having passed.
    pub fn try_acquire(&mut self, now: u64, n: u64) -> Acquire {
        if n > self.burst {
            return Acquire::Never;
        }
        self.refill(now);

        let need = n as u128 * self.rate.per_nanos() as u128;
        if self.level_scaled >= need {
            self.level_scaled -= need;
            return Acquire::Granted;
        }

        let deficit = need - self.level_scaled;
        let wait_nanos = deficit.div_ceil(self.rate.units() as u128);
        let retry_at = now.saturating_add(u64::try_from(wait_nanos).unwrap_or(u64::MAX));
        Acquire::RetryAt(retry_at)
    }

    /// Give back up to `n` previously spent units, saturating at the
    /// burst capacity.
    ///
    /// Intended for callers that reserve budget upfront and end up
    /// using less (e.g. a short write).
    pub fn refund(&mut self, n: u64) {
        let scaled = n as u128 * self.rate.per_nanos() as u128;
        self.level_scaled = self
            .level_scaled
            .saturating_add(scaled)
            .min(self.capacity_scaled());
    }

    /// The number of whole units available at monotonic instant `now`
    /// (nanoseconds, caller's clock).
    pub fn available(&mut self, now: u64) -> u64 {
        self.refill(now);
        // level <= capacity_scaled, so this always fits u64
        (self.level_scaled / self.rate.per_nanos() as u128) as u64
    }

    fn refill(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.last_refill);
        if elapsed == 0 {
            return;
        }
        self.level_scaled = self
            .level_scaled
            .saturating_add(elapsed as u128 * self.rate.units() as u128)
            .min(self.capacity_scaled());
        self.last_refill = now;
    }

    fn capacity_scaled(&self) -> u128 {
        Self::capacity_scaled_for(self.rate, self.burst)
    }

    fn capacity_scaled_for(rate: Rate, burst: u64) -> u128 {
        burst as u128 * rate.per_nanos() as u128
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn starts_full_and_drains() {
        let mut bucket = TokenBucket::from_rate(Rate::per_sec(10));
        assert_eq!(bucket.burst(), 10);
        for _ in 0..10 {
            assert_eq!(bucket.try_acquire(0, 1), Acquire::Granted);
        }
        assert_eq!(bucket.try_acquire(0, 1), Acquire::RetryAt(SEC / 10));
    }

    #[test]
    fn retry_at_is_exact() {
        let mut bucket = TokenBucket::from_rate(Rate::per_sec(10));
        assert_eq!(bucket.try_acquire(0, 10), Acquire::Granted);

        let at = match bucket.try_acquire(0, 3) {
            Acquire::RetryAt(at) => at,
            other => panic!("expected retry-at, got {other:?}"),
        };
        assert_eq!(at, 3 * SEC / 10);
        // one nano earlier: still denied
        assert!(matches!(
            bucket.try_acquire(at - 1, 3),
            Acquire::RetryAt(again) if again == at
        ));
        // at the advertised instant: granted
        assert_eq!(bucket.try_acquire(at, 3), Acquire::Granted);
    }

    #[test]
    fn burst_capacity_is_a_hard_cap() {
        let mut bucket = TokenBucket::new(Rate::per_sec(10), 4);
        assert_eq!(bucket.try_acquire(0, 5), Acquire::Never);
        // even after any amount of time
        assert_eq!(bucket.try_acquire(100 * SEC, 5), Acquire::Never);
        assert_eq!(bucket.try_acquire(100 * SEC, 4), Acquire::Granted);
    }

    #[test]
    fn zero_units_always_granted() {
        let mut bucket = TokenBucket::new(Rate::per_sec(1), 1);
        assert_eq!(bucket.try_acquire(0, 1), Acquire::Granted);
        assert_eq!(bucket.try_acquire(0, 0), Acquire::Granted);
    }

    #[test]
    fn available_tracks_partial_refill() {
        let mut bucket = TokenBucket::from_rate(Rate::per_sec(10));
        assert_eq!(bucket.available(0), 10);
        assert_eq!(bucket.try_acquire(0, 10), Acquire::Granted);
        assert_eq!(bucket.available(0), 0);
        assert_eq!(bucket.available(550_000_000), 5);
        assert_eq!(bucket.available(SEC), 10);
        // never above burst
        assert_eq!(bucket.available(100 * SEC), 10);
    }

    #[test]
    fn refund_saturates_at_capacity() {
        let mut bucket = TokenBucket::from_rate(Rate::per_sec(10));
        assert_eq!(bucket.try_acquire(0, 3), Acquire::Granted);
        assert_eq!(bucket.available(0), 7);
        bucket.refund(2);
        assert_eq!(bucket.available(0), 9);
        bucket.refund(100);
        assert_eq!(bucket.available(0), 10);
    }

    #[test]
    fn fractional_refill_has_no_drift() {
        // 3 units per second: one unit refills every 333_333_333.33.. ns;
        // over 3 units the total must be exactly one second, not 3 * ceil.
        let mut bucket = TokenBucket::from_rate(Rate::per_sec(3));
        assert_eq!(bucket.try_acquire(0, 3), Acquire::Granted);

        let mut now = 0;
        for i in 1..=3 {
            let at = match bucket.try_acquire(now, 1) {
                Acquire::RetryAt(at) => at,
                other => panic!("expected retry-at, got {other:?}"),
            };
            assert_eq!(at, (i * SEC as u128).div_ceil(3) as u64);
            assert_eq!(bucket.try_acquire(at, 1), Acquire::Granted);
            now = at;
        }
        // after spending 3 units the bucket refills the last one at exactly 1s ...
        assert_eq!(now, SEC);
        // ... with zero accumulated drift for the next round
        assert_eq!(
            bucket.try_acquire(now, 1),
            Acquire::RetryAt(now + SEC / 3 + 1)
        );
    }

    #[test]
    fn time_regression_is_ignored() {
        let mut bucket = TokenBucket::from_rate(Rate::per_sec(10));
        assert_eq!(bucket.try_acquire(SEC, 10), Acquire::Granted);
        // clock goes backwards: no refill, no panic
        assert_eq!(bucket.available(0), 0);
        assert!(matches!(bucket.try_acquire(0, 1), Acquire::RetryAt(_)));
    }

    #[test]
    fn sub_second_period() {
        let mut bucket = TokenBucket::from_rate(Rate::new(5, Duration::from_millis(100)));
        assert_eq!(bucket.try_acquire(0, 5), Acquire::Granted);
        assert_eq!(bucket.try_acquire(0, 5), Acquire::RetryAt(100_000_000));
        assert_eq!(bucket.try_acquire(100_000_000, 5), Acquire::Granted);
    }

    #[test]
    #[should_panic(expected = "burst must be non-zero")]
    fn zero_burst_panics() {
        assert_eq!(TokenBucket::new(Rate::per_sec(1), 0).burst(), 0);
    }

    mod properties {
        use super::*;
        use quickcheck::{Arbitrary, Gen, quickcheck};

        #[derive(Debug, Clone, Copy)]
        struct Op {
            advance_nanos: u32,
            n: u16,
        }

        impl Arbitrary for Op {
            fn arbitrary(g: &mut Gen) -> Self {
                Self {
                    advance_nanos: u32::arbitrary(g),
                    n: u16::arbitrary(g),
                }
            }
        }

        quickcheck! {
            /// total grants over any run never exceed burst + rate * elapsed
            fn never_exceeds_rate(units: u64, per_millis: u16, burst: u16, ops: Vec<Op>) -> bool {
                let units = units % 1_000 + 1;
                let per = Duration::from_millis(u64::from(per_millis) + 1);
                let burst = u64::from(burst) + 1;
                let rate = Rate::new(units, per);
                let mut bucket = TokenBucket::new(rate, burst);

                let mut now = 0u64;
                let mut granted = 0u128;
                for op in ops {
                    now = now.saturating_add(u64::from(op.advance_nanos));
                    let n = u64::from(op.n) % (burst + 1);
                    if bucket.try_acquire(now, n) == Acquire::Granted {
                        granted += u128::from(n);
                    }
                }

                let budget_scaled =
                    u128::from(burst) * u128::from(rate.per_nanos())
                    + u128::from(now) * u128::from(units);
                granted * u128::from(rate.per_nanos()) <= budget_scaled
            }

            /// a denied acquire is granted exactly at the advertised instant,
            /// and denied one nanosecond before it
            fn retry_at_is_tight(units: u64, per_millis: u16, burst: u16, drain: u16, n: u16) -> bool {
                let units = units % 1_000 + 1;
                let per = Duration::from_millis(u64::from(per_millis) + 1);
                let burst = u64::from(burst) + 1;
                let mut bucket = TokenBucket::new(Rate::new(units, per), burst);

                let _ = bucket.try_acquire(0, u64::from(drain) % (burst + 1));
                let n = u64::from(n) % burst + 1;
                match bucket.try_acquire(0, n) {
                    Acquire::Granted | Acquire::Never => true,
                    Acquire::RetryAt(at) => {
                        let denied_before = at == 0
                            || matches!(bucket.clone().try_acquire(at - 1, n), Acquire::RetryAt(_));
                        let granted_at = bucket.try_acquire(at, n) == Acquire::Granted;
                        denied_before && granted_at
                    }
                }
            }

            /// available() never exceeds burst, and refund() cannot lift it above
            fn available_bounded_by_burst(units: u64, burst: u16, now: u64, refund: u64) -> bool {
                let units = units % 1_000 + 1;
                let burst = u64::from(burst) + 1;
                let mut bucket = TokenBucket::new(Rate::per_sec(units), burst);
                bucket.refund(refund);
                bucket.available(now) <= burst
            }
        }
    }
}
