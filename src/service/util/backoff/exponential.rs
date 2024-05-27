use parking_lot::Mutex;
use std::fmt::Display;
use std::time::Duration;
use tokio::time;

use crate::service::util::rng::{HasherRng, Rng};

use super::Backoff;

/// A jittered [exponential backoff] strategy.
///
/// The backoff duration will increase exponentially for every subsequent
/// backoff, up to a maximum duration. A small amount of [random jitter] is
/// added to each backoff duration, in order to avoid retry spikes.
///
/// [exponential backoff]: https://en.wikipedia.org/wiki/Exponential_backoff
/// [random jitter]: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
#[derive(Debug)]
pub struct ExponentialBackoff<F, R = HasherRng> {
    min: time::Duration,
    max: time::Duration,
    jitter: f64,
    rng_creator: F,
    state: Mutex<ExponentialBackoffState<R>>,
}

impl<F, R> Clone for ExponentialBackoff<F, R>
where
    R: Rng + Clone,
    F: Fn() -> R + Clone,
{
    fn clone(&self) -> Self {
        Self {
            min: self.min,
            max: self.max,
            jitter: self.jitter,
            rng_creator: self.rng_creator.clone(),
            state: Mutex::new(ExponentialBackoffState {
                rng: (self.rng_creator)(),
                iterations: 0,
            }),
        }
    }
}

impl Clone for ExponentialBackoff<(), HasherRng> {
    fn clone(&self) -> Self {
        Self {
            min: self.min,
            max: self.max,
            jitter: self.jitter,
            rng_creator: (),
            state: Mutex::new(ExponentialBackoffState {
                rng: HasherRng::default(),
                iterations: 0,
            }),
        }
    }
}

#[derive(Debug)]
struct ExponentialBackoffState<R = HasherRng> {
    rng: R,
    iterations: u32,
}

impl<F, R> ExponentialBackoff<F, R>
where
    R: Rng + Clone,
    F: Fn() -> R + Clone,
{
    /// Create a new `ExponentialBackoff`.
    ///
    /// # Error
    ///
    /// Returns a config validation error if:
    /// - `min` > `max`
    /// - `max` > 0
    /// - `jitter` >= `0.0`
    /// - `jitter` < `100.0`
    /// - `jitter` is finite
    pub fn new(
        min: time::Duration,
        max: time::Duration,
        jitter: f64,
        rng_creator: F,
    ) -> Result<Self, InvalidBackoff> {
        let rng = rng_creator();
        Self::new_inner(min, max, jitter, rng_creator, rng)
    }
}

impl<F, R> ExponentialBackoff<F, R> {
    fn new_inner(
        min: time::Duration,
        max: time::Duration,
        jitter: f64,
        rng_creator: F,
        rng: R,
    ) -> Result<Self, InvalidBackoff> {
        if min > max {
            return Err(InvalidBackoff("maximum must not be less than minimum"));
        }
        if max == time::Duration::from_millis(0) {
            return Err(InvalidBackoff("maximum must be non-zero"));
        }
        if jitter < 0.0 {
            return Err(InvalidBackoff("jitter must not be negative"));
        }
        if jitter > 100.0 {
            return Err(InvalidBackoff("jitter must not be greater than 100"));
        }
        if !jitter.is_finite() {
            return Err(InvalidBackoff("jitter must be finite"));
        }

        Ok(ExponentialBackoff {
            min,
            max,
            jitter,
            rng_creator,
            state: Mutex::new(ExponentialBackoffState { rng, iterations: 0 }),
        })
    }
}

impl<F, R: Rng> ExponentialBackoff<F, R> {
    fn base(&self) -> time::Duration {
        debug_assert!(
            self.min <= self.max,
            "maximum backoff must not be less than minimum backoff"
        );
        debug_assert!(
            self.max > time::Duration::from_millis(0),
            "Maximum backoff must be non-zero"
        );
        self.min
            .checked_mul(2_u32.saturating_pow(self.state.lock().iterations))
            .unwrap_or(self.max)
            .min(self.max)
    }

    /// Returns a random, uniform duration on `[0, base*self.jitter]` no greater
    /// than `self.max`.
    fn jitter(&self, base: time::Duration) -> Option<time::Duration> {
        if self.jitter <= 0.0 {
            None
        } else {
            let jitter_factor = self.state.lock().rng.next_f64();
            debug_assert!(
                jitter_factor > 0.0,
                "rng returns values between 0.0 and 1.0"
            );
            let rand_jitter = jitter_factor * self.jitter;
            let secs = (base.as_secs() as f64) * rand_jitter;
            let nanos = (base.subsec_nanos() as f64) * rand_jitter;
            let remaining = self.max - base;
            let result = time::Duration::new(secs as u64, nanos as u32);
            if remaining.is_zero() || result.is_zero() {
                None
            } else {
                Some(result.min(remaining))
            }
        }
    }
}

impl<F, R> Backoff for ExponentialBackoff<F, R>
where
    R: Rng,
    F: Send + Sync + 'static,
{
    async fn next_backoff(&self) -> bool {
        let base = self.base();
        let jitter = match self.jitter(base) {
            Some(jitter) => jitter,
            None => {
                self.reset().await;
                return false;
            }
        };

        let next = base + jitter;

        self.state.lock().iterations += 1;

        tokio::time::sleep(next).await;
        true
    }

    async fn reset(&self) {
        self.state.lock().iterations = 0;
    }
}

impl Default for ExponentialBackoff<(), HasherRng> {
    fn default() -> Self {
        ExponentialBackoff::new_inner(
            Duration::from_millis(50),
            Duration::from_secs(3),
            0.99,
            (),
            HasherRng::default(),
        )
        .expect("Unable to create ExponentialBackoff")
    }
}

/// Backoff validation error.
#[derive(Debug)]
pub struct InvalidBackoff(&'static str);

impl Display for InvalidBackoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid backoff: {}", self.0)
    }
}

impl std::error::Error for InvalidBackoff {}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    #[tokio::test]
    async fn backoff_default() {
        let backoff = ExponentialBackoff::default();
        assert!(backoff.next_backoff().await);
    }

    #[tokio::test]
    async fn backoff_reset() {
        let backoff = ExponentialBackoff::default();
        assert!(backoff.next_backoff().await);
        assert!(backoff.state.lock().iterations == 1);
        backoff.reset().await;
        assert!(backoff.state.lock().iterations == 0);
    }

    #[tokio::test]
    async fn backoff_clone() {
        let backoff = ExponentialBackoff::default();

        assert!(backoff.state.lock().iterations == 0);
        assert!(backoff.next_backoff().await);
        assert!(backoff.state.lock().iterations == 1);

        let cloned = backoff.clone();
        assert!(cloned.state.lock().iterations == 0);
        assert!(backoff.state.lock().iterations == 1);

        assert!(cloned.next_backoff().await);
        assert!(cloned.state.lock().iterations == 1);
        assert!(backoff.state.lock().iterations == 1);
    }

    quickcheck! {
        fn backoff_base_first(min_ms: u64, max_ms: u64) -> TestResult {
            let min = time::Duration::from_millis(min_ms);
            let max = time::Duration::from_millis(max_ms);
            let backoff = match ExponentialBackoff::new(min, max, 0.0, HasherRng::default) {
                Err(_) => return TestResult::discard(),
                Ok(backoff) => backoff,
            };

            let delay = backoff.base();
            TestResult::from_bool(min == delay)
        }

        fn backoff_base(min_ms: u64, max_ms: u64, iterations: u32) -> TestResult {
            let min = time::Duration::from_millis(min_ms);
            let max = time::Duration::from_millis(max_ms);
            let backoff = match ExponentialBackoff::new(min, max, 0.0, HasherRng::default) {
                Err(_) => return TestResult::discard(),
                Ok(backoff) => backoff,
            };

            backoff.state.lock().iterations = iterations;
            let delay = backoff.base();
            TestResult::from_bool(min <= delay && delay <= max)
        }

        fn backoff_jitter(base_ms: u64, max_ms: u64, jitter: f64) -> TestResult {
            let base = time::Duration::from_millis(base_ms);
            let max = time::Duration::from_millis(max_ms);
            let backoff = match ExponentialBackoff::new(base, max, jitter, HasherRng::default) {
                Err(_) => return TestResult::discard(),
                Ok(backoff) => backoff,
            };

            let j = backoff.jitter(base);
            if jitter == 0.0 || base_ms == 0 || max_ms == base_ms {
                TestResult::from_bool(j.is_none())
            } else {
                TestResult::from_bool(j.is_some())
            }
        }
    }
}
