use core::fmt;
use std::time::Duration;

use rama_core::error::{BoxError, ErrorExt as _};
use rama_core::layer::limit::policy::{Policy, PolicyOutput, PolicyResult, RateLimitReached};
use rama_utils::rate::{Acquire, Rate, RateLimiter};

use super::InputToRateKey;

/// A limit [`Policy`] that rate limits inputs *per key*: every key gets
/// its own token bucket, lazily created on first use and stored in a
/// bounded, idle-evicting cache.
///
/// The typical use is per-client fairness, keying on the client IP with
/// [`ClientIpRateKey`](super::ClientIpRateKey); any
/// [`InputToRateKey`] extractor (including plain closures) works.
///
/// Modes mirror [`RatePolicy`](rama_core::layer::limit::policy::RatePolicy):
/// [`KeyedRatePolicy::abort`] rejects over-budget inputs with
/// [`RateLimitReached`] (a 429 path), [`KeyedRatePolicy::wait`] paces them.
/// Inputs without a derivable key are allowed through by default; use
/// [`KeyedRatePolicy::set_missing_key_allowed`] to abort them with
/// [`MissingRateKey`] instead.
///
/// Memory is bounded: at most [`KeyedRatePolicy::set_max_keys`] buckets
/// are kept, and buckets idle longer than
/// [`KeyedRatePolicy::set_idle_timeout`] are evicted. The idle timeout is
/// clamped to the time it takes to refill the configured burst from empty,
/// so a bucket evicted for *idleness* and recreated full cannot regain
/// budget any faster than one that stayed cached.
///
/// That guarantee does not extend to *capacity* eviction: once more than
/// `max_keys` keys are live the cache may drop a bucket before it is idle
/// and recreate it full on its next hit, resetting its budget. Size
/// `max_keys` comfortably above the number of distinct keys you expect
/// within one `idle_timeout`, so it stays a memory backstop rather than a
/// routine limit bypass.
pub struct KeyedRatePolicy<X, K> {
    extractor: X,
    rate: Rate,
    burst: u64,
    mode: Mode,
    missing_key_allowed: bool,
    max_keys: u64,
    idle_timeout: Duration,
    buckets: moka::sync::Cache<K, RateLimiter, ahash::RandomState>,
}

impl<X: fmt::Debug, K> fmt::Debug for KeyedRatePolicy<X, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyedRatePolicy")
            .field("extractor", &self.extractor)
            .field("rate", &self.rate)
            .field("burst", &self.burst)
            .field("mode", &self.mode)
            .field("missing_key_allowed", &self.missing_key_allowed)
            .field("max_keys", &self.max_keys)
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Wait,
    Abort,
}

const DEFAULT_MAX_KEYS: u64 = 65_536;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_mins(1);

impl<X, K> KeyedRatePolicy<X, K>
where
    K: super::RateKey,
{
    /// Create a new [`KeyedRatePolicy`] that paces inputs beyond the
    /// given per-key [`Rate`]: they wait, they never fail.
    pub fn wait(extractor: X, rate: Rate) -> Self {
        Self::new(extractor, rate, Mode::Wait)
    }

    /// Create a new [`KeyedRatePolicy`] that aborts inputs beyond the
    /// given per-key [`Rate`] with [`RateLimitReached`].
    pub fn abort(extractor: X, rate: Rate) -> Self {
        Self::new(extractor, rate, Mode::Abort)
    }

    fn new(extractor: X, rate: Rate, mode: Mode) -> Self {
        let mut policy = Self {
            extractor,
            rate,
            burst: rate.units(),
            mode,
            missing_key_allowed: true,
            max_keys: DEFAULT_MAX_KEYS,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            // placeholder, rebuilt right after with the actual config
            buckets: moka::sync::Cache::builder().build_with_hasher(ahash::RandomState::default()),
        };
        policy.rebuild_buckets();
        policy
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override the per-key burst capacity
        /// (default: one period worth of units).
        ///
        /// # Panics
        ///
        /// Panics if `burst` is zero.
        pub fn burst(mut self, burst: u64) -> Self {
            assert!(burst > 0, "KeyedRatePolicy: burst must be non-zero");
            self.burst = burst;
            self.rebuild_buckets();
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Allow (default) or abort — with [`MissingRateKey`] — inputs
        /// for which no key can be derived.
        pub fn missing_key_allowed(mut self, allowed: bool) -> Self {
            self.missing_key_allowed = allowed;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound the number of tracked keys (default: 65 536); beyond it
        /// the cache evicts to stay within the bound (approximately
        /// least-frequently-used, not strict LRU). Eviction recreates a
        /// key's bucket full on its next hit, so keep this well above the
        /// count of concurrently-active keys (see the type-level docs).
        ///
        /// # Panics
        ///
        /// Panics if `max_keys` is zero.
        pub fn max_keys(mut self, max_keys: u64) -> Self {
            assert!(max_keys > 0, "KeyedRatePolicy: max_keys must be non-zero");
            self.max_keys = max_keys;
            self.rebuild_buckets();
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Evict buckets idle for this long (default: 1 minute), clamped
        /// to at least the time required to refill the burst from empty.
        pub fn idle_timeout(mut self, idle_timeout: Duration) -> Self {
            self.idle_timeout = idle_timeout;
            self.rebuild_buckets();
            self
        }
    }

    /// (Re)build the bucket cache; changing storage config
    /// drops all live buckets.
    fn rebuild_buckets(&mut self) {
        self.buckets = moka::sync::Cache::builder()
            .max_capacity(self.max_keys)
            .time_to_idle(
                self.idle_timeout
                    .max(full_refill_time(self.rate, self.burst)),
            )
            .build_with_hasher(ahash::RandomState::default());
    }

    fn limiter(&self, key: K) -> RateLimiter {
        let (rate, burst) = (self.rate, self.burst);
        // coalesced: exactly one bucket is created per key
        self.buckets
            .get_with(key, move || RateLimiter::new(rate, burst))
    }
}

fn full_refill_time(rate: Rate, burst: u64) -> Duration {
    let nanos = u128::from(burst)
        .saturating_mul(rate.per().as_nanos())
        .div_ceil(u128::from(rate.units()))
        .min(Duration::MAX.as_nanos());
    Duration::new(
        (nanos / 1_000_000_000) as u64,
        (nanos % 1_000_000_000) as u32,
    )
}

rama_utils::macros::error::static_str_error! {
    #[doc = "serve aborted: no rate key could be derived for input"]
    pub struct MissingRateKey;
}

impl<X, K, Input> Policy<Input> for KeyedRatePolicy<X, K>
where
    X: InputToRateKey<Input, Key = K>,
    K: super::RateKey,
    Input: Send + 'static,
{
    type Guard = ();
    type Error = BoxError;

    async fn check(&self, input: Input) -> PolicyResult<Input, Self::Guard, Self::Error> {
        let key = match self.extractor.rate_key(&input) {
            Ok(Some(key)) => key,
            Ok(None) => {
                let output = if self.missing_key_allowed {
                    PolicyOutput::Ready(())
                } else {
                    PolicyOutput::Abort(MissingRateKey.into())
                };
                return PolicyResult { input, output };
            }
            Err(err) => {
                return PolicyResult {
                    input,
                    output: PolicyOutput::Abort(err.context("derive rate key")),
                };
            }
        };

        let limiter = self.limiter(key);
        let output = match self.mode {
            Mode::Wait => {
                limiter.acquire(1).await;
                PolicyOutput::Ready(())
            }
            Mode::Abort => match limiter.try_acquire(1) {
                Acquire::Granted => PolicyOutput::Ready(()),
                Acquire::RetryAt(at) => {
                    let retry_after = limiter
                        .deadline(at)
                        .saturating_duration_since(tokio::time::Instant::now());
                    PolicyOutput::Abort(RateLimitReached::new(retry_after).into())
                }
                Acquire::Never => {
                    // defence-in-depth: cost is 1 and burst is non-zero
                    debug_assert!(false, "single unit reported Acquire::Never");
                    PolicyOutput::Abort(RateLimitReached::new(Duration::ZERO).into())
                }
            },
        };
        PolicyResult { input, output }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::{Extensions, ExtensionsRef};
    use std::net::{IpAddr, Ipv4Addr};

    use crate::stream::SocketInfo;

    fn input_for_ip(ip: [u8; 4]) -> Extensions {
        let ext = Extensions::new();
        ext.insert(SocketInfo::new(
            None,
            (IpAddr::V4(Ipv4Addr::from(ip)), 40_000).into(),
        ));
        ext
    }

    fn assert_ready<R, G, E>(result: PolicyResult<R, G, E>) {
        assert!(
            matches!(result.output, PolicyOutput::Ready(_)),
            "unexpected output, expected ready"
        );
        drop(result);
    }

    fn assert_abort<R, G>(result: PolicyResult<R, G, BoxError>) -> BoxError {
        match result.output {
            PolicyOutput::Abort(err) => err,
            PolicyOutput::Ready(_) | PolicyOutput::Retry => {
                panic!("unexpected output, expected abort")
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn per_key_budgets_are_independent() {
        let policy = KeyedRatePolicy::abort(super::super::ClientIpRateKey::new(), Rate::per_sec(1));

        assert_ready(policy.check(input_for_ip([10, 0, 0, 1])).await);
        // same client again: over budget, with a downcastable error
        let err = assert_abort(policy.check(input_for_ip([10, 0, 0, 1])).await);
        assert!(err.downcast_ref::<RateLimitReached>().is_some());

        // a different client has its own bucket
        assert_ready(policy.check(input_for_ip([10, 0, 0, 2])).await);
    }

    #[tokio::test(start_paused = true)]
    async fn refills_per_key() {
        let policy = KeyedRatePolicy::abort(super::super::ClientIpRateKey::new(), Rate::per_sec(2));

        assert_ready(policy.check(input_for_ip([10, 0, 0, 1])).await);
        assert_ready(policy.check(input_for_ip([10, 0, 0, 1])).await);
        assert_abort(policy.check(input_for_ip([10, 0, 0, 1])).await);

        tokio::time::advance(Duration::from_millis(500)).await;
        assert_ready(policy.check(input_for_ip([10, 0, 0, 1])).await);
    }

    #[tokio::test(start_paused = true)]
    async fn missing_key_modes() {
        let allowing =
            KeyedRatePolicy::abort(super::super::ClientIpRateKey::new(), Rate::per_sec(1));
        // no SocketInfo extension: no key
        assert_ready(allowing.check(Extensions::new()).await);
        assert_ready(allowing.check(Extensions::new()).await);

        let strict = KeyedRatePolicy::abort(super::super::ClientIpRateKey::new(), Rate::per_sec(1))
            .with_missing_key_allowed(false);
        let err = assert_abort(strict.check(Extensions::new()).await);
        assert!(err.downcast_ref::<MissingRateKey>().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn closure_extractor() {
        let policy = KeyedRatePolicy::abort(
            |input: &Extensions| {
                Ok(input
                    .extensions()
                    .get_ref::<SocketInfo>()
                    .map(|info| u64::from(info.peer_addr().port)))
            },
            Rate::per_sec(1),
        );

        assert_ready(policy.check(input_for_ip([10, 0, 0, 1])).await);
        assert_abort(policy.check(input_for_ip([10, 0, 0, 1])).await);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_mode_paces_per_key() {
        let policy = KeyedRatePolicy::wait(super::super::ClientIpRateKey::new(), Rate::per_sec(10));

        let start = tokio::time::Instant::now();
        for _ in 0..10 {
            assert_ready(policy.check(input_for_ip([10, 0, 0, 1])).await);
        }
        assert_eq!(start.elapsed(), Duration::ZERO);

        // over budget for .1, but .2 is instant
        assert_ready(policy.check(input_for_ip([10, 0, 0, 2])).await);
        assert_eq!(start.elapsed(), Duration::ZERO);

        assert_ready(policy.check(input_for_ip([10, 0, 0, 1])).await);
        assert_eq!(start.elapsed(), Duration::from_millis(100));
    }

    #[test]
    fn idle_timeout_covers_a_full_burst_refill() {
        assert_eq!(
            full_refill_time(Rate::per_sec(2), 5),
            Duration::from_millis(2_500)
        );
        assert_eq!(
            full_refill_time(Rate::new(3, Duration::from_millis(10)), 1),
            Duration::from_nanos(3_333_334)
        );
    }

    #[test]
    #[should_panic(expected = "burst must be non-zero")]
    fn zero_burst_is_rejected_at_configuration_time() {
        drop(
            KeyedRatePolicy::<_, IpAddr>::abort(
                super::super::ClientIpRateKey::new(),
                Rate::per_sec(1),
            )
            .with_burst(0),
        );
    }

    #[test]
    #[should_panic(expected = "max_keys must be non-zero")]
    fn zero_max_keys_is_rejected_at_configuration_time() {
        drop(
            KeyedRatePolicy::<_, IpAddr>::abort(
                super::super::ClientIpRateKey::new(),
                Rate::per_sec(1),
            )
            .with_max_keys(0),
        );
    }

    #[tokio::test]
    async fn max_keys_bounds_the_bucket_cache() {
        // key on a distinct id per request, then flood far past max_keys
        let policy =
            KeyedRatePolicy::abort(|n: &u64| Ok::<_, BoxError>(Some(*n)), Rate::per_sec(1))
                .with_max_keys(8);

        for k in 0..2_000u64 {
            assert_ready(policy.check(k).await);
        }

        policy.buckets.run_pending_tasks();
        assert!(
            policy.buckets.entry_count() <= 8,
            "cache must stay within max_keys, got {}",
            policy.buckets.entry_count(),
        );
    }
}
