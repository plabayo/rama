use core::fmt;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::time::Duration;

use ahash::{HashMap, HashMapExt as _};
use parking_lot::Mutex;
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
/// Inputs without a derivable key are allowed through by default. This is
/// convenient for stacks where the key is genuinely optional, but is
/// fail-open when the extractor depends on missing metadata; security limits
/// should set [`KeyedRatePolicy::set_missing_key_allowed`] to `false` and
/// abort them with [`MissingRateKey`] instead.
///
/// Memory is bounded: at most [`KeyedRatePolicy::set_max_keys`] buckets
/// are kept, and buckets idle longer than
/// [`KeyedRatePolicy::set_idle_timeout`] are evicted. The idle timeout is
/// clamped to the time it takes to refill the configured burst from empty,
/// so a bucket evicted for *idleness* and recreated full cannot regain
/// budget any faster than one that stayed cached.
///
/// A new key is rejected with [`RateKeyCapacityReached`] while `max_keys`
/// non-idle buckets are live. Live buckets are never evicted to admit another
/// key, because recreating an exhausted bucket full would let callers bypass
/// the rate limit by cycling keys at the memory bound.
///
/// Size `max_keys` for the number of simultaneously active keys after
/// aggregation. The default IPv6 `/64` aggregation means one routed `/48`
/// can still fill the default 65 536-key capacity; deployments serving larger
/// IPv6 populations can aggregate more broadly with
/// [`ClientIpRateKey::set_ipv6_prefix`](super::ClientIpRateKey::set_ipv6_prefix)
/// and/or raise this bound.
pub struct KeyedRatePolicy<X, K> {
    extractor: X,
    rate: Rate,
    burst: u64,
    mode: Mode,
    missing_key_allowed: bool,
    max_keys: u64,
    idle_timeout: Duration,
    buckets: BucketCache<K>,
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
    /// given per-key [`Rate`]. A known key waits rather than failing when its
    /// bucket is empty; a new key can still fail closed when the configured
    /// key capacity is exhausted.
    pub fn wait(extractor: X, rate: Rate) -> Self {
        Self::new(extractor, rate, Mode::Wait)
    }

    /// Create a new [`KeyedRatePolicy`] that aborts inputs beyond the
    /// given per-key [`Rate`] with [`RateLimitReached`].
    pub fn abort(extractor: X, rate: Rate) -> Self {
        Self::new(extractor, rate, Mode::Abort)
    }

    fn new(extractor: X, rate: Rate, mode: Mode) -> Self {
        let burst = rate.units();
        Self {
            extractor,
            rate,
            burst,
            mode,
            missing_key_allowed: true,
            max_keys: DEFAULT_MAX_KEYS,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            buckets: BucketCache::new(
                DEFAULT_MAX_KEYS,
                DEFAULT_IDLE_TIMEOUT.max(full_refill_time(rate, burst)),
                rate,
                burst,
            ),
        }
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
        /// Bound the number of tracked keys (default: 65 536). When all
        /// tracked buckets are still active, a new key is rejected with
        /// [`RateKeyCapacityReached`] instead of evicting a live bucket and
        /// resetting its budget.
        ///
        /// This is an availability bound as well as a memory bound. With the
        /// default IPv6 `/64` keys, one `/48` contains 65 536 distinct keys.
        /// Aggregate more broadly or raise this value when that is a realistic
        /// share of the expected active client population.
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
        self.buckets = BucketCache::new(
            self.max_keys,
            self.idle_timeout
                .max(full_refill_time(self.rate, self.burst)),
            self.rate,
            self.burst,
        );
    }

    fn limiter(&self, key: K) -> Result<Arc<RateLimiter>, RateKeyCapacityReached> {
        self.buckets.get_or_insert(key)
    }
}

struct BucketCache<K> {
    state: Mutex<BucketCacheState<K>>,
    max_keys: u64,
    idle_timeout: Duration,
    rate: Rate,
    burst: u64,
}

struct BucketCacheState<K> {
    entries: HashMap<K, BucketEntry>,
    expirations: BinaryHeap<Expiration<K>>,
}

struct BucketEntry {
    limiter: Arc<RateLimiter>,
    last_used: tokio::time::Instant,
}

struct Expiration<K> {
    at: tokio::time::Instant,
    key: K,
}

impl<K> PartialEq for Expiration<K> {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
    }
}

impl<K> Eq for Expiration<K> {}

impl<K> PartialOrd for Expiration<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for Expiration<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse chronological order makes BinaryHeap a min-heap.
        other.at.cmp(&self.at)
    }
}

impl<K> BucketCache<K>
where
    K: super::RateKey,
{
    fn new(max_keys: u64, idle_timeout: Duration, rate: Rate, burst: u64) -> Self {
        Self {
            state: Mutex::new(BucketCacheState {
                entries: HashMap::new(),
                expirations: BinaryHeap::new(),
            }),
            max_keys,
            idle_timeout,
            rate,
            burst,
        }
    }

    fn get_or_insert(&self, key: K) -> Result<Arc<RateLimiter>, RateKeyCapacityReached> {
        let now = tokio::time::Instant::now();
        let mut state = self.state.lock();

        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = now;
            return Ok(entry.limiter.clone());
        }
        // Cleanup is only relevant when a new key arrives. Keeping the hot
        // existing-key path independent of the number of simultaneously
        // expired entries avoids a periodic O(max_keys) latency spike.
        self.expire_idle(&mut state, now);
        if state.entries.len() as u64 >= self.max_keys {
            return Err(RateKeyCapacityReached);
        }

        let limiter = Arc::new(RateLimiter::new(self.rate, self.burst));
        state.entries.insert(
            key.clone(),
            BucketEntry {
                limiter: limiter.clone(),
                last_used: now,
            },
        );
        state.expirations.push(Expiration {
            at: expiration_at(now, self.idle_timeout),
            key,
        });
        Ok(limiter)
    }

    fn expire_idle(&self, state: &mut BucketCacheState<K>, now: tokio::time::Instant) {
        while state
            .expirations
            .peek()
            .is_some_and(|expiry| expiry.at <= now)
        {
            let Some(expiry) = state.expirations.pop() else {
                break;
            };
            let Some((last_used, in_use)) = state
                .entries
                .get(&expiry.key)
                .map(|entry| (entry.last_used, Arc::strong_count(&entry.limiter) > 1))
            else {
                continue;
            };
            if in_use {
                state.expirations.push(Expiration {
                    at: expiration_at(now, self.idle_timeout),
                    key: expiry.key,
                });
                continue;
            }
            match expiration_at(last_used, self.idle_timeout) {
                at if at > now => state.expirations.push(Expiration {
                    at,
                    key: expiry.key,
                }),
                _ => {
                    state.entries.remove(&expiry.key);
                }
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state.lock().entries.len()
    }
}

/// Add even a platform-unrepresentable timeout without dropping the cache
/// entry from the expiration index. Only such extreme values are shortened.
fn expiration_at(now: tokio::time::Instant, mut timeout: Duration) -> tokio::time::Instant {
    loop {
        if let Some(at) = now.checked_add(timeout) {
            return at;
        }
        timeout /= 2;
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

rama_utils::macros::error::static_str_error! {
    #[doc = "serve aborted: the keyed rate-limit capacity is occupied by active keys"]
    pub struct RateKeyCapacityReached;
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

        let limiter = match self.limiter(key) {
            Ok(limiter) => limiter,
            Err(err) => {
                return PolicyResult {
                    input,
                    output: PolicyOutput::Abort(err.into()),
                };
            }
        };
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

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "InputToRateKey extractors receive a reference"
    )]
    fn u64_key(value: &u64) -> Result<Option<u64>, BoxError> {
        Ok(Some(*value))
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
    fn unrepresentable_idle_timeout_stays_in_the_expiration_index() {
        let buckets = BucketCache::<u64>::new(1, Duration::MAX, Rate::per_sec(1), 1);
        let _limiter = buckets.get_or_insert(1).expect("insert bucket");
        assert_eq!(buckets.state.lock().expirations.len(), 1);
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
    async fn capacity_rejects_new_keys_without_resetting_live_buckets() {
        let policy = KeyedRatePolicy::abort(u64_key, Rate::per_sec(1)).with_max_keys(1);

        assert_ready(policy.check(1).await);
        assert!(
            assert_abort(policy.check(1).await)
                .downcast_ref::<RateLimitReached>()
                .is_some()
        );

        let err = assert_abort(policy.check(2).await);
        assert!(err.downcast_ref::<RateKeyCapacityReached>().is_some());

        assert!(
            assert_abort(policy.check(1).await)
                .downcast_ref::<RateLimitReached>()
                .is_some(),
            "refusing key 2 must not reset key 1",
        );
        assert_eq!(policy.buckets.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn fully_refilled_idle_bucket_makes_room_for_a_new_key() {
        let policy = KeyedRatePolicy::abort(u64_key, Rate::per_sec(1))
            .with_max_keys(1)
            .with_idle_timeout(Duration::ZERO);

        assert_ready(policy.check(1).await);
        assert!(
            assert_abort(policy.check(2).await)
                .downcast_ref::<RateKeyCapacityReached>()
                .is_some()
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_ready(policy.check(2).await);
        assert_eq!(policy.buckets.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiting_acquisition_keeps_its_bucket_live() {
        let policy = Arc::new(
            KeyedRatePolicy::wait(u64_key, Rate::per_sec(1))
                .with_max_keys(1)
                .with_idle_timeout(Duration::ZERO),
        );

        assert_ready(policy.check(1).await);
        let first = {
            let policy = policy.clone();
            tokio::spawn(async move { policy.check(1).await })
        };
        let second = {
            let policy = policy.clone();
            tokio::spawn(async move { policy.check(1).await })
        };
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            assert_abort(policy.check(2).await)
                .downcast_ref::<RateKeyCapacityReached>()
                .is_some(),
            "a bucket with an active waiter must not be evicted",
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_ready(first.await.unwrap());
        assert_ready(second.await.unwrap());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_ready(policy.check(2).await);
    }
}
