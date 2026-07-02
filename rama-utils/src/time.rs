//! Time utilities providing a high-performance, cached wall clock.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

/// Frequency at which we resync the cached wall clock with the system clock.
const RESYNC_EVERY_MS: u64 = 60 * 60 * 1000;

struct State {
    start_instant: Instant,

    /// Difference between wall clock unix ms and monotonic elapsed ms.
    ///
    /// Stored in a single atomic so readers observe a consistent snapshot.
    skew_ms: AtomicI64,

    /// Next eligible resync time expressed as elapsed ms since `start_instant`.
    next_resync_elapsed_ms: AtomicU64,
}

static STATE: LazyLock<State> = LazyLock::new(State::init);

impl State {
    fn init() -> Self {
        let start_instant = Instant::now();
        let unix_ms = unix_timestamp_millis_slow();
        Self {
            start_instant,
            skew_ms: AtomicI64::new(unix_ms),
            next_resync_elapsed_ms: AtomicU64::new(RESYNC_EVERY_MS),
        }
    }

    #[inline]
    fn elapsed_ms_now(&self) -> u64 {
        self.start_instant.elapsed().as_millis() as u64
    }

    #[inline]
    fn elapsed_nanos(&self) -> u64 {
        self.start_instant.elapsed().as_nanos() as u64
    }

    #[inline]
    fn instant_from_nanos(&self, nanos: u64) -> Instant {
        self.start_instant + Duration::from_nanos(nanos)
    }

    fn maybe_resync(&self, elapsed_now_ms: u64) {
        let next = self.next_resync_elapsed_ms.load(Ordering::Relaxed);
        if elapsed_now_ms < next {
            return;
        }

        let new_next = elapsed_now_ms.saturating_add(RESYNC_EVERY_MS);

        // Best effort. If multiple threads race, only one wins the right to resync.
        if self
            .next_resync_elapsed_ms
            .compare_exchange(next, new_next, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let unix_now_ms = unix_timestamp_millis_slow();
        let new_skew = unix_now_ms - elapsed_now_ms as i64;
        self.skew_ms.store(new_skew, Ordering::Relaxed);
    }

    fn now_unix_ms(&self) -> i64 {
        let elapsed_now_ms = self.elapsed_ms_now();
        self.maybe_resync(elapsed_now_ms);

        let skew = self.skew_ms.load(Ordering::Relaxed);
        elapsed_now_ms as i64 + skew
    }
}

#[inline(always)]
/// Returns the current unix timestamp in milliseconds by reading the system clock.
pub fn unix_timestamp_millis() -> i64 {
    unix_timestamp_millis_slow()
}

fn unix_timestamp_millis_slow() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis().try_into().unwrap_or(i64::MAX),
        Err(e) => {
            let ms: i64 = e.duration().as_millis().try_into().unwrap_or(i64::MAX);
            -ms
        }
    }
}

/// Returns an approximate unix timestamp in milliseconds.
///
/// Optimized for high-frequency calls. The underlying wall clock skew is refreshed
/// roughly once per hour.
pub fn now_unix_ms() -> i64 {
    STATE.now_unix_ms()
}

/// Returns monotonic nanoseconds elapsed since a fixed process epoch.
///
/// Suitable for cheap, lock-free recency/ordering comparisons (e.g. via
/// [`AtomicInstant`]). This is not wall-clock time; use [`now_unix_ms`] for that.
#[must_use]
pub fn now_monotonic_nanos() -> u64 {
    STATE.elapsed_nanos()
}

#[inline]
/// Returns an approximate unix timestamp in seconds.
///
/// Optimized for high-frequency calls. The underlying wall clock skew is refreshed
/// roughly once per hour.
pub fn now_unix() -> i64 {
    // floor-division so that 999 ms -> 0 s, -1 ms -> -1 s; matches the unix-seconds
    // contract `floor(ms/1000)` even for pre-epoch (negative) timestamps.
    now_unix_ms().div_euclid(1000)
}

#[inline]
/// Returns an approximate system time using approximate unix timestamp.
///
/// Optimized for high-frequency calls. The underlying wall clock skew is refreshed
/// roughly once per hour.
pub fn now_system_time() -> SystemTime {
    let ms = now_unix_ms();
    let epoch = SystemTime::UNIX_EPOCH;
    let elapsed_since_epoch = Duration::from_millis(ms.wrapping_abs() as u64);
    if ms >= 0 {
        epoch + elapsed_since_epoch
    } else {
        epoch - elapsed_since_epoch
    }
}

/// Returns a rotating index in range `0..len` derived from current unix ms time.
pub fn time_modulo_index(len: usize) -> usize {
    if len == 0 {
        return 0;
    }

    // Cast to u64 makes pre-epoch values wrap in a stable way for modulo.
    (now_unix_ms() as u64 % len as u64) as usize
}

/// A monotonic instant stored in a single [`AtomicU64`] as nanoseconds since a
/// shared process epoch (see [`now_monotonic_nanos`]).
///
/// Lock-free to read and update, useful for recency tracking (e.g. "least
/// recently used") without a `Mutex<Instant>`. Reads/writes use relaxed
/// ordering, so it is a heuristic timestamp, not a synchronization point.
#[derive(Debug)]
pub struct AtomicInstant(AtomicU64);

impl AtomicInstant {
    /// Create an [`AtomicInstant`] set to now.
    #[must_use]
    pub fn now() -> Self {
        Self(AtomicU64::new(now_monotonic_nanos()))
    }

    /// Set this instant to now.
    pub fn set_now(&self) {
        self.0.store(now_monotonic_nanos(), Ordering::Relaxed);
    }

    /// Nanoseconds since the shared epoch, for cheap ordering comparisons.
    #[must_use]
    pub fn as_nanos(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Duration elapsed since this instant (zero if it is in the future).
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        Duration::from_nanos(now_monotonic_nanos().saturating_sub(self.as_nanos()))
    }

    /// Convert back to a real [`Instant`].
    #[must_use]
    pub fn to_instant(&self) -> Instant {
        STATE.instant_from_nanos(self.as_nanos())
    }
}

impl Default for AtomicInstant {
    fn default() -> Self {
        Self::now()
    }
}

impl From<&AtomicInstant> for Instant {
    fn from(value: &AtomicInstant) -> Self {
        value.to_instant()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    #[test]
    fn test_progression_non_decreasing() {
        let a = now_unix_ms();
        thread::sleep(Duration::from_millis(2));
        let b = now_unix_ms();
        assert!(b >= a);
    }

    #[test]
    fn now_unix_ms_is_close_to_system_clock() {
        let sys = unix_timestamp_millis();
        let approx = now_unix_ms();
        let diff = (sys - approx).abs();
        assert!(diff <= 1_000);
    }

    #[test]
    fn test_skew_math() {
        let state = State::init();
        let elapsed = state.elapsed_ms_now();

        // Force an artificial skew and verify the formula.
        let target_unix = unix_timestamp_millis_slow() + 1234;
        state
            .skew_ms
            .store(target_unix - elapsed as i64, Ordering::Relaxed);

        let now = state.now_unix_ms();
        assert!(now >= target_unix);
    }

    #[test]
    fn modulo_index_zero_len() {
        assert_eq!(time_modulo_index(0), 0);
    }

    #[test]
    fn atomic_instant_roundtrip_and_elapsed() {
        let t = AtomicInstant::now();
        thread::sleep(Duration::from_millis(5));
        assert!(t.elapsed() >= Duration::from_millis(5));

        // ordering: a later instant has a larger nanos value
        let later = AtomicInstant::now();
        assert!(later.as_nanos() > t.as_nanos());

        // converting back to an Instant agrees with the original epoch math
        let recovered = t.to_instant();
        assert!(recovered.elapsed() >= Duration::from_millis(5));

        // set_now advances it
        let before = t.as_nanos();
        thread::sleep(Duration::from_millis(1));
        t.set_now();
        assert!(t.as_nanos() > before);
    }

    #[test]
    fn now_unix_floor_division() {
        // Sanity: now_unix must equal floor(now_unix_ms / 1000) and must not exceed
        // the system clock's seconds value at the call site.
        let sys_s = unix_timestamp_millis() / 1000;
        let approx_s = now_unix();
        let ms = now_unix_ms();
        assert_eq!(approx_s, ms.div_euclid(1000));
        // Allow a small drift either way (cached clock).
        assert!((sys_s - approx_s).abs() <= 1);
    }

    #[test]
    fn test_modulo_bounds() {
        for len in 1..50 {
            assert!(time_modulo_index(len) < len);
        }
    }
}
