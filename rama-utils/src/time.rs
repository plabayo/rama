//! Time utilities providing a high-performance, cached wall clock.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Frequency at which we resync the cached wall clock with the system clock.
const RESYNC_EVERY_MS: u64 = 60 * 60 * 1000;

struct State {
    start_instant: Instant,
    /// The "skew" is the difference: (SystemTime_ms - Instant_elapsed_ms).
    /// By storing this in a single atomic, we ensure readers always see a
    /// consistent snapshot of the clock relationship.
    skew_ms: AtomicI64,
    last_resync_elapsed_ms: AtomicU64,
}

impl State {
    fn init() -> Self {
        let start_instant = Instant::now();
        let unix_ms = unix_timestamp_millis_slow();

        Self {
            start_instant,
            // At t=0, skew is just the current unix time.
            skew_ms: AtomicI64::new(unix_ms),
            last_resync_elapsed_ms: AtomicU64::new(0),
        }
    }

    #[inline]
    fn elapsed_ms_now(&self) -> u64 {
        self.start_instant.elapsed().as_millis() as u64
    }

    fn maybe_resync(&self, elapsed_now_ms: u64) {
        let last = self.last_resync_elapsed_ms.load(Ordering::Relaxed);
        if elapsed_now_ms.saturating_sub(last) < RESYNC_EVERY_MS {
            return;
        }

        // Atomically claim the resync task to avoid multiple threads
        // calling the system clock simultaneously.
        if self
            .last_resync_elapsed_ms
            .compare_exchange(last, elapsed_now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let unix_now_ms = unix_timestamp_millis_slow();

        // New skew = Current Wall Clock - Current Monotonic Clock
        let new_skew = unix_now_ms - (elapsed_now_ms as i64);
        self.skew_ms.store(new_skew, Ordering::Relaxed);
    }

    fn now_unix_ms(&self) -> i64 {
        let elapsed_now_ms = self.elapsed_ms_now();
        self.maybe_resync(elapsed_now_ms);

        // Current Unix = Current Monotonic + Skew
        let skew = self.skew_ms.load(Ordering::Relaxed);
        (elapsed_now_ms as i64) + skew
    }
}

/// Returns the current unix timestamp in milliseconds by reading the system clock.
pub fn unix_timestamp_millis() -> i64 {
    unix_timestamp_millis_slow()
}

fn unix_timestamp_millis_slow() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

/// Returns an approximate unix timestamp in milliseconds.
/// Optimized for high-frequency calls; resyncs with system clock hourly.
pub fn now_unix_ms() -> i64 {
    static STATE: OnceLock<State> = OnceLock::new();
    STATE.get_or_init(State::init).now_unix_ms()
}

/// Returns a rotating index in range 0..len derived from current unix ms time.
pub fn rotime_modulo_index(len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    // Bit-casting i64 to u64 handles negative timestamps (pre-1970) correctly for modulo.
    (now_unix_ms() as u64 % len as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    #[test]
    fn test_progression() {
        let a = now_unix_ms();
        thread::sleep(Duration::from_millis(10));
        let b = now_unix_ms();
        assert!(b >= a + 10);
    }

    #[test]
    fn now_unix_ms_is_close_to_system_clock() {
        let sys = unix_timestamp_millis();
        let approx = now_unix_ms();
        let diff = (sys - approx).abs();
        assert!(diff <= 1_000);
    }

    #[test]
    fn test_consistency_under_resync() {
        let state = State::init();

        // Simulate a massive clock jump forward in the system clock
        let elapsed = state.elapsed_ms_now();
        state.last_resync_elapsed_ms.store(0, Ordering::Relaxed); // force resync

        // This simulates what happens inside maybe_resync
        let manual_unix_jump = unix_timestamp_millis_slow() + 100_000;
        state
            .skew_ms
            .store(manual_unix_jump - (elapsed as i64), Ordering::Relaxed);

        let now = state.now_unix_ms();
        // Ensure the calculation is consistent
        assert!(now >= manual_unix_jump);
    }

    #[test]
    fn modulo_index_zero_len() {
        assert_eq!(rotime_modulo_index(0), 0);
    }

    #[test]
    fn test_modulo_bounds() {
        for i in 1..50 {
            assert!(rotime_modulo_index(i) < i);
        }
    }
}
