//! Time utilities providing a high-performance, cached wall clock.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
    static STATE: OnceLock<State> = OnceLock::new();
    STATE.get_or_init(State::init).now_unix_ms()
}

/// Returns a rotating index in range `0..len` derived from current unix ms time.
pub fn time_modulo_index(len: usize) -> usize {
    if len == 0 {
        return 0;
    }

    // Cast to u64 makes pre-epoch values wrap in a stable way for modulo.
    (now_unix_ms() as u64 % len as u64) as usize
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
    fn test_modulo_bounds() {
        for len in 1..50 {
            assert!(time_modulo_index(len) < len);
        }
    }
}
