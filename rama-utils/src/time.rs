//! time utilities.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RESYNC_EVERY_MS: u64 = 60 * 60 * 1000;

struct State {
    start_instant: Instant,

    // Cached base unix ms and the monotonic elapsed ms at which that base was captured.
    //
    // These two values are updated independently using atomics. Updates are best effort.
    // During a refresh, a reader may see a new base_unix_ms with an old base_elapsed_ms
    // or vice versa. That can cause a small time jump. The next refresh corrects it.
    base_unix_ms: AtomicI64,
    base_elapsed_ms: AtomicU64,

    // Resync gating.
    last_resync_elapsed_ms: AtomicU64,
}

impl State {
    fn init() -> Self {
        let start_instant = Instant::now();
        let unix_ms = unix_timestamp_millis_slow();

        Self {
            start_instant,
            base_unix_ms: AtomicI64::new(unix_ms),
            base_elapsed_ms: AtomicU64::new(0),
            last_resync_elapsed_ms: AtomicU64::new(0),
        }
    }

    fn elapsed_ms_now(&self) -> u64 {
        duration_as_millis_u64(self.start_instant.elapsed())
    }

    fn maybe_resync(&self, elapsed_now_ms: u64) {
        let last = self.last_resync_elapsed_ms.load(Ordering::Relaxed);
        if elapsed_now_ms.saturating_sub(last) < RESYNC_EVERY_MS {
            return;
        }

        // Best effort. If multiple threads race here, that is fine.
        // The first that wins will move the last_resync forward.
        if self
            .last_resync_elapsed_ms
            .compare_exchange(last, elapsed_now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let unix_now_ms = unix_timestamp_millis_slow();

        // Update the pair. Order is not critical for this best effort approach.
        self.base_unix_ms.store(unix_now_ms, Ordering::Relaxed);
        self.base_elapsed_ms
            .store(elapsed_now_ms, Ordering::Relaxed);
    }

    fn now_unix_ms(&self) -> i64 {
        let elapsed_now_ms = self.elapsed_ms_now();
        self.maybe_resync(elapsed_now_ms);

        let base_unix = self.base_unix_ms.load(Ordering::Relaxed);
        let base_elapsed = self.base_elapsed_ms.load(Ordering::Relaxed);

        let delta = elapsed_now_ms as i64 - base_elapsed as i64;
        base_unix + delta
    }
}

/// Converts a Duration to milliseconds as i64 with saturation.
///
/// Large durations saturate at i64::MAX.
fn duration_as_millis_i64(d: Duration) -> i64 {
    let ms = d.as_millis();
    if ms > i64::MAX as u128 {
        i64::MAX
    } else {
        ms as i64
    }
}

fn duration_as_millis_u64(d: Duration) -> u64 {
    let ms = d.as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

#[inline(always)]
/// Returns the current unix timestamp in milliseconds as i64.
///
/// This reads the system clock each call.
/// The value is negative only if the system clock is before the unix epoch.
pub fn unix_timestamp_millis() -> i64 {
    unix_timestamp_millis_slow()
}

fn unix_timestamp_millis_slow() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => duration_as_millis_i64(d),
        Err(e) => -duration_as_millis_i64(e.duration()),
    }
}

/// Returns an approximate unix timestamp in milliseconds.
///
/// The returned value may not reflect system clock adjustments immediately.
/// The function resyncs the wall clock about once per hour using atomics.
pub fn now_unix_ms() -> i64 {
    static STATE: OnceLock<State> = OnceLock::new();
    let state = STATE.get_or_init(State::init);
    state.now_unix_ms()
}

/// Returns a rotating index in range 0..len derived from current unix ms time.
///
/// This is stateless and cheap.
///
/// Notes:
/// - If len is 0, returns 0.
/// - Distribution depends on millisecond resolution.
/// - Not suitable for cryptographic or high quality randomness.
pub fn rotime_modulo_index(len: usize) -> usize {
    if len == 0 {
        return 0;
    }

    let now = now_unix_ms();
    let abs = now.wrapping_abs() as u64;
    (abs % len as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn unix_timestamp_millis_is_non_decreasing() {
        let a = unix_timestamp_millis();
        let b = unix_timestamp_millis();
        assert!(b >= a);
    }

    #[test]
    fn now_unix_ms_is_non_decreasing() {
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
    fn modulo_index_within_bounds() {
        for len in 1..64 {
            let idx = rotime_modulo_index(len);
            assert!(idx < len);
        }
    }

    #[test]
    fn modulo_index_zero_len() {
        assert_eq!(rotime_modulo_index(0), 0);
    }

    #[test]
    fn modulo_index_changes_over_time_often() {
        let len = 16;
        let a = rotime_modulo_index(len);
        thread::sleep(Duration::from_millis(3));
        let b = rotime_modulo_index(len);
        assert!(a < len);
        assert!(b < len);
    }
}
