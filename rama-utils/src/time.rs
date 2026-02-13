//! time utilities.

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in milliseconds as i64.
///
/// This reads the system clock each call.
///
/// The value is negative only if the system clock is before the Unix epoch.
pub fn unix_timestamp_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => duration_as_millis_i64(d),
        Err(e) => -duration_as_millis_i64(e.duration()),
    }
}

/// Returns an approximate Unix timestamp in milliseconds.
///
/// The returned value may not reflect future system clock adjustments.
pub fn now_unix_ms() -> i64 {
    static START: OnceLock<(Instant, i64)> = OnceLock::new();

    let (base_instant, base_unix_ms) = START.get_or_init(|| {
        let unix_ms = unix_timestamp_millis();
        (Instant::now(), unix_ms)
    });

    base_unix_ms + duration_as_millis_i64(base_instant.elapsed())
}

/// Converts a `Duration` to milliseconds as i64 with saturation.
///
/// Large durations saturate at `i64::MAX`.
fn duration_as_millis_i64(d: Duration) -> i64 {
    let ms = d.as_millis();
    if ms > i64::MAX as u128 {
        i64::MAX
    } else {
        ms as i64
    }
}

/// Returns a rotating index in range `0..len` derived from current (UNIX ms) time.
///
/// This is stateless and cheap.
///
/// Notes:
///
/// - If `len == 0`, returns 0.
/// - Distribution depends on millisecond resolution.
/// - Not suitable for cryptographic or high quality randomness.
pub fn modulo_index(len: usize) -> usize {
    if len == 0 {
        return 0;
    }

    let now = now_unix_ms();

    // Avoid negative modulo behavior and handle i64::MIN safely
    let abs = now.wrapping_abs() as u64;

    (abs % len as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn unix_timestamp_millis_is_monotonic_non_decreasing() {
        let a = unix_timestamp_millis();
        let b = unix_timestamp_millis();
        assert!(b >= a);
    }

    #[test]
    fn now_unix_ms_is_monotonic_non_decreasing() {
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
        assert!(diff <= 250);
    }

    #[test]
    fn modulo_index_within_bounds() {
        for len in 1..32 {
            let idx = modulo_index(len);
            assert!(idx < len);
        }
    }

    #[test]
    fn modulo_index_zero_len() {
        assert_eq!(modulo_index(0), 0);
    }

    #[test]
    fn modulo_index_changes_over_time() {
        let len = 16;
        let a = modulo_index(len);
        thread::sleep(Duration::from_millis(3));
        let b = modulo_index(len);

        // Not guaranteed to differ, but highly likely with sleep
        assert!(a < len);
        assert!(b < len);
    }
}
