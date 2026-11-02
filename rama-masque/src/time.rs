use std::time::Duration;
use tokio::time::Instant;

/// `now + timeout`, shortened only when the platform cannot represent it.
pub(crate) fn expiration_at(now: Instant, mut timeout: Duration) -> Instant {
    loop {
        if let Some(at) = now.checked_add(timeout) {
            return at;
        }
        timeout /= 2;
    }
}
