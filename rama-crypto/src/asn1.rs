use std::time::SystemTime;

use jiff::Timestamp;
use rama_core::error::{BoxError, ErrorContext};

/// Whole-second ASN.1 timestamps; pre-epoch values are unsupported.
pub(super) fn timestamp(t: SystemTime) -> Result<Timestamp, BoxError> {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("timestamp before unix epoch")?
        .as_secs();
    let secs = i64::try_from(secs).context("timestamp exceeds i64 seconds")?;
    Timestamp::from_second(secs).context("invalid timestamp")
}

/// Adapt to rcgen/yasna's `time` API without losing subsecond precision.
pub(super) fn datetime(t: Timestamp) -> Result<time::OffsetDateTime, BoxError> {
    time::OffsetDateTime::from_unix_timestamp_nanos(t.as_nanosecond())
        .context("invalid ASN.1 timestamp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timestamp_bounds() {
        let epoch = SystemTime::UNIX_EPOCH;
        assert_eq!(
            timestamp(epoch + Duration::from_nanos(999_999_999)).unwrap(),
            Timestamp::UNIX_EPOCH
        );
        assert!(timestamp(epoch - Duration::from_secs(1)).is_err());

        let beyond_range = Timestamp::MAX.as_second().unsigned_abs() + 1;
        for secs in [beyond_range, i64::MAX.unsigned_abs() + 1, u64::MAX] {
            if let Some(t) = epoch.checked_add(Duration::from_secs(secs)) {
                assert!(timestamp(t).is_err());
            }
        }

        for t in [
            Timestamp::MIN,
            Timestamp::new(1, 123_456_789).unwrap(),
            Timestamp::MAX,
        ] {
            assert_eq!(
                datetime(t).unwrap().unix_timestamp_nanos(),
                t.as_nanosecond()
            );
        }
    }
}
