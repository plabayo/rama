use std::time::SystemTime;

use rama_core::error::{BoxError, ErrorContext};
use time::OffsetDateTime;

/// Whole-second ASN.1 timestamps; pre-epoch values are unsupported.
pub(super) fn datetime(t: SystemTime) -> Result<OffsetDateTime, BoxError> {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("timestamp before unix epoch")?
        .as_secs();
    let secs = i64::try_from(secs).context("timestamp exceeds i64 seconds")?;
    OffsetDateTime::from_unix_timestamp(secs).context("invalid timestamp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn datetime_bounds() {
        let epoch = SystemTime::UNIX_EPOCH;
        assert_eq!(
            datetime(epoch + Duration::from_nanos(999_999_999)).unwrap(),
            OffsetDateTime::UNIX_EPOCH
        );
        assert!(datetime(epoch - Duration::from_secs(1)).is_err());

        let beyond_range = time::Date::MAX
            .midnight()
            .assume_utc()
            .unix_timestamp()
            .unsigned_abs()
            + 86_400;
        for secs in [beyond_range, i64::MAX.unsigned_abs() + 1, u64::MAX] {
            if let Some(t) = epoch.checked_add(Duration::from_secs(secs)) {
                assert!(datetime(t).is_err());
            }
        }
    }
}
