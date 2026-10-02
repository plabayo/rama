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
        datetime(epoch - Duration::from_secs(1)).unwrap_err();

        let max_asn1 = epoch + Duration::from_secs(253_402_300_799);
        assert_eq!(datetime(max_asn1).unwrap().year(), 9999);

        // Not every platform's SystemTime reaches past time's own range.
        let beyond_range = time::Date::MAX
            .midnight()
            .assume_utc()
            .unix_timestamp()
            .unsigned_abs()
            + 86_400;
        if let Some(t) = epoch.checked_add(Duration::from_secs(beyond_range)) {
            datetime(t).unwrap_err();
        }
    }
}
