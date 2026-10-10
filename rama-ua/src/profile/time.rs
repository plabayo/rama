//! UTC retention timestamps checked against the receiver's trusted clock.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{ProfileDataError, RetentionWindow};

const SECONDS_PER_DAY: u64 = 86_400;
/// Last UTC day in the supported calendar, 9999-12-31.
pub(super) const MAXIMUM_UTC_DAY: u32 = 2_932_896;

/// Convert an absolute instant; local timezone offsets do not enter day bucketing.
pub fn profile_utc_day(timestamp: SystemTime) -> Result<u32, ProfileDataError> {
    let elapsed = timestamp
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| ProfileDataError::Invalid("profile time before Unix epoch"))?;
    let day = elapsed.as_secs() / SECONDS_PER_DAY;
    if day > u64::from(MAXIMUM_UTC_DAY) {
        return Err(ProfileDataError::Unsupported("profile UTC calendar range"));
    }
    u32::try_from(day).map_err(|_error| ProfileDataError::Unsupported("profile UTC day"))
}

/// Validated import times. Small future clock skew is assigned to the receiver's
/// current day; it cannot create a future bucket or advance the retained watermark.
#[derive(Debug, Clone, Copy)]
pub struct ProfileObservationTime {
    pub current_day: u32,
    pub observation_day: u32,
}

impl ProfileObservationTime {
    pub fn new(
        received_at: SystemTime,
        observed_at: SystemTime,
        maximum_future_skew: Duration,
        retention: RetentionWindow,
    ) -> Result<Self, ProfileDataError> {
        let current_day = profile_utc_day(received_at)?;
        let observed_day = profile_utc_day(observed_at)?;
        if observed_at
            .duration_since(received_at)
            .is_ok_and(|skew| skew > maximum_future_skew)
        {
            return Err(ProfileDataError::Invalid("profile observation clock skew"));
        }
        let observation_day = observed_day.min(current_day);
        retention.validate_observation(current_day, observation_day)?;
        Ok(Self {
            current_day,
            observation_day,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileCaptureCompleteness;
    use crate::profile::{
        CanonicalDomain, HeaderCapturePolicy, ObservationId, ProfileWindowLimits,
        RetainedBucketWindow, ValueId,
    };
    use rama_http::{HeaderMap, HeaderValue, Version};

    #[test]
    fn utc_midnight_skew_offsets_and_pre_epoch_have_explicit_boundaries() {
        let midnight = UNIX_EPOCH + Duration::from_secs(100 * SECONDS_PER_DAY);
        assert_eq!(
            profile_utc_day(midnight - Duration::from_millis(1)).unwrap(),
            99
        );
        assert_eq!(profile_utc_day(midnight).unwrap(), 100);
        // 02:00 at UTC+02:00 and 19:00 at UTC-05:00 denote that same instant.
        let east_local = midnight + Duration::from_secs(2 * 3600);
        let west_local = midnight - Duration::from_secs(5 * 3600);
        assert_eq!(
            profile_utc_day(east_local - Duration::from_secs(2 * 3600)).unwrap(),
            100
        );
        assert_eq!(
            profile_utc_day(west_local + Duration::from_secs(5 * 3600)).unwrap(),
            100
        );
        profile_utc_day(UNIX_EPOCH - Duration::from_millis(1)).unwrap_err();
        let received = midnight - Duration::from_millis(1);
        let retention = RetentionWindow::default();
        let accepted =
            ProfileObservationTime::new(received, midnight, Duration::from_millis(1), retention)
                .unwrap();
        assert_eq!((accepted.current_day, accepted.observation_day), (99, 99));
        ProfileObservationTime::new(received, midnight, Duration::ZERO, retention).unwrap_err();
        assert!(matches!(
            ProfileObservationTime::new(
                midnight,
                midnight - Duration::from_secs(14 * SECONDS_PER_DAY),
                Duration::ZERO,
                retention
            ),
            Err(ProfileDataError::Expired)
        ));
        ProfileObservationTime::new(
            midnight,
            midnight - Duration::from_secs(13 * SECONDS_PER_DAY),
            Duration::ZERO,
            retention,
        )
        .unwrap();
    }

    #[test]
    fn unsupported_days_cannot_erase_or_poison_retained_state() {
        let mut window = RetainedBucketWindow::new(
            CanonicalDomain::Headers,
            ValueId([1; 32]),
            [2; 32],
            ProfileWindowLimits::default(),
        )
        .unwrap();
        let policy = HeaderCapturePolicy::default();
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("text/plain"));
        let value = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_2,
                &headers,
                None,
            )
            .unwrap()
            .canonical(&policy)
            .unwrap();
        window
            .observe(
                100,
                100,
                ObservationId {
                    run: [3; 16],
                    sequence: 1,
                },
                &value,
            )
            .unwrap();
        let before = serde_json::to_vec(&window.snapshot()).unwrap();
        for day in [MAXIMUM_UTC_DAY + 1, u32::MAX] {
            window.advance(day).unwrap_err();
            window.select(day, 14).unwrap_err();
            assert_eq!(before, serde_json::to_vec(&window.snapshot()).unwrap());
            let mut corrupt = window.snapshot();
            corrupt.buckets = Box::default();
            corrupt.last_day = day;
            RetainedBucketWindow::from_snapshot(
                &corrupt,
                CanonicalDomain::Headers,
                ValueId([1; 32]),
                [2; 32],
                ProfileWindowLimits::default(),
            )
            .unwrap_err();
        }
        profile_utc_day(
            UNIX_EPOCH + Duration::from_secs(u64::from(MAXIMUM_UTC_DAY + 1) * SECONDS_PER_DAY),
        )
        .unwrap_err();
        assert_eq!(
            profile_utc_day(
                UNIX_EPOCH + Duration::from_secs(u64::from(MAXIMUM_UTC_DAY) * SECONDS_PER_DAY)
            )
            .unwrap(),
            MAXIMUM_UTC_DAY
        );
    }
}
