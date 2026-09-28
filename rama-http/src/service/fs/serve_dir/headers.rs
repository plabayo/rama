use crate::header::HeaderValue;
use crate::headers::{self, ETag};
use httpdate::HttpDate;
use std::time::{Duration, SystemTime};

/// Generate a strong [`ETag`] from file metadata (size + mtime with nanosecond precision).
///
/// Returns `None` for pre-epoch modification times, which are unsupported. The exact format is
/// an implementation detail and may change between versions; clients must treat ETags as opaque
/// values (RFC 9110 §8.8.3).
pub(super) fn etag_from_metadata(size: u64, modified: SystemTime) -> Option<ETag> {
    let duration = modified.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    // NOTE: changing this format busts every client's cache, but is not a semver break since
    // ETags are opaque per RFC 9110 §8.8.3.
    let value = format!(
        "\"{:x}.{:08x}-{:x}\"",
        duration.as_secs(),
        duration.subsec_nanos(),
        size
    );
    value.parse().ok()
}

#[derive(Clone)]
pub(super) struct LastModified(pub(super) HttpDate);

impl LastModified {
    /// `None` for modification times an HTTP-date cannot represent (pre-epoch or past year 9999).
    pub(super) fn try_from_system_time(time: SystemTime) -> Option<Self> {
        headers::util::HttpDate::try_from_system_time(time).map(|_| Self(time.into()))
    }

    pub(super) fn to_typed(&self) -> headers::LastModified {
        headers::LastModified::from(SystemTime::from(self.0))
    }

    /// RFC 9110 §8.8.2.2: only a date at least a second in the past is a strong validator.
    pub(super) fn is_strong(&self, now: SystemTime) -> bool {
        now.duration_since(SystemTime::from(self.0))
            .is_ok_and(|age| age >= Duration::from_secs(1))
    }
}

pub(super) struct IfModifiedSince(HttpDate);

impl IfModifiedSince {
    /// Check if the supplied time means the resource has been modified.
    pub(super) fn is_modified(&self, last_modified: &LastModified) -> bool {
        self.0 < last_modified.0
    }

    /// convert a header value into a IfModifiedSince, invalid values are silently ignored
    pub(super) fn from_header_value(value: &HeaderValue) -> Option<Self> {
        let value = value.to_str().ok()?;
        let date = value.parse().ok()?;
        Some(Self(date))
    }
}

pub(super) struct IfUnmodifiedSince(HttpDate);

impl IfUnmodifiedSince {
    /// Check if the supplied time passes the precondition.
    pub(super) fn precondition_passes(&self, last_modified: &LastModified) -> bool {
        self.0 >= last_modified.0
    }

    /// Convert a header value into an IfUnmodifiedSince, invalid values are silently ignored
    pub(super) fn from_header_value(value: &HeaderValue) -> Option<Self> {
        let value = value.to_str().ok()?;
        let date = value.parse().ok()?;
        Some(Self(date))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_modified_rejects_unrepresentable_times() {
        let epoch = SystemTime::UNIX_EPOCH;
        assert!(LastModified::try_from_system_time(epoch).is_some());
        let last = epoch
            .checked_add(Duration::from_secs(253_402_300_799))
            .unwrap();
        assert!(LastModified::try_from_system_time(last).is_some());

        let before_epoch = epoch.checked_sub(Duration::from_secs(1)).unwrap();
        let past_9999 = last.checked_add(Duration::from_secs(1)).unwrap();
        assert!(LastModified::try_from_system_time(before_epoch).is_none());
        assert!(LastModified::try_from_system_time(past_9999).is_none());
    }

    #[test]
    fn last_modified_strength_needs_a_second_of_age() {
        let now = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(1_700_000_000))
            .unwrap();
        let fresh = LastModified::try_from_system_time(now).unwrap();
        let old =
            LastModified::try_from_system_time(now.checked_sub(Duration::from_secs(1)).unwrap())
                .unwrap();
        assert!(!fresh.is_strong(now));
        assert!(old.is_strong(now));
    }
}
