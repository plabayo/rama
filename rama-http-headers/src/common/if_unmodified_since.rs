use rama_core::telemetry::tracing;
use rama_http_types::HeaderValue;

use crate::util::HttpDate;
use std::time::SystemTime;

/// `If-Unmodified-Since` header, defined in
/// [RFC7232](https://datatracker.ietf.org/doc/html/rfc7232#section-3.4)
///
/// The `If-Unmodified-Since` header field makes the request method
/// conditional on the selected representation's last modification date
/// being earlier than or equal to the date provided in the field-value.
/// This field accomplishes the same purpose as If-Match for cases where
/// the user agent does not have an entity-tag for the representation.
///
/// # ABNF
///
/// ```text
/// If-Unmodified-Since = HTTP-date
/// ```
///
/// # Example values
///
/// * `Sat, 29 Oct 1994 19:43:31 GMT`
///
/// # Example
///
/// ```
/// use rama_http_headers::IfUnmodifiedSince;
/// use std::time::Duration;
/// use rama_utils::time::now_system_time;
///
/// let time = now_system_time() - Duration::from_hours(24);
/// let if_unmod = IfUnmodifiedSince::from(time);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IfUnmodifiedSince(HttpDate);

impl crate::TypedHeader for IfUnmodifiedSince {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::IF_UNMODIFIED_SINCE
    }
}

impl crate::HeaderDecode for IfUnmodifiedSince {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        crate::util::TryFromValues::try_from_values(values).map(IfUnmodifiedSince)
    }
}

impl crate::HeaderEncode for IfUnmodifiedSince {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!("failed to encode if-unmodified-since value as header: {err}");
            }
        }
    }
}

impl IfUnmodifiedSince {
    /// Check if the supplied time passes the precondtion.
    #[must_use]
    pub fn precondition_passes(&self, last_modified: SystemTime) -> bool {
        // whole-second precision like an HTTP-date, total for any `SystemTime`
        match last_modified.duration_since(SystemTime::from(self.0)) {
            Ok(newer_by) => newer_by.as_secs() == 0,
            Err(_) => true,
        }
    }
}

impl From<SystemTime> for IfUnmodifiedSince {
    fn from(time: SystemTime) -> Self {
        Self(time.into())
    }
}

impl From<IfUnmodifiedSince> for SystemTime {
    fn from(date: IfUnmodifiedSince) -> Self {
        date.0.into()
    }
}

#[cfg(test)]
mod tests {
    use rama_utils::time::now_system_time;

    use super::*;
    use crate::common::test_decode;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn precondition_passes() {
        let newer = now_system_time();
        let exact = newer - Duration::from_secs(2);
        let older = newer - Duration::from_secs(4);

        let if_unmod = IfUnmodifiedSince::from(exact);
        assert!(!if_unmod.precondition_passes(newer));
        assert!(if_unmod.precondition_passes(exact));
        assert!(if_unmod.precondition_passes(older));
    }

    #[test]
    fn precondition_ignores_sub_second_precision() {
        let if_unmod =
            test_decode::<IfUnmodifiedSince>(&["Sun, 06 Nov 1994 08:49:37 GMT"]).unwrap();
        let exact = SystemTime::from(if_unmod);
        assert!(if_unmod.precondition_passes(exact + Duration::from_millis(999)));
        assert!(!if_unmod.precondition_passes(exact + Duration::from_secs(1)));
    }

    #[test]
    fn precondition_with_out_of_range_last_modified() {
        let if_unmod =
            test_decode::<IfUnmodifiedSince>(&["Thu, 01 Jan 1970 00:00:00 GMT"]).unwrap();
        if let Some(before_epoch) = UNIX_EPOCH.checked_sub(Duration::from_millis(1)) {
            assert!(if_unmod.precondition_passes(before_epoch));
        }
        if let Some(after_year_9999) = UNIX_EPOCH.checked_add(Duration::from_secs(253_402_300_800))
        {
            assert!(!if_unmod.precondition_passes(after_year_9999));
        }
    }
}
