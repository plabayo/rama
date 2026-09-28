use rama_core::telemetry::tracing;
use rama_http_types::HeaderValue;

use crate::util::HttpDate;
use std::time::SystemTime;

/// `If-Modified-Since` header, defined in
/// [RFC7232](https://datatracker.ietf.org/doc/html/rfc7232#section-3.3)
///
/// The `If-Modified-Since` header field makes a GET or HEAD request
/// method conditional on the selected representation's modification date
/// being more recent than the date provided in the field-value.
/// Transfer of the selected representation's data is avoided if that
/// data has not changed.
///
/// # ABNF
///
/// ```text
/// If-Modified-Since = HTTP-date
/// ```
///
/// # Example values
/// * `Sat, 29 Oct 1994 19:43:31 GMT`
///
/// # Example
///
/// ```
/// use rama_http_headers::IfModifiedSince;
/// use std::time::Duration;
/// use rama_utils::time::now_system_time;
///
/// let time = now_system_time() - Duration::from_hours(24);
/// let if_mod = IfModifiedSince::from(time);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IfModifiedSince(HttpDate);

impl crate::TypedHeader for IfModifiedSince {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::IF_MODIFIED_SINCE
    }
}

impl crate::HeaderDecode for IfModifiedSince {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        crate::util::TryFromValues::try_from_values(values).map(IfModifiedSince)
    }
}

impl crate::HeaderEncode for IfModifiedSince {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!("failed to encode if-modified-since value as header: {err}");
            }
        }
    }
}

impl IfModifiedSince {
    /// Check if the supplied time means the resource has been modified.
    #[must_use]
    pub fn is_modified(&self, last_modified: SystemTime) -> bool {
        // whole-second precision like an HTTP-date, total for any `SystemTime`
        last_modified
            .duration_since(SystemTime::from(self.0))
            .is_ok_and(|newer_by| newer_by.as_secs() > 0)
    }
}

impl From<SystemTime> for IfModifiedSince {
    fn from(time: SystemTime) -> Self {
        Self(time.into())
    }
}

impl From<IfModifiedSince> for SystemTime {
    fn from(date: IfModifiedSince) -> Self {
        date.0.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_decode;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn is_modified() {
        let newer = SystemTime::now();
        let exact = newer - Duration::from_secs(2);
        let older = newer - Duration::from_secs(4);

        let if_mod = IfModifiedSince::from(exact);
        assert!(if_mod.is_modified(newer));
        assert!(!if_mod.is_modified(exact));
        assert!(!if_mod.is_modified(older));
    }

    #[test]
    fn is_modified_ignores_sub_second_precision() {
        let if_mod = test_decode::<IfModifiedSince>(&["Sun, 06 Nov 1994 08:49:37 GMT"]).unwrap();
        let exact = SystemTime::from(if_mod);
        assert!(!if_mod.is_modified(exact + Duration::from_millis(999)));
        assert!(if_mod.is_modified(exact + Duration::from_secs(1)));
    }

    #[test]
    fn is_modified_with_out_of_range_last_modified() {
        let if_mod = test_decode::<IfModifiedSince>(&["Thu, 01 Jan 1970 00:00:00 GMT"]).unwrap();
        if let Some(before_epoch) = UNIX_EPOCH.checked_sub(Duration::from_millis(1)) {
            assert!(!if_mod.is_modified(before_epoch));
        }
        if let Some(after_year_9999) = UNIX_EPOCH.checked_add(Duration::from_secs(253_402_300_800))
        {
            assert!(if_mod.is_modified(after_year_9999));
        }

        // clamping the last-modified time to 9999 would hide this modification
        let if_mod = test_decode::<IfModifiedSince>(&["Fri, 31 Dec 9999 23:59:59 GMT"]).unwrap();
        let year_10001 = UNIX_EPOCH
            .checked_add(Duration::from_secs(253_433_923_200))
            .unwrap();
        assert!(if_mod.is_modified(year_10001));
    }
}
