use std::time::SystemTime;

use rama_http_types::{HeaderValue, utils::http_date::format_http_date_now_bytes};

use crate::util::HttpDate;

/// `Date` header, defined in [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.1.2)
///
/// The `Date` header field represents the date and time at which the
/// message was originated.
///
/// ## ABNF
///
/// ```text
/// Date = HTTP-date
/// ```
///
/// ## Example values
///
/// * `Tue, 15 Nov 1994 08:12:31 GMT`
///
/// # Example
///
/// ```
/// use rama_http_headers::Date;
/// use rama_utils::time::now_system_time;
///
/// let date = Date::from(now_system_time());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date(HttpDate);

impl crate::TypedHeader for Date {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::DATE
    }
}

impl crate::HeaderDecode for Date {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        crate::util::TryFromValues::try_from_values(values).map(Date)
    }
}

impl crate::HeaderEncode for Date {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(HeaderValue::from(&self.0)));
    }
}

/// The `Date` header for the current second of rama's cached wall clock.
///
/// Encode-only: read a received `Date` with [`Date`]. Every value encoded within
/// one second on a thread shares one allocation, which suits stamping every response.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct DateNow;

impl DateNow {
    #[must_use]
    #[inline(always)]
    /// Create a new [`DateNow`].
    pub fn new() -> Self {
        Self
    }
}

impl crate::TypedHeader for DateNow {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::DATE
    }
}

impl crate::HeaderEncode for DateNow {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        // SAFETY: an IMF-fixdate is visible ASCII only.
        let value =
            unsafe { HeaderValue::from_maybe_shared_unchecked(format_http_date_now_bytes()) };
        values.extend(::std::iter::once(value));
    }
}

impl From<SystemTime> for Date {
    fn from(time: SystemTime) -> Self {
        Self(time.into())
    }
}

impl From<Date> for SystemTime {
    fn from(date: Date) -> Self {
        date.0.into()
    }
}

#[cfg(test)]
mod tests {
    use super::{Date, DateNow};
    use crate::HeaderMapExt;
    use rama_http_types::{HeaderMap, header::DATE};
    use rama_utils::time::now_system_time;
    use std::time::{Duration, SystemTime};

    #[test]
    fn date_now_encodes_the_current_date() {
        let mut headers = HeaderMap::new();
        headers.typed_insert(DateNow::new());

        let date: SystemTime = headers.typed_get::<Date>().unwrap().into();
        let now = now_system_time();
        let skew = now
            .duration_since(date)
            .unwrap_or_else(|ahead| ahead.duration());
        assert!(skew <= Duration::from_secs(2), "skew: {skew:?}");
    }

    #[test]
    fn date_now_replaces_an_existing_date() {
        let mut headers = HeaderMap::new();
        headers.typed_insert(Date::from(SystemTime::UNIX_EPOCH));
        headers.typed_insert(DateNow::new());

        assert_eq!(headers.get_all(DATE).iter().count(), 1);
        assert_ne!(
            headers.typed_get::<Date>(),
            Some(Date::from(SystemTime::UNIX_EPOCH))
        );
    }

    #[test]
    fn date_now_shares_bytes_within_a_second() {
        let mut first = HeaderMap::new();
        let mut second = HeaderMap::new();
        first.typed_insert(DateNow::new());
        second.typed_insert(DateNow::new());

        let (first, second) = (&first[DATE], &second[DATE]);
        if first == second {
            assert_eq!(first.as_bytes().as_ptr(), second.as_bytes().as_ptr());
        }
    }
}
