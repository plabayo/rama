use std::time::SystemTime;

use rama_core::telemetry::tracing;
use rama_http_types::HeaderValue;

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
/// use std::time::SystemTime;
///
/// let date = Date::from(SystemTime::now());
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
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!("failed to encode date value as header: {err}");
            }
        }
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
