use std::time::SystemTime;

use rama_core::telemetry::tracing;
use rama_http_types::HeaderValue;

use crate::util::HttpDate;

/// `Expires` header, defined in [RFC7234](https://datatracker.ietf.org/doc/html/rfc7234#section-5.3)
///
/// The `Expires` header field gives the date/time after which the
/// response is considered stale.
///
/// The presence of an Expires field does not imply that the original
/// resource will change or cease to exist at, before, or after that
/// time.
///
/// # ABNF
///
/// ```text
/// Expires = HTTP-date
/// ```
///
/// # Example values
/// * `Thu, 01 Dec 1994 16:00:00 GMT`
///
/// # Example
///
/// ```
/// use rama_http_headers::Expires;
/// use std::time::{SystemTime, Duration};
///
/// let time = SystemTime::now() + Duration::from_hours(24);
/// let expires = Expires::from(time);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Expires(HttpDate);

impl crate::TypedHeader for Expires {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::EXPIRES
    }
}

impl crate::HeaderDecode for Expires {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        crate::util::TryFromValues::try_from_values(values).map(Expires)
    }
}

impl crate::HeaderEncode for Expires {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!("failed to encode expires value as header: {err}");
            }
        }
    }
}

impl From<SystemTime> for Expires {
    fn from(time: SystemTime) -> Self {
        Self(time.into())
    }
}

impl From<Expires> for SystemTime {
    fn from(date: Expires) -> Self {
        date.0.into()
    }
}
