use rama_core::telemetry::tracing;
use rama_http_types::HeaderValue;

use crate::util::HttpDate;
use std::time::SystemTime;

/// `Last-Modified` header, defined in
/// [RFC7232](https://datatracker.ietf.org/doc/html/rfc7232#section-2.2)
///
/// The `Last-Modified` header field in a response provides a timestamp
/// indicating the date and time at which the origin server believes the
/// selected representation was last modified, as determined at the
/// conclusion of handling the request.
///
/// # ABNF
///
/// ```text
/// Expires = HTTP-date
/// ```
///
/// # Example values
///
/// * `Sat, 29 Oct 1994 19:43:31 GMT`
///
/// # Example
///
/// ```
/// use rama_http_headers::LastModified;
/// use std::time::{Duration, SystemTime};
///
/// let modified = LastModified::from(
///     SystemTime::now() - Duration::from_secs(60 * 60 * 24)
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LastModified(pub(super) HttpDate);

impl crate::TypedHeader for LastModified {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::LAST_MODIFIED
    }
}

impl crate::HeaderDecode for LastModified {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        crate::util::TryFromValues::try_from_values(values).map(LastModified)
    }
}

impl crate::HeaderEncode for LastModified {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!("failed to encode last-modified value as header: {err}");
            }
        }
    }
}

impl From<SystemTime> for LastModified {
    fn from(time: SystemTime) -> Self {
        Self(time.into())
    }
}

impl From<LastModified> for SystemTime {
    fn from(date: LastModified) -> Self {
        date.0.into()
    }
}
