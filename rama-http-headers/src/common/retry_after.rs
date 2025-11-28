use std::time::SystemTime;

use rama_core::telemetry::tracing;
use rama_error::OpaqueError;
use rama_http_types::HeaderValue;

use crate::Error;
use crate::util::{HttpDate, Seconds, TryFromValues};

/// The `Retry-After` header.
///
/// The `Retry-After` response-header field can be used with a 503 (Service
/// Unavailable) response to indicate how long the service is expected to be
/// unavailable to the requesting client. This field MAY also be used with any
/// 3xx (Redirection) response to indicate the minimum time the user-agent is
/// asked wait before issuing the redirected request. The value of this field
/// can be either an HTTP-date or an integer number of seconds (in decimal)
/// after the time of the response.
///
/// # Examples
/// ```
/// use std::time::{SystemTime};
/// use rama_http_headers::{RetryAfter, util::Seconds};
///
/// let delay = RetryAfter::delay(Seconds::new(300));
/// let date = RetryAfter::date(SystemTime::now());
/// ```
///
/// Retry-After header, defined in [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.3)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RetryAfter(After);

impl crate::TypedHeader for RetryAfter {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::RETRY_AFTER
    }
}

impl crate::HeaderDecode for RetryAfter {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        crate::util::TryFromValues::try_from_values(values).map(RetryAfter)
    }
}

impl crate::HeaderEncode for RetryAfter {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!("failed to encode retry-after value as header: {err}");
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum After {
    /// Retry after the given DateTime
    DateTime(HttpDate),
    /// Retry after this duration has elapsed
    Delay(Seconds),
}

impl RetryAfter {
    /// Create an `RetryAfter` header with a date value.
    #[must_use]
    pub fn date(time: SystemTime) -> Self {
        Self(After::DateTime(time.into()))
    }

    /// Create an `RetryAfter` header with a delay value in seconds
    #[must_use]
    pub fn delay(seconds: Seconds) -> Self {
        Self(After::Delay(seconds))
    }

    #[must_use]
    pub fn after(&self) -> After {
        self.0
    }
}

impl TryFromValues for After {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .next()
            .and_then(|val| {
                if let Some(delay) = Seconds::try_from_val(val) {
                    return Some(Self::Delay(delay));
                }

                let date = HttpDate::from_val(val)?;
                Some(Self::DateTime(date))
            })
            .ok_or_else(Error::invalid)
    }
}

impl<'a> TryFrom<&'a After> for HeaderValue {
    type Error = OpaqueError;

    fn try_from(after: &'a After) -> Result<Self, Self::Error> {
        match *after {
            After::Delay(ref delay) => Ok(delay.into()),
            After::DateTime(ref date) => date.try_into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::{RetryAfter, Seconds};
    use crate::util::HttpDate;

    #[test]
    fn delay_decode() {
        let r: RetryAfter = test_decode(&["1234"]).unwrap();
        assert_eq!(r, RetryAfter::delay(Seconds::new(1234)));
    }

    macro_rules! test_retry_after_datetime {
        ($name:ident, $s:expr) => {
            #[test]
            fn $name() {
                let r: RetryAfter = test_decode(&[$s]).unwrap();
                let dt = "Sun, 06 Nov 1994 08:49:37 GMT".parse::<HttpDate>().unwrap();

                assert_eq!(r, RetryAfter(super::After::DateTime(dt)));
            }
        };
    }

    test_retry_after_datetime!(date_decode_rfc1123, "Sun, 06 Nov 1994 08:49:37 GMT");
    test_retry_after_datetime!(date_decode_rfc850, "Sunday, 06-Nov-94 08:49:37 GMT");
    test_retry_after_datetime!(date_decode_asctime, "Sun Nov  6 08:49:37 1994");
}
