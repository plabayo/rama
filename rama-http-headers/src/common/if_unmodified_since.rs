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
/// use std::time::{SystemTime, Duration};
///
/// let time = SystemTime::now() - Duration::from_hours(24);
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
        self.0 >= last_modified.into()
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
    use super::*;
    use std::time::Duration;

    #[test]
    fn precondition_passes() {
        let newer = SystemTime::now();
        let exact = newer - Duration::from_secs(2);
        let older = newer - Duration::from_secs(4);

        let if_unmod = IfUnmodifiedSince::from(exact);
        assert!(!if_unmod.precondition_passes(newer));
        assert!(if_unmod.precondition_passes(exact));
        assert!(if_unmod.precondition_passes(older));
    }
}
