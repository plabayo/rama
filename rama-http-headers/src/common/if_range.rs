use std::time::SystemTime;

use rama_core::error::BoxError;
use rama_core::telemetry::tracing;
use rama_http_types::HeaderValue;

use super::{ETag, LastModified};
use crate::Error;
use crate::util::{EntityTag, HttpDate, TryFromValues};

/// `If-Range` header, defined in [RFC7233](https://datatracker.ietf.org/doc/html/rfc7233#section-3.2)
///
/// If a client has a partial copy of a representation and wishes to have
/// an up-to-date copy of the entire representation, it could use the
/// Range header field with a conditional GET (using either or both of
/// If-Unmodified-Since and If-Match.)  However, if the precondition
/// fails because the representation has been modified, the client would
/// then have to make a second request to obtain the entire current
/// representation.
///
/// The `If-Range` header field allows a client to \"short-circuit\" the
/// second request.  Informally, its meaning is as follows: if the
/// representation is unchanged, send me the part(s) that I am requesting
/// in Range; otherwise, send me the entire representation.
///
/// # ABNF
///
/// ```text
/// If-Range = entity-tag / HTTP-date
/// ```
///
/// # Example values
///
/// * `Sat, 29 Oct 1994 19:43:31 GMT`
/// * `\"xyzzy\"`
///
/// # Examples
///
/// ```
/// use rama_http_headers::IfRange;
/// use std::time::{SystemTime, Duration};
///
/// let fetched = SystemTime::now() - Duration::from_hours(24);
/// let if_range = IfRange::date(fetched);
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct IfRange(IfRange_);

impl crate::TypedHeader for IfRange {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::IF_RANGE
    }
}

impl crate::HeaderDecode for IfRange {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        crate::util::TryFromValues::try_from_values(values).map(IfRange)
    }
}

impl crate::HeaderEncode for IfRange {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!("failed to encode if-range value as header: {err}");
            }
        }
    }
}

impl IfRange {
    /// Create an `IfRange` header with an entity tag.
    pub fn etag(tag: ETag) -> Self {
        Self(IfRange_::EntityTag(tag.0))
    }

    /// Create an `IfRange` header with a date value.
    #[must_use]
    pub fn date(time: SystemTime) -> Self {
        Self(IfRange_::Date(time.into()))
    }

    /// Checks if the resource has been modified, or if the range request
    /// can be served.
    pub fn is_modified(&self, etag: Option<&ETag>, last_modified: Option<&LastModified>) -> bool {
        match self.0 {
            IfRange_::Date(since) => last_modified.map(|time| since < time.0).unwrap_or(true),
            IfRange_::EntityTag(ref entity) => {
                etag.map(|etag| !etag.0.strong_eq(entity)).unwrap_or(true)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum IfRange_ {
    /// The entity-tag the client has of the resource
    EntityTag(EntityTag),
    /// The date when the client retrieved the resource
    Date(HttpDate),
}

impl TryFromValues for IfRange_ {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .next()
            .and_then(|val| {
                if let Some(tag) = EntityTag::from_val(val) {
                    return Some(Self::EntityTag(tag));
                }

                let date = HttpDate::from_val(val)?;
                Some(Self::Date(date))
            })
            .ok_or_else(Error::invalid)
    }
}

impl<'a> TryFrom<&'a IfRange_> for HeaderValue {
    type Error = BoxError;

    fn try_from(if_range: &'a IfRange_) -> Result<Self, Self::Error> {
        match *if_range {
            IfRange_::EntityTag(ref tag) => Ok(tag.into()),
            IfRange_::Date(ref date) => date.try_into(),
        }
    }
}

/*
#[cfg(test)]
mod tests {
    use std::str;
    use *;
    use super::IfRange as HeaderField;
    test_header!(test1, vec![b"Sat, 29 Oct 1994 19:43:31 GMT"]);
    test_header!(test2, vec![b"\"xyzzy\""]);
    test_header!(test3, vec![b"this-is-invalid"], None::<IfRange>);
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_modified_etag() {
        let etag = ETag::from_static("\"xyzzy\"");
        let if_range = IfRange::etag(etag.clone());

        assert!(!if_range.is_modified(Some(&etag), None));

        let etag = ETag::from_static("W/\"xyzzy\"");
        assert!(if_range.is_modified(Some(&etag), None));
    }
}
