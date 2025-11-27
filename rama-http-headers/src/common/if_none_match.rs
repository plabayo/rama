use rama_core::telemetry::tracing;
use rama_http_types::HeaderValue;
use rama_utils::collections::NonEmptyVec;

use super::ETag;
use crate::util::{EntityTagRange, TryFromValues as _};

/// `If-None-Match` header, defined in
/// [RFC7232](https://tools.ietf.org/html/rfc7232#section-3.2)
///
/// The `If-None-Match` header field makes the request method conditional
/// on a recipient cache or origin server either not having any current
/// representation of the target resource, when the field-value is "*",
/// or having a selected representation with an entity-tag that does not
/// match any of those listed in the field-value.
///
/// A recipient MUST use the weak comparison function when comparing
/// entity-tags for If-None-Match (Section 2.3.2), since weak entity-tags
/// can be used for cache validation even if there have been changes to
/// the representation data.
///
/// # ABNF
///
/// ```text
/// If-None-Match = "*" / 1#entity-tag
/// ```
///
/// # Example values
///
/// * `"xyzzy"`
/// * `W/"xyzzy"`
/// * `"xyzzy", "r2d2xxxx", "c3piozzzz"`
/// * `W/"xyzzy", W/"r2d2xxxx", W/"c3piozzzz"`
/// * `*`
///
/// # Examples
///
/// ```
/// use rama_http_headers::IfNoneMatch;
///
/// let if_none_match = IfNoneMatch::any();
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct IfNoneMatch(EntityTagRange);

impl crate::TypedHeader for IfNoneMatch {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::IF_NONE_MATCH
    }
}

impl crate::HeaderDecode for IfNoneMatch {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        EntityTagRange::try_from_values(values).map(Self)
    }
}

impl crate::HeaderEncode for IfNoneMatch {
    fn encode<E: Extend<::rama_http_types::HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!(
                    "failed to encode if-none-match entity-tag-range as header value: {err}"
                );
            }
        }
    }
}

impl IfNoneMatch {
    /// Create a new `If-None-Match: *` header.
    pub fn any() -> Self {
        Self(EntityTagRange::Any)
    }

    /// Checks whether the ETag passes this precondition.
    pub fn precondition_passes(&self, etag: &ETag) -> bool {
        !self.0.matches_weak(&etag.0)
    }
}

impl From<ETag> for IfNoneMatch {
    fn from(etag: ETag) -> Self {
        Self(EntityTagRange::Tags(NonEmptyVec::new(etag.0)))
    }
}

/*
test_if_none_match {
    test_header!(test1, vec![b"\"xyzzy\""]);
    test_header!(test2, vec![b"W/\"xyzzy\""]);
    test_header!(test3, vec![b"\"xyzzy\", \"r2d2xxxx\", \"c3piozzzz\""]);
    test_header!(test4, vec![b"W/\"xyzzy\", W/\"r2d2xxxx\", W/\"c3piozzzz\""]);
    test_header!(test5, vec![b"*"]);
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precondition_fails() {
        let foo = ETag::from_static("\"foo\"");
        let weak_foo = ETag::from_static("W/\"foo\"");

        let if_none = IfNoneMatch::from(foo.clone());

        assert!(!if_none.precondition_passes(&foo));
        assert!(!if_none.precondition_passes(&weak_foo));
    }

    #[test]
    fn precondition_passes() {
        let if_none = IfNoneMatch::from(ETag::from_static("\"foo\""));

        let bar = ETag::from_static("\"bar\"");
        let weak_bar = ETag::from_static("W/\"bar\"");

        assert!(if_none.precondition_passes(&bar));
        assert!(if_none.precondition_passes(&weak_bar));
    }

    #[test]
    fn precondition_any() {
        let foo = ETag::from_static("\"foo\"");

        let if_none = IfNoneMatch::any();

        assert!(!if_none.precondition_passes(&foo));
    }
}
