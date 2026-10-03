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
    use crate::HeaderDecode as _;
    use crate::common::test_decode;

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

    #[test]
    fn decode_rejects_malformed_tags_without_panic() {
        let etag = ETag::from_static("\"a\"");
        for value in [
            "", "x", "W", "W/", "W/\"", "\"", "*, \"a\"", "\"a\", *", "\"a b\"",
        ] {
            let decoded = test_decode::<IfNoneMatch>(&[value]);
            if let Some(if_none) = &decoded {
                _ = if_none.precondition_passes(&etag);
            }
            assert!(decoded.is_none(), "value: {value:?}");
        }
        assert!(test_decode::<IfNoneMatch>(&["*", "\"a\""]).is_none());
    }

    #[test]
    fn decode_any_and_list() {
        let etag = ETag::from_static("\"a\"");
        let any: IfNoneMatch = test_decode(&["*"]).unwrap();
        assert_eq!(any, IfNoneMatch::any());
        assert!(!any.precondition_passes(&etag));

        let list: IfNoneMatch = test_decode(&["\"b\", W/\"a\""]).unwrap();
        assert!(!list.precondition_passes(&etag));
        assert!(list.precondition_passes(&ETag::from_static("\"c\"")));
    }

    #[test]
    fn decode_obs_text_and_backslash_entity_tags() {
        let values = [
            HeaderValue::from_static("\"a\""),
            HeaderValue::from_bytes(b"\"\x80\xff\", \"b\\\"").unwrap(),
        ];
        let list = IfNoneMatch::decode(&mut values.iter()).unwrap();
        for tag in ["\"a\"", "\"b\\\""] {
            assert!(!list.precondition_passes(&tag.parse().unwrap()), "{tag}");
        }
        let obs_text =
            ETag::decode(&mut [HeaderValue::from_bytes(b"\"\x80\xff\"").unwrap()].iter()).unwrap();
        assert!(!list.precondition_passes(&obs_text));
        assert!(list.precondition_passes(&ETag::from_static("\"c\"")));
    }

    #[test]
    fn decode_ignores_empty_list_members() {
        let etag = ETag::from_static("\"a\"");
        for values in [
            &["\"a\","][..],
            &[", \"a\""],
            &["\"b\",, \"a\""],
            &["", "\"a\""],
        ] {
            let list: IfNoneMatch = test_decode(values).unwrap();
            assert!(!list.precondition_passes(&etag), "values: {values:?}");
        }
    }
}
