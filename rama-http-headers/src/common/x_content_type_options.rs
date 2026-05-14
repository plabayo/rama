use rama_http_types::{HeaderName, HeaderValue};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `X-Content-Type-Options` header, as defined by the
/// Fetch Living Standard, section "X-Content-Type-Options header"
/// (vendored at `rama-http-headers/specifications/fetch.whatwg.org.bs`).
///
/// The only legal value is `nosniff`, instructing browsers to block requests
/// whose response MIME type does not match the `destination` (style/script).
///
/// The value is matched ASCII case-insensitively on parse, but always encoded
/// as the canonical lowercase `nosniff`.
///
/// # Example
///
/// ```
/// use rama_http_headers::XContentTypeOptions;
///
/// let header = XContentTypeOptions::nosniff();
/// ```
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct XContentTypeOptions;

impl XContentTypeOptions {
    /// Construct the `nosniff` value (the only legal value).
    #[must_use]
    pub const fn nosniff() -> Self {
        Self
    }
}

impl TypedHeader for XContentTypeOptions {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::X_CONTENT_TYPE_OPTIONS
    }
}

impl HeaderDecode for XContentTypeOptions {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .next()
            .and_then(|value| {
                let s = value.to_str().ok()?;
                if s.eq_ignore_ascii_case("nosniff") {
                    Some(Self)
                } else {
                    None
                }
            })
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for XContentTypeOptions {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(HeaderValue::from_static("nosniff")));
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::*;

    #[test]
    fn decode_nosniff() {
        assert_eq!(
            test_decode::<XContentTypeOptions>(&["nosniff"]),
            Some(XContentTypeOptions),
        );
    }

    #[test]
    fn decode_case_insensitive() {
        assert_eq!(
            test_decode::<XContentTypeOptions>(&["NoSniff"]),
            Some(XContentTypeOptions),
        );
        assert_eq!(
            test_decode::<XContentTypeOptions>(&["NOSNIFF"]),
            Some(XContentTypeOptions),
        );
    }

    #[test]
    fn decode_rejects_other_values() {
        assert_eq!(test_decode::<XContentTypeOptions>(&[""]), None);
        assert_eq!(test_decode::<XContentTypeOptions>(&["sniff"]), None);
        assert_eq!(test_decode::<XContentTypeOptions>(&["nosniff,"]), None);
        assert_eq!(test_decode::<XContentTypeOptions>(&["no-sniff"]), None);
    }
}
