use rama_http_types::{HeaderName, HeaderValue};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `X-Frame-Options` header, as defined in
/// [RFC 7034](https://datatracker.ietf.org/doc/html/rfc7034).
///
/// Controls whether a browser is allowed to render a page in a `<frame>`,
/// `<iframe>`, `<embed>` or `<object>`. The deprecated `ALLOW-FROM` directive
/// is rejected on parse — it was removed from the modern HTML/Fetch specs and
/// is no longer supported by any major browser. Use `Content-Security-Policy:
/// frame-ancestors` for origin-scoped framing controls instead.
///
/// Token matching is ASCII case-insensitive on parse; encoding emits the
/// canonical uppercase tokens.
///
/// # Example
///
/// ```
/// use rama_http_headers::XFrameOptions;
///
/// let header = XFrameOptions::Deny;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum XFrameOptions {
    /// `DENY`: the page cannot be displayed in a frame, regardless of origin.
    Deny,
    /// `SAMEORIGIN`: the page can only be displayed in a frame of the same origin.
    SameOrigin,
}

impl XFrameOptions {
    fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "DENY",
            Self::SameOrigin => "SAMEORIGIN",
        }
    }
}

impl TypedHeader for XFrameOptions {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::X_FRAME_OPTIONS
    }
}

impl HeaderDecode for XFrameOptions {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .next()
            .and_then(|value| {
                let s = value.to_str().ok()?.trim();
                if s.eq_ignore_ascii_case("DENY") {
                    Some(Self::Deny)
                } else if s.eq_ignore_ascii_case("SAMEORIGIN") {
                    Some(Self::SameOrigin)
                } else {
                    // ALLOW-FROM is intentionally rejected (removed from the spec).
                    None
                }
            })
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for XFrameOptions {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(HeaderValue::from_static(self.as_str())));
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::*;

    #[test]
    fn decode_deny() {
        assert_eq!(
            test_decode::<XFrameOptions>(&["DENY"]),
            Some(XFrameOptions::Deny),
        );
    }

    #[test]
    fn decode_sameorigin() {
        assert_eq!(
            test_decode::<XFrameOptions>(&["SAMEORIGIN"]),
            Some(XFrameOptions::SameOrigin),
        );
    }

    #[test]
    fn decode_case_insensitive() {
        assert_eq!(
            test_decode::<XFrameOptions>(&["deny"]),
            Some(XFrameOptions::Deny),
        );
        assert_eq!(
            test_decode::<XFrameOptions>(&["SameOrigin"]),
            Some(XFrameOptions::SameOrigin),
        );
    }

    #[test]
    fn decode_rejects_allow_from() {
        assert_eq!(
            test_decode::<XFrameOptions>(&["ALLOW-FROM https://example.com"]),
            None,
        );
        assert_eq!(test_decode::<XFrameOptions>(&["ALLOW-FROM"]), None);
        assert_eq!(test_decode::<XFrameOptions>(&["allow-from *"]), None);
    }

    #[test]
    fn decode_rejects_other_values() {
        assert_eq!(test_decode::<XFrameOptions>(&[""]), None);
        assert_eq!(test_decode::<XFrameOptions>(&["allowall"]), None);
        assert_eq!(test_decode::<XFrameOptions>(&["DENY, SAMEORIGIN"]), None);
    }
}
