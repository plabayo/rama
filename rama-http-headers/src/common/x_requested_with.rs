use rama_http_types::{HeaderName, HeaderValue};
use rama_utils::macros::enums::enum_builder;

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader, util::single_value};

enum_builder! {
    /// The `X-Requested-With` request header.
    ///
    /// Not a standard header, and browsers do not send it on their own.
    /// JavaScript libraries such as jQuery set it to `XMLHttpRequest` on the
    /// requests they make, so a server can tell a script request from a
    /// navigation. Android WebView has also sent it on its own requests,
    /// carrying the embedding app's package name (e.g. `com.example.app`);
    /// such values are kept as [`XRequestedWith::Unknown`].
    ///
    /// Matching is ASCII case-insensitive; encoding emits the canonical
    /// spelling of a known value.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http_headers::{HeaderMapExt, XRequestedWith};
    /// use rama_http_types::HeaderMap;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.insert("x-requested-with", "xmlhttprequest".parse().unwrap());
    /// assert_eq!(headers.typed_get(), Some(XRequestedWith::XmlHttpRequest));
    ///
    /// headers.typed_insert(XRequestedWith::XmlHttpRequest);
    /// assert_eq!(headers["x-requested-with"], "XMLHttpRequest");
    /// ```
    @String
    pub enum XRequestedWith {
        /// `XMLHttpRequest`: a request made from script.
        XmlHttpRequest => "XMLHttpRequest",
    }
}

impl TypedHeader for XRequestedWith {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::X_REQUESTED_WITH
    }
}

impl HeaderDecode for XRequestedWith {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = single_value(values)?;
        value
            .to_str()
            .ok()
            .map(str::trim)
            .and_then(|s| (!s.is_empty()).then(|| Self::from(s)))
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for XRequestedWith {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match self.as_static_str() {
            std::borrow::Cow::Borrowed(s) => {
                values.extend(std::iter::once(HeaderValue::from_static(s)));
            }
            std::borrow::Cow::Owned(s) => values.extend(HeaderValue::try_from(s).ok()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    #[test]
    fn decodes_xml_http_request_ignoring_case() {
        for raw in [
            "XMLHttpRequest",
            "xmlhttprequest",
            "XMLHTTPREQUEST",
            " XMLHttpRequest ",
        ] {
            assert_eq!(
                test_decode::<XRequestedWith>(&[raw]),
                Some(XRequestedWith::XmlHttpRequest),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn keeps_other_values() {
        let value = test_decode::<XRequestedWith>(&["com.example.app"]).unwrap();
        assert_eq!(value, XRequestedWith::Unknown("com.example.app".into()));
        assert_eq!(test_encode(value)["x-requested-with"], "com.example.app");
    }

    #[test]
    fn encodes_canonical_spelling() {
        let decoded = test_decode::<XRequestedWith>(&["xmlhttprequest"]).unwrap();
        assert_eq!(test_encode(decoded)["x-requested-with"], "XMLHttpRequest");
    }

    #[test]
    fn rejects_empty_and_multiple_lines() {
        assert_eq!(test_decode::<XRequestedWith>(&[""]), None);
        assert_eq!(test_decode::<XRequestedWith>(&["  "]), None);
        assert_eq!(
            test_decode::<XRequestedWith>(&["XMLHttpRequest", "XMLHttpRequest"]),
            None
        );
    }
}
