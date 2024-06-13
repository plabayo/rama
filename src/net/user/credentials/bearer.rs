use crate::{
    error::{ErrorContext, OpaqueError},
    http::headers::authorization,
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Bearer credentials.
pub struct Bearer(Cow<'static, str>);

impl Bearer {
    /// Try to create a [`Bearer`] from a header string.
    pub fn try_from_header_str(value: impl AsRef<str>) -> Result<Self, OpaqueError> {
        let value = value.as_ref();

        if value.as_bytes().len() <= BEARER_SCHEME.len() + 1 {
            return Err(OpaqueError::from_display("invalid bearer scheme length"));
        }
        if !value.as_bytes()[..BEARER_SCHEME.len()].eq_ignore_ascii_case(BEARER_SCHEME.as_bytes()) {
            return Err(OpaqueError::from_display("invalid bearer scheme"));
        }

        let bytes = &value.as_bytes()[BEARER_SCHEME.len() + 1..];

        let non_space_pos = bytes
            .iter()
            .position(|b| *b != b' ')
            .ok_or_else(|| OpaqueError::from_display("missing space separator in bearer str"))?;
        let bytes = &bytes[non_space_pos..];

        let s =
            std::str::from_utf8(bytes).context("turn scheme-trimmed bearer back into utf-8 str")?;
        Self::try_from_clear_str(s.to_owned())
    }

    /// Try to create a [`Bearer`] from a [`&'static str`][str] or [`String`].
    pub fn try_from_clear_str(s: impl Into<Cow<'static, str>>) -> Result<Self, OpaqueError> {
        let s = s.into();
        if s.is_empty() {
            return Err(OpaqueError::from_display(
                "empty str cannot be used as Bearer",
            ));
        }
        if s.as_bytes().iter().any(|b| *b < 32 || *b >= 127) {
            return Err(OpaqueError::from_display(
                "string contains non visible ASCII characters",
            ));
        }

        Ok(Self(s))
    }

    /// Serialize this [`Bearer`] credential as a header string.
    pub fn as_header_string(&self) -> String {
        format!("{BEARER_SCHEME} {}", self.0)
    }

    /// View this [`Bearer`] as a [`HeaderValue`][http::HeaderValue].
    pub fn as_header_value(&self) -> http::HeaderValue {
        let encoded = self.as_header_string();
        // we validate the inner value upon creation
        http::HeaderValue::from_str(&encoded).expect("inner value should always be valid")
    }

    /// Serialize this [`Bearer`] credential as a clear (not encoded) string.
    pub fn as_clear_string(&self) -> String {
        self.0.to_string()
    }

    /// View the token part as a `&str`.
    pub fn token(&self) -> &str {
        &self.0
    }
}

const BEARER_SCHEME: &str = "Bearer";

impl authorization::Credentials for Bearer {
    const SCHEME: &'static str = BEARER_SCHEME;

    fn decode(value: &http::HeaderValue) -> Option<Self> {
        Self::try_from_header_str(value.to_str().ok()?).ok()
    }

    fn encode(&self) -> http::HeaderValue {
        self.as_header_value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorization::Credentials;

    #[test]
    fn bearer_parse_empty() {
        let value = Bearer::try_from_header_str("");
        assert!(value.is_err());
    }

    #[test]
    fn bearer_clear_text_empty() {
        let value = Bearer::try_from_clear_str("");
        assert!(value.is_err());
    }

    #[test]
    fn bearer_encode() {
        let auth = Bearer::try_from_clear_str("foobar").unwrap();
        let value = auth.encode();

        assert_eq!(value, "Bearer foobar",);
    }

    #[test]
    fn bearer_decode() {
        let auth = Bearer::decode(&http::HeaderValue::from_static("Bearer foobar")).unwrap();
        assert_eq!(auth.token(), "foobar");
    }

    #[test]
    fn bearer_decode_case_insensitive() {
        let auth = Bearer::decode(&http::HeaderValue::from_static("bearer foobar")).unwrap();
        assert_eq!(auth.token(), "foobar");
    }

    #[test]
    fn bearer_decode_extra_whitespaces() {
        let auth = Bearer::decode(&http::HeaderValue::from_static(
            "Bearer  QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        ))
        .unwrap();
        assert_eq!(auth.token(), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }

    #[test]
    fn bearer_header() {
        let auth = Bearer::try_from_header_str("Bearer 123abc").unwrap();
        assert_eq!(auth.token(), "123abc");
        assert_eq!("Bearer 123abc", auth.as_header_string());
    }

    #[test]
    fn bearer_clear() {
        let auth = Bearer::try_from_clear_str("foobar".to_owned()).unwrap();
        assert_eq!(auth.token(), "foobar");
        assert_eq!("foobar", auth.as_clear_string());
    }
}
