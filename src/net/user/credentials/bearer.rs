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
        let s =
            std::str::from_utf8(bytes).context("turn scheme-trimmed bearer back into utf-8 str")?;
        Self::try_from_clear_str(s.to_owned())
    }

    /// Try to create a [`Bearer`] from a [`&'static str`][str] or [`String`].
    pub fn try_from_clear_str(s: impl Into<Cow<'static, str>>) -> Result<Self, OpaqueError> {
        let s = s.into();
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
        let encoded = self.as_header_string();
        // we validate the inner value upon creation
        http::HeaderValue::from_str(&encoded).expect("inner value should always be valid")
    }
}
