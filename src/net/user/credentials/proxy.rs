use super::{Basic, Bearer};
use crate::error::{ErrorContext, OpaqueError};
use crate::http::HeaderValue;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Proxy credentials.
pub enum ProxyCredential {
    /// [`Basic`]` credentials.
    Basic(Basic),
    /// [`Bearer`] credentials.
    Bearer(Bearer),
}

impl From<Basic> for ProxyCredential {
    fn from(basic: Basic) -> Self {
        Self::Basic(basic)
    }
}

impl From<Bearer> for ProxyCredential {
    fn from(bearer: Bearer) -> Self {
        Self::Bearer(bearer)
    }
}

impl ProxyCredential {
    /// Try to create a [`ProxyCredential`] from a header string,
    /// which is expected to be either a [`Basic`] or [`Bearer`] credential.
    pub fn try_from_header_str(value: impl AsRef<str>) -> Result<Self, OpaqueError> {
        let value = value.as_ref();
        Basic::try_from_header_str(value)
            .map(Into::into)
            .or_else(|_| Bearer::try_from_header_str(value).map(Into::into))
            .context("try to construct proxy credentials from header str")
    }

    /// Try to create a [`Bearer`] from a [`&'static str`][str] or [`String`].
    pub fn try_from_clear_str(s: impl Into<Cow<'static, str>>) -> Result<Self, OpaqueError> {
        let s: Cow<'static, str> = s.into();
        if s.contains(':') {
            Basic::try_from_clear_str(s.into_owned()).map(Into::into)
        } else {
            Bearer::try_from_clear_str(s).map(Into::into)
        }
    }

    /// Serialize this [`ProxyCredential`] credential as a header string.
    pub fn as_header_string(&self) -> String {
        match self {
            Self::Basic(basic) => basic.as_header_string(),
            Self::Bearer(bearer) => bearer.as_header_string(),
        }
    }

    /// View this [`ProxyCredential`] as a [`HeaderValue`]
    pub fn as_header_value(&self) -> HeaderValue {
        match self {
            Self::Basic(basic) => basic.as_header_value(),
            Self::Bearer(bearer) => bearer.as_header_value(),
        }
    }

    /// Serialize this [`ProxyCredential`] credential as a clear (not encoded) string.
    pub fn as_clear_string(&self) -> String {
        match self {
            Self::Basic(basic) => basic.as_clear_string(),
            Self::Bearer(bearer) => bearer.as_clear_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_credentials_clear_invalid() {
        assert!(
            ProxyCredential::try_from_clear_str("").is_err(),
            "parse: empty",
        );
    }

    enum Is {
        Basic(&'static str),
        Bearer(&'static str),
    }

    fn assert_is(proxy: ProxyCredential, expected: Is) {
        match expected {
            Is::Basic(value) => match proxy {
                ProxyCredential::Bearer(other) => panic!(
                    "expected proxy bearer {} to be the basic credential: {}",
                    other.as_clear_string(),
                    value
                ),
                ProxyCredential::Basic(other) => assert_eq!(other.as_clear_string(), value),
            },
            Is::Bearer(value) => match proxy {
                ProxyCredential::Basic(other) => panic!(
                    "expected proxy basic {} to be the bearer: {}",
                    other.as_clear_string(),
                    value
                ),
                ProxyCredential::Bearer(other) => assert_eq!(other.as_clear_string(), value),
            },
        }
    }

    #[test]
    fn proxy_credentials_header_valid() {
        for (s, expected) in [
            (
                "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
                Is::Basic("Aladdin:open sesame"),
            ),
            ("Basic QWxhZGRpbjo=", Is::Basic("Aladdin:")),
            ("Bearer QWxhZGRpbjo=", Is::Bearer("QWxhZGRpbjo=")),
            ("Bearer foobar", Is::Bearer("foobar")),
        ] {
            let credential = ProxyCredential::try_from_header_str(s)
                .unwrap_or_else(|_| panic!("invalid proxy credential header str: {s}"));
            assert_eq!(s, credential.as_header_string());
            assert_is(credential, expected);
        }
    }

    #[test]
    fn proxy_credentials_clear_valid() {
        for (s, expected) in [
            ("Aladdin:open sesame", Is::Basic("Aladdin:open sesame")),
            ("Aladdin:", Is::Basic("Aladdin:")),
            ("QWxhZGRpbjo=", Is::Bearer("QWxhZGRpbjo=")),
            ("foobar", Is::Bearer("foobar")),
        ] {
            let credential = ProxyCredential::try_from_clear_str(s)
                .unwrap_or_else(|_| panic!("invalid proxy credential clear str: {s}"));
            assert_eq!(s, credential.as_clear_string());
            assert_is(credential, expected);
        }
    }
}
