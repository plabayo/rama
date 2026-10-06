use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::{
    HeaderName, HeaderValue,
    header::{self, ToStrError},
};
use rama_net::uri::Uri;

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader, util::single_value};

/// `Location` header, defined in
/// [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.2)
///
/// The `Location` header field is used in some responses to refer to a
/// specific resource in relation to the response.  The type of
/// relationship is defined by the combination of request method and
/// status code semantics.
///
/// # ABNF
///
/// ```text
/// Location = URI-reference
/// ```
///
/// # Example values
/// * `/People.html#tim`
/// * `http://www.example.net/index.html`
///
/// # Examples
///
#[derive(Clone, Debug, PartialEq)]
pub struct Location(HeaderValue);

impl TypedHeader for Location {
    fn name() -> &'static HeaderName {
        &header::LOCATION
    }
}

impl HeaderDecode for Location {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        // One target: a client fails on several lines (Fetch §2.2.2, "location URL").
        single_value(values).map(Self)
    }
}

impl HeaderEncode for Location {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(std::iter::once(self.0.clone()));
    }
}

impl Location {
    pub fn new(value: HeaderValue) -> Self {
        Self(value)
    }

    pub fn to_str(&self) -> Result<&str, ToStrError> {
        self.0.to_str()
    }
}

impl TryFrom<Uri> for Location {
    type Error = BoxError;

    #[inline]
    fn try_from(value: Uri) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&Uri> for Location {
    type Error = BoxError;

    fn try_from(value: &Uri) -> Result<Self, Self::Error> {
        Ok(Self(
            HeaderValue::try_from(value.to_string()).context("parse uri as header value")?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_decode;

    #[test]
    fn absolute_uri() {
        let s = "http://www.example.net/index.html";
        let loc = test_decode::<Location>(&[s]).unwrap();

        assert_eq!(loc, Location(HeaderValue::from_static(s)));
    }

    #[test]
    fn relative_uri_with_fragment() {
        let s = "/People.html#tim";
        let loc = test_decode::<Location>(&[s]).unwrap();

        assert_eq!(loc, Location(HeaderValue::from_static(s)));
    }
}
