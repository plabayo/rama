use rama_error::{ErrorContext as _, OpaqueError};
use rama_http_types::{HeaderValue, Uri, header::ToStrError};

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

derive_header! {
    Location(_),
    name: LOCATION
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
    type Error = OpaqueError;

    #[inline]
    fn try_from(value: Uri) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&Uri> for Location {
    type Error = OpaqueError;

    fn try_from(value: &Uri) -> Result<Self, Self::Error> {
        Ok(Self(
            HeaderValue::try_from(value.to_string()).context("parse uri as header value")?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::*;

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
