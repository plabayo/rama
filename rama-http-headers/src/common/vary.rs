use rama_core::telemetry::tracing;
use rama_error::OpaqueError;
use rama_http_types::{HeaderName, HeaderValue, header};
use rama_utils::collections::{NonEmptyVec, non_empty_vec};

use crate::util::{
    FlatCsvSeparator, TryFromValues, try_decode_flat_csv_header_values_as_non_empty_vec,
    try_encode_non_empty_vec_as_flat_csv_header_value,
};

/// `Vary` header, defined in [RFC7231](https://tools.ietf.org/html/rfc7231#section-7.1.4)
///
/// The "Vary" header field in a response describes what parts of a
/// request message, aside from the method, Host header field, and
/// request target, might influence the origin server's process for
/// selecting and representing this response.  The value consists of
/// either a single asterisk ("*") or a list of header field names
/// (case-insensitive).
///
/// # ABNF
///
/// ```text
/// Vary = "*" / 1#field-name
/// ```
///
/// # Example values
///
/// * `accept-encoding, accept-language`
///
/// # Example
///
/// ```
/// use rama_http_headers::Vary;
///
/// let vary = Vary::any();
/// ```
#[derive(Clone, Debug)]
pub struct Vary(Directive);

#[derive(Clone, Debug)]
enum Directive {
    Any,
    Headers(NonEmptyVec<HeaderName>),
}

impl TryFrom<&Directive> for HeaderValue {
    type Error = OpaqueError;

    fn try_from(value: &Directive) -> Result<Self, Self::Error> {
        match value {
            Directive::Any => Ok(DIRECTIVE_HEADER_VALUE_ANY),
            Directive::Headers(values) => {
                try_encode_non_empty_vec_as_flat_csv_header_value(values, FlatCsvSeparator::Comma)
            }
        }
    }
}

impl TryFromValues for Directive {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        match try_decode_flat_csv_header_values_as_non_empty_vec(values, FlatCsvSeparator::Comma) {
            Ok(values) => {
                if values.len() == 1 && values.first() == "*" {
                    Ok(Self::Any)
                } else {
                    Ok(Self::Headers(values))
                }
            }
            Err(err) => {
                tracing::trace!("invalid vary directive: {err}");
                Err(crate::Error::invalid())
            }
        }
    }
}

const DIRECTIVE_HEADER_VALUE_ANY: HeaderValue = HeaderValue::from_static("*");

impl crate::TypedHeader for Vary {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::VARY
    }
}

impl crate::HeaderDecode for Vary {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        Directive::try_from_values(values).map(Self)
    }
}

impl crate::HeaderEncode for Vary {
    fn encode<E: Extend<::rama_http_types::HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                rama_core::telemetry::tracing::debug!(
                    "failed to encode vary directive {:?} as flat csv header: {err}",
                    self.0,
                );
            }
        }
    }
}

impl Vary {
    /// Create a new `Vary: *` header.
    #[must_use]
    pub const fn any() -> Self {
        Self(Directive::Any)
    }

    /// Creates a new `Vary` header with the request headers that may be involved in a CORS preflight request.
    #[must_use]
    #[inline(always)]
    pub fn preflight_request_headers() -> Self {
        Self::headers(non_empty_vec![
            header::ORIGIN,
            header::ACCESS_CONTROL_REQUEST_METHOD,
            header::ACCESS_CONTROL_REQUEST_HEADERS,
        ])
    }

    /// Create a new `Vary` header for the given header (CS) names.
    #[must_use]
    pub fn headers(values: NonEmptyVec<HeaderName>) -> Self {
        Self(Directive::Headers(values))
    }

    /// Check if this includes `*`.
    pub const fn is_any(&self) -> bool {
        matches!(&self.0, Directive::Any)
    }

    /// Iterate the header names of this `Vary`
    /// or `None` if it was an 'any' vary header.
    pub fn iter_strs(&self) -> Option<impl Iterator<Item = &HeaderName>> {
        match &self.0 {
            Directive::Any => None,
            Directive::Headers(non_empty_vec) => Some(non_empty_vec.iter()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn any_is_any() {
        assert!(Vary::any().is_any());
    }

    #[test]
    fn decode_header_single_open() {
        let Vary(directive) = test_decode(&["foo, bar"]).unwrap();
        match directive {
            Directive::Any => panic!("unexpected any directive"),
            Directive::Headers(non_empty_vec) => {
                assert_eq!(2, non_empty_vec.len());
                assert_eq!(non_empty_vec[0], "foo");
                assert_eq!(non_empty_vec[1], "bar");
            }
        }
    }

    #[test]
    fn decode_header_single_close() {
        let Vary(directive) = test_decode(&["*"]).unwrap();
        match directive {
            Directive::Any => (),
            Directive::Headers(non_empty_vec) => {
                panic!("unexpected headers directive, headers: {non_empty_vec:?}")
            }
        }
    }

    #[test]
    fn encode_headers() {
        let vary = Vary::headers(non_empty_vec![
            ::rama_http_types::header::USER_AGENT,
            ::rama_http_types::header::CONTENT_ENCODING,
        ]);

        let headers = test_encode(vary);
        assert_eq!(headers["vary"], "user-agent, content-encoding");
    }

    #[test]
    fn decode_with_empty_header_value() {
        assert!(test_decode::<Vary>(&[""]).is_none());
    }

    #[test]
    fn decode_with_no_headers() {
        assert!(test_decode::<Vary>(&[]).is_none());
    }

    #[test]
    fn decode_with_invalid_value_str() {
        assert!(test_decode::<Vary>(&["foo foo, bar"]).is_none());
    }
}
