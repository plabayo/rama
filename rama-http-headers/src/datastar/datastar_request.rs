use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};
use rama_core::telemetry::tracing;
use rama_http_types::{HeaderName, HeaderValue};

/// `Datastar-Request` header, sent by the [🚀 Datastar](https://data-star.dev/)
/// client on every request it makes (e.g. through `@get` or `@post` actions).
///
/// Servers use it to tell Datastar fetches apart from regular browser
/// navigations, e.g. to reply with a `401` instead of a redirect
/// to a sign-in page, or to only read Datastar signals when present.
///
/// Datastar always sends the value `true`, but this header is treated as a
/// presence marker: decoding succeeds for any value, as the mere presence of
/// the header is what identifies a Datastar request. Encoding always writes `true`.
///
/// # Example values
/// * "true"
///
/// # Examples
///
/// ```
/// use rama_http_headers::{DatastarRequest, HeaderMapExt};
/// use rama_http_types::HeaderMap;
///
/// let mut headers = HeaderMap::new();
/// assert!(headers.typed_get::<DatastarRequest>().is_none());
///
/// headers.typed_insert(DatastarRequest::new());
/// assert!(headers.typed_get::<DatastarRequest>().is_some());
/// ```
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct DatastarRequest;

impl DatastarRequest {
    /// Create a new [`DatastarRequest`] typed header.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl TypedHeader for DatastarRequest {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::DATASTAR_REQUEST
    }
}

impl HeaderDecode for DatastarRequest {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(Error::invalid)?;
        if value != "true" {
            tracing::trace!(
                "unexpected Datastar-Request header value {value:?}; only true is expected, treating it as present anyway"
            );
        }
        Ok(Self)
    }
}

impl HeaderEncode for DatastarRequest {
    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let value = HeaderValue::from_static("true");
        values.extend(std::iter::once(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderMapExt;
    use rama_http_types::HeaderMap;

    fn decode(values: &[&str]) -> Option<DatastarRequest> {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(DatastarRequest::name(), value.parse().unwrap());
        }
        map.typed_get()
    }

    #[test]
    fn decode_true() {
        assert_eq!(decode(&["true"]), Some(DatastarRequest));
    }

    #[test]
    fn decode_any_value_is_present() {
        for value in ["True", "1", "false", ""] {
            assert_eq!(decode(&[value]), Some(DatastarRequest), "value: {value:?}");
        }
    }

    #[test]
    fn decode_multiple_values() {
        assert_eq!(decode(&["true", "true"]), Some(DatastarRequest));
    }

    #[test]
    fn decode_absent() {
        assert_eq!(decode(&[]), None);
    }

    #[test]
    fn encode_writes_true() {
        let mut map = HeaderMap::new();
        map.typed_insert(DatastarRequest::new());
        assert_eq!(map.get(DatastarRequest::name()).unwrap(), "true");
        assert_eq!(map.typed_get::<DatastarRequest>(), Some(DatastarRequest));
    }
}
