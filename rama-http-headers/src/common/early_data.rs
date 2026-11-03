//! The `Early-Data` request header (RFC 8470 §5.1).

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};
use rama_http_types::{HeaderName, HeaderValue, header};

/// A request might have been replayed on an earlier hop.
///
/// Presence carries the entire signal: even empty, invalid or repeated values
/// decode to this marker. Absence is distinct from any present value. Encoding
/// produces `Early-Data: 1`; forwarding proxies should preserve received values.
///
/// Completing a later hop's handshake does not remove the replay exposure.
/// This field belongs in request heads, never responses or request trailers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct EarlyData;

impl TypedHeader for EarlyData {
    fn name() -> &'static HeaderName {
        &header::EARLY_DATA
    }
}

impl HeaderDecode for EarlyData {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values.next().map(|_| Self).ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for EarlyData {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(std::iter::once(HeaderValue::from_static("1")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderMapExt;
    use rama_http_types::HeaderMap;

    #[test]
    fn any_present_value_marks_early_data() {
        let mut headers = HeaderMap::new();
        assert_eq!(headers.typed_try_get::<EarlyData>().unwrap(), None);
        for value in [b"1".as_slice(), b"0", b"", b"1, 1", b"invalid", b"\xff"] {
            headers.insert(header::EARLY_DATA, HeaderValue::from_bytes(value).unwrap());
            assert_eq!(
                headers.typed_try_get::<EarlyData>().unwrap(),
                Some(EarlyData)
            );
            headers.append(header::EARLY_DATA, HeaderValue::from_static("0"));
            assert_eq!(
                headers.typed_try_get::<EarlyData>().unwrap(),
                Some(EarlyData)
            );
        }
    }

    #[test]
    fn encodes_single_canonical_value() {
        let mut headers = HeaderMap::new();
        headers.typed_insert(EarlyData);
        assert_eq!(headers[header::EARLY_DATA], "1");
        assert_eq!(headers.get_all(header::EARLY_DATA).iter().count(), 1);
    }
}
