use rama_http_types::{
    HeaderName, HeaderValue,
    structured_fields::{BareItem, parse_item},
};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader, util::single_value};

/// The `Sec-Fetch-User` [fetch metadata request header][mdn].
///
/// Sent by browsers on a navigation triggered by user activation, such as a
/// click or a key press. It is a Structured Field Boolean that browsers only
/// ever send as `?1` and omit otherwise, so its presence is the signal.
///
/// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-User
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SecFetchUser;

impl TypedHeader for SecFetchUser {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::SEC_FETCH_USER
    }
}

impl HeaderDecode for SecFetchUser {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = single_value(values)?;
        // Browsers omit the header rather than send `?0`.
        match parse_item(value.as_bytes()) {
            Ok(BareItem::Boolean(true)) => Ok(Self),
            _ => Err(Error::invalid()),
        }
    }
}

impl HeaderEncode for SecFetchUser {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(std::iter::once(HeaderValue::from_static("?1")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    #[test]
    fn decodes_true_only() {
        assert_eq!(test_decode::<SecFetchUser>(&["?1"]), Some(SecFetchUser));
        assert_eq!(test_decode::<SecFetchUser>(&["?0"]), None);
        assert_eq!(test_decode::<SecFetchUser>(&["1"]), None);
        assert_eq!(test_decode::<SecFetchUser>(&["true"]), None);
        assert_eq!(test_decode::<SecFetchUser>(&[""]), None);
    }

    #[test]
    fn rejects_multiple_lines() {
        assert_eq!(test_decode::<SecFetchUser>(&["?1", "?1"]), None);
    }

    #[test]
    fn encode_round_trip() {
        let headers = test_encode(SecFetchUser);
        assert_eq!(headers["sec-fetch-user"], "?1");
        assert_eq!(test_decode::<SecFetchUser>(&["?1"]), Some(SecFetchUser));
    }
}
