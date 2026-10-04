use rama_http_types::{HeaderName, HeaderValue};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// The `Sec-WebSocket-Version` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SecWebSocketVersion(u8);

impl SecWebSocketVersion {
    /// `Sec-WebSocket-Version: 13`
    pub const V13: Self = Self(13);
}

impl TypedHeader for SecWebSocketVersion {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::SEC_WEBSOCKET_VERSION
    }
}

impl HeaderDecode for SecWebSocketVersion {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        // RFC 6455 §11.3.5: a request carries it once.
        let value = crate::util::single_value(values)?;
        if value == "13" {
            Ok(Self::V13)
        } else {
            Err(Error::invalid())
        }
    }
}

impl HeaderEncode for SecWebSocketVersion {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        debug_assert_eq!(self.0, 13);

        values.extend(::std::iter::once(HeaderValue::from_static("13")));
    }
}

#[cfg(test)]
mod tests {
    use super::SecWebSocketVersion;
    use crate::common::{test_decode, test_encode};

    /// RFC 6455 §11.3.5: a request carries its version once.
    #[test]
    fn version_appears_once() {
        assert_eq!(
            test_decode::<SecWebSocketVersion>(&["13"]),
            Some(SecWebSocketVersion::V13)
        );
        assert_eq!(test_decode::<SecWebSocketVersion>(&["13", "8"]), None);
        assert_eq!(test_decode::<SecWebSocketVersion>(&["13", "13"]), None);
    }

    #[test]
    fn decode_v13() {
        assert_eq!(
            test_decode::<SecWebSocketVersion>(&["13"]),
            Some(SecWebSocketVersion::V13),
        );
    }

    #[test]
    fn decode_fail() {
        assert_eq!(test_decode::<SecWebSocketVersion>(&["1"]), None,);
    }

    #[test]
    fn encode_v13() {
        let headers = test_encode(SecWebSocketVersion::V13);
        assert_eq!(headers["sec-websocket-version"], "13");
    }
}
