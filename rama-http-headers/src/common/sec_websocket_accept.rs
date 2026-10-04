use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;
use rama_core::bytes::Bytes;
use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::HeaderValue;
use sha1::{Digest, Sha1};

use super::SecWebSocketKey;

/// The `Sec-WebSocket-Accept` header.
///
/// This header is used in the WebSocket handshake, sent back by the
/// server indicating a successful handshake. It is a signature
/// of the `Sec-WebSocket-Key` header.
///
/// # Example
///
/// ```no_run
/// use rama_http_headers::{SecWebSocketAccept, SecWebSocketKey};
///
/// let sec_key: SecWebSocketKey = /* from request headers */
/// #    unimplemented!();
///
/// let sec_accept = SecWebSocketAccept::try_from(sec_key).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecWebSocketAccept(HeaderValue);

impl crate::TypedHeader for SecWebSocketAccept {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::SEC_WEBSOCKET_ACCEPT
    }
}

impl crate::HeaderDecode for SecWebSocketAccept {
    // RFC 6455 §11.3.3: it appears only once in a response.
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        crate::util::single_value(values).map(Self)
    }
}

impl crate::HeaderEncode for SecWebSocketAccept {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(self.0.clone()));
    }
}

impl TryFrom<SecWebSocketKey> for SecWebSocketAccept {
    type Error = BoxError;

    fn try_from(key: SecWebSocketKey) -> Result<Self, Self::Error> {
        try_sign(key.0.as_bytes())
    }
}

fn try_sign(key: &[u8]) -> Result<SecWebSocketAccept, BoxError> {
    let mut sha1 = Sha1::default();
    sha1.update(key);
    sha1.update(&b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"[..]);
    let b64 = Bytes::from(ENGINE.encode(sha1.finalize()));

    let val =
        HeaderValue::from_maybe_shared(b64).context("create header value from base64 signature")?;

    Ok(SecWebSocketAccept(val))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    /// RFC 6455 §11.3.1 and §11.3.3: the key and the accept each appear only once, so a second
    /// line, even an equal one, makes either invalid.
    #[test]
    fn key_and_accept_appear_once() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert!(test_decode::<SecWebSocketKey>(&[key]).is_some());
        assert!(test_decode::<SecWebSocketKey>(&[key, key]).is_none());
        let accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert!(test_decode::<SecWebSocketAccept>(&[accept]).is_some());
        assert!(test_decode::<SecWebSocketAccept>(&[accept, accept]).is_none());
    }

    #[test]
    fn key_to_accept() {
        // From https://tools.ietf.org/html/rfc6455#section-1.2
        let key = test_decode::<SecWebSocketKey>(&["dGhlIHNhbXBsZSBub25jZQ=="]).expect("key");
        let accept = SecWebSocketAccept::try_from(key).unwrap();
        let headers = test_encode(accept);

        assert_eq!(
            headers["sec-websocket-accept"],
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
