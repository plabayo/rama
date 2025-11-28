use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;
use rama_core::bytes::Bytes;
use rama_error::{ErrorContext as _, OpaqueError};
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

derive_header! {
    SecWebSocketAccept(_),
    name: SEC_WEBSOCKET_ACCEPT
}

impl TryFrom<SecWebSocketKey> for SecWebSocketAccept {
    type Error = OpaqueError;

    fn try_from(key: SecWebSocketKey) -> Result<Self, Self::Error> {
        try_sign(key.0.as_bytes())
    }
}

fn try_sign(key: &[u8]) -> Result<SecWebSocketAccept, OpaqueError> {
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
    use super::super::{test_decode, test_encode};
    use super::*;

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
