use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;
use rama_core::bytes::Bytes;
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
/// let sec_accept = SecWebSocketAccept::from(sec_key);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecWebSocketAccept(HeaderValue);

derive_header! {
    SecWebSocketAccept(_),
    name: SEC_WEBSOCKET_ACCEPT
}

impl From<SecWebSocketKey> for SecWebSocketAccept {
    fn from(key: SecWebSocketKey) -> Self {
        sign(key.0.as_bytes())
    }
}

fn sign(key: &[u8]) -> SecWebSocketAccept {
    let mut sha1 = Sha1::default();
    sha1.update(key);
    sha1.update(&b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"[..]);
    let b64 = Bytes::from(ENGINE.encode(sha1.finalize()));

    let val = HeaderValue::from_maybe_shared(b64).expect("base64 is a valid value");

    SecWebSocketAccept(val)
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;

    #[test]
    fn key_to_accept() {
        // From https://tools.ietf.org/html/rfc6455#section-1.2
        let key = test_decode::<SecWebSocketKey>(&["dGhlIHNhbXBsZSBub25jZQ=="]).expect("key");
        let accept = SecWebSocketAccept::from(key);
        let headers = test_encode(accept);

        assert_eq!(
            headers["sec-websocket-accept"],
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
