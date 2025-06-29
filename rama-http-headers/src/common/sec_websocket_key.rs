use base64::{Engine, engine::general_purpose::STANDARD};
use rama_http_types::HeaderValue;

/// The `Sec-Websocket-Key` header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecWebsocketKey(pub(super) HeaderValue);

impl SecWebsocketKey {
    pub fn random() -> Self {
        let r: [u8; 16] = rand::random();
        r.into()
    }
}

derive_header! {
    SecWebsocketKey(_),
    name: SEC_WEBSOCKET_KEY
}

impl From<[u8; 16]> for SecWebsocketKey {
    fn from(bytes: [u8; 16]) -> Self {
        let mut value = HeaderValue::try_from(STANDARD.encode(bytes)).unwrap();
        value.set_sensitive(true);
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes() {
        let bytes: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let _ = SecWebsocketKey::from(bytes);
    }
}
