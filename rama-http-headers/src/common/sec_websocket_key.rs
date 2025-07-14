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

impl crate::Header for SecWebsocketKey {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::SEC_WEBSOCKET_KEY
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        let value = crate::util::TryFromValues::try_from_values(values).map(SecWebsocketKey)?;
        let mut k = [0u8; 16];
        if STANDARD.decode_slice(value.0.as_bytes(), &mut k[..]).ok() != Some(16) {
            Err(crate::Error::invalid())
        } else {
            Ok(value)
        }
    }

    fn encode<E: Extend<::rama_http_types::HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once((&self.0).into()));
    }
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
