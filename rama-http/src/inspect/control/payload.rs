//! Borrowed serialization for editable payloads on upgraded connections.

use rama_core::bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Payload bytes retain their encoding so editing and storage do not require a
/// temporary UTF-8 or base64 string. Text is supplied through a string type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    #[serde(with = "rama_utils::bytes::serde_base64")]
    bytes: Bytes,
    binary: bool,
}

impl Payload {
    pub fn text(text: impl AsRef<str> + Into<Bytes>) -> Self {
        Self {
            bytes: text.into(),
            binary: false,
        }
    }

    pub fn binary(bytes: Bytes) -> Self {
        Self {
            bytes,
            binary: true,
        }
    }

    pub(crate) fn replace_bytes(&mut self, bytes: Bytes) -> Bytes {
        std::mem::replace(&mut self.bytes, bytes)
    }

    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    pub fn is_binary(&self) -> bool {
        self.binary
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Display for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.binary {
            write!(f, "{}", rama_utils::fmt::hex(&self.bytes))
        } else {
            write!(f, "{}", rama_utils::fmt::utf8_or_hex(&self.bytes))
        }
    }
}

#[expect(
    clippy::ref_option,
    reason = "Serde serialize_with receives a reference to the field"
)]
pub(super) fn serialize_editor<S: serde::Serializer>(
    payload: &Option<Payload>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match payload {
        None => serializer.serialize_none(),
        Some(payload) if payload.binary => {
            serializer.collect_str(&base64::display::Base64Display::new(
                &payload.bytes,
                &base64::engine::general_purpose::STANDARD,
            ))
        }
        Some(payload) => serializer
            .serialize_str(std::str::from_utf8(&payload.bytes).map_err(serde::ser::Error::custom)?),
    }
}
