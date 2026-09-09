//! Serialize byte fields as base64 strings.
//! Serialization borrows the bytes without allocating an intermediate string.
//! Owned deserialization allocates only its decoded output. Large capture payloads
//! should use a raw record stream instead of an owned Serde field.

use core::{fmt, marker::PhantomData};

use base64::{Engine as _, display::Base64Display, engine::general_purpose::STANDARD};
use serde::{
    Deserializer, Serializer,
    de::{Error, Visitor},
};

use crate::std::Vec;

pub fn serialize<S: Serializer, B: AsRef<[u8]> + ?Sized>(
    bytes: &B,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&Base64Display::new(bytes.as_ref(), &STANDARD))
}

pub fn deserialize<'de, D: Deserializer<'de>, B: From<Vec<u8>>>(
    deserializer: D,
) -> Result<B, D::Error> {
    struct BytesVisitor<B>(PhantomData<B>);
    impl<'de, B: From<Vec<u8>>> Visitor<'de> for BytesVisitor<B> {
        type Value = B;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a base64 string")
        }

        fn visit_str<E: Error>(self, value: &str) -> Result<B, E> {
            STANDARD.decode(value).map(B::from).map_err(E::custom)
        }
    }
    deserializer.deserialize_str(BytesVisitor(PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Payload(#[serde(with = "super")] Vec<u8>);
    #[test]
    fn compact_owned_bytes_round_trip() {
        let bytes = Payload(Vec::from(&b"hello\0\xff"[..]));
        let json = serde_json::to_string(&bytes).unwrap();
        assert_eq!(json, "\"aGVsbG8A/w==\"");
        assert_eq!(serde_json::from_str::<Payload>(&json).unwrap(), bytes);
        serde_json::from_str::<Payload>("\"invalid!\"").unwrap_err();
    }
}
