//! [`XpcUuid`] — round-trippable UUID through [`crate::xpc_serde`].
//!
//! `XpcMessage::Uuid([u8; 16])` cannot be expressed faithfully via the default
//! Serde derive for a `[u8; 16]` field: Serde routes fixed-size byte arrays
//! through `deserialize_tuple` / `visit_seq`, which our serializer maps to
//! `XpcMessage::Array(16)`, not `Uuid`. [`XpcUuid`] is a newtype wrapper that
//! carries a magic newtype-struct name; [`XpcSerializer`](super::types::ser)
//! and [`XpcDeserializer`](super::types::de) recognise the name and route the
//! payload through the [`XpcMessage::Uuid`](crate::XpcMessage::Uuid) variant.
//!
//! Any other serializer/deserializer falls back to a plain bytes
//! representation, so `XpcUuid` is also safe to round-trip through e.g. JSON.

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};

/// Sentinel newtype-struct name used to signal `XpcUuid` to our custom
/// (de)serializer. Other serde backends ignore it and treat the value as
/// plain bytes.
pub(crate) const XPC_UUID_NEWTYPE_NAME: &str = "$xpc::Uuid";

/// A 16-byte XPC UUID that round-trips through [`crate::xpc_serde`] as an
/// [`XpcMessage::Uuid`](crate::XpcMessage::Uuid) variant rather than a 16-byte array.
///
/// Use this wrapper in place of `[u8; 16]` (or the `uuid` crate's `Uuid`) when
/// you want the value to be emitted as the native XPC UUID type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XpcUuid(pub [u8; 16]);

impl XpcUuid {
    /// Wrap a 16-byte array as an `XpcUuid`.
    #[inline]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw 16 bytes of this UUID.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for XpcUuid {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl From<XpcUuid> for [u8; 16] {
    fn from(uuid: XpcUuid) -> Self {
        uuid.0
    }
}

impl Serialize for XpcUuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Send the bytes through a dedicated newtype-struct so that XpcSerializer
        // can detect the marker name and emit `XpcMessage::Uuid`. Any other
        // serializer that ignores the marker still gets a bytes representation.
        struct Inner<'a>(&'a [u8; 16]);
        impl<'a> Serialize for Inner<'a> {
            fn serialize<S2: Serializer>(&self, s: S2) -> Result<S2::Ok, S2::Error> {
                s.serialize_bytes(self.0)
            }
        }
        serializer.serialize_newtype_struct(XPC_UUID_NEWTYPE_NAME, &Inner(&self.0))
    }
}

impl<'de> Deserialize<'de> for XpcUuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UuidVisitor;
        impl<'de> Visitor<'de> for UuidVisitor {
            type Value = XpcUuid;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 16-byte XPC UUID")
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                let arr: [u8; 16] = v
                    .try_into()
                    .map_err(|_e| E::custom("XpcUuid must be exactly 16 bytes"))?;
                Ok(XpcUuid(arr))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&v)
            }

            fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
                self.visit_bytes(v)
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut arr = [0u8; 16];
                for (i, slot) in arr.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &"16 bytes"))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::invalid_length(17, &"16 bytes"));
                }
                Ok(XpcUuid(arr))
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_bytes(self)
            }
        }

        deserializer.deserialize_newtype_struct(XPC_UUID_NEWTYPE_NAME, UuidVisitor)
    }
}
