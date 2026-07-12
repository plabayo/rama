//! Native XPC data support for typed Serde routes.

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};

pub(crate) const XPC_DATA_NEWTYPE_NAME: &str = "$xpc::Data";

/// Bytes encoded as [`crate::XpcMessage::Data`] instead of an integer array.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XpcData(pub Vec<u8>);

impl XpcData {
    #[inline]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for XpcData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        struct Bytes<'a>(&'a [u8]);

        impl Serialize for Bytes<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(self.0)
            }
        }

        serializer.serialize_newtype_struct(XPC_DATA_NEWTYPE_NAME, &Bytes(&self.0))
    }
}

impl<'de> Deserialize<'de> for XpcData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DataVisitor;

        impl<'de> Visitor<'de> for DataVisitor {
            type Value = XpcData;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("native XPC data")
            }

            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(XpcData(value.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                Ok(XpcData(value))
            }

            fn visit_borrowed_bytes<E: de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.visit_bytes(value)
            }
        }

        deserializer.deserialize_newtype_struct(XPC_DATA_NEWTYPE_NAME, DataVisitor)
    }
}
