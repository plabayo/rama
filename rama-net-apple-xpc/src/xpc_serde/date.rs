//! Native XPC date support for typed Serde routes.

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};

pub(crate) const XPC_DATE_NEWTYPE_NAME: &str = "$xpc::Date";

/// Nanoseconds since the Unix epoch encoded as [`crate::XpcMessage::Date`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XpcDate(pub i64);

impl XpcDate {
    #[inline]
    pub const fn from_unix_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    #[inline]
    pub const fn unix_nanos(self) -> i64 {
        self.0
    }
}

impl Serialize for XpcDate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_struct(XPC_DATE_NEWTYPE_NAME, &self.0)
    }
}

impl<'de> Deserialize<'de> for XpcDate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DateVisitor;

        impl<'de> Visitor<'de> for DateVisitor {
            type Value = XpcDate;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a native XPC date in Unix nanoseconds")
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(XpcDate(value))
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_i64(self)
            }
        }

        deserializer.deserialize_newtype_struct(XPC_DATE_NEWTYPE_NAME, DateVisitor)
    }
}
