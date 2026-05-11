use serde::de::{Error as _, IntoDeserializer, Visitor};

use crate::{
    XpcMessage,
    xpc_serde::types::{err::DeError, map::MapDe, seq::SeqDe, variant::EnumDe},
};

pub(crate) struct XpcDeserializer(pub(crate) XpcMessage);

impl<'de> serde::Deserializer<'de> for XpcDeserializer {
    type Error = DeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Null => visitor.visit_unit(),
            XpcMessage::Bool(b) => visitor.visit_bool(b),
            XpcMessage::Int64(i) => visitor.visit_i64(i),
            XpcMessage::Uint64(u) => visitor.visit_u64(u),
            XpcMessage::Double(f) => visitor.visit_f64(f),
            XpcMessage::String(s) => visitor.visit_string(s),
            XpcMessage::Data(b) => visitor.visit_byte_buf(b),
            XpcMessage::Array(a) => visitor.visit_seq(SeqDe::new(a)),
            XpcMessage::Dictionary(m) => visitor.visit_map(MapDe::new(m)),
            XpcMessage::Uuid(u) => visitor.visit_byte_buf(u.to_vec()),
            XpcMessage::Date(d) => visitor.visit_i64(d),
            other => Err(DeError::custom(format!(
                "cannot deserialize XPC variant {other:?} via deserialize_any"
            ))),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Bool(b) => visitor.visit_bool(b),
            other => Err(DeError::custom(format!("expected Bool, got {other:?}"))),
        }
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_i64(visitor)
    }
    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_i64(visitor)
    }
    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_i64(visitor)
    }
    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Int64(i) => visitor.visit_i64(i),
            XpcMessage::Uint64(u) => visitor.visit_u64(u),
            other => Err(DeError::custom(format!("expected integer, got {other:?}"))),
        }
    }
    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Int64(i) => visitor.visit_i128(i as i128),
            XpcMessage::Uint64(u) => visitor.visit_u128(u as u128),
            XpcMessage::String(s) => {
                let n: i128 = s
                    .parse()
                    .map_err(|_e| DeError::custom(format!("cannot parse {s:?} as i128")))?;
                visitor.visit_i128(n)
            }
            other => Err(DeError::custom(format!("expected integer, got {other:?}"))),
        }
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_u64(visitor)
    }
    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_u64(visitor)
    }
    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_u64(visitor)
    }
    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Uint64(u) => visitor.visit_u64(u),
            XpcMessage::Int64(i) => visitor.visit_i64(i),
            other => Err(DeError::custom(format!(
                "expected unsigned integer, got {other:?}"
            ))),
        }
    }
    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Uint64(u) => visitor.visit_u128(u as u128),
            XpcMessage::Int64(i) => visitor.visit_i128(i as i128),
            XpcMessage::String(s) => {
                let n: u128 = s
                    .parse()
                    .map_err(|_e| DeError::custom(format!("cannot parse {s:?} as u128")))?;
                visitor.visit_u128(n)
            }
            other => Err(DeError::custom(format!("expected integer, got {other:?}"))),
        }
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_f64(visitor)
    }
    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Double(f) => visitor.visit_f64(f),
            XpcMessage::Int64(i) => visitor.visit_f64(i as f64),
            XpcMessage::Uint64(u) => visitor.visit_f64(u as f64),
            other => Err(DeError::custom(format!("expected Double, got {other:?}"))),
        }
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::String(s) => {
                let mut chars = s.chars();
                match (chars.next(), chars.next()) {
                    (Some(c), None) => visitor.visit_char(c),
                    _ => Err(DeError::custom(format!(
                        "expected single-char string, got {s:?}"
                    ))),
                }
            }
            other => Err(DeError::custom(format!(
                "expected String for char, got {other:?}"
            ))),
        }
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_string(visitor)
    }
    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::String(s) => visitor.visit_string(s),
            other => Err(DeError::custom(format!("expected String, got {other:?}"))),
        }
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_byte_buf(visitor)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Data(b) => visitor.visit_byte_buf(b),
            XpcMessage::Uuid(u) => visitor.visit_byte_buf(u.to_vec()),
            other => Err(DeError::custom(format!("expected Data, got {other:?}"))),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Null => visitor.visit_none(),
            other => visitor.visit_some(Self(other)),
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Array(a) => visitor.visit_seq(SeqDe::new(a)),
            other => Err(DeError::custom(format!("expected Array, got {other:?}"))),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::Dictionary(m) => visitor.visit_map(MapDe::new(m)),
            other => Err(DeError::custom(format!(
                "expected Dictionary, got {other:?}"
            ))),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self.0 {
            XpcMessage::String(s) => visitor.visit_enum(s.into_deserializer()),
            XpcMessage::Dictionary(mut map) => {
                let Some((variant, value)) = map.pop_first() else {
                    return Err(DeError::custom(
                        "expected single-key Dictionary for enum: no entries found",
                    ));
                };
                if !map.is_empty() {
                    return Err(DeError::custom(
                        "expected single-key Dictionary for enum: too many entries found",
                    ));
                }
                visitor.visit_enum(EnumDe { variant, value })
            }
            _ => Err(DeError::custom(
                "expected String or single-key Dictionary for enum",
            )),
        }
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_unit()
    }
}
