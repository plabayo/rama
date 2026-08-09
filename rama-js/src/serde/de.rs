use serde::de::IntoDeserializer;

use super::{MAX_SAFE_INTEGER, SerdeError};
use crate::value::{JsStr, JsValue};

pub(super) struct ValueDeserializer(pub(super) JsValue);

impl<'de> serde::Deserializer<'de> for ValueDeserializer {
    type Error = SerdeError;

    fn deserialize_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self.0 {
            JsValue::Undefined | JsValue::Null => visitor.visit_unit(),
            JsValue::Bool(b) => visitor.visit_bool(b),
            JsValue::Number(n) => {
                if n == 0.0 && n.is_sign_negative() {
                    visitor.visit_f64(n)
                } else if n.fract() == 0.0 && n.is_finite() && n.abs() <= MAX_SAFE_INTEGER as f64 {
                    if n < 0.0 {
                        visitor.visit_i64(n as i64)
                    } else {
                        visitor.visit_u64(n as u64)
                    }
                } else {
                    visitor.visit_f64(n)
                }
            }
            JsValue::String(s) => visitor.visit_str(s.as_str()),
            JsValue::Array(arr) => visitor.visit_seq(SeqDeserializer {
                values: arr,
                index: 0,
            }),
            JsValue::Object(obj) => visitor.visit_map(MapDeserializer {
                entries: obj,
                index: 0,
                pending_value: None,
            }),
        }
    }

    fn deserialize_option<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        if self.0.is_null_or_undefined() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        if self.0.is_null_or_undefined() {
            visitor.visit_unit()
        } else {
            self.deserialize_any(visitor)
        }
    }

    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self.0 {
            JsValue::String(s) => visitor.visit_enum(String::from(s).into_deserializer()),
            JsValue::Object(obj) => {
                let (variant, value) = match (obj.len(), obj.iter().next()) {
                    (1, Some((variant, value))) => (variant.clone(), value.clone()),
                    _ => {
                        return Err(SerdeError(
                            "expected an object with a single variant key".to_owned(),
                        ));
                    }
                };
                visitor.visit_enum(EnumDeserializer { variant, value })
            }
            other => Err(SerdeError(format!(
                "expected a string or object for an enum, got {}",
                other.type_name()
            ))),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit_struct seq tuple tuple_struct map struct
        identifier ignored_any
    }
}

pub(super) struct SeqDeserializer {
    values: crate::value::JsArray,
    index: usize,
}

impl<'de> serde::de::SeqAccess<'de> for SeqDeserializer {
    type Error = SerdeError;

    fn next_element_seed<T: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        match self.values.get(self.index).cloned() {
            Some(value) => {
                self.index += 1;
                seed.deserialize(ValueDeserializer(value)).map(Some)
            }
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.values.len().saturating_sub(self.index))
    }
}

pub(super) struct MapDeserializer {
    entries: crate::value::JsObject,
    index: usize,
    pending_value: Option<JsValue>,
}

impl<'de> serde::de::MapAccess<'de> for MapDeserializer {
    type Error = SerdeError;

    fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        match self.entries.get_index(self.index) {
            Some((key, value)) => {
                self.index += 1;
                self.pending_value = Some(value.clone());
                seed.deserialize(MapKeyDeserializer(key.clone())).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        let value = self
            .pending_value
            .take()
            .ok_or_else(|| SerdeError("next_value called before next_key".to_owned()))?;
        seed.deserialize(ValueDeserializer(value))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len().saturating_sub(self.index))
    }
}

/// Object keys are always strings on the JS side; integer map keys
/// round-trip by parsing the decimal form the key serializer produced.
struct MapKeyDeserializer(JsStr);

macro_rules! deserialize_numeric_key {
    ($($method:ident => $visit:ident: $t:ty),+ $(,)?) => {
        $(
            fn $method<V: serde::de::Visitor<'de>>(
                self,
                visitor: V,
            ) -> Result<V::Value, Self::Error> {
                match self.0.as_str().parse::<$t>() {
                    Ok(n) => visitor.$visit(n),
                    Err(_) => visitor.visit_str(self.0.as_str()),
                }
            }
        )+
    };
}

impl<'de> serde::Deserializer<'de> for MapKeyDeserializer {
    type Error = SerdeError;

    fn deserialize_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_str(self.0.as_str())
    }

    deserialize_numeric_key! {
        deserialize_i8 => visit_i8: i8,
        deserialize_i16 => visit_i16: i16,
        deserialize_i32 => visit_i32: i32,
        deserialize_i64 => visit_i64: i64,
        deserialize_i128 => visit_i128: i128,
        deserialize_u8 => visit_u8: u8,
        deserialize_u16 => visit_u16: u16,
        deserialize_u32 => visit_u32: u32,
        deserialize_u64 => visit_u64: u64,
        deserialize_u128 => visit_u128: u128,
    }

    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_enum(String::from(self.0).into_deserializer())
    }

    serde::forward_to_deserialize_any! {
        bool f32 f64 char str string bytes byte_buf option unit unit_struct
        seq tuple tuple_struct map struct identifier ignored_any
    }
}

pub(super) struct EnumDeserializer {
    variant: JsStr,
    value: JsValue,
}

impl<'de> serde::de::EnumAccess<'de> for EnumDeserializer {
    type Error = SerdeError;
    type Variant = VariantDeserializer;

    fn variant_seed<V: serde::de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Self::Error> {
        let variant = seed.deserialize(ValueDeserializer(JsValue::String(self.variant)))?;
        Ok((variant, VariantDeserializer { value: self.value }))
    }
}

pub(super) struct VariantDeserializer {
    value: JsValue,
}

impl<'de> serde::de::VariantAccess<'de> for VariantDeserializer {
    type Error = SerdeError;

    fn unit_variant(self) -> Result<(), Self::Error> {
        if self.value.is_null_or_undefined() {
            Ok(())
        } else {
            Err(SerdeError(
                "expected no value for a unit variant".to_owned(),
            ))
        }
    }

    fn newtype_variant_seed<T: serde::de::DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Self::Error> {
        seed.deserialize(ValueDeserializer(self.value))
    }

    fn tuple_variant<V: serde::de::Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        serde::Deserializer::deserialize_any(ValueDeserializer(self.value), visitor)
    }

    fn struct_variant<V: serde::de::Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        serde::Deserializer::deserialize_any(ValueDeserializer(self.value), visitor)
    }
}
