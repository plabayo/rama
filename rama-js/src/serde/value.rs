use std::fmt;

use serde::{Deserialize, Serialize};

use crate::value::{JsArray, JsObject, JsStr, JsValue};

impl Serialize for JsStr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for JsStr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Into::into)
    }
}

impl Serialize for JsArray {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl Serialize for JsObject {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.iter())
    }
}

impl Serialize for JsValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Undefined | Self::Null => serializer.serialize_unit(),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Number(n) => serializer.serialize_f64(*n),
            Self::String(s) => s.serialize(serializer),
            Self::Array(arr) => arr.serialize(serializer),
            Self::Object(obj) => obj.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for JsValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ValueVisitor;

        impl<'de> serde::de::Visitor<'de> for ValueVisitor {
            type Value = JsValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("any js-compatible value")
            }

            fn visit_bool<E>(self, b: bool) -> Result<Self::Value, E> {
                Ok(JsValue::Bool(b))
            }

            fn visit_i64<E: serde::de::Error>(self, n: i64) -> Result<Self::Value, E> {
                JsValue::try_from(n).map_err(serde::de::Error::custom)
            }

            fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<Self::Value, E> {
                JsValue::try_from(n).map_err(serde::de::Error::custom)
            }

            fn visit_f64<E>(self, n: f64) -> Result<Self::Value, E> {
                Ok(JsValue::Number(n))
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E> {
                Ok(JsValue::String(s.into()))
            }

            fn visit_string<E>(self, s: String) -> Result<Self::Value, E> {
                Ok(JsValue::String(s.into()))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(JsValue::Null)
            }

            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                JsValue::deserialize(deserializer)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(JsValue::Null)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values: Vec<JsValue> = Vec::new();
                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }
                Ok(JsValue::Array(values.into()))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut entries: Vec<(JsStr, JsValue)> = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, JsValue>()? {
                    entries.push((key.into(), value));
                }
                Ok(JsValue::Object(entries.into_iter().collect()))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}
