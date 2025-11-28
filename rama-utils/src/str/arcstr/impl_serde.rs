use super::ArcStr;
use super::Substr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::marker::PhantomData;

impl Serialize for ArcStr {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self)
    }
}

impl<'de> Deserialize<'de> for ArcStr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(StrVisitor::<Self>(PhantomData))
    }
}

impl Serialize for Substr {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self)
    }
}

impl<'de> Deserialize<'de> for Substr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(StrVisitor::<Self>(PhantomData))
    }
}

struct StrVisitor<StrTy>(PhantomData<fn() -> StrTy>);

impl<'de, StrTy> de::Visitor<'de> for StrVisitor<StrTy>
where
    for<'a> &'a str: Into<StrTy>,
{
    type Value = StrTy;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a string")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        match std::str::from_utf8(v) {
            Ok(s) => Ok(s.into()),
            Err(_) => Err(de::Error::invalid_value(de::Unexpected::Bytes(v), &self)),
        }
    }
}
