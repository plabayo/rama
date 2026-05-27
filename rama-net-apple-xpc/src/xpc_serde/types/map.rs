use std::collections::BTreeMap;

use serde::{
    de::{self, Error as _, IntoDeserializer as _},
    ser::Error as _,
};

use crate::{
    XpcMessage,
    xpc_serde::types::{
        de::XpcDeserializer,
        err::{DeError, SerError},
        ser::XpcSerializer,
    },
};

pub(crate) struct MapSer {
    map: BTreeMap<String, XpcMessage>,
    pending_key: Option<String>,
}

impl MapSer {
    pub(crate) fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            pending_key: None,
        }
    }
}

impl serde::ser::SerializeMap for MapSer {
    type Ok = XpcMessage;
    type Error = SerError;

    fn serialize_key<T: serde::Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Self::Error> {
        let k = match key.serialize(XpcSerializer)? {
            XpcMessage::String(s) => s,
            other => {
                return Err(SerError::custom(format!(
                    "XPC dictionary keys must be strings, got {other:?}"
                )));
            }
        };
        self.pending_key = Some(k);
        Ok(())
    }

    fn serialize_value<T: serde::Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), Self::Error> {
        let key = self.pending_key.take().ok_or_else(|| {
            SerError::custom("serialize_value called without a preceding serialize_key")
        })?;
        self.map.insert(key, value.serialize(XpcSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(XpcMessage::Dictionary(self.map))
    }
}

impl serde::ser::SerializeStruct for MapSer {
    type Ok = XpcMessage;
    type Error = SerError;

    fn serialize_field<T: serde::Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.map
            .insert(key.to_owned(), value.serialize(XpcSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(XpcMessage::Dictionary(self.map))
    }
}

pub(crate) struct MapDe {
    iter: std::collections::btree_map::IntoIter<String, XpcMessage>,
    value: Option<XpcMessage>,
}

impl MapDe {
    pub(crate) fn new(m: BTreeMap<String, XpcMessage>) -> Self {
        Self {
            iter: m.into_iter(),
            value: None,
        }
    }
}

impl<'de> de::MapAccess<'de> for MapDe {
    type Error = DeError;

    fn next_key_seed<K: de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        match self.iter.next() {
            Some((k, v)) => {
                self.value = Some(v);
                seed.deserialize(k.into_deserializer()).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V: de::DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        let val = self
            .value
            .take()
            .ok_or_else(|| DeError::custom("next_value_seed called before next_key_seed"))?;
        seed.deserialize(XpcDeserializer(val))
    }
}
