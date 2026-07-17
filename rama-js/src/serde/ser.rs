use serde::Serialize;
use serde::ser::{Impossible, SerializeSeq};

use super::{MAX_SAFE_INTEGER, SerdeError};
use crate::value::{JsStr, JsValue};

pub(super) struct ValueSerializer;

fn int_to_number(n: i128) -> Result<JsValue, SerdeError> {
    if n.unsigned_abs() <= u128::from(MAX_SAFE_INTEGER) {
        Ok(JsValue::Number(n as f64))
    } else {
        Err(SerdeError(format!(
            "integer {n} cannot be represented exactly as a js number"
        )))
    }
}

impl serde::Serializer for ValueSerializer {
    type Ok = JsValue;
    type Error = SerdeError;

    type SerializeSeq = SeqSerializer;
    type SerializeTuple = SeqSerializer;
    type SerializeTupleStruct = SeqSerializer;
    type SerializeTupleVariant = VariantSeqSerializer;
    type SerializeMap = MapSerializer;
    type SerializeStruct = MapSerializer;
    type SerializeStructVariant = VariantMapSerializer;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::Bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::from(v))
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::from(v))
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::from(v))
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        int_to_number(i128::from(v))
    }

    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        int_to_number(v)
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::from(v))
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::from(v))
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::from(v))
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        int_to_number(i128::from(v))
    }

    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        i128::try_from(v)
            .map_err(|_err| {
                SerdeError(format!(
                    "integer {v} cannot be represented exactly as a js number"
                ))
            })
            .and_then(int_to_number)
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::from(v))
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::Number(v))
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::from(v))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::from(v))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::Array(v.iter().copied().collect()))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::Null)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::Null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::from(variant))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        let value = value.serialize(Self)?;
        Ok(JsValue::Object([(variant, value)].into_iter().collect()))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(SeqSerializer {
            values: Vec::with_capacity(len.unwrap_or_default()),
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(VariantSeqSerializer {
            variant,
            values: Vec::with_capacity(len),
        })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(MapSerializer {
            entries: Vec::with_capacity(len.unwrap_or_default()),
            pending_key: None,
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(VariantMapSerializer {
            variant,
            entries: Vec::with_capacity(len),
        })
    }
}

pub(super) struct SeqSerializer {
    values: Vec<JsValue>,
}

impl serde::ser::SerializeSeq for SeqSerializer {
    type Ok = JsValue;
    type Error = SerdeError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.values.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::Array(self.values.into()))
    }
}

impl serde::ser::SerializeTuple for SeqSerializer {
    type Ok = JsValue;
    type Error = SerdeError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self)
    }
}

impl serde::ser::SerializeTupleStruct for SeqSerializer {
    type Ok = JsValue;
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self)
    }
}

pub(super) struct VariantSeqSerializer {
    variant: &'static str,
    values: Vec<JsValue>,
}

impl serde::ser::SerializeTupleVariant for VariantSeqSerializer {
    type Ok = JsValue;
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.values.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::Object(
            [(self.variant, JsValue::Array(self.values.into()))]
                .into_iter()
                .collect(),
        ))
    }
}

pub(super) struct MapSerializer {
    entries: Vec<(JsStr, JsValue)>,
    pending_key: Option<JsStr>,
}

impl serde::ser::SerializeMap for MapSerializer {
    type Ok = JsValue;
    type Error = SerdeError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.pending_key = Some(key.serialize(KeySerializer)?);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        let key = self
            .pending_key
            .take()
            .ok_or_else(|| SerdeError("serialize_value called before serialize_key".to_owned()))?;
        self.entries.push((key, value.serialize(ValueSerializer)?));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::Object(self.entries.into_iter().collect()))
    }
}

impl serde::ser::SerializeStruct for MapSerializer {
    type Ok = JsValue;
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.entries
            .push((key.into(), value.serialize(ValueSerializer)?));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(JsValue::Object(self.entries.into_iter().collect()))
    }
}

pub(super) struct VariantMapSerializer {
    variant: &'static str,
    entries: Vec<(JsStr, JsValue)>,
}

impl serde::ser::SerializeStructVariant for VariantMapSerializer {
    type Ok = JsValue;
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.entries
            .push((key.into(), value.serialize(ValueSerializer)?));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let inner = JsValue::Object(self.entries.into_iter().collect());
        Ok(JsValue::Object(
            [(self.variant, inner)].into_iter().collect(),
        ))
    }
}

/// Serializer for map keys: only string-like and integer keys are supported.
pub(super) struct KeySerializer;

macro_rules! impl_key_int {
    ($($method:ident: $t:ty),+ $(,)?) => {
        $(
            fn $method(self, v: $t) -> Result<Self::Ok, Self::Error> {
                Ok(JsStr::from(v.to_string()))
            }
        )+
    };
}

impl serde::Serializer for KeySerializer {
    type Ok = JsStr;
    type Error = SerdeError;

    type SerializeSeq = Impossible<JsStr, SerdeError>;
    type SerializeTuple = Impossible<JsStr, SerdeError>;
    type SerializeTupleStruct = Impossible<JsStr, SerdeError>;
    type SerializeTupleVariant = Impossible<JsStr, SerdeError>;
    type SerializeMap = Impossible<JsStr, SerdeError>;
    type SerializeStruct = Impossible<JsStr, SerdeError>;
    type SerializeStructVariant = Impossible<JsStr, SerdeError>;

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        Ok(JsStr::from(v))
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        Ok(JsStr::from(v))
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(JsStr::new_static(variant))
    }

    impl_key_int!(
        serialize_i8: i8,
        serialize_i16: i16,
        serialize_i32: i32,
        serialize_i64: i64,
        serialize_i128: i128,
        serialize_u8: u8,
        serialize_u16: u16,
        serialize_u32: u32,
        serialize_u64: u64,
        serialize_u128: u128,
    );

    fn serialize_bool(self, _: bool) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_f32(self, _: f32) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_f64(self, _: f64) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_bytes(self, _: &[u8]) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(SerdeError("map keys must be strings".to_owned()))
    }
}
