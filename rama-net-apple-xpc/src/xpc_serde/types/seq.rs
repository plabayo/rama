use serde::de;

use crate::{
    XpcMessage,
    xpc_serde::types::{
        de::XpcDeserializer,
        err::{DeError, SerError},
        ser::XpcSerializer,
    },
};

pub(crate) struct SeqSer(pub(crate) Vec<XpcMessage>);

impl serde::ser::SerializeSeq for SeqSer {
    type Ok = XpcMessage;
    type Error = SerError;

    fn serialize_element<T: serde::Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.0.push(value.serialize(XpcSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(XpcMessage::Array(self.0))
    }
}

impl serde::ser::SerializeTuple for SeqSer {
    type Ok = XpcMessage;
    type Error = SerError;

    fn serialize_element<T: serde::Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.0.push(value.serialize(XpcSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(XpcMessage::Array(self.0))
    }
}

impl serde::ser::SerializeTupleStruct for SeqSer {
    type Ok = XpcMessage;
    type Error = SerError;

    fn serialize_field<T: serde::Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.0.push(value.serialize(XpcSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(XpcMessage::Array(self.0))
    }
}

pub(crate) struct SeqDe {
    iter: std::vec::IntoIter<XpcMessage>,
}

impl SeqDe {
    pub(crate) fn new(v: Vec<XpcMessage>) -> Self {
        Self {
            iter: v.into_iter(),
        }
    }
}

impl<'de> de::SeqAccess<'de> for SeqDe {
    type Error = DeError;

    fn next_element_seed<T: de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        match self.iter.next() {
            Some(v) => seed.deserialize(XpcDeserializer(v)).map(Some),
            None => Ok(None),
        }
    }
}
