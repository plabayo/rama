use std::collections::BTreeMap;

use crate::{
    XpcMessage,
    xpc_serde::types::{err::SerError, ser::XpcSerializer},
};

pub(crate) struct TupleVariantSer {
    pub(crate) variant: &'static str,
    pub(crate) elements: Vec<XpcMessage>,
}

impl serde::ser::SerializeTupleVariant for TupleVariantSer {
    type Ok = XpcMessage;
    type Error = SerError;

    fn serialize_field<T: serde::Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.elements.push(value.serialize(XpcSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let mut map = BTreeMap::new();
        map.insert(self.variant.to_owned(), XpcMessage::Array(self.elements));
        Ok(XpcMessage::Dictionary(map))
    }
}
