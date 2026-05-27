use std::collections::BTreeMap;

use crate::{
    XpcMessage,
    xpc_serde::types::{err::SerError, ser::XpcSerializer},
};

pub(crate) struct StructVariantSer {
    pub(crate) variant: &'static str,
    pub(crate) fields: BTreeMap<String, XpcMessage>,
}

impl serde::ser::SerializeStructVariant for StructVariantSer {
    type Ok = XpcMessage;
    type Error = SerError;

    fn serialize_field<T: serde::Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.fields
            .insert(key.to_owned(), value.serialize(XpcSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let mut outer = BTreeMap::new();
        outer.insert(self.variant.to_owned(), XpcMessage::Dictionary(self.fields));
        Ok(XpcMessage::Dictionary(outer))
    }
}
