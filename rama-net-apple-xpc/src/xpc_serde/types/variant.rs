use serde::{
    Deserializer as _,
    de::{self, IntoDeserializer, Visitor},
};

use crate::{
    XpcMessage,
    xpc_serde::types::{de::XpcDeserializer, err::DeError},
};

pub(crate) struct EnumDe {
    pub(crate) variant: String,
    pub(crate) value: XpcMessage,
}

impl<'de> de::EnumAccess<'de> for EnumDe {
    type Error = DeError;
    type Variant = VariantDe;

    fn variant_seed<V: de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Self::Error> {
        let variant_val = seed.deserialize(self.variant.into_deserializer())?;
        Ok((variant_val, VariantDe(self.value)))
    }
}

pub(crate) struct VariantDe(pub(crate) XpcMessage);

impl<'de> de::VariantAccess<'de> for VariantDe {
    type Error = DeError;

    fn unit_variant(self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Self::Error> {
        seed.deserialize(XpcDeserializer(self.0))
    }

    fn tuple_variant<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        XpcDeserializer(self.0).deserialize_seq(visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        XpcDeserializer(self.0).deserialize_map(visitor)
    }
}
