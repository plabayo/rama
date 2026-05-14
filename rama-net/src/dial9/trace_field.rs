use crate::address::{Domain, Host};
#[cfg(feature = "tls")]
use crate::tls::{ApplicationProtocol, ProtocolVersion};
use dial9_trace_format::{
    EventEncoder, TraceField,
    types::{FieldType, FieldValueRef},
};
use std::io::{self, Write};

impl TraceField for Domain {
    type Ref<'a> = &'a str;

    fn field_type() -> FieldType {
        FieldType::String
    }

    fn encode<W: Write>(&self, enc: &mut EventEncoder<'_, W>) -> io::Result<()> {
        enc.write_string(self.as_str())
    }

    fn decode_ref<'a>(val: &FieldValueRef<'a>) -> Option<Self::Ref<'a>> {
        match val {
            FieldValueRef::String(s) => Some(s),
            _ => None,
        }
    }
}

impl TraceField for Host {
    type Ref<'a> = &'a str;

    fn field_type() -> FieldType {
        FieldType::String
    }

    fn encode<W: Write>(&self, enc: &mut EventEncoder<'_, W>) -> io::Result<()> {
        match self {
            Self::Name(domain) => enc.write_string(domain.as_str()),
            Self::Address(ip) => enc.write_string(&ip.to_string()),
        }
    }

    fn decode_ref<'a>(val: &FieldValueRef<'a>) -> Option<Self::Ref<'a>> {
        match val {
            FieldValueRef::String(s) => Some(s),
            _ => None,
        }
    }
}

#[cfg(feature = "tls")]
impl TraceField for ProtocolVersion {
    type Ref<'a> = Self;

    fn field_type() -> FieldType {
        FieldType::U16
    }

    fn encode<W: Write>(&self, enc: &mut EventEncoder<'_, W>) -> io::Result<()> {
        enc.write_u16(u16::from(*self))
    }

    fn decode_ref<'a>(val: &FieldValueRef<'a>) -> Option<Self::Ref<'a>> {
        match val {
            FieldValueRef::Varint(v) => u16::try_from(*v).ok().map(Self::from),
            _ => None,
        }
    }
}

#[cfg(feature = "tls")]
impl TraceField for ApplicationProtocol {
    type Ref<'a> = &'a [u8];

    fn field_type() -> FieldType {
        FieldType::Bytes
    }

    fn encode<W: Write>(&self, enc: &mut EventEncoder<'_, W>) -> io::Result<()> {
        enc.write_bytes(self.as_bytes())
    }

    fn decode_ref<'a>(val: &FieldValueRef<'a>) -> Option<Self::Ref<'a>> {
        match val {
            FieldValueRef::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }
}
