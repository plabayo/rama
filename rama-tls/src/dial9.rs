//! [dial9] telemetry `TraceField` impls for the TLS enum vocabulary.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry

use crate::{ApplicationProtocol, ProtocolVersion};
use dial9_trace_format::{
    EventEncoder, TraceField,
    types::{FieldType, FieldValueRef},
};
use std::io::{self, Write};

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
