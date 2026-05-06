#[cfg(feature = "tls")]
use crate::tls::{ApplicationProtocol, ProtocolVersion};
use crate::{
    address::{Domain, Host},
    proxy::BridgeCloseReason,
};
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

impl TraceField for BridgeCloseReason {
    type Ref<'a> = Self;

    fn field_type() -> FieldType {
        FieldType::U8
    }

    fn encode<W: Write>(&self, enc: &mut EventEncoder<'_, W>) -> io::Result<()> {
        let code = match self {
            Self::Shutdown => 1,
            Self::IdleTimeout => 2,
            Self::PeerEofLeft => 3,
            Self::PeerEofRight => 4,
            Self::ReadErrorLeft => 5,
            Self::ReadErrorRight => 6,
            Self::WriteErrorLeft => 7,
            Self::WriteErrorRight => 8,
            Self::PeekTimeout => 9,
            Self::HandlerDeadline => 10,
        };
        enc.write_u8(code)
    }

    fn decode_ref<'a>(val: &FieldValueRef<'a>) -> Option<Self::Ref<'a>> {
        match val {
            FieldValueRef::Varint(1) => Some(Self::Shutdown),
            FieldValueRef::Varint(2) => Some(Self::IdleTimeout),
            FieldValueRef::Varint(3) => Some(Self::PeerEofLeft),
            FieldValueRef::Varint(4) => Some(Self::PeerEofRight),
            FieldValueRef::Varint(5) => Some(Self::ReadErrorLeft),
            FieldValueRef::Varint(6) => Some(Self::ReadErrorRight),
            FieldValueRef::Varint(7) => Some(Self::WriteErrorLeft),
            FieldValueRef::Varint(8) => Some(Self::WriteErrorRight),
            FieldValueRef::Varint(9) => Some(Self::PeekTimeout),
            FieldValueRef::Varint(10) => Some(Self::HandlerDeadline),
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
