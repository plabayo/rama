use std::io::{self, Write};

use crate::address::{Domain, Host};

use dial9_trace_format::{
    EventEncoder, TraceField,
    types::{FieldType, FieldValueRef},
};
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
            // Wire-preserved reg-name / IP-literal — render through
            // `Display`, which handles the bracketed IPvFuture case
            // (re-adds `[...]`) and emits reg-name bytes verbatim.
            Self::Uninterpreted(host) => enc.write_string(&host.to_string()),
        }
    }

    fn decode_ref<'a>(val: &FieldValueRef<'a>) -> Option<Self::Ref<'a>> {
        match val {
            FieldValueRef::String(s) => Some(s),
            _ => None,
        }
    }
}
