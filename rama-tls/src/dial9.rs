//! [dial9] telemetry `TraceField` impls for the TLS enum vocabulary.
//!
//! [dial9]: https://github.com/dial9-rs/dial9

use crate::ProtocolVersion;
use dial9_trace_format::{EventEncoder, TraceField, types::FieldType};
use std::io::{self, Write};

impl TraceField for ProtocolVersion {
    fn field_type() -> FieldType {
        FieldType::U16
    }

    fn encode<W: Write>(&self, enc: &mut EventEncoder<'_, W>) -> io::Result<()> {
        enc.write_u16(u16::from(*self))
    }
}
