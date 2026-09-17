//! DNS wire-format vocabulary and parsing.
//!
//! This module contains protocol data, not request-context extensions.
//! [`Name`] handles case-preserving DNS names and RFC 1035 compression;
//! [`ServiceBinding`] represents the common RDATA wire format used by both
//! [`RecordType::SVCB`] and [`RecordType::HTTPS`] resource records.
//!
//! [`Message`] assembles that vocabulary into an RFC 1035 message parser for
//! the header, question section, and answer section. It stops there: the
//! authority and additional sections are skipped, and telemetry policy such as
//! answer caps, name normalisation, and string flattening stays with the
//! caller. Parsing is lenient by default and keeps every record decoded before
//! a failure; [`Message::parse_strict`] rejects such a message instead, while
//! still handing that partial result back with the error.

mod address;
mod message;
mod name;
mod record_class;
mod record_type;
mod response_code;
mod service_binding;
mod txt;

pub use address::{AddressRdataParseError, parse_a_rdata, parse_aaaa_rdata};
pub use message::{
    Message, MessageHeader, MessageParseError, Question, RecordData, ResourceRecord,
};
pub use name::{Name, NameParseError};
pub use record_class::RecordClass;
pub use record_type::RecordType;
pub use response_code::ResponseCode;
pub use service_binding::{
    AlpnList, ServiceBinding, ServiceBindingParseError, SvcParam, SvcParamKey,
};
pub use txt::{Txt, TxtParseError};

#[cfg(test)]
mod tests;
