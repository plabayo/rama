//! DNS wire-format vocabulary and parsing.
//!
//! This module contains protocol data, not request-context extensions. In
//! particular, [`ServiceBinding`] represents the common RDATA wire format used
//! by both [`RecordType::SVCB`] and [`RecordType::HTTPS`] resource records.

mod address;
mod name;
mod presentation;
mod record_type;
mod service_binding;
mod txt;

pub use address::{AddressRdataParseError, parse_a_rdata, parse_aaaa_rdata};
pub use name::{Name, NameParseError};
pub use record_type::RecordType;
pub use service_binding::{
    AlpnList, ServiceBinding, ServiceBindingParseError, SvcParam, SvcParamKey,
};
pub use txt::{Txt, TxtParseError};

#[cfg(test)]
mod tests;
