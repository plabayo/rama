//! DNS wire-format vocabulary and parsing.
//!
//! This module contains protocol data, not request-context extensions. In
//! particular, [`ServiceBinding`] represents the common RDATA wire format used
//! by both [`RecordType::SVCB`] and [`RecordType::HTTPS`] resource records.

mod name;
mod record_type;
mod service_binding;

pub use name::{Name, NameParseError};
pub use record_type::RecordType;
pub use service_binding::{
    AlpnList, ServiceBinding, ServiceBindingParseError, SvcParam, SvcParamKey,
};

#[cfg(test)]
mod tests;
