//! Utilities to allow custom DNS Resolution within Rama.

mod error;
pub use error::DnsError;

mod dns_resolve;
pub use dns_resolve::DynamicDnsResolver;

pub(crate) mod dns_map;

mod service;
pub use service::{DnsResolvedSocketAddresses, DnsService};

mod layer;
pub use layer::DnsLayer;
