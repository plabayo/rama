//! Layers in function of DNS.

mod dns_resolve;
pub use dns_resolve::{
    DnsResolveMode, DnsResolveModeLayer, DnsResolveModeService, DnsResolveModeUsernameParser,
};
