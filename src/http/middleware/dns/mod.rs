mod layer;
mod resolver;
mod service;

pub use layer::DnsLayer;
pub use resolver::{DefaultDnsResolver, DnsResolver, ResolvedSocketAddr};
pub use service::DnsService;
