pub mod resolver;

pub mod hickory;
#[doc(inline)]
pub use self::hickory::HickoryDnsResolver;

mod deny_all;
#[doc(inline)]
pub use self::deny_all::{DenyAllDnsResolver, DnsDeniedError};

mod empty;
#[doc(inline)]
pub use self::empty::EmptyDnsResolver;

mod global;
#[doc(inline)]
pub use global::{GlobalDnsResolver, init_global_dns_resolver, try_init_global_dns_resolver};

mod overwrite;
#[doc(inline)]
pub use self::overwrite::DnsAddresssResolverOverwrite;

mod chain;
mod tuple;
mod variant;
