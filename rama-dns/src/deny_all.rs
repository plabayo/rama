use std::fmt::Error;

use crate::DnsResolver;

#[derive(Debug, Clone)]
pub struct DenyAllDns {}
static_str_error! {
    #[doc = "Dns denied"]
    pub struct DnsDeniedError;
}

impl DnsResolver for DenyAllDns {
    type Error = DnsDeniedError;

    fn ipv4_lookup(&self, domain: rama_net::address::Domain) -> Result<Vec<Ipv4Addr>, Self::Error> {
        Err(DnsDeniedError)
    }

    fn ipv6_lookup(&self, domain: rama_net::address::Domain) -> Result<Vec<Ipv4Addr>, Self::Error> {
        Err(DnsDeniedError)
    }
}
