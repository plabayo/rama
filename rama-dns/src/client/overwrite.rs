use std::net::{Ipv4Addr, Ipv6Addr};

use rama_core::{error::BoxError, futures::Stream};
use rama_net::address::Domain;

use super::resolver::{BoxDnsAddressResolver, DnsAddressResolver};

#[derive(Debug, Clone)]
/// Wrapper struct that can be used to add
/// dns address overwrites to an input as an extension.
///
/// This is supported by the official `rama`
/// consumers such as `TcpConnector`.
pub struct DnsAddresssResolverOverwrite(BoxDnsAddressResolver);

impl DnsAddresssResolverOverwrite {
    #[inline(always)]
    pub fn new(resolver: impl DnsAddressResolver) -> Self {
        Self(resolver.into_box_dns_address_resolver())
    }
}

impl DnsAddressResolver for DnsAddresssResolverOverwrite {
    type Error = BoxError;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.0.lookup_ipv4(domain)
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.0.lookup_ipv6(domain)
    }

    #[inline(always)]
    fn into_box_dns_address_resolver(self) -> BoxDnsAddressResolver {
        self.0
    }
}
