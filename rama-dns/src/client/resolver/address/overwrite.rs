use std::net::{Ipv4Addr, Ipv6Addr};

use rama_core::{error::extra::OpaqueError, futures::Stream};
use rama_net::address::Domain;

use super::{BoxDnsAddressResolver, DnsAddressResolver};

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
    type Error = OpaqueError;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.0.lookup_ipv4(domain)
    }

    #[inline(always)]
    fn lookup_ipv4_first(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        self.0.lookup_ipv4_first(domain)
    }

    #[inline(always)]
    fn lookup_ipv4_rand(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        self.0.lookup_ipv4_rand(domain)
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.0.lookup_ipv6(domain)
    }

    #[inline(always)]
    fn lookup_ipv6_first(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        self.0.lookup_ipv6_first(domain)
    }

    #[inline(always)]
    fn lookup_ipv6_rand(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        self.0.lookup_ipv6_rand(domain)
    }

    #[inline(always)]
    fn into_box_dns_address_resolver(self) -> BoxDnsAddressResolver {
        self.0
    }
}
