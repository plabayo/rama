use rama_core::{bytes::Bytes, error::BoxError, futures::Stream};
use rama_net::address::Domain;

use crate::client::{
    HickoryDnsResolver,
    resolver::{BoxDnsResolver, DnsAddressResolver, DnsResolver, DnsTxtResolver},
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::OnceLock,
};

static GLOBAL_DNS_RESOLVER: OnceLock<BoxDnsResolver> = OnceLock::new();

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct GlobalDnsResolver;

impl GlobalDnsResolver {
    #[inline]
    /// Create a new [`GlobalDnsResolver`].
    ///
    /// This has no cost.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl DnsAddressResolver for GlobalDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        let resolver = global_dns_resolver();
        resolver.lookup_ipv4(domain)
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        let resolver = global_dns_resolver();
        resolver.lookup_ipv6(domain)
    }
}

impl DnsTxtResolver for GlobalDnsResolver {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        let resolver = global_dns_resolver();
        resolver.lookup_txt(domain)
    }
}

impl DnsResolver for GlobalDnsResolver {
    fn into_box_dns_resolver(self) -> BoxDnsResolver
    where
        Self: Sized,
    {
        global_dns_resolver().clone()
    }
}

/// Get the global [`DnsResolver`].
///
/// This is a shared once-time init dns resolver used by default in rama.
/// By default it is created in a lazy fashion using [`HickoryDns::default`].
///
/// Use [`init_global_dns_resolver`] or [`try_init_global_dns_resolver`] to overwrite
/// the global [`DnsResolver`]. This has to be done as early as possible,
/// as it fails if the global resolver was already initialised (e.g. using the default).
fn global_dns_resolver() -> &'static BoxDnsResolver {
    GLOBAL_DNS_RESOLVER.get_or_init(|| HickoryDnsResolver::default().into_box_dns_resolver())
}

#[inline(always)]
/// Initialises the global [`DnsResolver`].
///
/// # Panics
///
/// Panics in case the global [`DnsResolver`] was already set.
/// Use [`try_init_global_dns_resolver`] in case you wish to handle this more gracefully.
pub fn init_global_dns_resolver(resolver: impl DnsResolver) {
    if try_init_global_dns_resolver(resolver).is_err() {
        panic!("global DNS resolver already set");
    }
}

/// Tries to initialise the global [`DnsResolver`].
///
/// This returns the input [`DnsResolver`] boxed but useless back,
/// in case the global [`DnsResolver`] was already set.
///
/// You can use [`init_global_dns_resolver`] should you want to panic on failure instead.
pub fn try_init_global_dns_resolver(resolver: impl DnsResolver) -> Result<(), BoxDnsResolver> {
    GLOBAL_DNS_RESOLVER.set(resolver.into_box_dns_resolver())
}
