use std::{
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
};

use rama_core::{
    error::BoxError,
    futures::{Stream, TryStreamExt},
};
use rama_net::address::Domain;

/// A resolver of Domains into A or AAAA records.
pub trait DnsAddressResolver: Sized + Send + Sync + 'static {
    /// Error returned by the [`DnsAddressResolver`]
    type Error: Into<BoxError> + Send + 'static;

    /// Resolve the 'A' records accessible by this resolver for the given [`Domain`] into [`Ipv4Addr`]esses.
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_;

    /// Resolve the 'AAAA' records accessible by this resolver for the given [`Domain`] into [`Ipv6Addr`]esses.
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_;

    /// Box this resolver to allow for dynamic dispatch.
    fn into_box_dns_address_resolver(self) -> BoxDnsAddressResolver {
        BoxDnsAddressResolver::new(self)
    }
}

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented according to the pioneers of this Design Pattern
/// found at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>
/// and widely published at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>.
trait DynDnsAddressResolver {
    type Error: Into<BoxError> + Send + 'static;

    fn dyn_lookup_ipv4(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_>>;

    fn dyn_lookup_ipv6(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_>>;
}

impl<T: DnsAddressResolver> DynDnsAddressResolver for T {
    type Error = T::Error;

    fn dyn_lookup_ipv4(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_>> {
        Box::pin(self.lookup_ipv4(domain))
    }

    fn dyn_lookup_ipv6(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_>> {
        Box::pin(self.lookup_ipv6(domain))
    }
}

/// A boxed [`DnsAddressResolver`], to resolve dns,
/// for where you require dynamic dispatch.
pub struct BoxDnsAddressResolver {
    inner: Arc<dyn DynDnsAddressResolver<Error = BoxError> + Send + Sync + 'static>,
}

impl Clone for BoxDnsAddressResolver {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl BoxDnsAddressResolver {
    /// Create a new [`BoxDnsAddressResolver`] from the given dns resolver.
    #[inline]
    pub fn new<T>(address_resolver: T) -> Self
    where
        T: DnsAddressResolver,
    {
        Self {
            inner: Arc::new(InnerDnsAddressResolver(address_resolver)),
        }
    }
}

struct InnerDnsAddressResolver<T>(T);

impl<T: DnsAddressResolver> DnsAddressResolver for InnerDnsAddressResolver<T> {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.0.lookup_ipv4(domain).map_err(Into::into)
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.0.lookup_ipv6(domain).map_err(Into::into)
    }
}

impl std::fmt::Debug for BoxDnsAddressResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxDnsAddressResolver").finish()
    }
}

impl DnsAddressResolver for BoxDnsAddressResolver {
    type Error = BoxError;

    #[inline]
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_ipv4(domain)
    }

    #[inline]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_ipv6(domain)
    }

    fn into_box_dns_address_resolver(self) -> BoxDnsAddressResolver {
        self
    }
}
