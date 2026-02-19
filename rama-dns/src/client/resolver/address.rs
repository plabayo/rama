use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
};

use rama_core::{
    error::BoxError,
    futures::{Stream, StreamExt as _, TryStreamExt, stream},
};
use rama_net::address::{Domain, DomainTrie};

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

impl<R: DnsAddressResolver> DnsAddressResolver for Arc<R> {
    type Error = R::Error;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.as_ref().lookup_ipv4(domain)
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.as_ref().lookup_ipv6(domain)
    }
}

impl<R: DnsAddressResolver> DnsAddressResolver for Option<R> {
    type Error = R::Error;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::iter(self.as_ref().map(|resolver| resolver.lookup_ipv4(domain))).flatten()
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::iter(self.as_ref().map(|resolver| resolver.lookup_ipv6(domain))).flatten()
    }
}

impl DnsAddressResolver for IpAddr {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::iter(match self {
            Self::V4(ipv4_addr) => Some(Ok(*ipv4_addr)),
            Self::V6(_) => None,
        })
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::iter(match self {
            Self::V4(_) => None,
            Self::V6(ipv6_addr) => Some(Ok(*ipv6_addr)),
        })
    }
}

impl DnsAddressResolver for Ipv4Addr {
    type Error = Infallible;

    fn lookup_ipv4(&self, _: Domain) -> impl Stream<Item = Result<Self, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Ok(*self)))
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::empty()
    }
}

impl DnsAddressResolver for Ipv6Addr {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::empty()
    }

    fn lookup_ipv6(&self, _: Domain) -> impl Stream<Item = Result<Self, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Ok(*self)))
    }
}

impl<R: DnsAddressResolver> DnsAddressResolver for DomainTrie<R> {
    type Error = R::Error;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::iter(self.match_exact(domain.clone()))
            .flat_map(move |resolver| resolver.lookup_ipv4(domain.clone()))
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::iter(self.match_exact(domain.clone()))
            .flat_map(move |resolver| resolver.lookup_ipv6(domain.clone()))
    }
}

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented according to the pioneers of this Design Pattern
/// found at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>
/// and widely published at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>.
trait DynDnsAddressResolver {
    fn dyn_lookup_ipv4(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv4Addr, BoxError>> + Send + '_>>;

    fn dyn_lookup_ipv6(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv6Addr, BoxError>> + Send + '_>>;
}

impl<T: DnsAddressResolver> DynDnsAddressResolver for T {
    fn dyn_lookup_ipv4(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv4Addr, BoxError>> + Send + '_>> {
        Box::pin(self.lookup_ipv4(domain).map_err(Into::into))
    }

    fn dyn_lookup_ipv6(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv6Addr, BoxError>> + Send + '_>> {
        Box::pin(self.lookup_ipv6(domain).map_err(Into::into))
    }
}

/// A boxed [`DnsAddressResolver`], to resolve dns,
/// for where you require dynamic dispatch.
pub struct BoxDnsAddressResolver {
    inner: Arc<dyn DynDnsAddressResolver + Send + Sync + 'static>,
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
