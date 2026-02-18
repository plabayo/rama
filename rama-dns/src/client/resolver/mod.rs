mod address;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;

use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::futures::{Stream, TryStreamExt as _};
use rama_net::address::Domain;

pub use self::address::{BoxDnsAddressResolver, DnsAddressResolver};

mod txt;
pub use self::txt::{BoxDnsTxtResolver, DnsTxtResolver};

pub trait DnsResolver: DnsAddressResolver + DnsTxtResolver {
    fn into_box_dns_resolver(self) -> BoxDnsResolver
    where
        Self: Sized,
    {
        BoxDnsResolver::new(self)
    }
}

trait DynDnsResolver {
    fn dyn_lookup_ipv4(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv4Addr, BoxError>> + Send + '_>>;

    fn dyn_lookup_ipv6(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv6Addr, BoxError>> + Send + '_>>;

    fn dyn_lookup_txt(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, BoxError>> + Send + '_>>;
}

impl<T> DynDnsResolver for T
where
    T: DnsResolver,
{
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

    fn dyn_lookup_txt(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, BoxError>> + Send + '_>> {
        Box::pin(self.lookup_txt(domain).map_err(Into::into))
    }
}

/// A boxed [`DnsResolver`], mapping its error into [`BoxError`].
pub struct BoxDnsResolver {
    inner: Arc<dyn DynDnsResolver + Send + Sync + 'static>,
}

impl Clone for BoxDnsResolver {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl BoxDnsResolver {
    #[inline]
    pub fn new<T>(resolver: T) -> Self
    where
        T: DnsResolver,
    {
        Self {
            inner: Arc::new(resolver),
        }
    }
}

impl std::fmt::Debug for BoxDnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxDnsResolver").finish()
    }
}

impl DnsAddressResolver for BoxDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_ipv4(domain)
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_ipv6(domain)
    }

    fn into_box_dns_address_resolver(self) -> BoxDnsAddressResolver {
        BoxDnsAddressResolver::new(self)
    }
}

impl DnsTxtResolver for BoxDnsResolver {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_txt(domain)
    }

    fn into_box_dns_txt_resolver(self) -> BoxDnsTxtResolver {
        BoxDnsTxtResolver::new(self)
    }
}

impl DnsResolver for BoxDnsResolver {
    fn into_box_dns_resolver(self) -> BoxDnsResolver
    where
        Self: Sized,
    {
        self
    }
}
