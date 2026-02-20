mod address;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;

use rama_core::bytes::Bytes;
use rama_core::error::ErrorExt;
use rama_core::error::extra::OpaqueError;
use rama_core::futures::{FutureExt as _, Stream, TryStreamExt as _};
use rama_net::address::Domain;

pub use self::address::{BoxDnsAddressResolver, DnsAddressResolver, DnsAddresssResolverOverwrite};

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

impl<R: DnsResolver> DnsResolver for Arc<R> {}
impl<R: DnsResolver> DnsResolver for Option<R> {}

trait DynDnsResolver {
    fn dyn_lookup_ipv4(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv4Addr, OpaqueError>> + Send + '_>>;

    fn dyn_lookup_ipv4_first(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv4Addr, OpaqueError>>> + Send + '_>>;

    fn dyn_lookup_ipv4_rand(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv4Addr, OpaqueError>>> + Send + '_>>;

    fn dyn_lookup_ipv6(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv6Addr, OpaqueError>> + Send + '_>>;

    fn dyn_lookup_ipv6_first(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv6Addr, OpaqueError>>> + Send + '_>>;

    fn dyn_lookup_ipv6_rand(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv6Addr, OpaqueError>>> + Send + '_>>;

    fn dyn_lookup_txt(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, OpaqueError>> + Send + '_>>;
}

impl<T> DynDnsResolver for T
where
    T: DnsResolver,
{
    #[inline(always)]
    fn dyn_lookup_ipv4(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv4Addr, OpaqueError>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv4(domain)
                .map_err(ErrorExt::into_opaque_error),
        )
    }

    #[inline(always)]
    fn dyn_lookup_ipv4_first(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv4Addr, OpaqueError>>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv4_first(domain)
                .map(|output| output.map(|result| result.map_err(ErrorExt::into_opaque_error))),
        )
    }

    #[inline(always)]
    fn dyn_lookup_ipv4_rand(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv4Addr, OpaqueError>>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv4_rand(domain)
                .map(|output| output.map(|result| result.map_err(ErrorExt::into_opaque_error))),
        )
    }

    #[inline(always)]
    fn dyn_lookup_ipv6(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv6Addr, OpaqueError>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv6(domain)
                .map_err(ErrorExt::into_opaque_error),
        )
    }

    #[inline(always)]
    fn dyn_lookup_ipv6_first(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv6Addr, OpaqueError>>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv6_first(domain)
                .map(|output| output.map(|result| result.map_err(ErrorExt::into_opaque_error))),
        )
    }

    #[inline(always)]
    fn dyn_lookup_ipv6_rand(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv6Addr, OpaqueError>>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv6_rand(domain)
                .map(|output| output.map(|result| result.map_err(ErrorExt::into_opaque_error))),
        )
    }

    #[inline(always)]
    fn dyn_lookup_txt(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, OpaqueError>> + Send + '_>> {
        Box::pin(self.lookup_txt(domain).map_err(ErrorExt::into_opaque_error))
    }
}

/// A boxed [`DnsResolver`], mapping its error into [`OpaqueError`].
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
    type Error = OpaqueError;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_ipv4(domain)
    }

    #[inline(always)]
    fn lookup_ipv4_first(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        self.inner.dyn_lookup_ipv4_first(domain)
    }

    #[inline(always)]
    fn lookup_ipv4_rand(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        self.inner.dyn_lookup_ipv4_rand(domain)
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_ipv6(domain)
    }

    #[inline(always)]
    fn lookup_ipv6_first(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        self.inner.dyn_lookup_ipv6_first(domain)
    }

    #[inline(always)]
    fn lookup_ipv6_rand(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        self.inner.dyn_lookup_ipv6_rand(domain)
    }

    #[inline(always)]
    fn into_box_dns_address_resolver(self) -> BoxDnsAddressResolver {
        BoxDnsAddressResolver::new(self)
    }
}

impl DnsTxtResolver for BoxDnsResolver {
    type Error = OpaqueError;

    #[inline(always)]
    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_txt(domain)
    }

    #[inline(always)]
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
