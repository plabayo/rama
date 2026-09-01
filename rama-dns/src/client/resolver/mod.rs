mod address;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;

use rama_core::error::ErrorExt;
use rama_core::error::extra::OpaqueError;
use rama_core::futures::{FutureExt as _, Stream, TryStreamExt as _};
use rama_net::address::Domain;

use crate::wire::{Name, ServiceBinding, Txt};

pub use self::address::{
    BoxDnsAddressResolver, DnsAddressResolver, DnsAddresssResolverOverwrite,
    HappyEyeballAddressResolver, HappyEyeballAddressResolverExt,
};

mod cname;
pub use self::cname::{BoxDnsCnameResolver, DnsCnameResolver};

mod txt;
pub use self::txt::{BoxDnsTxtResolver, DnsTxtResolver};

mod service_binding;
pub use self::service_binding::{BoxDnsServiceBindingResolver, DnsServiceBindingResolver};

/// Aggregate resolver supporting address, CNAME, TXT, SVCB, and HTTPS lookups.
pub trait DnsResolver:
    DnsAddressResolver + DnsCnameResolver + DnsTxtResolver + DnsServiceBindingResolver
{
    /// Box this aggregate resolver for dynamic dispatch.
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
    ) -> Pin<Box<dyn Stream<Item = Result<Txt, OpaqueError>> + Send + '_>>;

    fn dyn_lookup_cname(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Name, OpaqueError>> + Send + '_>>;

    fn dyn_lookup_svcb(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<ServiceBinding, OpaqueError>> + Send + '_>>;

    fn dyn_lookup_https(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<ServiceBinding, OpaqueError>> + Send + '_>>;
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
    ) -> Pin<Box<dyn Stream<Item = Result<Txt, OpaqueError>> + Send + '_>> {
        Box::pin(self.lookup_txt(domain).map_err(ErrorExt::into_opaque_error))
    }

    #[inline(always)]
    fn dyn_lookup_cname(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Name, OpaqueError>> + Send + '_>> {
        Box::pin(
            self.lookup_cname(domain)
                .map_err(ErrorExt::into_opaque_error),
        )
    }

    #[inline(always)]
    fn dyn_lookup_svcb(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<ServiceBinding, OpaqueError>> + Send + '_>> {
        Box::pin(
            self.lookup_svcb(domain)
                .map_err(ErrorExt::into_opaque_error),
        )
    }

    #[inline(always)]
    fn dyn_lookup_https(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<ServiceBinding, OpaqueError>> + Send + '_>> {
        Box::pin(
            self.lookup_https(domain)
                .map_err(ErrorExt::into_opaque_error),
        )
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
    /// Box an aggregate DNS resolver.
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
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_txt(domain)
    }

    #[inline(always)]
    fn into_box_dns_txt_resolver(self) -> BoxDnsTxtResolver {
        BoxDnsTxtResolver::new(self)
    }
}

impl DnsCnameResolver for BoxDnsResolver {
    type Error = OpaqueError;

    #[inline(always)]
    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_cname(domain)
    }

    #[inline(always)]
    fn into_box_dns_cname_resolver(self) -> BoxDnsCnameResolver {
        BoxDnsCnameResolver::new(self)
    }
}

impl DnsServiceBindingResolver for BoxDnsResolver {
    type Error = OpaqueError;

    #[inline(always)]
    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_svcb(domain)
    }

    #[inline(always)]
    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_https(domain)
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rama_core::{
        bytes::Bytes,
        futures::{StreamExt as _, stream},
    };

    use super::*;

    struct FullResolver;

    impl DnsAddressResolver for FullResolver {
        type Error = Infallible;

        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            stream::empty()
        }

        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            stream::empty()
        }
    }

    impl DnsTxtResolver for FullResolver {
        type Error = Infallible;

        fn lookup_txt(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
            stream::empty()
        }
    }

    impl DnsCnameResolver for FullResolver {
        type Error = Infallible;

        fn lookup_cname(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Ok(Name::from_wire(
                b"\x05alias\x07example\x03com\0",
            )
            .unwrap())))
        }
    }

    impl DnsServiceBindingResolver for FullResolver {
        type Error = Infallible;

        fn lookup_svcb(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Ok(binding(8443))))
        }

        fn lookup_https(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Ok(binding(443))))
        }
    }

    impl DnsResolver for FullResolver {}

    fn binding(port: u16) -> ServiceBinding {
        let mut rdata = vec![0, 1, 0, 0, 3, 0, 2];
        rdata.extend_from_slice(&port.to_be_bytes());
        ServiceBinding::parse_rdata_bytes(&Bytes::from(rdata)).expect("valid service binding")
    }

    #[tokio::test]
    async fn boxed_full_resolver_dispatches_record_lookups() {
        let resolver = FullResolver.into_box_dns_resolver();
        let cname = std::pin::pin!(resolver.lookup_cname(Domain::example()))
            .next()
            .await
            .expect("one record")
            .expect("success");
        assert_eq!(cname.to_string(), "alias.example.com.");

        let svcb = std::pin::pin!(resolver.lookup_svcb(Domain::example()))
            .next()
            .await
            .expect("one record")
            .expect("success");
        assert_eq!(svcb.port(), Some(8443));

        let resolver = resolver.into_box_dns_resolver();
        let https = std::pin::pin!(resolver.lookup_https(Domain::example()))
            .next()
            .await
            .expect("one record")
            .expect("success");
        assert_eq!(https.port(), Some(443));
    }
}
