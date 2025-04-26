use std::{
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
};

use rama_net::address::Domain;

use crate::DnsResolver;

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented according to the pioneers of this Design Pattern
/// found at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>
/// and widely published at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>.
trait DynDnsResolver {
    type Error;

    fn ipv4_lookup_box(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Ipv4Addr>, Self::Error>> + Send + '_>>;

    fn ipv6_lookup_box(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Ipv6Addr>, Self::Error>> + Send + '_>>;
}

impl<T: DnsResolver> DynDnsResolver for T {
    type Error = T::Error;

    fn ipv4_lookup_box(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Ipv4Addr>, Self::Error>> + Send + '_>> {
        Box::pin(self.ipv4_lookup(domain))
    }

    fn ipv6_lookup_box(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Ipv6Addr>, Self::Error>> + Send + '_>> {
        Box::pin(self.ipv6_lookup(domain))
    }
}

/// A boxed [`DnsResolver`], to resolve dns,
/// for where you require dynamic dispatch.
pub struct BoxDnsResolver<Error> {
    inner: Arc<dyn DynDnsResolver<Error = Error> + Send + Sync + 'static>,
}

impl<Error> Clone for BoxDnsResolver<Error> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<Error> BoxDnsResolver<Error> {
    /// Create a new [`BoxDnsResolver`] from the given dns resolver.
    #[inline]
    pub fn new(resolver: impl DnsResolver<Error = Error>) -> Self {
        Self {
            inner: Arc::new(resolver),
        }
    }
}

impl<Error> std::fmt::Debug for BoxDnsResolver<Error> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxDnsResolver").finish()
    }
}

impl<Error> DnsResolver for BoxDnsResolver<Error>
where
    Error: Send + 'static,
{
    type Error = Error;

    #[inline]
    fn ipv4_lookup(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Result<Vec<Ipv4Addr>, Self::Error>> + Send + '_ {
        self.inner.ipv4_lookup_box(domain)
    }

    #[inline]
    fn ipv6_lookup(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Result<Vec<Ipv6Addr>, Self::Error>> + Send + '_ {
        self.inner.ipv6_lookup_box(domain)
    }

    fn boxed(self) -> BoxDnsResolver<Self::Error> {
        self
    }
}
