use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use rama_core::{
    error::{BoxError, ErrorExt, extra::OpaqueError},
    futures::{FutureExt as _, Stream, StreamExt as _, TryStreamExt, stream},
};
use rama_net::address::{Domain, DomainTrie};

use rand::{RngExt, rngs::SmallRng};
use tokio::time::Instant;

use crate::client::EmptyDnsResolver;

mod happy_eyeball;
#[doc(inline)]
pub use self::happy_eyeball::{HappyEyeballAddressResolver, HappyEyeballAddressResolverExt};

mod overwrite;
#[doc(inline)]
pub use self::overwrite::DnsAddresssResolverOverwrite;

/// A resolver of Domains into A or AAAA records.
pub trait DnsAddressResolver: Sized + Send + Sync + 'static {
    /// Error returned by the [`DnsAddressResolver`]
    type Error: Into<BoxError> + Send + 'static;

    /// Resolve the 'A' records accessible by this resolver for the given [`Domain`] into [`Ipv4Addr`]esses.
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_;

    /// Resolve the first 'A' record found for the resolver.
    fn lookup_ipv4_first(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        let stream = self.lookup_ipv4(domain);
        async move {
            let mut stream = std::pin::pin!(stream);

            let mut last_err = None;
            while let Some(result) = stream.next().await {
                match result {
                    Ok(addr) => return Some(Ok(addr)),
                    Err(err) => last_err = Some(Err(err)),
                }
            }
            last_err
        }
    }

    /// Resolve to a pseudo-random 'A' record found for the resolver.
    fn lookup_ipv4_rand(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        let stream = self.lookup_ipv4(domain);
        async move {
            let mut stream = std::pin::pin!(stream);

            enum Slot<E> {
                Ok(Ipv4Addr),
                Err(E),
                None,
            }
            let mut slot = Slot::None;

            let mut seen = 0;
            let mut rng: SmallRng = rand::make_rng();

            let start = Instant::now();

            while let Some(item) = stream.next().await {
                slot = match slot {
                    Slot::Ok(old_ip) => {
                        if start.elapsed() > Duration::from_millis(50) {
                            return Some(Ok(old_ip));
                        }

                        seen += 1;
                        Slot::Ok(
                            if let Ok(new_ip) = item
                                && rng.random_range(0..seen) == 0
                            {
                                new_ip
                            } else {
                                old_ip
                            },
                        )
                    }
                    Slot::Err(_) | Slot::None => match item {
                        Ok(addr) => Slot::Ok(addr),
                        Err(err) => Slot::Err(err),
                    },
                }
            }

            match slot {
                Slot::Ok(ip_addr) => Some(Ok(ip_addr)),
                Slot::Err(err) => Some(Err(err)),
                Slot::None => None,
            }
        }
    }

    /// Resolve the 'AAAA' records accessible by this resolver for the given [`Domain`] into [`Ipv6Addr`]esses.
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_;

    /// Resolve the first 'AAAA' record found for the resolver.
    fn lookup_ipv6_first(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        let stream = self.lookup_ipv6(domain);
        async move {
            let mut stream = std::pin::pin!(stream);

            let mut last_err = None;
            while let Some(result) = stream.next().await {
                match result {
                    Ok(addr) => return Some(Ok(addr)),
                    Err(err) => last_err = Some(Err(err)),
                }
            }
            last_err
        }
    }

    /// Resolve to a pseudo-random 'AAAA' record found for the resolver.
    fn lookup_ipv6_rand(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        let stream = self.lookup_ipv6(domain);
        async move {
            let mut stream = std::pin::pin!(stream);

            enum Slot<E> {
                Ok(Ipv6Addr),
                Err(E),
                None,
            }
            let mut slot = Slot::None;

            let mut seen = 0;
            let mut rng: SmallRng = rand::make_rng();

            let start = Instant::now();

            while let Some(item) = stream.next().await {
                slot = match slot {
                    Slot::Ok(old_ip) => {
                        if start.elapsed() > Duration::from_millis(50) {
                            return Some(Ok(old_ip));
                        }

                        seen += 1;
                        Slot::Ok(
                            if let Ok(new_ip) = item
                                && rng.random_range(0..seen) == 0
                            {
                                new_ip
                            } else {
                                old_ip
                            },
                        )
                    }
                    Slot::Err(_) | Slot::None => match item {
                        Ok(addr) => Slot::Ok(addr),
                        Err(err) => Slot::Err(err),
                    },
                }
            }

            match slot {
                Slot::Ok(ip_addr) => Some(Ok(ip_addr)),
                Slot::Err(err) => Some(Err(err)),
                Slot::None => None,
            }
        }
    }

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
    fn lookup_ipv4_first(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        self.as_ref().lookup_ipv4_first(domain)
    }

    #[inline(always)]
    fn lookup_ipv4_rand(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        self.as_ref().lookup_ipv4_rand(domain)
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.as_ref().lookup_ipv6(domain)
    }

    #[inline(always)]
    fn lookup_ipv6_first(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        self.as_ref().lookup_ipv6_first(domain)
    }

    #[inline(always)]
    fn lookup_ipv6_rand(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        self.as_ref().lookup_ipv6_rand(domain)
    }

    #[inline(always)]
    fn into_box_dns_address_resolver(self) -> BoxDnsAddressResolver {
        BoxDnsAddressResolver { inner: self }
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
    async fn lookup_ipv4_first(&self, domain: Domain) -> Option<Result<Ipv4Addr, Self::Error>> {
        if let Some(resolver) = self.as_ref() {
            resolver.lookup_ipv4_first(domain).await
        } else {
            None
        }
    }

    #[inline(always)]
    async fn lookup_ipv4_rand(&self, domain: Domain) -> Option<Result<Ipv4Addr, Self::Error>> {
        if let Some(resolver) = self.as_ref() {
            resolver.lookup_ipv4_rand(domain).await
        } else {
            None
        }
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::iter(self.as_ref().map(|resolver| resolver.lookup_ipv6(domain))).flatten()
    }

    #[inline(always)]
    async fn lookup_ipv6_first(&self, domain: Domain) -> Option<Result<Ipv6Addr, Self::Error>> {
        if let Some(resolver) = self.as_ref() {
            resolver.lookup_ipv6_first(domain).await
        } else {
            None
        }
    }

    #[inline(always)]
    async fn lookup_ipv6_rand(&self, domain: Domain) -> Option<Result<Ipv6Addr, Self::Error>> {
        if let Some(resolver) = self.as_ref() {
            resolver.lookup_ipv6_rand(domain).await
        } else {
            None
        }
    }

    #[inline(always)]
    fn into_box_dns_address_resolver(self) -> BoxDnsAddressResolver {
        match self {
            Some(resolver) => resolver.into_box_dns_address_resolver(),
            None => BoxDnsAddressResolver::new(EmptyDnsResolver::new()),
        }
    }
}

impl DnsAddressResolver for IpAddr {
    type Error = Infallible;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::iter(match self {
            Self::V4(ipv4_addr) => Some(Ok(*ipv4_addr)),
            Self::V6(_) => None,
        })
    }

    #[inline(always)]
    fn lookup_ipv4_first(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        std::future::ready(match self {
            Self::V4(ipv4_addr) => Some(Ok(*ipv4_addr)),
            Self::V6(_) => None,
        })
    }

    #[inline(always)]
    fn lookup_ipv4_rand(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        std::future::ready(match self {
            Self::V4(ipv4_addr) => Some(Ok(*ipv4_addr)),
            Self::V6(_) => None,
        })
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::iter(match self {
            Self::V4(_) => None,
            Self::V6(ipv6_addr) => Some(Ok(*ipv6_addr)),
        })
    }

    #[inline(always)]
    fn lookup_ipv6_first(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        std::future::ready(match self {
            Self::V4(_) => None,
            Self::V6(ipv6_addr) => Some(Ok(*ipv6_addr)),
        })
    }

    #[inline(always)]
    fn lookup_ipv6_rand(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        std::future::ready(match self {
            Self::V4(_) => None,
            Self::V6(ipv6_addr) => Some(Ok(*ipv6_addr)),
        })
    }
}

impl DnsAddressResolver for Ipv4Addr {
    type Error = Infallible;

    #[inline(always)]
    fn lookup_ipv4(&self, _: Domain) -> impl Stream<Item = Result<Self, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Ok(*self)))
    }

    #[inline(always)]
    fn lookup_ipv4_first(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Self, Self::Error>>> + Send + '_ {
        std::future::ready(Some(Ok(*self)))
    }

    #[inline(always)]
    fn lookup_ipv4_rand(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Self, Self::Error>>> + Send + '_ {
        std::future::ready(Some(Ok(*self)))
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::empty()
    }

    #[inline(always)]
    fn lookup_ipv6_first(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        std::future::ready(None)
    }

    #[inline(always)]
    fn lookup_ipv6_rand(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        std::future::ready(None)
    }
}

impl DnsAddressResolver for Ipv6Addr {
    type Error = Infallible;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::empty()
    }

    #[inline(always)]
    fn lookup_ipv4_first(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        std::future::ready(None)
    }

    #[inline(always)]
    fn lookup_ipv4_rand(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        std::future::ready(None)
    }

    #[inline(always)]
    fn lookup_ipv6(&self, _: Domain) -> impl Stream<Item = Result<Self, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Ok(*self)))
    }

    #[inline(always)]
    fn lookup_ipv6_first(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Self, Self::Error>>> + Send + '_ {
        std::future::ready(Some(Ok(*self)))
    }

    #[inline(always)]
    fn lookup_ipv6_rand(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Self, Self::Error>>> + Send + '_ {
        std::future::ready(Some(Ok(*self)))
    }
}

impl<R: DnsAddressResolver> DnsAddressResolver for DomainTrie<R> {
    type Error = R::Error;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::iter(
            self.match_exact(domain.clone())
                .map(|resolver| resolver.lookup_ipv4(domain)),
        )
        .flatten()
    }

    #[inline(always)]
    async fn lookup_ipv4_first(&self, domain: Domain) -> Option<Result<Ipv4Addr, Self::Error>> {
        if let Some(resolver) = self.match_exact(domain.clone()) {
            resolver.lookup_ipv4_first(domain).await
        } else {
            None
        }
    }

    #[inline(always)]
    async fn lookup_ipv4_rand(&self, domain: Domain) -> Option<Result<Ipv4Addr, Self::Error>> {
        if let Some(resolver) = self.match_exact(domain.clone()) {
            resolver.lookup_ipv4_rand(domain).await
        } else {
            None
        }
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::iter(
            self.match_exact(domain.clone())
                .map(|resolver| resolver.lookup_ipv6(domain)),
        )
        .flatten()
    }

    #[inline(always)]
    async fn lookup_ipv6_first(&self, domain: Domain) -> Option<Result<Ipv6Addr, Self::Error>> {
        if let Some(resolver) = self.match_exact(domain.clone()) {
            resolver.lookup_ipv6_first(domain).await
        } else {
            None
        }
    }

    #[inline(always)]
    async fn lookup_ipv6_rand(&self, domain: Domain) -> Option<Result<Ipv6Addr, Self::Error>> {
        if let Some(resolver) = self.match_exact(domain.clone()) {
            resolver.lookup_ipv6_rand(domain).await
        } else {
            None
        }
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
}

impl<T: DnsAddressResolver> DynDnsAddressResolver for T {
    fn dyn_lookup_ipv4(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv4Addr, OpaqueError>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv4(domain)
                .map_err(ErrorExt::into_opaque_error),
        )
    }

    fn dyn_lookup_ipv4_first(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv4Addr, OpaqueError>>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv4_first(domain)
                .map(|output| output.map(|result| result.map_err(ErrorExt::into_opaque_error))),
        )
    }

    fn dyn_lookup_ipv4_rand(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv4Addr, OpaqueError>>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv4_rand(domain)
                .map(|output| output.map(|result| result.map_err(ErrorExt::into_opaque_error))),
        )
    }

    fn dyn_lookup_ipv6(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Ipv6Addr, OpaqueError>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv6(domain)
                .map_err(ErrorExt::into_opaque_error),
        )
    }

    fn dyn_lookup_ipv6_first(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv6Addr, OpaqueError>>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv6_first(domain)
                .map(|output| output.map(|result| result.map_err(ErrorExt::into_opaque_error))),
        )
    }

    fn dyn_lookup_ipv6_rand(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Future<Output = Option<Result<Ipv6Addr, OpaqueError>>> + Send + '_>> {
        Box::pin(
            self.lookup_ipv6_rand(domain)
                .map(|output| output.map(|result| result.map_err(ErrorExt::into_opaque_error))),
        )
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

    fn into_box_dns_address_resolver(self) -> BoxDnsAddressResolver {
        self
    }
}
