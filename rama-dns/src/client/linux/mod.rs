//! Linux-native DNS resolver.
//!
//! On targets with `res_nquery` support, `A` / `AAAA` / `TXT` lookups are
//! backed by the native resolver stub.
//!
//! On other Linux libc environments, address lookups fall back to
//! `getaddrinfo`, while TXT lookups return a stable unsupported error.

use std::{
    ffi::CString,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use rama_core::{
    bytes::Bytes,
    error::BoxError,
    futures::{Stream, StreamExt as _, async_stream::stream_fn},
    telemetry::tracing,
};
use rama_net::address::Domain;
use rama_utils::{
    macros::{error::static_str_error, generate_set_and_with},
    str::arcstr::ArcStr,
};

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

mod cache;

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
mod legacy;

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
mod res_nquery;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_CACHE_CAPACITY: u64 = 65_536;

#[derive(Debug, Clone)]
/// Used to build a [`LinuxDnsResolver`] instance.
pub struct LinuxDnsResolverBuilder {
    timeout: Duration,
    cache_ttl: Duration,
    cache_capacity: u64,
}

impl Default for LinuxDnsResolverBuilder {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            cache_ttl: DEFAULT_CACHE_TTL,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
        }
    }
}

impl LinuxDnsResolverBuilder {
    generate_set_and_with! {
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        pub fn cache_ttl(mut self, cache_ttl: Duration) -> Self {
            self.cache_ttl = cache_ttl;
            self
        }
    }

    generate_set_and_with! {
        pub fn cache_capacity(mut self, cache_capacity: u64) -> Self {
            self.cache_capacity = cache_capacity;
            self
        }
    }

    #[must_use]
    pub fn build(self) -> LinuxDnsResolver {
        LinuxDnsResolver {
            timeout: self.timeout,
            cache_ttl: self.cache_ttl,
            cache_capacity: self.cache_capacity,
            cache: Arc::new(cache::LinuxDnsCache::new(
                self.cache_capacity,
                self.cache_ttl,
            )),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LinuxDnsResolver {
    timeout: Duration,
    cache_ttl: Duration,
    cache_capacity: u64,
    cache: Arc<cache::LinuxDnsCache>,
}

impl Default for LinuxDnsResolver {
    fn default() -> Self {
        LinuxDnsResolverBuilder::default().build()
    }
}

impl LinuxDnsResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    #[must_use]
    pub const fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }

    #[must_use]
    pub const fn cache_capacity(&self) -> u64 {
        self.cache_capacity
    }

    generate_set_and_with! {
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    #[must_use]
    pub fn builder() -> LinuxDnsResolverBuilder {
        LinuxDnsResolverBuilder::default()
    }
}

impl DnsAddressResolver for LinuxDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache_ttl,
            self.cache.clone(),
            move |cache, domain| cache.get_ipv4(domain),
            move |cache, domain, values| cache.insert_ipv4(domain, values),
            lookup_ipv4_uncached_stream,
        )
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache_ttl,
            self.cache.clone(),
            move |cache, domain| cache.get_ipv6(domain),
            move |cache, domain, values| cache.insert_ipv6(domain, values),
            lookup_ipv6_uncached_stream,
        )
    }
}

impl DnsTxtResolver for LinuxDnsResolver {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache_ttl,
            self.cache.clone(),
            move |cache, domain| cache.get_txt(domain),
            move |cache, domain, values| cache.insert_txt(domain, values),
            lookup_txt_uncached_stream,
        )
    }
}

impl DnsResolver for LinuxDnsResolver {}

fn lookup_cached_stream<T, S, G, I, F>(
    domain: Domain,
    timeout: Duration,
    cache_ttl: Duration,
    cache: Arc<cache::LinuxDnsCache>,
    get_cached: G,
    insert_cached: I,
    lookup: F,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: Clone + Send + Sync + 'static,
    S: Stream<Item = Result<T, BoxError>> + Send + 'static,
    G: Fn(&cache::LinuxDnsCache, &Domain) -> Option<Arc<[T]>> + Send + 'static,
    I: Fn(&cache::LinuxDnsCache, Domain, Vec<T>) + Send + 'static,
    F: FnOnce(Domain, Duration) -> S + Send + 'static,
{
    stream_fn(async move |mut yielder| {
        if let Some(values) = get_cached(&cache, &domain) {
            tracing::debug!(?cache_ttl, %domain, "dns::linux: cache hit");
            for value in values.iter().cloned() {
                yielder.yield_item(Ok(value)).await;
            }
            return;
        }

        let mut values = Vec::new();
        let mut lookup = std::pin::pin!(lookup(domain.clone(), timeout));
        while let Some(item) = lookup.next().await {
            match item {
                Ok(value) => {
                    values.push(value.clone());
                    yielder.yield_item(Ok(value)).await;
                }
                Err(err) => {
                    yielder.yield_item(Err(err)).await;
                    return;
                }
            }
        }

        insert_cached(&cache, domain, values);
    })
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn lookup_ipv4_uncached_stream(
    domain: Domain,
    timeout: Duration,
) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send {
    res_nquery::lookup_ipv4_stream(domain, timeout)
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
fn lookup_ipv4_uncached_stream(
    domain: Domain,
    timeout: Duration,
) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send {
    legacy::lookup_ipv4_stream(domain, timeout)
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn lookup_ipv6_uncached_stream(
    domain: Domain,
    timeout: Duration,
) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send {
    res_nquery::lookup_ipv6_stream(domain, timeout)
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
fn lookup_ipv6_uncached_stream(
    domain: Domain,
    timeout: Duration,
) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send {
    legacy::lookup_ipv6_stream(domain, timeout)
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn lookup_txt_uncached_stream(
    domain: Domain,
    timeout: Duration,
) -> impl Stream<Item = Result<Bytes, BoxError>> + Send {
    res_nquery::lookup_txt_stream(domain, timeout)
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
fn lookup_txt_uncached_stream(
    _domain: Domain,
    _timeout: Duration,
) -> impl Stream<Item = Result<Bytes, BoxError>> + Send {
    rama_core::futures::stream::once(std::future::ready(Err(BoxError::from(
        LinuxDnsTxtUnsupportedError,
    ))))
}

fn dns_name_from_domain(domain: &str) -> Result<CString, BoxError> {
    let name = domain.trim_end_matches('.');
    CString::new(name).map_err(|_| {
        LinuxDnsResolverError::message(format!("domain contains interior NUL byte: {name}")).into()
    })
}

#[derive(Debug)]
struct LinuxDnsResolverError(ArcStr);

impl LinuxDnsResolverError {
    fn message(message: impl Into<ArcStr>) -> Self {
        Self(message.into())
    }

    fn timeout(timeout: Duration) -> Self {
        Self::message(format!("linux dns query timed out after {timeout:?}"))
    }
}

impl fmt::Display for LinuxDnsResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LinuxDnsResolverError {}

static_str_error! {
    #[doc = "Linux native TXT resolution is unsupported on this libc target (opt-in to hickory instead)"]
    pub struct LinuxDnsTxtUnsupportedError;
}
