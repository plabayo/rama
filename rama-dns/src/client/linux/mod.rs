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
const DEFAULT_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);
const DEFAULT_CACHE_CAPACITY: u64 = 65_536;
/// Default `res_nquery` response buffer size.
///
/// Most DNS responses fit comfortably in 4 KiB, but large TXT/AAAA fan-outs
/// (DKIM, long SPF, multi-record AAAA sets) can exceed that. 16 KiB matches
/// what most TCP-fallback paths advertise via EDNS0 and keeps the per-query
/// allocation in the blocking thread modest.
const DEFAULT_RESPONSE_BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone)]
/// Used to build a [`LinuxDnsResolver`] instance.
pub struct LinuxDnsResolverBuilder {
    timeout: Duration,
    cache_ttl: Duration,
    negative_cache_ttl: Duration,
    cache_capacity: u64,
    response_buffer_size: usize,
}

impl Default for LinuxDnsResolverBuilder {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            cache_ttl: DEFAULT_CACHE_TTL,
            negative_cache_ttl: DEFAULT_NEGATIVE_CACHE_TTL,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
            response_buffer_size: DEFAULT_RESPONSE_BUFFER_SIZE,
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
        /// Maximum positive-cache lifetime. Per-record TTLs from the wire are
        /// honored when shorter than this bound.
        pub fn cache_ttl(mut self, cache_ttl: Duration) -> Self {
            self.cache_ttl = cache_ttl;
            self
        }
    }

    generate_set_and_with! {
        /// Lifetime for negative (NXDOMAIN / NODATA) cache entries.
        pub fn negative_cache_ttl(mut self, negative_cache_ttl: Duration) -> Self {
            self.negative_cache_ttl = negative_cache_ttl;
            self
        }
    }

    generate_set_and_with! {
        pub fn cache_capacity(mut self, cache_capacity: u64) -> Self {
            self.cache_capacity = cache_capacity;
            self
        }
    }

    generate_set_and_with! {
        /// Per-query response buffer size used by `res_nquery`. Responses that
        /// exceed this bound are reported as an error; bump this for workloads
        /// that legitimately receive large TXT/AAAA fan-outs.
        pub fn response_buffer_size(mut self, response_buffer_size: usize) -> Self {
            self.response_buffer_size = response_buffer_size;
            self
        }
    }

    #[must_use]
    pub fn build(self) -> LinuxDnsResolver {
        LinuxDnsResolver {
            timeout: self.timeout,
            cache_ttl: self.cache_ttl,
            negative_cache_ttl: self.negative_cache_ttl,
            cache_capacity: self.cache_capacity,
            response_buffer_size: self.response_buffer_size,
            cache: Arc::new(cache::LinuxDnsCache::new(
                self.cache_capacity,
                self.cache_ttl,
                self.negative_cache_ttl,
            )),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LinuxDnsResolver {
    timeout: Duration,
    cache_ttl: Duration,
    negative_cache_ttl: Duration,
    cache_capacity: u64,
    response_buffer_size: usize,
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
    pub const fn negative_cache_ttl(&self) -> Duration {
        self.negative_cache_ttl
    }

    #[must_use]
    pub const fn cache_capacity(&self) -> u64 {
        self.cache_capacity
    }

    #[must_use]
    pub const fn response_buffer_size(&self) -> usize {
        self.response_buffer_size
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
        let response_buffer_size = self.response_buffer_size;
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache.clone(),
            cache::RecordKind::Ipv4,
            move |cache, domain| cache.get_ipv4(domain),
            move |cache, domain, values, ttl| cache.insert_ipv4(domain, values, ttl),
            move |domain, timeout| {
                lookup_ipv4_uncached_stream(domain, timeout, response_buffer_size)
            },
        )
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        let response_buffer_size = self.response_buffer_size;
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache.clone(),
            cache::RecordKind::Ipv6,
            move |cache, domain| cache.get_ipv6(domain),
            move |cache, domain, values, ttl| cache.insert_ipv6(domain, values, ttl),
            move |domain, timeout| {
                lookup_ipv6_uncached_stream(domain, timeout, response_buffer_size)
            },
        )
    }
}

impl DnsTxtResolver for LinuxDnsResolver {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        let response_buffer_size = self.response_buffer_size;
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache.clone(),
            cache::RecordKind::Txt,
            move |cache, domain| cache.get_txt(domain),
            move |cache, domain, values, ttl| cache.insert_txt(domain, values, ttl),
            move |domain, timeout| {
                lookup_txt_uncached_stream(domain, timeout, response_buffer_size)
            },
        )
    }
}

impl DnsResolver for LinuxDnsResolver {}

/// Events emitted by uncached lookup streams.
///
/// `AuthoritativeNegative` is only emitted by backends that can distinguish
/// "the zone says there is no such record" (the `res_nquery` path) from
/// "this lookup returned nothing for unrelated reasons" (the legacy
/// `getaddrinfo` path, where `AI_ADDRCONFIG` can suppress whole families
/// based on local interface state). Only the former is safe to cache as a
/// negative entry.
pub(super) enum LookupEvent<T> {
    Record(T, u32),
    // Only constructed by the `res_nquery` backend (glibc / BSDs). The
    // legacy `getaddrinfo` fallback (used on e.g. musl) cannot distinguish
    // authoritative DNS negatives from local-policy empties — see
    // `legacy.rs` — so it never emits this variant. The `cfg_attr` only
    // applies the lint expectation on the exact targets where the variant
    // is dead, so `expect` is fulfilled there and absent elsewhere.
    #[cfg_attr(
        not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
        )),
        expect(dead_code, reason = "only constructed by the res_nquery backend")
    )]
    AuthoritativeNegative {
        soa_ttl: Option<u32>,
    },
}

fn lookup_cached_stream<T, S, G, I, F>(
    domain: Domain,
    timeout: Duration,
    cache: Arc<cache::LinuxDnsCache>,
    kind: cache::RecordKind,
    get_cached: G,
    insert_cached: I,
    lookup: F,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: Clone + Send + Sync + 'static,
    S: Stream<Item = Result<LookupEvent<T>, BoxError>> + Send + 'static,
    G: Fn(&cache::LinuxDnsCache, &Domain) -> Option<cache::CacheLookup<T>> + Send + 'static,
    I: Fn(&cache::LinuxDnsCache, Domain, Vec<T>, Option<Duration>) + Send + 'static,
    F: FnOnce(Domain, Duration) -> S + Send + 'static,
{
    stream_fn(async move |mut yielder| {
        match get_cached(&cache, &domain) {
            Some(cache::CacheLookup::Positive(values)) => {
                tracing::debug!(%domain, "dns::linux: cache hit (positive)");
                for value in values.iter().cloned() {
                    yielder.yield_item(Ok(value)).await;
                }
                return;
            }
            Some(cache::CacheLookup::Negative) => {
                tracing::debug!(%domain, "dns::linux: cache hit (negative)");
                return;
            }
            None => {}
        }

        let mut values = Vec::new();
        let mut min_ttl_secs: Option<u32> = None;
        let mut authoritative_negative: Option<u32> = None;
        let mut lookup = std::pin::pin!(lookup(domain.clone(), timeout));
        while let Some(item) = lookup.next().await {
            match item {
                Ok(LookupEvent::Record(value, ttl)) => {
                    if ttl > 0 {
                        min_ttl_secs = Some(min_ttl_secs.map_or(ttl, |prev| prev.min(ttl)));
                    }
                    values.push(value.clone());
                    yielder.yield_item(Ok(value)).await;
                }
                Ok(LookupEvent::AuthoritativeNegative { soa_ttl }) => {
                    authoritative_negative = soa_ttl;
                }
                Err(err) => {
                    yielder.yield_item(Err(err)).await;
                    return;
                }
            }
        }

        if values.is_empty() {
            // RFC 2308 §5: negative responses MAY be cached, but only if they
            // carry an SOA from which to derive a bounded TTL. Responses
            // without an SOA "SHOULD NOT be cached" — there is no
            // authoritative countdown to prevent looping. A SOA-derived TTL
            // of zero likewise means "do not cache". We additionally require
            // the backend to have signalled that the empty result is an
            // authoritative DNS negative (the legacy `getaddrinfo` path
            // cannot — see `legacy.rs`).
            if let Some(soa_ttl_secs) = authoritative_negative {
                cache.insert_negative(domain, kind, Duration::from_secs(u64::from(soa_ttl_secs)));
            }
        } else {
            let ttl = min_ttl_secs.map(|secs| Duration::from_secs(u64::from(secs)));
            insert_cached(&cache, domain, values, ttl);
        }
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
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Ipv4Addr>, BoxError>> + Send {
    res_nquery::lookup_ipv4_stream(domain, timeout, response_buffer_size)
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
    _response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Ipv4Addr>, BoxError>> + Send {
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
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Ipv6Addr>, BoxError>> + Send {
    res_nquery::lookup_ipv6_stream(domain, timeout, response_buffer_size)
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
    _response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Ipv6Addr>, BoxError>> + Send {
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
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Bytes>, BoxError>> + Send {
    res_nquery::lookup_txt_stream(domain, timeout, response_buffer_size)
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
    _response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Bytes>, BoxError>> + Send {
    rama_core::futures::stream::once(std::future::ready(Err(BoxError::from(
        LinuxDnsTxtUnsupportedError,
    ))))
}

fn dns_name_from_domain(domain: &str) -> Result<CString, BoxError> {
    let name = domain.trim_end_matches('.');
    CString::new(name).map_err(|_e| {
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

#[cfg(test)]
mod tests {
    use super::cache;
    use rama_net::address::Domain;
    use std::time::Duration;

    #[test]
    fn cache_stores_when_soa_ttl_is_positive() {
        let cache =
            cache::LinuxDnsCache::new(64, Duration::from_secs(300), Duration::from_secs(30));
        let domain: Domain = "with-soa.example.".try_into().expect("valid domain");

        cache.insert_negative(
            domain.clone(),
            cache::RecordKind::Ipv4,
            Duration::from_secs(45),
        );

        match cache.get_ipv4(&domain) {
            Some(cache::CacheLookup::Negative) => {}
            _ => panic!("expected negative cache entry"),
        }
    }
}
