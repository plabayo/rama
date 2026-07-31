//! Linux-native DNS resolver.
//!
//! When systemd-resolved's varlink socket is reachable, lookups are served
//! through it first — fully async, no blocking-pool worker — falling back to
//! the libc paths below per query and whenever the daemon is unavailable
//! (see [`super::systemd_resolved`]).
//!
//! On targets with `res_nsearch` support, `A` / `AAAA` / `TXT` lookups are
//! backed by the native resolver stub. `res_nsearch` (not `res_nquery`) is
//! used so the resolver walks the `search` list from `/etc/resolv.conf` and
//! respects `ndots`, matching the behavior of `getaddrinfo` and hickory's
//! system resolver.
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
    octets::kib,
    str::arcstr::ArcStr,
};

use super::{
    resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver},
    systemd_resolved::{self, ResolvedLookup, SystemdResolved},
};

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
mod res_nsearch;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CACHE_TTL: Duration = Duration::from_mins(5);
const DEFAULT_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);
const DEFAULT_CACHE_CAPACITY: u64 = 65_536;
/// Default `res_nsearch` response buffer size.
///
/// Most DNS responses fit comfortably in 4 KiB, but large TXT/AAAA fan-outs
/// (DKIM, long SPF, multi-record AAAA sets) can exceed that. 16 KiB matches
/// what most TCP-fallback paths advertise via EDNS0 and keeps the per-query
/// allocation in the blocking thread modest.
const DEFAULT_RESPONSE_BUFFER_SIZE: usize = kib(16);

#[derive(Debug, Clone)]
/// Used to build a [`LinuxDnsResolver`] instance.
pub struct LinuxDnsResolverBuilder {
    timeout: Duration,
    cache_ttl: Duration,
    negative_cache_ttl: Duration,
    cache_capacity: u64,
    response_buffer_size: usize,
    systemd_resolved: bool,
    systemd_resolved_config: systemd_resolved::Config,
}

impl Default for LinuxDnsResolverBuilder {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            cache_ttl: DEFAULT_CACHE_TTL,
            negative_cache_ttl: DEFAULT_NEGATIVE_CACHE_TTL,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
            response_buffer_size: DEFAULT_RESPONSE_BUFFER_SIZE,
            systemd_resolved: true,
            systemd_resolved_config: systemd_resolved::Config::default(),
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
        /// Per-query response buffer size used by `res_nsearch`. Responses that
        /// exceed this bound are reported as an error; bump this for workloads
        /// that legitimately receive large TXT/AAAA fan-outs.
        pub fn response_buffer_size(mut self, response_buffer_size: usize) -> Self {
            self.response_buffer_size = response_buffer_size;
            self
        }
    }

    generate_set_and_with! {
        /// Route lookups through systemd-resolved's varlink API when its
        /// socket is reachable (default: enabled), falling back to the libc
        /// paths per query and whenever the daemon is unavailable.
        pub fn systemd_resolved(mut self, enabled: bool) -> Self {
            self.systemd_resolved = enabled;
            self
        }
    }

    generate_set_and_with! {
        /// How often an unavailable systemd-resolved is re-probed.
        pub fn systemd_resolved_reprobe_interval(mut self, interval: Duration) -> Self {
            self.systemd_resolved_config.reprobe_interval = interval;
            self
        }
    }

    generate_set_and_with! {
        /// Consecutive transport failures before systemd-resolved is marked
        /// unavailable. Resolution answers (incl. negative ones) never count.
        pub fn systemd_resolved_breaker_threshold(mut self, threshold: u32) -> Self {
            self.systemd_resolved_config.breaker_threshold = threshold;
            self
        }
    }

    generate_set_and_with! {
        /// Connect timeout for the systemd-resolved varlink socket. A healthy
        /// local daemon accepts near-instantly.
        pub fn systemd_resolved_connect_timeout(mut self, timeout: Duration) -> Self {
            self.systemd_resolved_config.connect_timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum in-flight systemd-resolved queries. Keep below resolved's
        /// varlink server default of 128 connections per UID, a budget shared
        /// with every other same-UID client (e.g. `nss-resolve`).
        pub fn systemd_resolved_max_concurrency(mut self, max: usize) -> Self {
            self.systemd_resolved_config.max_concurrency = max;
            self
        }
    }

    generate_set_and_with! {
        /// Cache TTL for address records resolved via systemd-resolved, whose
        /// replies carry no per-record TTLs. Keep short: the daemon's own
        /// TTL-accurate cache sits underneath. Zero means "unknown", falling
        /// back to the full [`Self::cache_ttl`] bound.
        pub fn systemd_resolved_hostname_cache_ttl(mut self, ttl: Duration) -> Self {
            self.systemd_resolved_config.hostname_ttl = ttl;
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
            systemd_resolved: self
                .systemd_resolved
                .then(|| Arc::new(SystemdResolved::new(self.systemd_resolved_config))),
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
    systemd_resolved: Option<Arc<SystemdResolved>>,
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

    #[must_use]
    pub fn systemd_resolved_enabled(&self) -> bool {
        self.systemd_resolved.is_some()
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
        let resolved = self.systemd_resolved.clone();
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache.clone(),
            cache::RecordKind::Ipv4,
            move |cache, domain| cache.get_ipv4(domain),
            move |cache, domain, values, ttl| cache.insert_ipv4(domain, values, ttl),
            move |domain, timeout| {
                lookup_ipv4_uncached_stream(resolved, domain, timeout, response_buffer_size)
            },
        )
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        let response_buffer_size = self.response_buffer_size;
        let resolved = self.systemd_resolved.clone();
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache.clone(),
            cache::RecordKind::Ipv6,
            move |cache, domain| cache.get_ipv6(domain),
            move |cache, domain, values, ttl| cache.insert_ipv6(domain, values, ttl),
            move |domain, timeout| {
                lookup_ipv6_uncached_stream(resolved, domain, timeout, response_buffer_size)
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
        let resolved = self.systemd_resolved.clone();
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache.clone(),
            cache::RecordKind::Txt,
            move |cache, domain| cache.get_txt(domain),
            move |cache, domain, values, ttl| cache.insert_txt(domain, values, ttl),
            move |domain, timeout| {
                lookup_txt_uncached_stream(resolved, domain, timeout, response_buffer_size)
            },
        )
    }
}

impl DnsResolver for LinuxDnsResolver {}

/// Events emitted by uncached lookup streams.
///
/// `AuthoritativeNegative` is only emitted by backends that can distinguish
/// "the zone says there is no such record" (the `res_nsearch` and
/// systemd-resolved paths) from "this lookup returned nothing for unrelated
/// reasons" (the legacy `getaddrinfo` path, where `AI_ADDRCONFIG` can
/// suppress whole families based on local interface state). Only the former
/// is safe to cache as a negative entry, and only with a SOA-derived TTL —
/// systemd-resolved negatives carry none (the daemon does its own RFC 2308
/// negative caching), so they end up uncached here.
pub(super) enum LookupEvent<T> {
    Record(T, u32),
    AuthoritativeNegative { soa_ttl: Option<u32> },
}

/// Lookup a domain and produce a stream that is cached on succes. If a
/// cached result is available we use that instead of doing a fresh lookup.
///
/// WARNING: the output of lookup() is fully buffered and not streamed!
/// This is needed so we can cache results even if the output stream is never
/// fully consumed (which is the case when we do things like `race_connect`).
/// This function should only be used where this behaviour is not a problem,
/// e.g. the result of lookup() is already buffered internally (like linux dns resolvers).
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

        // Instead of yielding each item directly, we need to: collect all of them first,
        // cache them, and yield them one by one. If we yield them one by one
        // and the consumer stops polling we never reach our cache logic, so
        // we need to make sure that we have cached everything before this generator
        // could be suspended. Buffering a `Stream` here is fine since both
        // `res_nsearch.rs` and `legacy.rs` actually return a single complete response,
        // which is then just parsed and then send over a channel piece by piece. By draining it fast
        // here, we also release our `spawn_blocking` worker, which is important since these
        // are finite and having all of them in use becomes a single bottleneck for the entire stack.
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
                    values.push(value);
                }
                Ok(LookupEvent::AuthoritativeNegative { soa_ttl }) => {
                    authoritative_negative = soa_ttl;
                }
                Err(err) => {
                    // Still yield all items we got, but we dont cache these on error
                    for value in values {
                        yielder.yield_item(Ok(value)).await;
                    }
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
            insert_cached(&cache, domain, values.clone(), ttl);

            for value in values {
                yielder.yield_item(Ok(value)).await;
            }
        }
    })
}

fn lookup_ipv4_uncached_stream(
    resolved: Option<Arc<SystemdResolved>>,
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Ipv4Addr>, BoxError>> + Send {
    let varlink = resolved.map(|resolved| {
        let domain = domain.clone();
        async move { resolved.lookup_ipv4(&domain, timeout).await }
    });
    resolved_first_stream(varlink, move || {
        native_lookup_ipv4_stream(domain, timeout, response_buffer_size)
    })
}

fn lookup_ipv6_uncached_stream(
    resolved: Option<Arc<SystemdResolved>>,
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Ipv6Addr>, BoxError>> + Send {
    let varlink = resolved.map(|resolved| {
        let domain = domain.clone();
        async move { resolved.lookup_ipv6(&domain, timeout).await }
    });
    resolved_first_stream(varlink, move || {
        native_lookup_ipv6_stream(domain, timeout, response_buffer_size)
    })
}

fn lookup_txt_uncached_stream(
    resolved: Option<Arc<SystemdResolved>>,
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Bytes>, BoxError>> + Send {
    let varlink = resolved.map(|resolved| {
        let domain = domain.clone();
        async move { resolved.lookup_txt(&domain, timeout).await }
    });
    resolved_first_stream(varlink, move || {
        native_lookup_txt_stream(domain, timeout, response_buffer_size)
    })
}

/// Serve the lookup via systemd-resolved when a usable answer comes back,
/// and stream from the native libc backend otherwise.
fn resolved_first_stream<T, F, N, S>(
    varlink: Option<F>,
    native: N,
) -> impl Stream<Item = Result<LookupEvent<T>, BoxError>> + Send
where
    T: Send + 'static,
    F: Future<Output = ResolvedLookup<T>> + Send + 'static,
    N: FnOnce() -> S + Send + 'static,
    S: Stream<Item = Result<LookupEvent<T>, BoxError>> + Send,
{
    stream_fn(async move |mut yielder| {
        if let Some(varlink) = varlink {
            match varlink.await {
                ResolvedLookup::Records(records) => {
                    for (value, ttl) in records {
                        yielder
                            .yield_item(Ok(LookupEvent::Record(value, ttl)))
                            .await;
                    }
                    return;
                }
                ResolvedLookup::Negative => {
                    yielder
                        .yield_item(Ok(LookupEvent::AuthoritativeNegative { soa_ttl: None }))
                        .await;
                    return;
                }
                ResolvedLookup::Failed(err) => {
                    yielder.yield_item(Err(err)).await;
                    return;
                }
                ResolvedLookup::Unavailable => {}
            }
        }
        let mut native = std::pin::pin!(native());
        while let Some(item) = native.next().await {
            yielder.yield_item(item).await;
        }
    })
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn native_lookup_ipv4_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Ipv4Addr>, BoxError>> + Send {
    res_nsearch::lookup_ipv4_stream(domain, timeout, response_buffer_size)
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
fn native_lookup_ipv4_stream(
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
fn native_lookup_ipv6_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Ipv6Addr>, BoxError>> + Send {
    res_nsearch::lookup_ipv6_stream(domain, timeout, response_buffer_size)
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
fn native_lookup_ipv6_stream(
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
fn native_lookup_txt_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Bytes>, BoxError>> + Send {
    res_nsearch::lookup_txt_stream(domain, timeout, response_buffer_size)
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
fn native_lookup_txt_stream(
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
    use super::{LookupEvent, ResolvedLookup, cache, lookup_cached_stream, resolved_first_stream};
    use rama_core::{
        error::{BoxError, BoxErrorExt as _},
        futures::{Stream, StreamExt as _, stream},
    };
    use rama_net::address::Domain;
    use std::{
        net::Ipv4Addr,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    fn test_cache() -> Arc<cache::LinuxDnsCache> {
        Arc::new(cache::LinuxDnsCache::new(
            64,
            Duration::from_secs(300),
            Duration::from_secs(30),
        ))
    }

    fn test_domain() -> Domain {
        "example.com.".try_into().expect("valid domain")
    }

    fn cached_ipv4_stream<S>(
        domain: Domain,
        cache: Arc<cache::LinuxDnsCache>,
        backend: S,
    ) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send
    where
        S: Stream<Item = Result<LookupEvent<Ipv4Addr>, BoxError>> + Send + 'static,
    {
        lookup_cached_stream(
            domain,
            Duration::from_secs(5),
            cache,
            cache::RecordKind::Ipv4,
            move |cache, domain| cache.get_ipv4(domain),
            move |cache, domain, values, ttl| cache.insert_ipv4(domain, values, ttl),
            move |_domain, _timeout| backend,
        )
    }

    fn cached_ipv4(cache: &cache::LinuxDnsCache, domain: &Domain) -> Option<Vec<Ipv4Addr>> {
        match cache.get_ipv4(domain) {
            Some(cache::CacheLookup::Positive(values)) => Some(values.to_vec()),
            Some(cache::CacheLookup::Negative) => panic!("expected positive entry, got negative"),
            None => None,
        }
    }

    #[tokio::test]
    async fn positive_cache_is_written_when_consumer_drops_after_one_item() {
        let cache = test_cache();
        let domain = test_domain();
        let addrs = [
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(93, 184, 216, 35),
            Ipv4Addr::new(93, 184, 216, 36),
        ];
        let backend = stream::iter(
            addrs
                .into_iter()
                .map(|addr| Ok(LookupEvent::Record(addr, 60))),
        );

        let mut stream = Box::pin(cached_ipv4_stream(domain.clone(), cache.clone(), backend));
        let first = stream.next().await;
        assert!(matches!(first, Some(Ok(addr)) if addr == addrs[0]));
        drop(stream);

        assert_eq!(
            cached_ipv4(&cache, &domain).as_deref(),
            Some(addrs.as_slice()),
            "early-exiting consumer must still leave the full record set cached",
        );
    }

    #[tokio::test]
    async fn positive_cache_is_written_when_consumer_drains_fully() {
        let cache = test_cache();
        let domain = test_domain();
        let addrs = [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)];
        let backend = stream::iter(
            addrs
                .into_iter()
                .map(|addr| Ok(LookupEvent::Record(addr, 60))),
        );

        let yielded: Vec<_> = cached_ipv4_stream(domain.clone(), cache.clone(), backend)
            .filter_map(|item| std::future::ready(item.ok()))
            .collect()
            .await;

        assert_eq!(yielded, addrs);
        assert_eq!(
            cached_ipv4(&cache, &domain).as_deref(),
            Some(addrs.as_slice())
        );
    }

    #[tokio::test]
    async fn errors_are_yielded_after_prior_records_and_are_not_cached() {
        let cache = test_cache();
        let domain = test_domain();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let backend = stream::iter([
            Ok(LookupEvent::Record(addr, 60)),
            Err(BoxError::from_static_str("boom")),
        ]);

        let items: Vec<_> = cached_ipv4_stream(domain.clone(), cache.clone(), backend)
            .collect()
            .await;

        assert_eq!(items.len(), 2);
        assert!(matches!(items[0], Ok(got) if got == addr));
        assert!(matches!(items[1], Err(ref err) if err.to_string() == "boom"));
        assert!(
            cached_ipv4(&cache, &domain).is_none(),
            "a failed lookup must not be cached",
        );
    }

    fn tracked_native(
        called: &Arc<AtomicBool>,
    ) -> impl FnOnce() -> stream::Iter<std::vec::IntoIter<Result<LookupEvent<Ipv4Addr>, BoxError>>>
    + Send
    + 'static {
        let called = called.clone();
        move || {
            called.store(true, Ordering::SeqCst);
            stream::iter(vec![Ok(LookupEvent::Record(Ipv4Addr::new(9, 9, 9, 9), 30))])
        }
    }

    #[tokio::test]
    async fn resolved_records_short_circuit_native() {
        let native_called = Arc::new(AtomicBool::new(false));
        let items: Vec<_> = resolved_first_stream(
            Some(std::future::ready(ResolvedLookup::Records(vec![(
                Ipv4Addr::new(1, 2, 3, 4),
                60,
            )]))),
            tracked_native(&native_called),
        )
        .collect()
        .await;

        assert_eq!(items.len(), 1);
        assert!(
            matches!(items[0], Ok(LookupEvent::Record(addr, 60)) if addr == Ipv4Addr::new(1, 2, 3, 4)),
        );
        assert!(!native_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn resolved_negative_yields_authoritative_event() {
        let native_called = Arc::new(AtomicBool::new(false));
        let items: Vec<_> = resolved_first_stream(
            Some(std::future::ready(ResolvedLookup::<Ipv4Addr>::Negative)),
            tracked_native(&native_called),
        )
        .collect()
        .await;

        assert_eq!(items.len(), 1);
        assert!(matches!(
            items[0],
            Ok(LookupEvent::AuthoritativeNegative { soa_ttl: None }),
        ));
        assert!(!native_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn resolved_failure_is_surfaced() {
        let native_called = Arc::new(AtomicBool::new(false));
        let items: Vec<_> = resolved_first_stream(
            Some(std::future::ready(ResolvedLookup::<Ipv4Addr>::Failed(
                BoxError::from_static_str("nope"),
            ))),
            tracked_native(&native_called),
        )
        .collect()
        .await;

        assert_eq!(items.len(), 1);
        assert!(matches!(items[0], Err(ref err) if err.to_string() == "nope"));
        assert!(!native_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn resolved_unavailable_falls_back_to_native() {
        let native_called = Arc::new(AtomicBool::new(false));
        let items: Vec<_> = resolved_first_stream(
            Some(std::future::ready(ResolvedLookup::<Ipv4Addr>::Unavailable)),
            tracked_native(&native_called),
        )
        .collect()
        .await;

        assert_eq!(items.len(), 1);
        assert!(
            matches!(items[0], Ok(LookupEvent::Record(addr, 30)) if addr == Ipv4Addr::new(9, 9, 9, 9)),
        );
        assert!(native_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn disabled_resolved_uses_native() {
        let native_called = Arc::new(AtomicBool::new(false));
        let items: Vec<_> = resolved_first_stream(
            None::<std::future::Ready<ResolvedLookup<Ipv4Addr>>>,
            tracked_native(&native_called),
        )
        .collect()
        .await;

        assert_eq!(items.len(), 1);
        assert!(native_called.load(Ordering::SeqCst));
    }

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
