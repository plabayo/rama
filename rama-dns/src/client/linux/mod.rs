//! Linux-native DNS resolver.
//!
//! When the host selects `nss-resolve`, lookups are served through
//! systemd-resolved's varlink socket first — fully async, no blocking-pool
//! worker — falling back to the libc paths below per query and whenever the
//! daemon is unavailable (see [`super::systemd_resolved`]). The builder may
//! explicitly enable or disable this path regardless of the NSS configuration.
//!
//! On targets with `res_nsearch` support, `A` / `AAAA` / `CNAME` / `TXT` /
//! `SVCB` / `HTTPS` lookups are
//! backed by the native resolver stub. `res_nsearch` (not `res_nquery`) is
//! used so the resolver walks the `search` list from `/etc/resolv.conf` and
//! respects `ndots`, matching the behavior of `getaddrinfo` and hickory's
//! system resolver.
//!
//! On other Linux libc environments, address lookups fall back to
//! `getaddrinfo`, while non-address lookups return stable unsupported errors
//! when systemd-resolved is unavailable.

use std::{
    ffi::CString,
    fmt, fs,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, OnceLock},
    time::Duration,
};

use rama_core::{
    error::BoxError,
    futures::{Stream, StreamExt as _, async_stream::stream_fn},
    telemetry::tracing,
};
use rama_net::address::Domain;
use rama_utils::{
    macros::{error::static_str_error, generate_set_and_with},
    str::arcstr::ArcStr,
};

use super::{
    resolver::{
        DnsAddressResolver, DnsCnameResolver, DnsResolver, DnsServiceBindingResolver,
        DnsTxtResolver,
    },
    systemd_resolved::{self, ResolvedLookup, SystemdResolved},
};
use crate::wire::{Name, ServiceBinding, Txt};

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
/// Default maximum `res_nsearch` response size.
///
/// This accepts the largest DNS wire message. The native backend starts with
/// a modest allocation and grows only when libc reports a larger response,
/// accommodating large TXT and SVCB/HTTPS RRsets such as ECH-heavy answers.
const DEFAULT_RESPONSE_BUFFER_SIZE: usize = u16::MAX as usize;
const NSSWITCH_CONF_PATH: &str = "/etc/nsswitch.conf";

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
            // A running daemon may only be maintained as a secondary DNS
            // view. Use it automatically only when NSS actually selects
            // nss-resolve; callers can still opt in explicitly below.
            systemd_resolved: systemd_resolved_selected_by_nss(),
            systemd_resolved_config: systemd_resolved::Config::default(),
        }
    }
}

impl LinuxDnsResolverBuilder {
    generate_set_and_with! {
        /// Timeout for each DNS backend attempt.
        ///
        /// If a systemd-resolved transport attempt consumes this budget and
        /// falls back to the native backend, that fallback receives a fresh
        /// budget. During the short pre-breaker window, total lookup latency
        /// can therefore approach twice this value.
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
        /// Maximum per-query allocation and positive response size for `res_nsearch`.
        ///
        /// The initial allocation remains modest and grows on demand. Responses
        /// exceeding this bound are errors when libc reports their required size;
        /// lower it only when deliberately rejecting large TXT, SVCB, or HTTPS
        /// RRsets. Some libc implementations do not report the size of negative
        /// replies; an oversized negative reply can therefore fall back to the
        /// resolver's default uncached-negative behavior. Values below the 12-byte
        /// fixed DNS header are rejected before calling libc.
        pub fn response_buffer_size(mut self, response_buffer_size: usize) -> Self {
            self.response_buffer_size = response_buffer_size;
            self
        }
    }

    generate_set_and_with! {
        /// Force whether lookups route through systemd-resolved's varlink API,
        /// falling back to the libc paths per query and whenever the daemon is
        /// unavailable.
        ///
        /// By default this is enabled automatically only when the host's
        /// `hosts:` NSS configuration selects `resolve` before `dns`. Merely
        /// finding a live systemd-resolved socket is insufficient: the daemon
        /// may maintain a secondary DNS view that is not the process's system
        /// resolver. Explicitly enabling the backend also opts into
        /// systemd-resolved's name semantics for address lookups: names
        /// containing a dot are treated as fully qualified instead of
        /// following libc's `ndots` search expansion. CNAME, TXT, SVCB, and
        /// HTTPS lookups keep the libc `search` behavior — a negative answer
        /// for a relative name is retried through the native backend; only a
        /// positive as-is answer can shadow a search-list candidate under
        /// `ndots` larger than one.
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

fn systemd_resolved_selected_by_nss() -> bool {
    // process-lifetime snapshot: resolvers are built freely and the
    // builder flag overrides whenever runtime control is needed
    static SELECTED: OnceLock<bool> = OnceLock::new();
    *SELECTED.get_or_init(|| {
        cfg!(target_env = "gnu")
            && fs::read_to_string(NSSWITCH_CONF_PATH)
                .is_ok_and(|contents| nsswitch_hosts_selects_resolve(&contents))
    })
}

// assumes the stock `resolve [!UNAVAIL=return] dns` line, where negative
// answers are final — matching this backend's own short-circuit on them
fn nsswitch_hosts_selects_resolve(contents: &str) -> bool {
    for raw_line in contents.lines() {
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(before_comment, _)| before_comment)
            .trim();
        let Some((database, sources)) = line.split_once(':') else {
            continue;
        };
        if database.trim() != "hosts" {
            continue;
        }

        let mut resolve_index = None;
        let mut dns_index = None;
        for (index, source) in sources.split_ascii_whitespace().enumerate() {
            match source {
                "resolve" => resolve_index.get_or_insert(index),
                "dns" => dns_index.get_or_insert(index),
                _ => continue,
            };
        }
        return resolve_index.is_some_and(|resolve| dns_index.is_none_or(|dns| resolve < dns));
    }
    false
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
        /// Set the timeout for each DNS backend attempt.
        ///
        /// See [`LinuxDnsResolverBuilder::timeout`] for fallback latency
        /// semantics.
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
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
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

impl DnsCnameResolver for LinuxDnsResolver {
    type Error = BoxError;

    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        let response_buffer_size = self.response_buffer_size;
        let resolved = self.systemd_resolved.clone();
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache.clone(),
            cache::RecordKind::Cname,
            move |cache, domain| cache.get_cname(domain),
            move |cache, domain, values, ttl| cache.insert_cname(domain, values, ttl),
            move |domain, timeout| {
                lookup_cname_uncached_stream(resolved, domain, timeout, response_buffer_size)
            },
        )
    }
}

impl DnsServiceBindingResolver for LinuxDnsResolver {
    type Error = BoxError;

    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, BoxError>> + Send + '_ {
        let response_buffer_size = self.response_buffer_size;
        let resolved = self.systemd_resolved.clone();
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache.clone(),
            cache::RecordKind::Svcb,
            move |cache, domain| cache.get_svcb(domain),
            move |cache, domain, values, ttl| cache.insert_svcb(domain, values, ttl),
            move |domain, timeout| {
                lookup_svcb_uncached_stream(resolved, domain, timeout, response_buffer_size)
            },
        )
    }

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, BoxError>> + Send + '_ {
        let response_buffer_size = self.response_buffer_size;
        let resolved = self.systemd_resolved.clone();
        lookup_cached_stream(
            domain,
            self.timeout,
            self.cache.clone(),
            cache::RecordKind::Https,
            move |cache, domain| cache.get_https(domain),
            move |cache, domain, values, ttl| cache.insert_https(domain, values, ttl),
            move |domain, timeout| {
                lookup_https_uncached_stream(resolved, domain, timeout, response_buffer_size)
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
    /// `None` means the backend could not expose a TTL; `Some(0)` is a real
    /// wire TTL and must prevent the record from being retained in the cache.
    Record(T, Option<u32>),
    AuthoritativeNegative {
        soa_ttl: Option<u32>,
    },
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
                    if let Some(ttl) = ttl {
                        min_ttl_secs = Some(min_ttl_secs.map_or(ttl, |prev| prev.min(ttl)));
                    }
                    values.push(value);
                }
                Ok(LookupEvent::AuthoritativeNegative { soa_ttl }) => {
                    authoritative_negative = soa_ttl;
                }
                Err(err) => {
                    // Preserve values the backend already accepted, but do not
                    // cache an incomplete lookup. Backends requiring atomic
                    // RRsets validate the complete response before emitting.
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
) -> impl Stream<Item = Result<LookupEvent<Txt>, BoxError>> + Send {
    let varlink = resolved.map(|resolved| {
        let domain = domain.clone();
        async move { resolved.lookup_txt(&domain, timeout).await }
    });
    resolved_first_stream(varlink, move || {
        native_lookup_txt_stream(domain, timeout, response_buffer_size)
    })
}

fn lookup_cname_uncached_stream(
    resolved: Option<Arc<SystemdResolved>>,
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Name>, BoxError>> + Send {
    let varlink = resolved.map(|resolved| {
        let domain = domain.clone();
        async move { resolved.lookup_cname(&domain, timeout).await }
    });
    resolved_first_stream(varlink, move || {
        native_lookup_cname_stream(domain, timeout, response_buffer_size)
    })
}

fn lookup_svcb_uncached_stream(
    resolved: Option<Arc<SystemdResolved>>,
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    let varlink = resolved.map(|resolved| {
        let domain = domain.clone();
        async move { resolved.lookup_svcb(&domain, timeout).await }
    });
    resolved_first_stream(varlink, move || {
        native_lookup_svcb_stream(domain, timeout, response_buffer_size)
    })
}

fn lookup_https_uncached_stream(
    resolved: Option<Arc<SystemdResolved>>,
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    let varlink = resolved.map(|resolved| {
        let domain = domain.clone();
        async move { resolved.lookup_https(&domain, timeout).await }
    });
    resolved_first_stream(varlink, move || {
        native_lookup_https_stream(domain, timeout, response_buffer_size)
    })
}

/// Serve the lookup via systemd-resolved when a usable answer comes back,
/// and stream from the native libc backend otherwise.
///
/// The native fallback deliberately runs with its own full timeout: during
/// the short window before the breaker trips on a wedged daemon, a slow
/// success beats failing queries at the configured deadline.
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
) -> impl Stream<Item = Result<LookupEvent<Txt>, BoxError>> + Send {
    res_nsearch::lookup_txt_stream(domain, timeout, response_buffer_size)
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn native_lookup_cname_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Name>, BoxError>> + Send {
    res_nsearch::lookup_cname_stream(domain, timeout, response_buffer_size)
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
fn native_lookup_cname_stream(
    _domain: Domain,
    _timeout: Duration,
    _response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Name>, BoxError>> + Send {
    rama_core::futures::stream::once(std::future::ready(Err(BoxError::from(
        LinuxDnsCnameUnsupportedError,
    ))))
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn native_lookup_svcb_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    res_nsearch::lookup_svcb_stream(domain, timeout, response_buffer_size)
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
fn native_lookup_svcb_stream(
    _domain: Domain,
    _timeout: Duration,
    _response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    unsupported_service_binding_stream()
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn native_lookup_https_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    res_nsearch::lookup_https_stream(domain, timeout, response_buffer_size)
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
fn native_lookup_https_stream(
    _domain: Domain,
    _timeout: Duration,
    _response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    unsupported_service_binding_stream()
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
fn unsupported_service_binding_stream()
-> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    rama_core::futures::stream::once(std::future::ready(Err(BoxError::from(
        LinuxDnsServiceBindingUnsupportedError,
    ))))
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
) -> impl Stream<Item = Result<LookupEvent<Txt>, BoxError>> + Send {
    rama_core::futures::stream::once(std::future::ready(Err(BoxError::from(
        LinuxDnsTxtUnsupportedError,
    ))))
}

fn dns_name_from_domain(domain: &str) -> Result<CString, BoxError> {
    CString::new(domain).map_err(|_e| {
        LinuxDnsResolverError::message(format!("domain contains interior NUL byte: {domain}"))
            .into()
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

static_str_error! {
    #[doc = "Linux native CNAME resolution is unsupported on this libc target (opt-in to hickory instead)"]
    pub struct LinuxDnsCnameUnsupportedError;
}

static_str_error! {
    #[doc = "Linux native SVCB and HTTPS resolution is unsupported on this libc target (opt-in to hickory instead)"]
    pub struct LinuxDnsServiceBindingUnsupportedError;
}

#[cfg(test)]
mod tests {
    use super::{
        LookupEvent, ResolvedLookup, cache, dns_name_from_domain, lookup_cached_stream,
        resolved_first_stream,
    };
    use rama_core::{
        bytes::Bytes,
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

    use crate::wire::{ServiceBinding, Txt};

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

    #[test]
    fn native_query_preserves_absolute_root_label() {
        assert_eq!(
            dns_name_from_domain("printer.")
                .expect("valid domain")
                .to_bytes(),
            b"printer.",
        );
        assert_eq!(
            dns_name_from_domain("printer")
                .expect("valid domain")
                .to_bytes(),
            b"printer",
        );
    }

    fn service_binding(port: u16) -> ServiceBinding {
        let mut rdata = vec![0, 1, 0, 0, 3, 0, 2];
        rdata.extend_from_slice(&port.to_be_bytes());
        ServiceBinding::parse_rdata_bytes(&Bytes::from(rdata)).expect("valid service binding")
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

    #[derive(Clone, Copy)]
    enum ServiceBindingKind {
        Svcb,
        Https,
    }

    impl ServiceBindingKind {
        fn record_kind(self) -> cache::RecordKind {
            match self {
                Self::Svcb => cache::RecordKind::Svcb,
                Self::Https => cache::RecordKind::Https,
            }
        }

        fn get(
            self,
            cache: &cache::LinuxDnsCache,
            domain: &Domain,
        ) -> Option<cache::CacheLookup<ServiceBinding>> {
            match self {
                Self::Svcb => cache.get_svcb(domain),
                Self::Https => cache.get_https(domain),
            }
        }

        fn insert(
            self,
            cache: &cache::LinuxDnsCache,
            domain: Domain,
            values: Vec<ServiceBinding>,
            ttl: Option<Duration>,
        ) {
            match self {
                Self::Svcb => cache.insert_svcb(domain, values, ttl),
                Self::Https => cache.insert_https(domain, values, ttl),
            }
        }
    }

    fn cached_service_binding_stream<S>(
        domain: Domain,
        cache: Arc<cache::LinuxDnsCache>,
        kind: ServiceBindingKind,
        backend: S,
    ) -> impl Stream<Item = Result<ServiceBinding, BoxError>> + Send
    where
        S: Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send + 'static,
    {
        lookup_cached_stream(
            domain,
            Duration::from_secs(5),
            cache,
            kind.record_kind(),
            move |cache, domain| kind.get(cache, domain),
            move |cache, domain, values, ttl| kind.insert(cache, domain, values, ttl),
            move |_domain, _timeout| backend,
        )
    }

    fn cached_txt_stream<S>(
        domain: Domain,
        cache: Arc<cache::LinuxDnsCache>,
        backend: S,
    ) -> impl Stream<Item = Result<Txt, BoxError>> + Send
    where
        S: Stream<Item = Result<LookupEvent<Txt>, BoxError>> + Send + 'static,
    {
        lookup_cached_stream(
            domain,
            Duration::from_secs(5),
            cache,
            cache::RecordKind::Txt,
            move |cache, domain| cache.get_txt(domain),
            move |cache, domain, values, ttl| cache.insert_txt(domain, values, ttl),
            move |_domain, _timeout| backend,
        )
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
                .map(|addr| Ok(LookupEvent::Record(addr, Some(60)))),
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
                .map(|addr| Ok(LookupEvent::Record(addr, Some(60)))),
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
    async fn txt_cache_preserves_rr_grouping_hits_and_zero_ttl() {
        let records = vec![
            Txt::try_from_strings([b"first".as_slice(), b"continued".as_slice()])
                .expect("valid TXT"),
            Txt::try_from_strings([b"second".as_slice()]).expect("valid TXT"),
        ];
        let cache = test_cache();
        let domain = test_domain();
        let backend = stream::iter(
            records
                .clone()
                .into_iter()
                .map(|record| Ok(LookupEvent::Record(record, Some(60)))),
        );

        let fresh: Vec<_> = cached_txt_stream(domain.clone(), cache.clone(), backend)
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(fresh, records);

        let backend_polled = Arc::new(AtomicBool::new(false));
        let marker = backend_polled.clone();
        let backend = stream::once(async move {
            marker.store(true, Ordering::SeqCst);
            Err::<LookupEvent<Txt>, _>(BoxError::from_static_str("cache miss"))
        });
        let hit: Vec<_> = cached_txt_stream(domain.clone(), cache.clone(), backend)
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(hit, records);
        assert!(!backend_polled.load(Ordering::SeqCst));
        assert_eq!(
            hit[0].iter().collect::<Vec<_>>(),
            [b"first".as_slice(), b"continued".as_slice()]
        );

        let zero_ttl_cache = test_cache();
        let backend = stream::once(std::future::ready(Ok(LookupEvent::Record(
            records[0].clone(),
            Some(0),
        ))));
        let values: Vec<_> = cached_txt_stream(domain.clone(), zero_ttl_cache.clone(), backend)
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(values, [records[0].clone()]);
        assert!(zero_ttl_cache.get_txt(&domain).is_none());
    }

    #[tokio::test]
    async fn errors_follow_prior_records_and_are_not_cached() {
        let cache = test_cache();
        let domain = test_domain();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let backend = stream::iter([
            Ok(LookupEvent::Record(addr, Some(60))),
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

    #[tokio::test]
    async fn zero_wire_ttl_does_not_retain_svcb_or_https_records() {
        for kind in [ServiceBindingKind::Svcb, ServiceBindingKind::Https] {
            let cache = test_cache();
            let domain = test_domain();
            let binding = service_binding(443);
            let backend = stream::iter([Ok(LookupEvent::Record(binding.clone(), Some(0)))]);

            let values: Vec<_> =
                cached_service_binding_stream(domain.clone(), cache.clone(), kind, backend)
                    .map(Result::unwrap)
                    .collect()
                    .await;
            assert_eq!(values, [binding]);

            let cached = kind.get(&cache, &domain);
            assert!(
                cached.is_none(),
                "a wire TTL of zero must expire immediately"
            );
        }
    }

    #[tokio::test]
    async fn unavailable_record_ttl_uses_the_configured_cache_bound() {
        let cache = test_cache();
        let domain = test_domain();
        let addr = Ipv4Addr::new(192, 0, 2, 1);
        let native_called = Arc::new(AtomicBool::new(false));
        let backend = resolved_first_stream(
            Some(std::future::ready(ResolvedLookup::Records(vec![(
                addr, None,
            )]))),
            tracked_native(&native_called),
        );

        let values: Vec<_> = cached_ipv4_stream(domain.clone(), cache.clone(), backend)
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(values, [addr]);
        assert_eq!(cached_ipv4(&cache, &domain), Some(vec![addr]));
        assert!(!native_called.load(Ordering::SeqCst));
    }

    #[test]
    fn builder_settings_propagate() {
        let resolver = super::LinuxDnsResolver::builder()
            .with_timeout(Duration::from_secs(9))
            .with_systemd_resolved(false)
            .build();
        assert_eq!(resolver.timeout(), Duration::from_secs(9));
        assert_eq!(resolver.response_buffer_size(), usize::from(u16::MAX));
        assert!(!resolver.systemd_resolved_enabled());

        let resolver = super::LinuxDnsResolver::builder()
            .with_response_buffer_size(4096)
            .with_systemd_resolved(true)
            .build();
        assert_eq!(resolver.response_buffer_size(), 4096);
        assert!(resolver.systemd_resolved_enabled());
    }

    #[test]
    fn nsswitch_auto_detection_requires_resolve_before_dns() {
        assert!(super::nsswitch_hosts_selects_resolve(
            "passwd: files\nhosts: files resolve [!UNAVAIL=return] dns\n"
        ));
        assert!(super::nsswitch_hosts_selects_resolve(
            "hosts: files resolve # dns resolve in a comment does not count\n"
        ));

        assert!(!super::nsswitch_hosts_selects_resolve(
            "hosts: files dns resolve\n"
        ));
        assert!(!super::nsswitch_hosts_selects_resolve(
            "hosts: files mdns4_minimal [NOTFOUND=return] dns\n"
        ));
        assert!(!super::nsswitch_hosts_selects_resolve(
            "# hosts: resolve\npasswd: files\n"
        ));
    }

    fn tracked_native(
        called: &Arc<AtomicBool>,
    ) -> impl FnOnce() -> stream::Iter<std::vec::IntoIter<Result<LookupEvent<Ipv4Addr>, BoxError>>>
    + Send
    + 'static {
        let called = called.clone();
        move || {
            called.store(true, Ordering::SeqCst);
            stream::iter(vec![Ok(LookupEvent::Record(
                Ipv4Addr::new(9, 9, 9, 9),
                Some(30),
            ))])
        }
    }

    #[tokio::test]
    async fn resolved_records_short_circuit_native() {
        let native_called = Arc::new(AtomicBool::new(false));
        let items: Vec<_> = resolved_first_stream(
            Some(std::future::ready(ResolvedLookup::Records(vec![(
                Ipv4Addr::new(1, 2, 3, 4),
                Some(60),
            )]))),
            tracked_native(&native_called),
        )
        .collect()
        .await;

        assert_eq!(items.len(), 1);
        assert!(
            matches!(items[0], Ok(LookupEvent::Record(addr, Some(60))) if addr == Ipv4Addr::new(1, 2, 3, 4)),
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
            matches!(items[0], Ok(LookupEvent::Record(addr, Some(30))) if addr == Ipv4Addr::new(9, 9, 9, 9)),
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

    #[test]
    fn cache_keeps_svcb_and_https_rrsets_distinct() {
        let cache = test_cache();
        let domain = test_domain();
        cache.insert_svcb(
            domain.clone(),
            vec![service_binding(8443)],
            Some(Duration::from_secs(60)),
        );
        cache.insert_https(
            domain.clone(),
            vec![service_binding(443)],
            Some(Duration::from_secs(120)),
        );

        match cache.get_svcb(&domain) {
            Some(cache::CacheLookup::Positive(values)) => {
                assert_eq!(values.len(), 1);
                assert_eq!(values[0].port(), Some(8443));
            }
            _ => panic!("expected cached SVCB record"),
        }
        match cache.get_https(&domain) {
            Some(cache::CacheLookup::Positive(values)) => {
                assert_eq!(values.len(), 1);
                assert_eq!(values[0].port(), Some(443));
            }
            _ => panic!("expected cached HTTPS record"),
        }
    }
}
