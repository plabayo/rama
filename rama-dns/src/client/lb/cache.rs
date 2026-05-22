use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use moka::future::Cache;
use rama_core::{
    error::{BoxError, ErrorExt},
    extensions::Extensions,
    futures::StreamExt as _,
    telemetry::tracing,
};
use rama_net::{address::Domain, mode::DnsResolveIpMode};
use rama_utils::collections::NonEmptyVec;
use tokio::time::Instant;

use crate::client::resolver::DnsAddressResolver;

use super::HostResolution;

/// One cache slot per host.
///
/// The slot is created on first successful resolve and reused for the lifetime
/// of the host in the cache. Background refreshes swap [`Self::current`]
/// atomically and never rebuild the slot, so [`Self::state`] is preserved
/// across refreshes.
struct HostEntry {
    current: ArcSwap<ResolvedSnapshot>,
    state: Extensions,
    refreshing: AtomicBool,
}

struct ResolvedSnapshot {
    ips: Arc<NonEmptyVec<IpAddr>>,
    fetched_at: Instant,
}

impl HostEntry {
    fn snapshot(&self) -> HostResolution {
        let snap = self.current.load_full();
        HostResolution {
            ips: snap.ips.clone(),
            fetched_at: snap.fetched_at,
            state: self.state.clone(),
        }
    }

    /// Try to acquire the per-entry refresh slot. Returns a guard that resets
    /// the flag on drop (also on panic), or `None` if a refresh is already in
    /// flight for this host.
    fn try_acquire_refresh(self: &Arc<Self>) -> Option<RefreshGuard> {
        self.refreshing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| RefreshGuard(self.clone()))
    }
}

struct RefreshGuard(Arc<HostEntry>);

impl RefreshGuard {
    fn update(&self, value: Arc<ResolvedSnapshot>) {
        self.0.current.store(value)
    }
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.0.refreshing.store(false, Ordering::Release);
    }
}

/// Inmemory cache of resolved IPs per host.
pub(super) struct DnsLbCache<R> {
    resolver: R,
    refresh_after: Duration,
    evict_after_stale: Duration,
    mode: DnsResolveIpMode,
    entries: Cache<Domain, Arc<HostEntry>, ahash::RandomState>,
}

impl<R> std::fmt::Debug for DnsLbCache<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsLbCache")
            .field("refresh_after", &self.refresh_after)
            .field("evict_after_stale", &self.evict_after_stale)
            .field("mode", &self.mode)
            .field("entries", &self.entries.entry_count())
            .finish_non_exhaustive()
    }
}

impl<R> DnsLbCache<R>
where
    R: DnsAddressResolver + Clone,
{
    pub(super) fn new(
        resolver: R,
        refresh_after: Duration,
        evict_after_idle: Duration,
        evict_after_stale: Duration,
        mode: DnsResolveIpMode,
        max_entries: u64,
    ) -> Self {
        Self {
            resolver,
            refresh_after,
            evict_after_stale,
            mode,
            entries: Cache::builder()
                .max_capacity(max_entries)
                .time_to_idle(evict_after_idle)
                .build_with_hasher(ahash::RandomState::default()),
        }
    }

    /// Returns the cache entry for `host`, using cached values when fresh and
    /// triggering a background refresh when stale. The stale data is still used
    /// so this only blocks the readers if no cached item is found.
    pub(super) async fn lookup(
        self: &Arc<Self>,
        host: &Domain,
    ) -> Result<HostResolution, BoxError> {
        if let Some(entry) = self.entries.get(host).await {
            let elapsed = entry.current.load().fetched_at.elapsed();
            if elapsed < self.refresh_after {
                return Ok(entry.snapshot());
            }
            if elapsed < self.evict_after_stale {
                // Stale but still usable: serve while refreshing in background.
                self.clone().spawn_refresh(host.clone(), &entry);
                return Ok(entry.snapshot());
            }
            // Too stale (this only happens if refresh is not working)
            self.entries.invalidate(host).await;
        }

        // Cold path: moka merges concurrent inits for the same key so only
        // one resolve runs and all waiters share the resulting entry.
        let this = self.clone();
        let init_host = host.clone();
        let entry = self
            .entries
            .try_get_with(host.clone(), async move {
                let ips = this.resolve(&init_host).await?;
                Ok::<_, BoxError>(Arc::new(HostEntry {
                    current: ArcSwap::from_pointee(ResolvedSnapshot {
                        ips: Arc::new(ips),
                        fetched_at: Instant::now(),
                    }),
                    state: Extensions::new(),
                    refreshing: AtomicBool::new(false),
                }))
            })
            .await
            .map_err(|e: Arc<BoxError>| -> BoxError {
                format!("dns lb: initial resolve failed: {e}").into()
            })?;

        Ok(entry.snapshot())
    }

    fn spawn_refresh(self: Arc<Self>, host: Domain, entry: &Arc<HostEntry>) {
        let Some(refresh) = entry.try_acquire_refresh() else {
            // already refreshing, dedup
            return;
        };

        tokio::spawn(async move {
            match self.resolve(&host).await {
                Ok(ips) => {
                    tracing::trace!(%host, ?ips, "dns lb: refreshed addresses");
                    refresh.update(Arc::new(ResolvedSnapshot {
                        ips: Arc::new(ips),
                        fetched_at: Instant::now(),
                    }));
                }
                Err(err) => {
                    tracing::debug!(%host, %err, "dns lb: background refresh failed, keeping stale entry");
                }
            }
        });
    }

    async fn resolve(&self, host: &Domain) -> Result<NonEmptyVec<IpAddr>, BoxError> {
        let mut ips = Vec::new();
        match self.mode {
            DnsResolveIpMode::SingleIpV4 => self.collect_v4(host, &mut ips).await,
            DnsResolveIpMode::SingleIpV6 => self.collect_v6(host, &mut ips).await,
            DnsResolveIpMode::Dual => {
                self.collect_v6(host, &mut ips).await;
                self.collect_v4(host, &mut ips).await;
            }
            DnsResolveIpMode::DualPreferIpV4 => {
                self.collect_v4(host, &mut ips).await;
                self.collect_v6(host, &mut ips).await;
            }
        }
        NonEmptyVec::from_vec(ips).ok_or_else(|| {
            BoxError::from("dns lb: resolver returned no addresses")
                .context_str_field("host", host.to_string())
        })
    }

    async fn collect_v4(&self, host: &Domain, out: &mut Vec<IpAddr>) {
        let mut stream = std::pin::pin!(self.resolver.lookup_ipv4(host.clone()));
        while let Some(item) = stream.next().await {
            match item {
                Ok(ip) => out.push(IpAddr::V4(ip)),
                Err(err) => {
                    tracing::debug!(%host, err = %err.into_box_error(), "dns lb: ipv4 lookup error",)
                }
            }
        }
    }

    async fn collect_v6(&self, host: &Domain, out: &mut Vec<IpAddr>) {
        let mut stream = std::pin::pin!(self.resolver.lookup_ipv6(host.clone()));
        while let Some(item) = stream.next().await {
            match item {
                Ok(ip) => out.push(IpAddr::V6(ip)),
                Err(err) => {
                    tracing::debug!(%host, err = %err.into_box_error(), "dns lb: ipv6 lookup error")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{
        extensions::Extension,
        futures::{Stream, future::join_all, stream},
    };
    use std::{
        convert::Infallible,
        net::{Ipv4Addr, Ipv6Addr},
        sync::atomic::AtomicUsize,
    };

    #[derive(Clone)]
    struct FixedV4Resolver {
        ips: Vec<Ipv4Addr>,
        calls: Arc<AtomicUsize>,
    }

    impl FixedV4Resolver {
        fn new(ips: Vec<Ipv4Addr>) -> Self {
            Self {
                ips,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl DnsAddressResolver for FixedV4Resolver {
        type Error = Infallible;

        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            self.calls.fetch_add(1, Ordering::SeqCst);
            stream::iter(self.ips.clone().into_iter().map(Ok))
        }

        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            stream::empty()
        }
    }

    /// Yield enough times for any pending spawned tasks to make progress
    async fn drain_spawned() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn cold_lookup_resolves_and_caches() {
        let resolver = FixedV4Resolver::new(vec![Ipv4Addr::new(10, 0, 0, 1)]);
        let cache = Arc::new(DnsLbCache::new(
            resolver.clone(),
            Duration::from_secs(60),
            Duration::from_secs(600),
            Duration::from_secs(600),
            DnsResolveIpMode::SingleIpV4,
            1024,
        ));
        let host = Domain::from_static("example.com");

        let first = cache.lookup(&host).await.unwrap();
        let second = cache.lookup(&host).await.unwrap();
        assert_eq!(first.ips, second.ips);
        assert_eq!(first.ips.len(), 1);
        assert_eq!(first.ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(resolver.call_count(), 1);
    }

    #[tokio::test]
    async fn concurrent_cold_lookup_resolves_once() {
        let resolver = FixedV4Resolver::new(vec![Ipv4Addr::new(10, 0, 0, 1)]);
        let cache = Arc::new(DnsLbCache::new(
            resolver.clone(),
            Duration::from_secs(60),
            Duration::from_secs(600),
            Duration::from_secs(600),
            DnsResolveIpMode::SingleIpV4,
            1024,
        ));
        let host = Domain::from_static("example.com");

        let results = join_all((0..8).map(|_| cache.lookup(&host))).await;
        for r in results {
            r.unwrap();
        }

        assert_eq!(resolver.call_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_triggers_background_refresh() {
        let resolver = FixedV4Resolver::new(vec![Ipv4Addr::new(10, 0, 0, 1)]);
        let cache = Arc::new(DnsLbCache::new(
            resolver.clone(),
            Duration::from_secs(30),
            Duration::from_secs(600),
            Duration::from_secs(600),
            DnsResolveIpMode::SingleIpV4,
            1024,
        ));
        let host = Domain::from_static("example.com");

        cache.lookup(&host).await.unwrap();
        assert_eq!(resolver.call_count(), 1);

        tokio::time::advance(Duration::from_secs(60)).await;
        cache.lookup(&host).await.unwrap();
        drain_spawned().await;

        assert_eq!(resolver.call_count(), 2);
    }

    #[tokio::test]
    async fn empty_resolver_errors_on_cold_lookup() {
        let resolver = FixedV4Resolver::new(vec![]);
        let cache = Arc::new(DnsLbCache::new(
            resolver,
            Duration::from_secs(60),
            Duration::from_secs(600),
            Duration::from_secs(600),
            DnsResolveIpMode::SingleIpV4,
            1024,
        ));
        let host = Domain::from_static("example.com");
        assert!(cache.lookup(&host).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn state_survives_background_refresh() {
        #[derive(Debug, Extension)]
        struct Marker(usize);

        let resolver = FixedV4Resolver::new(vec![Ipv4Addr::new(10, 0, 0, 1)]);
        let cache = Arc::new(DnsLbCache::new(
            resolver.clone(),
            Duration::from_secs(30),
            Duration::from_secs(600),
            Duration::from_secs(600),
            DnsResolveIpMode::SingleIpV4,
            1024,
        ));
        let host = Domain::from_static("example.com");

        let entry = cache.lookup(&host).await.unwrap();
        entry.state.insert(Marker(42));

        tokio::time::advance(Duration::from_secs(60)).await;
        // Trigger refresh.
        cache.lookup(&host).await.unwrap();
        drain_spawned().await;

        let after = cache.lookup(&host).await.unwrap();
        assert_eq!(after.state.get_ref::<Marker>().map(|m| m.0), Some(42));
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_is_single_flight() {
        let resolver = FixedV4Resolver::new(vec![Ipv4Addr::new(10, 0, 0, 1)]);
        let cache = Arc::new(DnsLbCache::new(
            resolver.clone(),
            Duration::from_secs(30),
            Duration::from_secs(600),
            Duration::from_secs(600),
            DnsResolveIpMode::SingleIpV4,
            1024,
        ));
        let host = Domain::from_static("example.com");

        cache.lookup(&host).await.unwrap();
        tokio::time::advance(Duration::from_secs(60)).await;

        // Concurrent stale reads: only the first should spawn a refresh
        let results = join_all((0..5).map(|_| cache.lookup(&host))).await;
        for r in results {
            r.unwrap();
        }
        drain_spawned().await;

        assert_eq!(resolver.call_count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn evict_after_stale_forces_cold_lookup() {
        let resolver = FixedV4Resolver::new(vec![Ipv4Addr::new(10, 0, 0, 1)]);
        let cache = Arc::new(DnsLbCache::new(
            resolver.clone(),
            Duration::from_secs(30),
            Duration::from_secs(3600),
            Duration::from_secs(120),
            DnsResolveIpMode::SingleIpV4,
            1024,
        ));
        let host = Domain::from_static("example.com");

        cache.lookup(&host).await.unwrap();
        assert_eq!(resolver.call_count(), 1);

        tokio::time::advance(Duration::from_secs(180)).await;
        cache.lookup(&host).await.unwrap();
        // No need to drain_spawned here since this happened in a blocking way
        assert_eq!(resolver.call_count(), 2);
    }
}
