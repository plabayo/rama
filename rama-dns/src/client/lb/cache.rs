use std::{net::IpAddr, sync::Arc, time::Duration};

use ahash::{HashSet, HashSetExt as _};
use moka::sync::Cache;
use parking_lot::Mutex;
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

/// Inmemory cache of resolved IPs per host.
pub(super) struct DnsLbCache<R> {
    resolver: R,
    refresh_after: Duration,
    evict_after_stale: Duration,
    mode: DnsResolveIpMode,
    entries: Cache<Domain, HostResolution, ahash::RandomState>,
    refreshing: Mutex<HashSet<Domain>>,
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
            refreshing: Mutex::new(HashSet::new()),
        }
    }

    /// Returns the cache entry for `host`, using cached values when fresh and
    /// triggering a background refresh when stale. The stale data is still used
    /// so this only blocks the readers if no cached item is found.
    pub(super) async fn lookup(
        self: &Arc<Self>,
        host: &Domain,
    ) -> Result<HostResolution, BoxError> {
        if let Some(entry) = self.entries.get(host) {
            let elapsed = entry.fetched_at.elapsed();
            if elapsed < self.refresh_after {
                return Ok(entry);
            }
            if elapsed < self.evict_after_stale {
                // Stale but still usable: serve while refreshing in background.
                self.clone().spawn_refresh(host.clone());
                return Ok(entry);
            }
            // Too stale (this only happens if refresh is not working)
            self.entries.invalidate(host);
        }

        // Initial lookup is (async) blocking and may double resolve (this should be cheap and rare)
        let ips = self.resolve(host).await?;
        let entry = HostResolution {
            ips: Arc::new(ips),
            fetched_at: Instant::now(),
            state: Extensions::new(),
        };
        self.entries.insert(host.clone(), entry.clone());
        Ok(entry)
    }

    fn spawn_refresh(self: Arc<Self>, host: Domain) {
        let acquired = self.refreshing.lock().insert(host.clone());
        // already refreshing, dedup
        if !acquired {
            return;
        }

        tokio::spawn(async move {
            let result = self.resolve(&host).await;
            self.refreshing.lock().remove(&host);
            match result {
                Ok(ips) => {
                    tracing::trace!(%host, ?ips, "dns lb: refreshed addresses");

                    let state = self.entries.get(&host).map(|e| e.state).unwrap_or_default();
                    self.entries.insert(
                        host,
                        HostResolution {
                            ips: Arc::new(ips),
                            fetched_at: Instant::now(),
                            state,
                        },
                    );
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
            DnsResolveIpMode::Dual | DnsResolveIpMode::DualPreferIpV4 => {
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
        sync::atomic::{AtomicUsize, Ordering},
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
