use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorExt as _},
};
use rama_net::{Protocol, uri::Uri};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use tokio::{sync::Mutex, time::Instant};

use super::{OptionsRequest, ServiceCapabilities};

/// OPTIONS cache bounds and refresh behavior.
#[derive(Clone, Debug)]
pub struct OptionsCacheConfig {
    max_entries: usize,
    max_in_flight: usize,
    missing_ttl: Option<Duration>,
    max_ttl: Option<Duration>,
    stale_if_error: Option<Duration>,
    failure_backoff: Duration,
}

impl Default for OptionsCacheConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl OptionsCacheConfig {
    /// Create the RFC-preserving cache policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_entries: 16,
            max_in_flight: 16,
            missing_ttl: None,
            max_ttl: None,
            stale_if_error: None,
            failure_backoff: Duration::from_secs(30),
        }
    }

    generate_set_and_with! {
        /// Set the bounded number of service-policy entries.
        pub const fn max_entries(mut self, max_entries: usize) -> Self {
            self.max_entries = if max_entries == 0 { 1 } else { max_entries };
            self
        }
    }

    generate_set_and_with! {
        /// Set the number of distinct concurrent OPTIONS exchanges.
        pub const fn max_in_flight(mut self, max_in_flight: usize) -> Self {
            self.max_in_flight = if max_in_flight == 0 { 1 } else { max_in_flight };
            self
        }
    }

    generate_set_and_with! {
        /// Override the RFC's non-expiring default for a missing Options-TTL.
        pub const fn missing_ttl(mut self, ttl: Option<Duration>) -> Self {
            self.missing_ttl = ttl;
            self
        }
    }

    generate_set_and_with! {
        /// Clamp a peer-supplied Options-TTL.
        pub const fn max_ttl(mut self, ttl: Option<Duration>) -> Self {
            self.max_ttl = ttl;
            self
        }
    }

    generate_set_and_with! {
        /// Permit an expired snapshot during refresh and after failure.
        ///
        /// The duration is measured from normal expiry. The default is
        /// `None`, so an expired snapshot is never served.
        pub const fn stale_if_error(mut self, duration: Option<Duration>) -> Self {
            self.stale_if_error = duration;
            self
        }
    }

    generate_set_and_with! {
        /// Suppress repeated refresh attempts after one completed failure.
        pub const fn failure_backoff(mut self, duration: Duration) -> Self {
            self.failure_backoff = duration;
            self
        }
    }

    /// Return the maximum entry count.
    #[must_use]
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Return the maximum distinct concurrent OPTIONS exchanges.
    #[must_use]
    pub const fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    /// Return the local lifetime for a missing peer TTL.
    #[must_use]
    pub const fn missing_ttl(&self) -> Option<Duration> {
        self.missing_ttl
    }

    /// Return the maximum accepted peer TTL.
    #[must_use]
    pub const fn max_ttl(&self) -> Option<Duration> {
        self.max_ttl
    }

    /// Return the bounded stale-on-error horizon.
    #[must_use]
    pub const fn stale_if_error(&self) -> Option<Duration> {
        self.stale_if_error
    }

    /// Return the completed-refresh failure backoff.
    #[must_use]
    pub const fn failure_backoff(&self) -> Duration {
        self.failure_backoff
    }
}

/// Adds bounded, per-service OPTIONS caching to a discovery service.
///
/// Refreshes are single-flight per URI, offer set, and explicit cache
/// partition. Cancellation publishes no state, and invalidation fences older
/// in-flight responses.
#[derive(Clone, Debug)]
pub struct OptionsCacheLayer {
    config: OptionsCacheConfig,
}

impl OptionsCacheLayer {
    /// Create an OPTIONS cache layer with RFC-preserving defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: OptionsCacheConfig::new(),
        }
    }

    generate_set_and_with! {
        /// Set explicit OPTIONS cache policy.
        pub const fn config(mut self, config: OptionsCacheConfig) -> Self {
            self.config = config;
            self
        }
    }

    /// Return cache policy.
    #[must_use]
    pub const fn config(&self) -> &OptionsCacheConfig {
        &self.config
    }
}

impl Default for OptionsCacheLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for OptionsCacheLayer {
    type Service = OptionsCache<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OptionsCache {
            inner,
            config: self.config.clone(),
            entries: Arc::new(Mutex::new(Vec::new())),
            refreshes: Arc::new(Mutex::new(Vec::new())),
            cache_invalidation_epoch: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Cached OPTIONS discovery service produced by [`OptionsCacheLayer`].
#[derive(Clone, Debug)]
pub struct OptionsCache<S> {
    inner: S,
    config: OptionsCacheConfig,
    // Entries and refresh coordination use independent locks. Neither guard
    // survives a per-key wait or network call; a hit touches only `entries`.
    //
    // Exact LRU makes a hit a short write. An ArcSwap directory would instead
    // copy and publish the entire list on every hit.
    entries: Arc<Mutex<Vec<CacheEntry>>>,
    // Weak per-key coordinators, never locked during network I/O.
    refreshes: Arc<Mutex<Vec<FetchRegistration>>>,
    // Generation changed only by invalidating this cache instance.
    cache_invalidation_epoch: Arc<AtomicU64>,
}

/// Cloneable invalidation access to one OPTIONS cache instance.
///
/// This handle does not expose the discovery service. It exists so completed
/// adaptation responses can invalidate future discovery when their ISTag
/// differs from the capability snapshot used for that transaction.
#[derive(Clone, Debug)]
pub struct OptionsCacheHandle {
    entries: Arc<Mutex<Vec<CacheEntry>>>,
    refreshes: Arc<Mutex<Vec<FetchRegistration>>>,
    cache_invalidation_epoch: Arc<AtomicU64>,
}

/// One weak registry entry for per-key single-flight coordination.
///
/// The registry mutex protects only lookup, insertion, and pruning. Callers
/// release it before awaiting [`FetchState::lock`], so unrelated service URIs
/// do not wait behind another URI's network exchange.
#[derive(Debug)]
struct FetchRegistration {
    key: CacheKey,
    state: Weak<FetchState>,
}

#[derive(Debug)]
struct FetchState {
    lock: Mutex<()>,
    invalidation_epoch: AtomicU64,
}

impl FetchState {
    fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            invalidation_epoch: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Debug)]
struct CacheKey {
    uri: Uri,
    application_protocol: Option<Protocol>,
    partition: super::OptionsCachePartition,
    allow_204_offered: bool,
    allow_206_offered: bool,
    allow_icap_trailers_offered: bool,
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.uri == other.uri
            && self.application_protocol == other.application_protocol
            && self.partition.shares_cache_with(&other.partition)
            && self.allow_204_offered == other.allow_204_offered
            && self.allow_206_offered == other.allow_206_offered
            && self.allow_icap_trailers_offered == other.allow_icap_trailers_offered
    }
}

impl Eq for CacheKey {}

impl CacheKey {
    fn from_request(request: &OptionsRequest) -> Self {
        Self {
            uri: request.service_uri().clone(),
            application_protocol: request.application_protocol().cloned(),
            partition: request.cache_partition().clone(),
            allow_204_offered: request.allow_204_offered(),
            allow_206_offered: request.allow_206_offered(),
            allow_icap_trailers_offered: request.allow_icap_trailers_offered(),
        }
    }
}

#[derive(Debug)]
struct CacheEntry {
    key: CacheKey,
    snapshot: Option<Arc<ServiceCapabilities>>,
    fetched_at: Option<Instant>,
    failure_at: Option<Instant>,
}

enum Cached {
    Hit(Arc<ServiceCapabilities>),
    Backoff,
    Refresh(RefreshPlan),
}

/// Snapshot identity observed before joining a possibly in-flight refresh.
///
/// Keeping the observed `Arc` alive prevents allocator-address reuse, so
/// pointer identity cannot suffer an ABA race. The enum also makes it
/// impossible to permit stale fallback without an observed snapshot.
enum RefreshPlan {
    Empty,
    Snapshot {
        identity: Arc<ServiceCapabilities>,
        stale: StalePermission,
    },
}

#[derive(Clone, Copy)]
enum StalePermission {
    Deny,
    Allow,
}

impl RefreshPlan {
    fn snapshot(identity: Arc<ServiceCapabilities>, may_serve_stale: bool) -> Self {
        Self::Snapshot {
            identity,
            stale: if may_serve_stale {
                StalePermission::Allow
            } else {
                StalePermission::Deny
            },
        }
    }

    fn observed(&self) -> Option<&Arc<ServiceCapabilities>> {
        match self {
            Self::Empty => None,
            Self::Snapshot { identity, .. } => Some(identity),
        }
    }

    fn stale(&self) -> Option<&Arc<ServiceCapabilities>> {
        match self {
            Self::Snapshot {
                identity,
                stale: StalePermission::Allow,
            } => Some(identity),
            Self::Empty
            | Self::Snapshot {
                stale: StalePermission::Deny,
                ..
            } => None,
        }
    }
}

impl OptionsCacheHandle {
    /// Invalidate every cached variant of one exact service URI.
    pub async fn invalidate(&self, uri: &Uri) {
        let mut refreshes = self.refreshes.lock().await;
        refreshes.retain(|registration| registration.state.strong_count() > 0);
        for registration in refreshes
            .iter()
            .filter(|registration| &registration.key.uri == uri)
        {
            if let Some(state) = Weak::upgrade(&registration.state) {
                state.invalidation_epoch.fetch_add(1, Ordering::AcqRel);
            }
        }
        drop(refreshes);
        let mut entries = self.entries.lock().await;
        entries.retain(|entry| &entry.key.uri != uri);
    }

    /// Invalidate all cached OPTIONS snapshots.
    pub async fn invalidate_all(&self) {
        let mut entries = self.entries.lock().await;
        entries.clear();
        self.cache_invalidation_epoch.fetch_add(1, Ordering::AcqRel);
    }
}

impl<S> OptionsCache<S> {
    define_inner_service_accessors!();

    /// Return cache policy.
    #[must_use]
    pub const fn config(&self) -> &OptionsCacheConfig {
        &self.config
    }

    /// Return a cloneable invalidation handle for this cache instance.
    #[must_use]
    pub fn handle(&self) -> OptionsCacheHandle {
        OptionsCacheHandle {
            entries: Arc::clone(&self.entries),
            refreshes: Arc::clone(&self.refreshes),
            cache_invalidation_epoch: Arc::clone(&self.cache_invalidation_epoch),
        }
    }

    /// Invalidate every cached variant of one exact service URI.
    pub async fn invalidate(&self, uri: &Uri) {
        self.handle().invalidate(uri).await;
    }

    /// Invalidate all cached OPTIONS snapshots.
    pub async fn invalidate_all(&self) {
        self.handle().invalidate_all().await;
    }

    async fn cached(&self, key: &CacheKey) -> Cached {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        let Some(index) = entries.iter().position(|entry| &entry.key == key) else {
            return Cached::Refresh(RefreshPlan::Empty);
        };
        // The vector is ordered from least to most recently used. Moving the
        // selected entry makes recency exact even when multiple accesses
        // observe the same clock tick.
        let mut entry = entries.remove(index);
        let snapshot = entry.snapshot.as_ref();
        let fetched_at = entry.fetched_at;
        let lifetime = snapshot.map(|snapshot| self.effective_lifetime(snapshot));
        if let (Some(snapshot), Some(fetched_at), Some(lifetime)) = (snapshot, fetched_at, lifetime)
            && lifetime.is_none_or(|ttl| now.duration_since(fetched_at) < ttl)
        {
            let result = Cached::Hit(Arc::clone(snapshot));
            entries.push(entry);
            return result;
        }
        let may_serve_stale = match (snapshot, fetched_at, lifetime.flatten()) {
            (Some(_snapshot), Some(fetched_at), Some(ttl)) => self
                .config
                .stale_if_error
                .filter(|horizon| now.duration_since(fetched_at) <= ttl.saturating_add(*horizon))
                .is_some(),
            _ => false,
        };
        let backing_off = entry
            .failure_at
            .is_some_and(|at| now.duration_since(at) < self.config.failure_backoff);
        let result = if backing_off {
            match (may_serve_stale, snapshot) {
                (true, Some(snapshot)) => Cached::Hit(Arc::clone(snapshot)),
                _ => Cached::Backoff,
            }
        } else {
            entry.failure_at = None;
            Cached::Refresh(match snapshot {
                Some(snapshot) => RefreshPlan::snapshot(Arc::clone(snapshot), may_serve_stale),
                None => RefreshPlan::Empty,
            })
        };
        entries.push(entry);
        result
    }

    fn effective_lifetime(&self, snapshot: &ServiceCapabilities) -> Option<Duration> {
        let peer = snapshot.cache_lifetime();
        let ttl = if peer.is_none() {
            self.config.missing_ttl
        } else {
            peer
        };
        match (ttl, self.config.max_ttl) {
            (Some(ttl), Some(max)) => Some(ttl.min(max)),
            (ttl, _) => ttl,
        }
    }

    async fn fetch_lock(&self, key: &CacheKey) -> Result<Arc<FetchState>, BoxError> {
        let mut registrations = self.refreshes.lock().await;
        registrations.retain(|registration| registration.state.strong_count() > 0);
        if let Some(state) = registrations
            .iter()
            .find(|registration| &registration.key == key)
            .and_then(|registration| Weak::upgrade(&registration.state))
        {
            return Ok(state);
        }
        if registrations.len() >= self.config.max_in_flight {
            return Err(BoxError::from_static_str(
                "OPTIONS cache has reached its in-flight limit",
            ));
        }
        let state = Arc::new(FetchState::new());
        registrations.push(FetchRegistration {
            key: key.clone(),
            state: Arc::downgrade(&state),
        });
        Ok(state)
    }

    async fn snapshot_is_current(
        &self,
        key: &CacheKey,
        snapshot: &Arc<ServiceCapabilities>,
    ) -> bool {
        self.entries.lock().await.iter().any(|entry| {
            &entry.key == key
                && entry
                    .snapshot
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, snapshot))
        })
    }

    async fn changed_snapshot(
        &self,
        key: &CacheKey,
        observed: Option<&Arc<ServiceCapabilities>>,
    ) -> Option<Arc<ServiceCapabilities>> {
        let entries = self.entries.lock().await;
        let entry = entries.iter().find(|entry| &entry.key == key)?;
        let current = entry.snapshot.as_ref()?;
        if observed.is_some_and(|observed| Arc::ptr_eq(current, observed)) {
            None
        } else {
            Some(Arc::clone(current))
        }
    }

    async fn install(
        &self,
        key: CacheKey,
        snapshot: Arc<ServiceCapabilities>,
        fetch: &FetchState,
        expected_cache_epoch: u64,
        expected_key_epoch: u64,
    ) {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        if self.cache_invalidation_epoch.load(Ordering::Acquire) != expected_cache_epoch
            || fetch.invalidation_epoch.load(Ordering::Acquire) != expected_key_epoch
        {
            return;
        }
        if let Some(index) = entries.iter().position(|entry| entry.key == key) {
            let mut entry = entries.remove(index);
            entry.snapshot = Some(snapshot);
            entry.fetched_at = Some(now);
            entry.failure_at = None;
            entries.push(entry);
            return;
        }
        let max_entries = self.config.max_entries.max(1);
        if entries.len() >= max_entries {
            entries.remove(0);
        }
        entries.push(CacheEntry {
            key,
            snapshot: Some(snapshot),
            fetched_at: Some(now),
            failure_at: None,
        });
    }

    async fn record_failure(
        &self,
        key: &CacheKey,
        fetch: &FetchState,
        expected_cache_epoch: u64,
        expected_key_epoch: u64,
    ) -> Option<Arc<ServiceCapabilities>> {
        let mut entries = self.entries.lock().await;
        if self.cache_invalidation_epoch.load(Ordering::Acquire) != expected_cache_epoch
            || fetch.invalidation_epoch.load(Ordering::Acquire) != expected_key_epoch
        {
            return None;
        }
        let now = Instant::now();
        if !entries.iter().any(|entry| &entry.key == key) {
            let max_entries = self.config.max_entries.max(1);
            if entries.len() >= max_entries {
                entries.remove(0);
            }
            entries.push(CacheEntry {
                key: key.clone(),
                snapshot: None,
                fetched_at: None,
                failure_at: Some(now),
            });
            return None;
        }
        let index = entries.iter().position(|entry| &entry.key == key)?;
        let mut entry = entries.remove(index);
        entry.failure_at = Some(now);
        let stale = entry.snapshot.as_ref().and_then(|snapshot| {
            let fetched_at = entry.fetched_at?;
            let lifetime = self.effective_lifetime(snapshot)?;
            self.config
                .stale_if_error
                .filter(|horizon| {
                    now.duration_since(fetched_at) <= lifetime.saturating_add(*horizon)
                })
                .map(|_horizon| Arc::clone(snapshot))
        });
        entries.push(entry);
        stale
    }
}

impl<S> Service<OptionsRequest> for OptionsCache<S>
where
    S: Service<OptionsRequest, Output = ServiceCapabilities, Error: Into<BoxError>>,
{
    type Output = Arc<ServiceCapabilities>;
    type Error = BoxError;

    async fn serve(&self, input: OptionsRequest) -> Result<Self::Output, Self::Error> {
        let key = CacheKey::from_request(&input);
        let refresh = match self.cached(&key).await {
            Cached::Hit(snapshot) => return Ok(snapshot),
            Cached::Backoff => {
                return Err(BoxError::from_static_str("OPTIONS refresh backing off")
                    .context("discover ICAP service capabilities"));
            }
            Cached::Refresh(refresh) => refresh,
        };

        let fetch = match self.fetch_lock(&key).await {
            Ok(fetch) => fetch,
            Err(error) => {
                if let Some(stale) = refresh.stale()
                    && self.snapshot_is_current(&key, stale).await
                {
                    return Ok(Arc::clone(stale));
                }
                return Err(error);
            }
        };
        let (guard, waited) = if let Ok(guard) = fetch.lock.try_lock() {
            (guard, false)
        } else if let Some(stale) = refresh.stale()
            && self.snapshot_is_current(&key, stale).await
        {
            return Ok(Arc::clone(stale));
        } else {
            (fetch.lock.lock().await, true)
        };
        let _guard = guard;

        // A zero-TTL response is stale immediately, but callers already
        // queued behind the exchange that completed during this call still
        // share that result. A later call starts a new exchange.
        if waited && let Some(snapshot) = self.changed_snapshot(&key, refresh.observed()).await {
            return Ok(snapshot);
        }

        match self.cached(&key).await {
            Cached::Hit(snapshot) => return Ok(snapshot),
            Cached::Backoff => {
                return Err(BoxError::from_static_str("OPTIONS refresh backing off")
                    .context("discover ICAP service capabilities"));
            }
            Cached::Refresh(_) => {}
        }

        let expected_cache_epoch = self.cache_invalidation_epoch.load(Ordering::Acquire);
        let expected_key_epoch = fetch.invalidation_epoch.load(Ordering::Acquire);

        match self.inner.serve(input).await {
            Ok(capabilities) => {
                let snapshot = Arc::new(capabilities);
                self.install(
                    key,
                    Arc::clone(&snapshot),
                    &fetch,
                    expected_cache_epoch,
                    expected_key_epoch,
                )
                .await;
                Ok(snapshot)
            }
            Err(error) => {
                let error = error.into();
                if let Some(stale) = self
                    .record_failure(&key, &fetch, expected_cache_epoch, expected_key_epoch)
                    .await
                {
                    Ok(stale)
                } else {
                    Err(error.context("discover ICAP service capabilities"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use rama_core::futures::future::join_all;
    use rama_net::{address::HostWithPort, client::ConnectRequest, uri::Uri};
    use tokio::sync::Notify;

    use crate::{
        codec::{Header, RequestLine, ResponseLine},
        message::{EncapsulatedParts, Request, Response},
        proto::{Method, MethodKind, StatusCode, header},
    };

    fn capabilities(ttl: Option<&'static [u8]>) -> ServiceCapabilities {
        let mut fields = vec![
            Header::new(header::METHODS, b"REQMOD, RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"test\"").unwrap(),
        ];
        if let Some(ttl) = ttl {
            fields.push(Header::new(header::OPTIONS_TTL, ttl).unwrap());
        }
        let response = Response::new(
            MethodKind::Options,
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            &fields,
            Some(EncapsulatedParts::null()),
        )
        .unwrap();
        ServiceCapabilities::parse(
            response,
            None,
            8,
            false,
            super::super::OptionsValidation::Compatible,
        )
        .unwrap()
    }

    fn request(partition: &super::super::OptionsCachePartition) -> OptionsRequest {
        request_for("icap://icap.test/service", partition)
    }

    fn request_for(
        service_uri: &str,
        partition: &super::super::OptionsCachePartition,
    ) -> OptionsRequest {
        request_for_protocol(service_uri, None, partition)
    }

    fn request_for_protocol(
        service_uri: &str,
        application_protocol: Option<Protocol>,
        partition: &super::super::OptionsCachePartition,
    ) -> OptionsRequest {
        let uri = Uri::parse_strict(service_uri).unwrap();
        let uri_text = uri.as_str();
        let request = Request::new(
            RequestLine::new(Method::Options, uri_text.as_ref()).unwrap(),
            &[Header::new(header::HOST, b"icap.test").unwrap()],
            Some(EncapsulatedParts::null()),
        )
        .unwrap();
        let connect = ConnectRequest::new("icap.test:1344".parse::<HostWithPort>().unwrap())
            .maybe_with_application_protocol(application_protocol);
        OptionsRequest::new(connect, request)
            .unwrap()
            .with_cache_partition(partition.clone())
    }

    fn request_with_allow(
        partition: &super::super::OptionsCachePartition,
        allow: &'static [u8],
    ) -> OptionsRequest {
        let uri = Uri::parse_strict("icap://icap.test/service").unwrap();
        let uri_text = uri.as_str();
        let fields = [
            Header::new(header::HOST, b"icap.test").unwrap(),
            Header::new(header::ALLOW, allow).unwrap(),
        ];
        let request = Request::new(
            RequestLine::new(Method::Options, uri_text.as_ref()).unwrap(),
            &fields,
            Some(EncapsulatedParts::null()),
        )
        .unwrap();
        OptionsRequest::new(
            ConnectRequest::new("icap.test:1344".parse::<HostWithPort>().unwrap()),
            request,
        )
        .unwrap()
        .with_cache_partition(partition.clone())
    }

    struct TestProvider {
        calls: AtomicUsize,
        fail: AtomicBool,
        hold: AtomicBool,
        entered: Notify,
        released: Notify,
        capabilities: ServiceCapabilities,
    }

    impl TestProvider {
        fn new(capabilities: ServiceCapabilities) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                fail: AtomicBool::new(false),
                hold: AtomicBool::new(false),
                entered: Notify::new(),
                released: Notify::new(),
                capabilities,
            })
        }

        async fn wait_until_held(&self) {
            self.wait_until_calls(1).await;
        }

        async fn wait_until_calls(&self, count: usize) {
            loop {
                let entered = self.entered.notified();
                if self.calls.load(Ordering::SeqCst) >= count {
                    return;
                }
                entered.await;
            }
        }

        fn release(&self) {
            self.hold.store(false, Ordering::SeqCst);
            self.released.notify_waiters();
        }
    }

    impl Service<OptionsRequest> for TestProvider {
        type Output = ServiceCapabilities;
        type Error = BoxError;

        async fn serve(&self, _input: OptionsRequest) -> Result<Self::Output, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.hold.load(Ordering::SeqCst) {
                let released = self.released.notified();
                self.entered.notify_waiters();
                released.await;
            }
            if self.fail.load(Ordering::SeqCst) {
                Err(BoxError::from_static_str("discovery failed"))
            } else {
                Ok(self.capabilities.clone())
            }
        }
    }

    #[tokio::test]
    async fn fresh_and_non_expiring_snapshots_are_shared() {
        let provider = TestProvider::new(capabilities(None));
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let input = request(&partition);

        let first = cache.serve(input.clone()).await.unwrap();
        let second = cache.serve(input).await.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn config_builders_and_layer_accessors_round_trip() {
        let config = OptionsCacheConfig::new()
            .with_max_entries(7)
            .with_max_in_flight(3)
            .with_missing_ttl(Some(Duration::from_secs(1)))
            .with_max_ttl(Some(Duration::from_secs(2)))
            .with_stale_if_error(Some(Duration::from_secs(3)))
            .with_failure_backoff(Duration::from_secs(4));
        assert_eq!(config.max_entries(), 7);
        assert_eq!(config.max_in_flight(), 3);
        assert_eq!(config.missing_ttl(), Some(Duration::from_secs(1)));
        assert_eq!(config.max_ttl(), Some(Duration::from_secs(2)));
        assert_eq!(config.stale_if_error(), Some(Duration::from_secs(3)));
        assert_eq!(config.failure_backoff(), Duration::from_secs(4));

        let layer = OptionsCacheLayer::new().with_config(config);
        assert_eq!(layer.config().max_entries(), 7);
        assert_eq!(layer.config().max_in_flight(), 3);
        assert_eq!(
            OptionsCacheConfig::new().with_max_entries(0).max_entries(),
            1
        );
        assert_eq!(
            OptionsCacheConfig::new()
                .with_max_in_flight(0)
                .max_in_flight(),
            1
        );
    }

    #[tokio::test]
    async fn negotiation_offers_partition_cache_entries() {
        let provider = TestProvider::new(capabilities(None));
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let none = request(&partition);
        let allow_204 = request_with_allow(&partition, b"204");
        let allow_206 = request_with_allow(&partition, b"206");
        let allow_trailers = request_with_allow(&partition, b"trailers");

        for input in [none, allow_204, allow_206, allow_trailers] {
            let first = cache.serve(input.clone()).await.unwrap();
            let second = cache.serve(input).await.unwrap();
            assert!(Arc::ptr_eq(&first, &second));
        }
        assert_eq!(provider.calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn application_protocol_partitions_cache_entries() {
        let provider = TestProvider::new(capabilities(None));
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();

        for protocol in [Protocol::ICAP, Protocol::ICAPS] {
            let input =
                request_for_protocol("icap://icap.test/service", Some(protocol), &partition);
            let first = cache.serve(input.clone()).await.unwrap();
            let second = cache.serve(input).await.unwrap();
            assert!(Arc::ptr_eq(&first, &second));
        }

        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cold_concurrent_callers_share_one_exchange() {
        let provider = TestProvider::new(capabilities(Some(b"0")));
        provider.hold.store(true, Ordering::SeqCst);
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let calls = join_all((0..50).map(|_| cache.serve(request(&partition))));
        let release = async {
            provider.wait_until_held().await;
            provider.release();
        };
        let (results, ()) = tokio::join!(calls, release);

        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        let first = results[0].as_ref().unwrap();
        assert!(
            results
                .iter()
                .all(|result| Arc::ptr_eq(first, result.as_ref().unwrap()))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn same_tick_waiters_share_the_successful_replacement() {
        let provider = TestProvider::new(capabilities(Some(b"0")));
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let input = request(&partition);
        let expired = cache.serve(input.clone()).await.unwrap();

        provider.hold.store(true, Ordering::SeqCst);
        let refresh = cache.serve(input.clone());
        let queued = async {
            provider.wait_until_calls(2).await;
            let mut waiter = std::pin::pin!(cache.serve(input));
            tokio::select! {
                biased;
                result = &mut waiter => panic!("waiter completed unexpectedly: {result:?}"),
                () = tokio::task::yield_now() => {}
            }
            provider.release();
            waiter.await
        };
        let (refresh, queued) = tokio::join!(refresh, queued);
        let refresh = refresh.unwrap();
        let queued = queued.unwrap();

        assert!(!Arc::ptr_eq(&expired, &refresh));
        assert!(Arc::ptr_eq(&refresh, &queued));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn stale_snapshot_is_served_while_its_refresh_is_in_flight() {
        let provider = TestProvider::new(capabilities(Some(b"0")));
        let cache = OptionsCacheLayer::new()
            .with_config(
                OptionsCacheConfig::new().with_stale_if_error(Some(Duration::from_secs(60))),
            )
            .layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let input = request(&partition);
        let stale = cache.serve(input.clone()).await.unwrap();

        provider.hold.store(true, Ordering::SeqCst);
        let refresh = cache.serve(input.clone());
        let concurrent = async {
            provider.wait_until_calls(2).await;
            let result = tokio::time::timeout(Duration::from_secs(1), cache.serve(input))
                .await
                .expect("stale snapshot should not wait for its refresh")
                .unwrap();
            assert!(Arc::ptr_eq(&stale, &result));
            provider.release();
        };
        let (refresh, ()) = tokio::join!(refresh, concurrent);

        assert!(!Arc::ptr_eq(&stale, &refresh.unwrap()));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_same_tick_refresh_never_serves_an_expired_snapshot() {
        let provider = TestProvider::new(capabilities(Some(b"0")));
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let input = request(&partition);
        cache.serve(input.clone()).await.unwrap();

        provider.fail.store(true, Ordering::SeqCst);
        provider.hold.store(true, Ordering::SeqCst);
        let refresh = cache.serve(input.clone());
        let queued = async {
            provider.wait_until_calls(2).await;
            let mut waiter = std::pin::pin!(cache.serve(input));
            tokio::select! {
                biased;
                result = &mut waiter => panic!("waiter completed unexpectedly: {result:?}"),
                () = tokio::task::yield_now() => {}
            }
            provider.release();
            waiter.await
        };
        let (refresh, queued) = tokio::join!(refresh, queued);

        refresh.unwrap_err();
        queued.unwrap_err();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn different_partitions_refresh_concurrently() {
        let provider = TestProvider::new(capabilities(Some(b"60")));
        provider.hold.store(true, Ordering::SeqCst);
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let first = super::super::OptionsCachePartition::new();
        let second = super::super::OptionsCachePartition::new();
        let calls =
            async { tokio::join!(cache.serve(request(&first)), cache.serve(request(&second))) };
        let release = async {
            while provider.calls.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
            provider.release();
        };
        let ((first, second), ()) = tokio::join!(calls, release);

        first.unwrap();
        second.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn distinct_in_flight_exchanges_are_bounded() {
        let provider = TestProvider::new(capabilities(Some(b"60")));
        provider.hold.store(true, Ordering::SeqCst);
        let cache = OptionsCacheLayer::new()
            .with_config(OptionsCacheConfig::new().with_max_in_flight(1))
            .layer(provider.clone());
        let first = super::super::OptionsCachePartition::new();
        let second = super::super::OptionsCachePartition::new();
        let held = cache.serve(request(&first));
        let bounded = async {
            provider.wait_until_held().await;
            cache.serve(request(&second)).await.unwrap_err();
            provider.release();
        };
        let (result, ()) = tokio::join!(held, bounded);

        result.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invalidation_during_refresh_prevents_late_publication() {
        let provider = TestProvider::new(capabilities(Some(b"60")));
        provider.hold.store(true, Ordering::SeqCst);
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let handle = cache.handle();
        let partition = super::super::OptionsCachePartition::new();
        let input = request(&partition);
        let refresh = cache.serve(input.clone());
        let invalidate = async {
            provider.wait_until_held().await;
            handle.invalidate(input.service_uri()).await;
            provider.release();
        };
        let (result, ()) = tokio::join!(refresh, invalidate);
        result.unwrap();

        cache.serve(input).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn exact_uri_invalidation_does_not_discard_an_unrelated_refresh() {
        let provider = TestProvider::new(capabilities(Some(b"60")));
        provider.hold.store(true, Ordering::SeqCst);
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let input = request_for("icap://icap.test/b", &partition);
        let refresh = cache.serve(input.clone());
        let invalidate = async {
            provider.wait_until_held().await;
            cache
                .invalidate(&Uri::parse_strict("icap://icap.test/a").unwrap())
                .await;
            provider.release();
        };
        let (result, ()) = tokio::join!(refresh, invalidate);
        result.unwrap();

        cache.serve(input).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exact_invalidation_removes_only_matching_entries_and_dead_refreshes() {
        let provider = TestProvider::new(capabilities(None));
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let first = request_for("icap://icap.test/a", &partition);
        let second = request_for("icap://icap.test/b", &partition);

        cache.serve(first.clone()).await.unwrap();
        cache.serve(second.clone()).await.unwrap();
        assert_eq!(cache.refreshes.lock().await.len(), 1);

        cache.invalidate(first.service_uri()).await;
        assert!(cache.refreshes.lock().await.is_empty());
        cache.serve(first).await.unwrap();
        cache.serve(second).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn global_invalidation_removes_every_cached_snapshot() {
        let provider = TestProvider::new(capabilities(None));
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let first = request_for("icap://icap.test/a", &partition);
        let second = request_for("icap://icap.test/b", &partition);

        cache.serve(first.clone()).await.unwrap();
        cache.serve(second.clone()).await.unwrap();
        cache.invalidate_all().await;
        cache.serve(first).await.unwrap();
        cache.serve(second).await.unwrap();

        assert_eq!(provider.calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn current_snapshot_requires_both_its_key_and_arc_identity() {
        let provider = TestProvider::new(capabilities(None));
        let cache = OptionsCacheLayer::new().layer(provider);
        let partition = super::super::OptionsCachePartition::new();
        let first = request_for("icap://icap.test/a", &partition);
        let second = request_for("icap://icap.test/b", &partition);
        let first_key = CacheKey::from_request(&first);
        let second_key = CacheKey::from_request(&second);
        let snapshot = cache.serve(first.clone()).await.unwrap();
        let other = Arc::new(capabilities(None));

        assert!(cache.snapshot_is_current(&first_key, &snapshot).await);
        assert!(!cache.snapshot_is_current(&first_key, &other).await);
        assert!(!cache.snapshot_is_current(&second_key, &snapshot).await);
        cache.invalidate(first.service_uri()).await;
        assert!(!cache.snapshot_is_current(&first_key, &snapshot).await);
    }

    #[tokio::test]
    async fn invalidation_discards_late_failure_and_stale_fallback() {
        let provider = TestProvider::new(capabilities(Some(b"0")));
        let cache = OptionsCacheLayer::new()
            .with_config(
                OptionsCacheConfig::new().with_stale_if_error(Some(Duration::from_secs(60))),
            )
            .layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let input = request(&partition);
        cache.serve(input.clone()).await.unwrap();

        provider.fail.store(true, Ordering::SeqCst);
        provider.hold.store(true, Ordering::SeqCst);
        let refresh = cache.serve(input.clone());
        let invalidate = async {
            while provider.calls.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
            cache.invalidate(input.service_uri()).await;
            provider.release();
        };
        let (result, ()) = tokio::join!(refresh, invalidate);
        result.unwrap_err();

        provider.fail.store(false, Ordering::SeqCst);
        cache.serve(input).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_cold_failure_backs_off_and_a_cancelled_attempt_does_not() {
        let provider = TestProvider::new(capabilities(Some(b"60")));
        provider.fail.store(true, Ordering::SeqCst);
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();

        cache.serve(request(&partition)).await.unwrap_err();
        cache.serve(request(&partition)).await.unwrap_err();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

        let provider = TestProvider::new(capabilities(Some(b"60")));
        provider.hold.store(true, Ordering::SeqCst);
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let mut attempt = Box::pin(cache.serve(request(&partition)));
        tokio::select! {
            result = &mut attempt => panic!("attempt completed unexpectedly: {result:?}"),
            () = provider.wait_until_held() => {}
        }
        drop(attempt);
        provider.release();
        cache.serve(request(&partition)).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn failure_backoff_expires_at_the_exact_deadline() {
        let provider = TestProvider::new(capabilities(Some(b"60")));
        provider.fail.store(true, Ordering::SeqCst);
        let cache = OptionsCacheLayer::new()
            .with_config(OptionsCacheConfig::new().with_failure_backoff(Duration::from_secs(1)))
            .layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();

        cache.serve(request(&partition)).await.unwrap_err();
        tokio::time::advance(Duration::from_millis(999)).await;
        cache.serve(request(&partition)).await.unwrap_err();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(1)).await;
        cache.serve(request(&partition)).await.unwrap_err();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failed_entries_respect_the_capacity_bound() {
        let provider = TestProvider::new(capabilities(Some(b"60")));
        provider.fail.store(true, Ordering::SeqCst);
        let cache = OptionsCacheLayer::new()
            .with_config(OptionsCacheConfig::new().with_max_entries(1))
            .layer(provider.clone());
        let first = super::super::OptionsCachePartition::new();
        let second = super::super::OptionsCachePartition::new();

        cache.serve(request(&first)).await.unwrap_err();
        cache.serve(request(&second)).await.unwrap_err();
        provider.fail.store(false, Ordering::SeqCst);
        cache.serve(request(&first)).await.unwrap();

        assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
        assert_eq!(cache.entries.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn independent_partitions_do_not_share_authenticated_state() {
        let provider = TestProvider::new(capabilities(None));
        let cache = OptionsCacheLayer::new().layer(provider.clone());

        cache
            .serve(request(&super::super::OptionsCachePartition::new()))
            .await
            .unwrap();
        cache
            .serve(request(&super::super::OptionsCachePartition::new()))
            .await
            .unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn peer_ttl_uses_monotonic_receipt_time() {
        let provider = TestProvider::new(capabilities(Some(b"1")));
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();

        cache.serve(request(&partition)).await.unwrap();
        tokio::time::advance(Duration::from_millis(999)).await;
        cache.serve(request(&partition)).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        cache.serve(request(&partition)).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_exchange_does_not_consume_the_returned_ttl() {
        let provider = TestProvider::new(capabilities(Some(b"1")));
        provider.hold.store(true, Ordering::SeqCst);
        let cache = OptionsCacheLayer::new().layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let input = request(&partition);
        let fetch = cache.serve(input.clone());
        let release = async {
            provider.wait_until_held().await;
            tokio::time::advance(Duration::from_secs(60)).await;
            provider.release();
        };
        let (result, ()) = tokio::join!(fetch, release);
        result.unwrap();

        tokio::time::advance(Duration::from_millis(999)).await;
        cache.serve(input.clone()).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        cache.serve(input).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn local_ttl_policy_clamps_and_bounds_missing_lifetimes() {
        let provider = TestProvider::new(capabilities(None));
        let cache = OptionsCacheLayer::new()
            .with_config(
                OptionsCacheConfig::new()
                    .with_missing_ttl(Some(Duration::from_secs(2)))
                    .with_max_ttl(Some(Duration::from_secs(1))),
            )
            .layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();

        cache.serve(request(&partition)).await.unwrap();
        tokio::time::advance(Duration::from_millis(999)).await;
        cache.serve(request(&partition)).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        cache.serve(request(&partition)).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_if_error_has_an_exact_bounded_horizon() {
        let provider = TestProvider::new(capabilities(Some(b"1")));
        let cache = OptionsCacheLayer::new()
            .with_config(
                OptionsCacheConfig::new()
                    .with_stale_if_error(Some(Duration::from_secs(2)))
                    .with_failure_backoff(Duration::from_secs(30)),
            )
            .layer(provider.clone());
        let partition = super::super::OptionsCachePartition::new();
        let first = cache.serve(request(&partition)).await.unwrap();

        provider.fail.store(true, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(1)).await;
        let stale = cache.serve(request(&partition)).await.unwrap();
        assert!(Arc::ptr_eq(&first, &stale));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);

        tokio::time::advance(Duration::from_secs(2)).await;
        cache.serve(request(&partition)).await.unwrap();
        tokio::time::advance(Duration::from_millis(1)).await;
        cache.serve(request(&partition)).await.unwrap_err();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn capacity_evicts_the_least_recently_used_partition() {
        let provider = TestProvider::new(capabilities(None));
        let cache = OptionsCacheLayer::new()
            .with_config(OptionsCacheConfig::new().with_max_entries(1))
            .layer(provider.clone());
        let first = super::super::OptionsCachePartition::new();
        let second = super::super::OptionsCachePartition::new();

        cache.serve(request(&first)).await.unwrap();
        cache.serve(request(&second)).await.unwrap();
        cache.serve(request(&first)).await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn lru_order_is_exact_when_accesses_share_one_clock_tick() {
        let provider = TestProvider::new(capabilities(None));
        let cache = OptionsCacheLayer::new()
            .with_config(OptionsCacheConfig::new().with_max_entries(2))
            .layer(provider.clone());
        let first = super::super::OptionsCachePartition::new();
        let second = super::super::OptionsCachePartition::new();
        let third = super::super::OptionsCachePartition::new();

        cache.serve(request(&first)).await.unwrap();
        cache.serve(request(&second)).await.unwrap();
        cache.serve(request(&first)).await.unwrap();
        cache.serve(request(&third)).await.unwrap();
        cache.serve(request(&second)).await.unwrap();

        assert_eq!(provider.calls.load(Ordering::SeqCst), 4);
    }
}
