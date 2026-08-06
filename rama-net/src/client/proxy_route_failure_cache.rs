use core::{
    fmt,
    hash::{Hash, Hasher},
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
    time::Duration,
};
use std::sync::Arc;

use moka::{Equivalent, policy::EvictionPolicy, sync::Cache};
use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_utils::{macros::define_inner_service_accessors, time::now_monotonic_nanos};

use crate::{
    AuthorityInputExt, Protocol, ProtocolInputExt, address::HostWithPort, user::ProxyCredential,
};

use super::{
    ConnectionError, ConnectionErrorDomain, ConnectionErrorKind, ConnectorService,
    EstablishedClientConnection, ProxyRoute,
};

/// Scope used to identify temporarily failing proxy routes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProxyRouteFailureCacheScope {
    /// Keep failures isolated per proxy route and final destination.
    #[default]
    PerDestination,
    /// Share failures for a proxy route across every final destination.
    PerProxy,
}

/// Configuration for a [`ProxyRouteFailureCache`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProxyRouteFailureCacheConfig {
    /// Duration of the first temporary block. Defaults to one minute.
    pub initial_backoff: Duration,
    /// Maximum temporary block after repeated failures. Defaults to 30 minutes.
    pub max_backoff: Duration,
    /// Maximum time reserved for one half-open health probe. Defaults to 30 seconds.
    pub probe_lease: Duration,
    /// Maximum number of remembered route keys. Defaults to 1,024.
    pub max_entries: u64,
    /// Whether failures are isolated by final destination. Defaults to
    /// [`ProxyRouteFailureCacheScope::PerDestination`].
    pub scope: ProxyRouteFailureCacheScope,
}

impl Default for ProxyRouteFailureCacheConfig {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(60),
            max_backoff: Duration::from_secs(30 * 60),
            probe_lease: Duration::from_secs(30),
            max_entries: 1_024,
            scope: ProxyRouteFailureCacheScope::PerDestination,
        }
    }
}

impl ProxyRouteFailureCacheConfig {
    fn validate(&self) -> Result<(), BoxError> {
        if self.initial_backoff.is_zero() {
            return Err(BoxError::from_static_str(
                "proxy route failure cache initial backoff must be non-zero",
            ));
        }
        if self.max_backoff < self.initial_backoff {
            return Err(BoxError::from_static_str(
                "proxy route failure cache max backoff must not be smaller than its initial backoff",
            ));
        }
        if self.probe_lease.is_zero() {
            return Err(BoxError::from_static_str(
                "proxy route failure cache probe lease must be non-zero",
            ));
        }
        if self.max_entries == 0 {
            return Err(BoxError::from_static_str(
                "proxy route failure cache capacity must be non-zero",
            ));
        }
        Ok(())
    }

    fn backoff(&self, previous_failures: u32) -> Duration {
        let multiplier = 1u32
            .checked_shl(previous_failures.min(31))
            .unwrap_or(u32::MAX);
        self.initial_backoff
            .saturating_mul(multiplier)
            .min(self.max_backoff)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FailureCacheKey {
    protocol: Option<Protocol>,
    proxy: HostWithPort,
    basic_username: Option<String>,
    bearer_credential: bool,
    destination_protocol: Option<Protocol>,
    destination: Option<HostWithPort>,
}

struct FailureCacheKeyRef<'a> {
    protocol: Option<&'a Protocol>,
    proxy: &'a HostWithPort,
    basic_username: Option<&'a str>,
    bearer_credential: bool,
    destination_protocol: Option<&'a Protocol>,
    destination: Option<&'a HostWithPort>,
}

impl Hash for FailureCacheKeyRef<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);
        self.proxy.hash(state);
        self.basic_username.hash(state);
        self.bearer_credential.hash(state);
        self.destination_protocol.hash(state);
        self.destination.hash(state);
    }
}

impl Equivalent<FailureCacheKey> for FailureCacheKeyRef<'_> {
    fn equivalent(&self, key: &FailureCacheKey) -> bool {
        self.protocol == key.protocol.as_ref()
            && self.proxy == &key.proxy
            && self.basic_username == key.basic_username.as_deref()
            && self.bearer_credential == key.bearer_credential
            && self.destination_protocol == key.destination_protocol.as_ref()
            && self.destination == key.destination.as_ref()
    }
}

struct FailureCacheKeyMaterial {
    route: Arc<ProxyRoute>,
    destination_protocol: Option<Protocol>,
    destination: Option<HostWithPort>,
}

impl FailureCacheKeyMaterial {
    fn from_input<Input>(input: &Input, scope: ProxyRouteFailureCacheScope) -> Option<Self>
    where
        Input: AuthorityInputExt + ExtensionsRef + ProtocolInputExt,
    {
        let route = input.extensions().get_arc::<ProxyRoute>()?;
        let ProxyRoute::Proxy(_) = route.as_ref() else {
            return None;
        };
        let (destination_protocol, destination) = match scope {
            ProxyRouteFailureCacheScope::PerDestination => (
                input.protocol().cloned(),
                Some(
                    input
                        .authority()?
                        .into_host_with_port(input.protocol_default_port())?,
                ),
            ),
            ProxyRouteFailureCacheScope::PerProxy => (None, None),
        };
        Some(Self {
            route,
            destination_protocol,
            destination,
        })
    }

    fn as_ref(&self) -> Option<FailureCacheKeyRef<'_>> {
        let ProxyRoute::Proxy(proxy) = self.route.as_ref() else {
            return None;
        };
        let (basic_username, bearer_credential) = match proxy.credential.as_ref() {
            Some(ProxyCredential::Basic(basic)) => (Some(basic.username()), false),
            Some(ProxyCredential::Bearer(_)) => (None, true),
            None => (None, false),
        };
        Some(FailureCacheKeyRef {
            protocol: proxy.protocol.as_ref(),
            proxy: &proxy.address,
            basic_username,
            bearer_credential,
            destination_protocol: self.destination_protocol.as_ref(),
            destination: self.destination.as_ref(),
        })
    }

    fn into_owned(self) -> Option<FailureCacheKey> {
        let ProxyRoute::Proxy(proxy) = self.route.as_ref() else {
            return None;
        };
        let (basic_username, bearer_credential) = match proxy.credential.as_ref() {
            Some(ProxyCredential::Basic(basic)) => (Some(basic.username().to_owned()), false),
            Some(ProxyCredential::Bearer(_)) => (None, true),
            None => (None, false),
        };
        Some(FailureCacheKey {
            protocol: proxy.protocol.clone(),
            proxy: proxy.address.clone(),
            basic_username,
            bearer_credential,
            destination_protocol: self.destination_protocol,
            destination: self.destination,
        })
    }
}

#[derive(Default)]
struct FailureEntry {
    blocked_until: AtomicU64,
    probe_until: AtomicU64,
    failure_count: AtomicU32,
    last_success: AtomicU64,
}

impl FailureEntry {
    fn mark_live(&self, now: u64) {
        self.last_success.store(now, Ordering::Release);
        self.blocked_until.store(0, Ordering::Release);
        self.probe_until.store(0, Ordering::Release);
        // Publish the healthy state last. A reader that observes this zero also
        // observes the cleared deadlines above.
        self.failure_count.store(0, Ordering::Release);
    }
}

struct AttemptPermit {
    entry: Option<Arc<FailureEntry>>,
    probe_lease: Option<u64>,
}

impl AttemptPermit {
    fn unrestricted() -> Self {
        Self {
            entry: None,
            probe_lease: None,
        }
    }

    fn release_probe(&mut self) {
        if let (Some(entry), Some(lease)) = (&self.entry, self.probe_lease.take()) {
            let _release_result =
                entry
                    .probe_until
                    .compare_exchange(lease, 0, Ordering::AcqRel, Ordering::Acquire);
        }
    }
}

impl Drop for AttemptPermit {
    fn drop(&mut self) {
        self.release_probe();
    }
}

enum CacheDecision {
    Attempt(AttemptPermit),
    Blocked(Duration),
}

/// Shared negative cache for temporarily failing proxy routes.
///
/// The cache is bounded and safe to clone across connector services. Healthy
/// routes normally perform one concurrent cache lookup without acquiring a
/// process-wide lock. State transitions for one route key use atomics and do
/// not contend with unrelated proxy routes or destinations. After a backoff
/// expires, at most one caller receives a half-open probe permit for that key.
///
/// Keys contain the proxy protocol and address, an optional Basic routing
/// username, and optionally the final destination protocol and address. Basic
/// passwords and bearer tokens are never retained in a key.
#[derive(Clone)]
pub struct ProxyRouteFailureCache {
    entries: Cache<FailureCacheKey, Arc<FailureEntry>>,
    config: Arc<ProxyRouteFailureCacheConfig>,
}

impl fmt::Debug for ProxyRouteFailureCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyRouteFailureCache")
            .field("config", &self.config)
            .field("entry_count", &self.entries.entry_count())
            .finish()
    }
}

impl Default for ProxyRouteFailureCache {
    fn default() -> Self {
        Self::build(ProxyRouteFailureCacheConfig::default())
    }
}

impl ProxyRouteFailureCache {
    /// Create a failure cache using the given validated configuration.
    pub fn try_new(config: ProxyRouteFailureCacheConfig) -> Result<Self, BoxError> {
        config.validate()?;
        Ok(Self::build(config))
    }

    fn build(config: ProxyRouteFailureCacheConfig) -> Self {
        let idle = config.max_backoff.saturating_mul(2);
        let entries = Cache::builder()
            .max_capacity(config.max_entries)
            .initial_capacity(config.max_entries.min(128) as usize)
            .eviction_policy(EvictionPolicy::lru())
            .time_to_idle(idle)
            .build();
        Self {
            entries,
            config: Arc::new(config),
        }
    }

    fn begin(&self, material: &FailureCacheKeyMaterial) -> CacheDecision {
        let Some(key) = material.as_ref() else {
            return CacheDecision::Attempt(AttemptPermit::unrestricted());
        };
        let Some(entry) = self.entries.get(&key) else {
            return CacheDecision::Attempt(AttemptPermit::unrestricted());
        };

        let failure_count = entry.failure_count.load(Ordering::Acquire);
        let blocked_until = entry.blocked_until.load(Ordering::Acquire);
        if failure_count == 0 && blocked_until == 0 {
            return CacheDecision::Attempt(AttemptPermit {
                entry: Some(entry),
                probe_lease: None,
            });
        }

        let mut now = now_monotonic_nanos();
        if blocked_until > now {
            return CacheDecision::Blocked(Duration::from_nanos(blocked_until - now));
        }

        let lease_duration = duration_nanos(self.config.probe_lease);
        loop {
            now = now_monotonic_nanos();
            let probe_until = entry.probe_until.load(Ordering::Acquire);
            if probe_until > now {
                return CacheDecision::Blocked(Duration::from_nanos(probe_until - now));
            }
            let new_probe_until = now.saturating_add(lease_duration);
            if entry
                .probe_until
                .compare_exchange(
                    probe_until,
                    new_probe_until,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return CacheDecision::Attempt(AttemptPermit {
                    entry: Some(entry),
                    probe_lease: Some(new_probe_until),
                });
            }
        }
    }

    fn entry_for_attempt(
        &self,
        material: FailureCacheKeyMaterial,
        permit: &AttemptPermit,
    ) -> Option<Arc<FailureEntry>> {
        if let Some(entry) = &permit.entry {
            return Some(entry.clone());
        }
        Some(
            self.entries
                .get_with(material.into_owned()?, || Arc::new(FailureEntry::default())),
        )
    }

    fn mark_failure(
        &self,
        material: FailureCacheKeyMaterial,
        permit: &mut AttemptPermit,
        started_at: u64,
    ) {
        let Some(entry) = self.entry_for_attempt(material, permit) else {
            permit.release_probe();
            return;
        };
        loop {
            let last_success = entry.last_success.load(Ordering::Acquire);
            if last_success != 0 && last_success >= started_at {
                break;
            }

            let current_deadline = entry.blocked_until.load(Ordering::Acquire);
            if current_deadline > started_at {
                break;
            }

            let previous_failures = entry.failure_count.load(Ordering::Relaxed);
            let new_deadline = now_monotonic_nanos()
                .saturating_add(duration_nanos(self.config.backoff(previous_failures)));
            if entry
                .blocked_until
                .compare_exchange(
                    current_deadline,
                    new_deadline,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                entry
                    .failure_count
                    .store(previous_failures.saturating_add(1), Ordering::Release);
                if entry.last_success.load(Ordering::Acquire) >= started_at {
                    entry.mark_live(now_monotonic_nanos());
                }
                break;
            }
        }
        permit.release_probe();
    }

    fn mark_live(&self, material: &FailureCacheKeyMaterial, permit: &mut AttemptPermit) {
        let entry = permit
            .entry
            .clone()
            .or_else(|| material.as_ref().and_then(|key| self.entries.get(&key)));
        if let Some(entry) = entry {
            entry.mark_live(now_monotonic_nanos());
        }
        permit.release_probe();
    }

    /// Return the configured cache policy.
    #[must_use]
    pub fn config(&self) -> &ProxyRouteFailureCacheConfig {
        &self.config
    }

    /// Return an approximate number of retained cache entries.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.entries.entry_count()
    }

    /// Clear every retained proxy failure and backoff state.
    pub fn invalidate_all(&self) {
        self.entries.invalidate_all();
    }
}

fn duration_nanos(duration: Duration) -> u64 {
    duration.as_nanos().try_into().unwrap_or(u64::MAX)
}

fn should_cache_failure(error: &ConnectionError) -> bool {
    error.domain() == ConnectionErrorDomain::Transport
        && matches!(
            error.kind(),
            ConnectionErrorKind::Unavailable
                | ConnectionErrorKind::Timeout
                | ConnectionErrorKind::Protocol
        )
}

/// Error returned when a proxy route is still inside its failure backoff.
#[derive(Debug)]
pub struct ProxyRouteFailureCachedError {
    retry_after: Duration,
}

impl ProxyRouteFailureCachedError {
    /// Remaining duration before this route can be probed again.
    #[must_use]
    pub const fn retry_after(&self) -> Duration {
        self.retry_after
    }
}

impl fmt::Display for ProxyRouteFailureCachedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proxy route is temporarily blocked after a connection failure (retry in {:?})",
            self.retry_after
        )
    }
}

impl core::error::Error for ProxyRouteFailureCachedError {}

/// Connector wrapper that applies a shared [`ProxyRouteFailureCache`].
///
/// This service reads only a singular selected [`ProxyRoute`]. Place it inside
/// a connection pool so an existing pooled connection is considered before a
/// new connection is suppressed by the negative cache.
///
/// Transport `Unavailable`, `Timeout`, and `Protocol` failures are cached.
/// A success or any non-cacheable failure clears existing backoff state so the
/// next request can try the route again. Direct and plural routes are ignored.
#[derive(Debug, Clone)]
pub struct ProxyRouteFailureCacheConnector<S> {
    inner: S,
    cache: ProxyRouteFailureCache,
}

impl<S> ProxyRouteFailureCacheConnector<S> {
    /// Wrap a connector with a shared proxy route failure cache.
    #[must_use]
    pub const fn new(inner: S, cache: ProxyRouteFailureCache) -> Self {
        Self { inner, cache }
    }

    /// Return the configured cache.
    #[must_use]
    pub const fn cache(&self) -> &ProxyRouteFailureCache {
        &self.cache
    }

    define_inner_service_accessors!();
}

impl<S, Input> Service<Input> for ProxyRouteFailureCacheConnector<S>
where
    S: ConnectorService<Input>,
    Input: AuthorityInputExt + ExtensionsRef + ProtocolInputExt + Send + 'static,
{
    type Output = EstablishedClientConnection<S::Connection, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let cache = &self.cache;
        let Some(material) = FailureCacheKeyMaterial::from_input(&input, cache.config.scope) else {
            return self.inner.connect(input).await;
        };

        let mut permit = match cache.begin(&material) {
            CacheDecision::Attempt(permit) => permit,
            CacheDecision::Blocked(retry_after) => {
                tracing::debug!(?retry_after, "skip temporarily failing proxy route",);
                return Err(ConnectionError::transport(
                    ProxyRouteFailureCachedError { retry_after },
                    ConnectionErrorKind::Unavailable,
                ));
            }
        };

        let started_at = now_monotonic_nanos();
        match self.inner.connect(input).await {
            Ok(established) => {
                cache.mark_live(&material, &mut permit);
                Ok(established)
            }
            Err(error) if should_cache_failure(&error) => {
                cache.mark_failure(material, &mut permit, started_at);
                Err(error)
            }
            Err(error) => {
                cache.mark_live(&material, &mut permit);
                Err(error)
            }
        }
    }
}

/// Layer that applies a shared [`ProxyRouteFailureCache`] to a connector.
#[derive(Debug, Clone)]
pub struct ProxyRouteFailureCacheLayer {
    cache: ProxyRouteFailureCache,
}

impl ProxyRouteFailureCacheLayer {
    /// Create a layer using the given shared failure cache.
    #[must_use]
    pub const fn new(cache: ProxyRouteFailureCache) -> Self {
        Self { cache }
    }

    /// Return the shared failure cache.
    #[must_use]
    pub const fn cache(&self) -> &ProxyRouteFailureCache {
        &self.cache
    }
}

impl<S> Layer<S> for ProxyRouteFailureCacheLayer {
    type Service = ProxyRouteFailureCacheConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyRouteFailureCacheConnector::new(inner, self.cache.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyRouteFailureCacheConnector::new(inner, self.cache)
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::{sync::Arc, time::Duration};

    use rama_core::{ServiceInput, service::service_fn};
    use tokio::sync::{Barrier, Notify};

    use crate::client::{ConnectRequest, ProxyRoute, ProxyRoutes};

    use super::*;

    fn cache(scope: ProxyRouteFailureCacheScope) -> ProxyRouteFailureCache {
        ProxyRouteFailureCache::try_new(ProxyRouteFailureCacheConfig {
            initial_backoff: Duration::from_millis(20),
            max_backoff: Duration::from_millis(80),
            probe_lease: Duration::from_secs(1),
            max_entries: 32,
            scope,
        })
        .unwrap()
    }

    fn proxy(username: Option<&str>) -> ProxyRoute {
        let address = match username {
            Some(username) => format!("http://{username}:secret@proxy.example:8080"),
            None => "http://proxy.example:8080".to_owned(),
        };
        ProxyRoute::Proxy(address.parse().unwrap())
    }

    fn request(destination: &str, route: ProxyRoute) -> ConnectRequest {
        let request = ConnectRequest::new(destination.parse().unwrap());
        request.extensions.insert(route);
        request
    }

    fn unavailable() -> ConnectionError {
        ConnectionError::transport(
            BoxError::from_static_str("proxy unavailable"),
            ConnectionErrorKind::Unavailable,
        )
    }

    #[tokio::test]
    async fn repeated_failure_is_suppressed_for_same_destination() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |_input: ConnectRequest| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                        unavailable(),
                    )
                }
            }
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerDestination),
        );

        let _first_error = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap_err();
        let error = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap_err();

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert!(
            error
                .get_ref()
                .downcast_ref::<ProxyRouteFailureCachedError>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn cached_error_does_not_expose_route_or_credentials() {
        let inner = service_fn(|_input: ConnectRequest| async {
            Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(unavailable())
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerDestination),
        );

        let _first_error = connector
            .serve(request("one.example:443", proxy(Some("alice"))))
            .await
            .unwrap_err();
        let error = connector
            .serve(request("one.example:443", proxy(Some("alice"))))
            .await
            .unwrap_err();
        let rendered = format!("{error:?} {error}");

        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("proxy.example"));
    }

    #[tokio::test]
    async fn timeout_and_protocol_failures_are_cached() {
        for kind in [ConnectionErrorKind::Timeout, ConnectionErrorKind::Protocol] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let inner = service_fn({
                let attempts = attempts.clone();
                move |_input: ConnectRequest| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                            ConnectionError::transport(
                                BoxError::from_static_str("cacheable proxy failure"),
                                kind,
                            ),
                        )
                    }
                }
            });
            let connector = ProxyRouteFailureCacheConnector::new(
                inner,
                cache(ProxyRouteFailureCacheScope::PerDestination),
            );

            let _first_error = connector
                .serve(request("one.example:443", proxy(None)))
                .await
                .unwrap_err();
            let cached = connector
                .serve(request("one.example:443", proxy(None)))
                .await
                .unwrap_err();

            assert_eq!(attempts.load(Ordering::SeqCst), 1, "{kind}");
            assert!(
                cached
                    .get_ref()
                    .downcast_ref::<ProxyRouteFailureCachedError>()
                    .is_some(),
                "{kind}"
            );
        }
    }

    #[tokio::test]
    async fn per_destination_scope_does_not_poison_another_target() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |_input: ConnectRequest| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                        unavailable(),
                    )
                }
            }
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerDestination),
        );

        let _first_error = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap_err();
        let _second_error = connector
            .serve(request("two.example:443", proxy(None)))
            .await
            .unwrap_err();

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn per_destination_scope_distinguishes_application_protocol() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |_input: ConnectRequest| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                        unavailable(),
                    )
                }
            }
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerDestination),
        );

        let _http_error = connector
            .serve(
                request("one.example:443", proxy(None)).with_application_protocol(Protocol::HTTP),
            )
            .await
            .unwrap_err();
        let _https_error = connector
            .serve(
                request("one.example:443", proxy(None)).with_application_protocol(Protocol::HTTPS),
            )
            .await
            .unwrap_err();

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn per_proxy_scope_shares_failure_across_targets() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |_input: ConnectRequest| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                        unavailable(),
                    )
                }
            }
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerProxy),
        );

        let _first_error = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap_err();
        let _second_error = connector
            .serve(request("two.example:443", proxy(None)))
            .await
            .unwrap_err();

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn routing_usernames_have_independent_failure_state() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |_input: ConnectRequest| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                        unavailable(),
                    )
                }
            }
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerDestination),
        );

        let _alice_error = connector
            .serve(request("one.example:443", proxy(Some("alice"))))
            .await
            .unwrap_err();
        let _bob_error = connector
            .serve(request("one.example:443", proxy(Some("bob"))))
            .await
            .unwrap_err();

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn direct_routes_are_never_cached() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |_input: ConnectRequest| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                        unavailable(),
                    )
                }
            }
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerDestination),
        );

        for _ in 0..2 {
            let _error = connector
                .serve(request("one.example:443", ProxyRoute::Direct))
                .await
                .unwrap_err();
        }

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn plural_routes_are_never_used_as_cache_keys() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |_input: ConnectRequest| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                        unavailable(),
                    )
                }
            }
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerDestination),
        );

        for _ in 0..2 {
            let request = ConnectRequest::new("one.example:443".parse().unwrap());
            request.extensions.insert(ProxyRoutes::new([proxy(None)]));
            let _error = connector.serve(request).await.unwrap_err();
        }

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn non_cacheable_failures_do_not_block_later_attempts() {
        for (domain, kind) in [
            (
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::Rejected,
            ),
            (ConnectionErrorDomain::Transport, ConnectionErrorKind::Other),
            (
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::Authentication,
            ),
            (
                ConnectionErrorDomain::Application,
                ConnectionErrorKind::Protocol,
            ),
            (
                ConnectionErrorDomain::Local,
                ConnectionErrorKind::InvalidInput,
            ),
            (ConnectionErrorDomain::Unknown, ConnectionErrorKind::Other),
        ] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let inner = service_fn({
                let attempts = attempts.clone();
                move |_input: ConnectRequest| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                            ConnectionError::new(
                                BoxError::from_static_str("not cacheable"),
                                domain,
                                kind,
                            ),
                        )
                    }
                }
            });
            let connector = ProxyRouteFailureCacheConnector::new(
                inner,
                cache(ProxyRouteFailureCacheScope::PerDestination),
            );

            for _ in 0..2 {
                let _error = connector
                    .serve(request("one.example:443", proxy(None)))
                    .await
                    .unwrap_err();
            }

            assert_eq!(attempts.load(Ordering::SeqCst), 2, "{domain}/{kind}");
        }
    }

    #[tokio::test]
    async fn success_clears_failure_backoff() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |input: ConnectRequest| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        Err(unavailable())
                    } else {
                        Ok(EstablishedClientConnection {
                            input,
                            conn: ServiceInput::new(()),
                        })
                    }
                }
            }
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerDestination),
        );

        let _first_error = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap_err();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let _first_connection = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap();
        let _second_connection = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap();

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn expired_entry_allows_only_one_concurrent_probe() {
        const TASKS: usize = 32;

        let attempts = Arc::new(AtomicUsize::new(0));
        let probe_started = Arc::new(Notify::new());
        let release_probe = Arc::new(Notify::new());
        let inner = service_fn({
            let attempts = attempts.clone();
            let probe_started = probe_started.clone();
            let release_probe = release_probe.clone();
            move |_input: ConnectRequest| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                let probe_started = probe_started.clone();
                let release_probe = release_probe.clone();
                async move {
                    if attempt > 0 {
                        probe_started.notify_one();
                        release_probe.notified().await;
                    }
                    Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                        unavailable(),
                    )
                }
            }
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerDestination),
        );

        let _initial_error = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap_err();
        tokio::time::sleep(Duration::from_millis(40)).await;

        let barrier = Arc::new(Barrier::new(TASKS + 1));
        let mut tasks = Vec::with_capacity(TASKS);
        for _ in 0..TASKS {
            let connector = connector.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                connector
                    .serve(request("one.example:443", proxy(None)))
                    .await
            }));
        }
        let probe_notification = probe_started.notified();
        barrier.wait().await;
        probe_notification.await;
        tokio::task::yield_now().await;
        release_probe.notify_one();

        for task in tasks {
            let _error = task.await.unwrap().unwrap_err();
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancelling_half_open_probe_releases_its_lease() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let probe_started = Arc::new(Notify::new());
        let hold_probe = Arc::new(Notify::new());
        let inner = service_fn({
            let attempts = attempts.clone();
            let probe_started = probe_started.clone();
            let hold_probe = hold_probe.clone();
            move |_input: ConnectRequest| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                let probe_started = probe_started.clone();
                let hold_probe = hold_probe.clone();
                async move {
                    if attempt == 1 {
                        probe_started.notify_one();
                        hold_probe.notified().await;
                    }
                    Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(
                        unavailable(),
                    )
                }
            }
        });
        let connector = ProxyRouteFailureCacheConnector::new(
            inner,
            cache(ProxyRouteFailureCacheScope::PerDestination),
        );

        let _initial_error = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap_err();
        tokio::time::sleep(Duration::from_millis(40)).await;

        let probe_notification = probe_started.notified();
        let task = tokio::spawn({
            let connector = connector.clone();
            async move {
                connector
                    .serve(request("one.example:443", proxy(None)))
                    .await
            }
        });
        probe_notification.await;
        task.abort();
        let _join_error = task.await.unwrap_err();

        let _probe_error = tokio::time::timeout(
            Duration::from_millis(100),
            connector.serve(request("one.example:443", proxy(None))),
        )
        .await
        .expect("cancelled probe must release its lease")
        .unwrap_err();
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn cache_never_retains_more_than_its_capacity() {
        const CAPACITY: u64 = 4;

        let failure_cache = ProxyRouteFailureCache::try_new(ProxyRouteFailureCacheConfig {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(1),
            probe_lease: Duration::from_secs(1),
            max_entries: CAPACITY,
            scope: ProxyRouteFailureCacheScope::PerDestination,
        })
        .unwrap();
        let inner = service_fn(|_input: ConnectRequest| async {
            Err::<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, _>(unavailable())
        });
        let connector = ProxyRouteFailureCacheConnector::new(inner, failure_cache.clone());

        for index in 0..16 {
            let _error = connector
                .serve(request(
                    &format!("destination-{index}.example:443"),
                    proxy(None),
                ))
                .await
                .unwrap_err();
        }
        failure_cache.entries.run_pending_tasks();

        assert!(failure_cache.entry_count() <= CAPACITY);
    }

    #[test]
    fn rejects_invalid_configuration() {
        for config in [
            ProxyRouteFailureCacheConfig {
                initial_backoff: Duration::ZERO,
                ..Default::default()
            },
            ProxyRouteFailureCacheConfig {
                initial_backoff: Duration::from_secs(2),
                max_backoff: Duration::from_secs(1),
                ..Default::default()
            },
            ProxyRouteFailureCacheConfig {
                probe_lease: Duration::ZERO,
                ..Default::default()
            },
            ProxyRouteFailureCacheConfig {
                max_entries: 0,
                ..Default::default()
            },
        ] {
            ProxyRouteFailureCache::try_new(config).unwrap_err();
        }
    }

    #[test]
    fn default_configuration_matches_easy_client_policy() {
        let config = ProxyRouteFailureCacheConfig::default();
        assert_eq!(config.scope, ProxyRouteFailureCacheScope::PerDestination);
        assert_eq!(config.initial_backoff, Duration::from_secs(60));
        assert_eq!(config.max_backoff, Duration::from_secs(30 * 60));
        assert_eq!(config.max_entries, 1_024);
    }

    #[test]
    fn backoff_doubles_until_configured_cap() {
        let config = ProxyRouteFailureCacheConfig {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(5),
            ..Default::default()
        };
        assert_eq!(config.backoff(0), Duration::from_secs(1));
        assert_eq!(config.backoff(1), Duration::from_secs(2));
        assert_eq!(config.backoff(2), Duration::from_secs(4));
        assert_eq!(config.backoff(3), Duration::from_secs(5));
        assert_eq!(config.backoff(u32::MAX), Duration::from_secs(5));
    }
}
