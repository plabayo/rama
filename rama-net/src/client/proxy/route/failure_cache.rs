use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    time::Duration,
};
use std::sync::Arc;

use moka::{policy::EvictionPolicy, sync::Cache};
use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_utils::{macros::define_inner_service_accessors, time::now_monotonic_nanos};

use crate::client::{
    ConnectionError, ConnectionErrorDomain, ConnectionErrorKind, ConnectorService,
    EstablishedClientConnection,
};
use crate::{
    AuthorityInputExt, Protocol, ProtocolInputExt, address::HostWithPort, user::ProxyCredential,
};

use super::ProxyRoute;

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
            max_backoff: Duration::from_mins(30),
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

type SharedFailureCacheKey = Arc<FailureCacheKey>;

#[derive(Default)]
struct FailureEntry {
    blocked_until: AtomicU64,
    probe_until: AtomicU64,
    failure_count: AtomicU32,
    active_attempts: AtomicU32,
    succeeded: AtomicBool,
}

impl FailureEntry {
    fn mark_live(&self) {
        // Publish success before clearing the failure state. A racing failure
        // either observes it before updating the deadline or clears its update
        // in the post-CAS success check.
        self.succeeded.store(true, Ordering::Release);
        self.blocked_until.store(0, Ordering::Release);
        self.probe_until.store(0, Ordering::Release);
        self.failure_count.store(0, Ordering::Release);
    }
}

struct AttemptPermit {
    entries: Arc<Cache<SharedFailureCacheKey, Arc<FailureEntry>>>,
    key: SharedFailureCacheKey,
    entry: Arc<FailureEntry>,
    started_time: u64,
    probe_lease: Option<u64>,
    remove_on_drop: bool,
}

impl AttemptPermit {
    fn release_probe(&mut self) {
        if let Some(lease) = self.probe_lease.take() {
            let _release_result = self.entry.probe_until.compare_exchange(
                lease,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }

    fn mark_live(&mut self) {
        self.entry.mark_live();
        self.release_probe();
        self.entries.invalidate(&self.key);
        self.remove_on_drop = false;
    }
}

impl Drop for AttemptPermit {
    fn drop(&mut self) {
        self.release_probe();
        let previous_attempts = self.entry.active_attempts.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous_attempts > 0);
        if self.remove_on_drop
            && previous_attempts == 1
            && self.entry.failure_count.load(Ordering::Acquire) == 0
        {
            self.entries.invalidate(&self.key);
        }
    }
}

enum CacheDecision {
    Attempt(AttemptPermit),
    Blocked(Duration),
}

/// Shared negative cache for temporarily failing proxy routes.
///
/// The cache is bounded and safe to clone across connector services. Healthy
/// routes create only transient state while an attempt is in flight; a success
/// or non-cacheable failure removes it, so retained entries represent negative
/// backoff state. State transitions for one route key use atomics and do not
/// contend with unrelated proxy routes or destinations. After a backoff expires,
/// at most one caller receives a half-open probe permit for that key.
///
/// Keys contain the proxy protocol and address, an optional Basic routing
/// username, and optionally the final destination protocol and address. Basic
/// passwords and bearer tokens are never retained in a key.
#[derive(Clone)]
pub struct ProxyRouteFailureCache {
    entries: Arc<Cache<SharedFailureCacheKey, Arc<FailureEntry>>>,
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
        let entries = Arc::new(
            Cache::builder()
                .max_capacity(config.max_entries)
                .initial_capacity(config.max_entries.min(128) as usize)
                .eviction_policy(EvictionPolicy::lru())
                .time_to_idle(idle)
                .build(),
        );
        Self {
            entries,
            config: Arc::new(config),
        }
    }

    fn begin<Input>(&self, input: &Input) -> Option<CacheDecision>
    where
        Input: AuthorityInputExt + ExtensionsRef + ProtocolInputExt,
    {
        let route = input.extensions().get_arc::<ProxyRoute>()?;
        let ProxyRoute::Proxy(proxy) = route.as_ref() else {
            return None;
        };
        let (destination_protocol, destination) = match self.config.scope {
            ProxyRouteFailureCacheScope::PerDestination => (
                input.protocol(),
                Some(
                    input
                        .authority()?
                        .into_host_with_port(input.protocol_default_port())?,
                ),
            ),
            ProxyRouteFailureCacheScope::PerProxy => (None, None),
        };
        let (basic_username, bearer_credential) = match proxy.credential.as_ref() {
            Some(ProxyCredential::Basic(basic)) => (Some(basic.username()), false),
            Some(ProxyCredential::Bearer(_)) => (None, true),
            None => (None, false),
        };
        let key = Arc::new(FailureCacheKey {
            protocol: proxy.protocol.clone(),
            proxy: proxy.address.clone(),
            basic_username: basic_username.map(ToOwned::to_owned),
            bearer_credential,
            destination_protocol: destination_protocol.cloned(),
            destination,
        });
        // Install transient state before starting the first attempt so a
        // concurrent success can publish its completion before an older
        // failing attempt tries to block the route. Successful state is
        // invalidated instead of being retained in the negative cache.
        let entry = self
            .entries
            .get_with(key.clone(), || Arc::new(FailureEntry::default()));

        let failure_count = entry.failure_count.load(Ordering::Acquire);
        let blocked_until = entry.blocked_until.load(Ordering::Acquire);
        if failure_count == 0 && blocked_until == 0 {
            entry.active_attempts.fetch_add(1, Ordering::AcqRel);
            return Some(CacheDecision::Attempt(AttemptPermit {
                entries: self.entries.clone(),
                key,
                started_time: now_monotonic_nanos(),
                entry,
                probe_lease: None,
                remove_on_drop: true,
            }));
        }

        let mut now = now_monotonic_nanos();
        if let Some(remaining) = remaining_duration(blocked_until, now) {
            return Some(CacheDecision::Blocked(remaining));
        }

        let lease_duration = duration_nanos(self.config.probe_lease);
        loop {
            now = now_monotonic_nanos();
            let probe_until = entry.probe_until.load(Ordering::Acquire);
            if let Some(remaining) = remaining_duration(probe_until, now) {
                return Some(CacheDecision::Blocked(remaining));
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
                entry.active_attempts.fetch_add(1, Ordering::AcqRel);
                return Some(CacheDecision::Attempt(AttemptPermit {
                    entries: self.entries.clone(),
                    key,
                    started_time: now_monotonic_nanos(),
                    entry,
                    probe_lease: Some(new_probe_until),
                    remove_on_drop: false,
                }));
            }
        }
    }

    fn mark_failure(&self, permit: &mut AttemptPermit) {
        let entry = &permit.entry;
        let started_time = permit.started_time;
        loop {
            if entry.succeeded.load(Ordering::Acquire) {
                break;
            }

            let current_deadline = entry.blocked_until.load(Ordering::Acquire);
            if current_deadline > started_time {
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
                if entry.succeeded.load(Ordering::Acquire) {
                    entry.mark_live();
                }
                break;
            }
        }
        permit.remove_on_drop = false;
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

fn remaining_duration(deadline: u64, now: u64) -> Option<Duration> {
    deadline
        .checked_sub(now)
        .filter(|remaining| *remaining != 0)
        .map(Duration::from_nanos)
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
        let mut permit = match cache.begin(&input) {
            None => return self.inner.connect(input).await,
            Some(CacheDecision::Attempt(permit)) => permit,
            Some(CacheDecision::Blocked(retry_after)) => {
                tracing::debug!(?retry_after, "skip temporarily failing proxy route",);
                return Err(ConnectionError::transport(
                    ProxyRouteFailureCachedError { retry_after },
                    ConnectionErrorKind::Unavailable,
                ));
            }
        };

        match self.inner.connect(input).await {
            Ok(established) => {
                permit.mark_live();
                Ok(established)
            }
            Err(error) if should_cache_failure(&error) => {
                cache.mark_failure(&mut permit);
                Err(error)
            }
            Err(error) => {
                permit.mark_live();
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
    use core::future::Future;
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

    async fn within_test_timeout<F: Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("concurrent failure-cache test operation should complete")
    }

    fn begin_attempt(
        failure_cache: &ProxyRouteFailureCache,
        request: &ConnectRequest,
    ) -> AttemptPermit {
        match failure_cache.begin(request) {
            Some(CacheDecision::Attempt(permit)) => permit,
            Some(CacheDecision::Blocked(_)) => panic!("route was unexpectedly blocked"),
            None => panic!("proxy route was unexpectedly ignored"),
        }
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

        assert!(rendered.contains("temporarily blocked"));
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

    #[tokio::test(start_paused = true)]
    async fn first_failure_is_cached_when_monotonic_time_is_zero() {
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
        let second_error = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap_err();

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(
            second_error
                .get_ref()
                .downcast_ref::<ProxyRouteFailureCachedError>()
                .is_some()
        );
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
    async fn successful_routes_are_not_retained() {
        let failure_cache = cache(ProxyRouteFailureCacheScope::PerDestination);
        let inner = service_fn(|input: ConnectRequest| async {
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let connector = ProxyRouteFailureCacheConnector::new(inner, failure_cache.clone());

        let _connection = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap();
        failure_cache.entries.run_pending_tasks();

        assert_eq!(failure_cache.entry_count(), 0);
    }

    #[test]
    fn cancelled_attempt_is_not_retained() {
        let failure_cache = cache(ProxyRouteFailureCacheScope::PerDestination);
        let request = request("one.example:443", proxy(None));

        let permit = begin_attempt(&failure_cache, &request);
        failure_cache.entries.run_pending_tasks();
        assert_eq!(failure_cache.entry_count(), 1);

        drop(permit);
        failure_cache.entries.run_pending_tasks();
        assert_eq!(failure_cache.entry_count(), 0);
    }

    #[test]
    fn published_failure_deadline_blocks_before_count_update() {
        let failure_cache = cache(ProxyRouteFailureCacheScope::PerDestination);
        let request = request("one.example:443", proxy(None));
        let permit = begin_attempt(&failure_cache, &request);
        permit.entry.blocked_until.store(
            now_monotonic_nanos().saturating_add(duration_nanos(Duration::from_secs(1))),
            Ordering::Release,
        );

        assert!(matches!(
            failure_cache.begin(&request),
            Some(CacheDecision::Blocked(_))
        ));
    }

    #[test]
    fn success_state_wins_over_an_in_flight_failure() {
        let failure_cache = cache(ProxyRouteFailureCacheScope::PerDestination);
        let request = request("one.example:443", proxy(None));
        let mut permit = begin_attempt(&failure_cache, &request);
        let entry = permit.entry.clone();

        entry.mark_live();
        failure_cache.mark_failure(&mut permit);

        assert!(entry.succeeded.load(Ordering::Acquire));
        assert_eq!(entry.blocked_until.load(Ordering::Acquire), 0);
        assert_eq!(entry.probe_until.load(Ordering::Acquire), 0);
        assert_eq!(entry.failure_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn newer_failure_deadline_is_not_replaced() {
        let failure_cache = cache(ProxyRouteFailureCacheScope::PerDestination);
        let request = request("one.example:443", proxy(None));
        let mut permit = begin_attempt(&failure_cache, &request);
        let entry = permit.entry.clone();
        let newer_deadline = permit.started_time.saturating_add(1);
        entry.blocked_until.store(newer_deadline, Ordering::Release);
        entry.failure_count.store(1, Ordering::Release);

        failure_cache.mark_failure(&mut permit);

        assert_eq!(entry.blocked_until.load(Ordering::Acquire), newer_deadline);
        assert_eq!(entry.failure_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn equal_failure_deadline_can_be_replaced() {
        let failure_cache = cache(ProxyRouteFailureCacheScope::PerDestination);
        let request = request("one.example:443", proxy(None));
        let mut permit = begin_attempt(&failure_cache, &request);
        let entry = permit.entry.clone();
        entry
            .blocked_until
            .store(permit.started_time, Ordering::Release);
        entry.failure_count.store(1, Ordering::Release);

        failure_cache.mark_failure(&mut permit);

        assert!(entry.blocked_until.load(Ordering::Acquire) > permit.started_time);
        assert_eq!(entry.failure_count.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn concurrent_new_success_prevents_older_failure_from_blocking() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let failure_started = Arc::new(Notify::new());
        let release_failure = Arc::new(Notify::new());
        let inner = service_fn({
            let attempts = attempts.clone();
            let failure_started = failure_started.clone();
            let release_failure = release_failure.clone();
            move |input: ConnectRequest| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                let failure_started = failure_started.clone();
                let release_failure = release_failure.clone();
                async move {
                    if attempt == 0 {
                        failure_started.notify_one();
                        release_failure.notified().await;
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

        let failure_notification = failure_started.notified();
        let failing_attempt = tokio::spawn({
            let connector = connector.clone();
            async move {
                connector
                    .serve(request("one.example:443", proxy(None)))
                    .await
            }
        });
        within_test_timeout(failure_notification).await;

        let _concurrent_success =
            within_test_timeout(connector.serve(request("one.example:443", proxy(None))))
                .await
                .unwrap();
        release_failure.notify_one();
        let _older_error = within_test_timeout(failing_attempt)
            .await
            .unwrap()
            .unwrap_err();

        let _later_success =
            within_test_timeout(connector.serve(request("one.example:443", proxy(None))))
                .await
                .expect("the older failure must not block a route that succeeded concurrently");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn cancelled_attempt_does_not_discard_concurrent_failure() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let failure_started = Arc::new(Notify::new());
        let cancelled_started = Arc::new(Notify::new());
        let release_failure = Arc::new(Notify::new());
        let hold_cancelled = Arc::new(Notify::new());
        let inner = service_fn({
            let attempts = attempts.clone();
            let failure_started = failure_started.clone();
            let cancelled_started = cancelled_started.clone();
            let release_failure = release_failure.clone();
            let hold_cancelled = hold_cancelled.clone();
            move |_input: ConnectRequest| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                let failure_started = failure_started.clone();
                let cancelled_started = cancelled_started.clone();
                let release_failure = release_failure.clone();
                let hold_cancelled = hold_cancelled.clone();
                async move {
                    if attempt == 0 {
                        failure_started.notify_one();
                        release_failure.notified().await;
                    } else {
                        cancelled_started.notify_one();
                        hold_cancelled.notified().await;
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

        let failure_notification = failure_started.notified();
        let failing_attempt = tokio::spawn({
            let connector = connector.clone();
            async move {
                connector
                    .serve(request("one.example:443", proxy(None)))
                    .await
            }
        });
        within_test_timeout(failure_notification).await;

        let cancelled_notification = cancelled_started.notified();
        let cancelled_attempt = tokio::spawn({
            let connector = connector.clone();
            async move {
                connector
                    .serve(request("one.example:443", proxy(None)))
                    .await
            }
        });
        within_test_timeout(cancelled_notification).await;

        release_failure.notify_one();
        let _failure = within_test_timeout(failing_attempt)
            .await
            .unwrap()
            .unwrap_err();
        cancelled_attempt.abort();
        let _cancelled = within_test_timeout(cancelled_attempt).await.unwrap_err();

        let cached = within_test_timeout(connector.serve(request("one.example:443", proxy(None))))
            .await
            .unwrap_err();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(
            cached
                .get_ref()
                .downcast_ref::<ProxyRouteFailureCachedError>()
                .is_some()
        );
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
        within_test_timeout(async {
            barrier.wait().await;
            probe_notification.await;
        })
        .await;
        tokio::task::yield_now().await;
        release_probe.notify_one();

        for task in tasks {
            let _error = within_test_timeout(task).await.unwrap().unwrap_err();
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
        within_test_timeout(probe_notification).await;
        task.abort();
        let _join_error = within_test_timeout(task).await.unwrap_err();

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

    #[tokio::test]
    async fn invalidating_cache_clears_retained_failure() {
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
        let failure_cache = cache(ProxyRouteFailureCacheScope::PerDestination);
        let connector = ProxyRouteFailureCacheConnector::new(inner, failure_cache.clone());

        let _first_error = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap_err();
        failure_cache.entries.run_pending_tasks();
        assert_eq!(failure_cache.entry_count(), 1);

        failure_cache.invalidate_all();
        let _second_error = connector
            .serve(request("one.example:443", proxy(None)))
            .await
            .unwrap_err();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
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
        let custom_cache = cache(ProxyRouteFailureCacheScope::PerProxy);
        assert_eq!(
            custom_cache.config().scope,
            ProxyRouteFailureCacheScope::PerProxy
        );
        assert_eq!(
            custom_cache.config().initial_backoff,
            Duration::from_millis(20)
        );

        let failure_cache = ProxyRouteFailureCache::default();
        let config = failure_cache.config();
        assert_eq!(config.scope, ProxyRouteFailureCacheScope::PerDestination);
        assert_eq!(config.initial_backoff, Duration::from_secs(60));
        assert_eq!(config.max_backoff, Duration::from_mins(30));
        assert_eq!(config.probe_lease, Duration::from_secs(30));
        assert_eq!(config.max_entries, 1_024);
        assert!(format!("{failure_cache:?}").contains("ProxyRouteFailureCache"));
    }

    #[test]
    fn remaining_duration_excludes_the_deadline_itself() {
        assert_eq!(remaining_duration(11, 10), Some(Duration::from_nanos(1)));
        assert_eq!(remaining_duration(10, 10), None);
        assert_eq!(remaining_duration(9, 10), None);
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
