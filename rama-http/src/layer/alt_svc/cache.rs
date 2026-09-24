//! Bounded, origin-scoped HTTP alternative-service advertisements.

use super::RouteContext;
use ahash::HashMap;
use moka::{ops::compute::Op, policy::EvictionPolicy, sync::Cache};
use parking_lot::Mutex;
use rama_core::bytes::Bytes;
use rama_http_headers::{Age, AltSvc, Date, HeaderDecode as _, HeaderMapExt as _};
use rama_http_types::{
    HeaderMap, HeaderValue,
    conn::{
        EstablishedHttpService, HttpOrigin, HttpServiceCandidate, HttpServiceCandidates,
        HttpServiceSource,
    },
    header,
    proto::h2::alt_svc::{AltSvcObserverExtension, AltSvcReceivedAt},
};
use rama_net::address::{Host, HostWithPort};
use rama_utils::macros::generate_set_and_with;
use std::{
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
#[cfg(test)]
use {
    rama_core::extensions::Extensions,
    rama_net::client::{ProxyRoute, ProxyRoutes},
};

const DEFAULT_ORIGIN_CAPACITY: u64 = 1024;
const DEFAULT_MAX_AGE: Duration = Duration::from_hours(24);
const DEFAULT_FAILURE_BACKOFF: Duration = Duration::from_secs(30);
const DEFAULT_ALTERNATIVES_PER_ORIGIN: usize = 16;
const DEFAULT_ADVERTISEMENT_BYTES: usize = rama_utils::octets::kib(16);

#[derive(Clone, Debug)]
struct Availability {
    expires: Instant,
    failure: Option<Failure>,
    persist: bool,
    removed: bool,
}

impl Availability {
    fn fresh_at(&self, now: Instant, network: u64) -> bool {
        !self.removed
            && now < self.expires
            && self.failure.as_ref().is_none_or(|failure| {
                failure.network != network || !failure.all_routes || now >= failure.until
            })
    }

    fn usable_at(&self, now: Instant, network: u64) -> bool {
        self.fresh_at(now, network)
            && self
                .failure
                .as_ref()
                .is_none_or(|failure| failure.network != network || now >= failure.until)
    }
}

#[derive(Clone, Debug)]
struct Failure {
    network: u64,
    until: Instant,
    attempts: u32,
    all_routes: bool,
}

#[derive(Clone, Debug)]
struct Advertisement {
    received_at: (Instant, u64),
    services: Arc<HttpServiceCandidates>,
    availability: Arc<[Availability]>,
}

/// Bounded Alt-Svc advertisements, independent of connector protocol capabilities.
///
/// Records retain preference order, protocol and endpoint, including protocols a
/// particular client does not support. Both the number of origins and alternatives
/// per origin are bounded. Lookup shares immutable candidate storage; freshness,
/// persistence and temporary failure state remain private to this cache.
///
/// Headers and HTTP/2 ALTSVC frames update the same origin entry: each accepted
/// advertisement replaces the previous list, and either source can clear it.
/// Neither source has precedence. RFC 7838 section 4 discourages mixing them
/// because their processing order can be difficult to predict.
///
/// These are hints, not proof of authority. An HTTPS alternative must authenticate
/// the logical origin and negotiate its advertised protocol. Using an alternative
/// for an HTTP origin additionally requires RFC 8164's origin authorization; TLS
/// authentication alone does not grant that permission.
///
/// Share a cache between connectors with the same default authentication policy:
/// endpoint failures are shared as well as advertisements. Middleware excludes
/// request-specific authentication from shared learning and failure updates;
/// opaque per-route configuration is excluded from shared backoff.
#[derive(Clone, Debug)]
pub struct AltSvcCache {
    storage: Arc<Storage>,
    capacity: u64,
    max_age: Duration,
    failure_backoff: Duration,
    max_alternatives_per_origin: usize,
    max_advertisement_bytes: usize,
}

/// Clients which never receive advertisements need no backing cache allocation.
/// Each store is initialized independently and shared by every cache clone.
#[derive(Debug, Default)]
struct Storage {
    entries: OnceLock<Cache<HttpOrigin, Advertisement>>,
    observers: Mutex<HashMap<HttpOrigin, Weak<AltSvcObserverExtension>>>,
    failures: OnceLock<Cache<(u64, HttpOrigin, HttpServiceCandidate), Failure>>,
    route_failures: OnceLock<Cache<(u64, HttpOrigin, HttpServiceCandidate, RouteContext), Failure>>,
    network: AtomicU64,
}

impl Default for AltSvcCache {
    fn default() -> Self {
        Self::new(
            DEFAULT_ORIGIN_CAPACITY,
            DEFAULT_MAX_AGE,
            DEFAULT_FAILURE_BACKOFF,
        )
    }
}

impl AltSvcCache {
    /// Set origin capacity, maximum retention and alternative failure backoff.
    pub fn new(capacity: u64, max_age: Duration, failure_backoff: Duration) -> Self {
        Self {
            storage: Arc::default(),
            capacity,
            max_age,
            failure_backoff,
            max_alternatives_per_origin: DEFAULT_ALTERNATIVES_PER_ORIGIN,
            max_advertisement_bytes: DEFAULT_ADVERTISEMENT_BYTES,
        }
    }

    fn entries(&self) -> &Cache<HttpOrigin, Advertisement> {
        self.storage.entries.get_or_init(|| {
            Cache::builder()
                .max_capacity(self.capacity)
                .eviction_policy(EvictionPolicy::lru())
                .time_to_live(self.max_age)
                .build()
        })
    }

    pub(super) fn cached_observer(
        &self,
        origin: HttpOrigin,
        create: impl FnOnce() -> Arc<AltSvcObserverExtension>,
    ) -> Arc<AltSvcObserverExtension> {
        let mut observers = self.storage.observers.lock();
        if let Some(observer) = observers.get(&origin).and_then(Weak::upgrade) {
            return observer;
        }
        let observer = create();
        if (observers.len() as u64) >= self.capacity {
            observers.retain(|_, observer| observer.strong_count() > 0);
        }
        if (observers.len() as u64) < self.capacity {
            observers.insert(origin, Arc::downgrade(&observer));
        }
        observer
    }

    fn failures(&self) -> &Cache<(u64, HttpOrigin, HttpServiceCandidate), Failure> {
        self.storage.failures.get_or_init(|| {
            Cache::builder()
                .max_capacity(
                    self.capacity
                        .saturating_mul(DEFAULT_ALTERNATIVES_PER_ORIGIN as u64),
                )
                .eviction_policy(EvictionPolicy::lru())
                .time_to_live(self.max_age)
                .build()
        })
    }

    fn route_failures(
        &self,
    ) -> &Cache<(u64, HttpOrigin, HttpServiceCandidate, RouteContext), Failure> {
        self.storage.route_failures.get_or_init(|| {
            Cache::builder()
                .max_capacity(
                    self.capacity
                        .saturating_mul(DEFAULT_ALTERNATIVES_PER_ORIGIN as u64),
                )
                .eviction_policy(EvictionPolicy::lru())
                .time_to_live(self.max_age)
                .build()
        })
    }

    generate_set_and_with! {
        /// Bound retained alternatives per advertisement. Zero disables retention.
        ///
        /// Configure this before sharing the cache; existing entries are unaffected.
        pub fn max_alternatives_per_origin(mut self, capacity: usize) -> Self {
            self.max_alternatives_per_origin = capacity;
            self
        }
    }

    generate_set_and_with! {
        /// Bound combined Alt-Svc field bytes before parsing or allocating records.
        /// Oversized advertisements are ignored, preserving existing cache state.
        pub fn max_advertisement_bytes(mut self, capacity: usize) -> Self {
            self.max_advertisement_bytes = capacity;
            self
        }
    }

    /// Record response hints for their logical origin, including plaintext HTTP.
    ///
    /// The caller must establish that these headers belong to this origin. HTTPS
    /// responses require origin authentication. Plaintext HTTP can advertise
    /// alternatives, but selection must also meet RFC 8164's origin-authorization
    /// requirements; this cache does not perform those checks.
    /// `response_delay` is the time from request dispatch to response headers.
    pub fn record(&self, origin: &HttpOrigin, headers: &HeaderMap, response_delay: Duration) {
        self.record_at(
            origin,
            headers,
            response_delay,
            SystemTime::now(),
            Instant::now(),
        );
    }

    /// Record the field value of an HTTP/2 ALTSVC frame for its verified origin.
    ///
    /// The caller must validate the frame's stream/origin association and ensure
    /// the connection is authoritative for `origin` (RFC 7838 section 4).
    /// `received_at` starts the freshness lifetime; delayed delivery does not
    /// extend it. Response `Age`, `Date` and request latency do not apply to frames.
    /// Malformed or oversized values leave existing advertisements unchanged.
    pub fn record_frame(&self, origin: &HttpOrigin, field_value: Bytes, received_at: Instant) {
        self.record_frame_received(
            origin,
            field_value,
            AltSvcReceivedAt {
                instant: received_at,
                ..AltSvcReceivedAt::now()
            },
        );
    }

    /// Record an authorized frame using its original receive ordering metadata.
    /// Custom observers must apply the same origin and shared-policy checks as
    /// the response middleware before calling this method.
    pub fn record_frame_received(
        &self,
        origin: &HttpOrigin,
        field_value: Bytes,
        received: AltSvcReceivedAt,
    ) {
        if field_value.len() > self.max_advertisement_bytes {
            return;
        }
        let Ok(value) = HeaderValue::from_maybe_shared(field_value) else {
            return;
        };
        let Ok(advertisement) = AltSvc::decode(&mut std::iter::once(&value)) else {
            return;
        };
        self.record_advertisement(origin, &advertisement, Duration::ZERO, received);
    }

    pub(super) fn record_at(
        &self,
        origin: &HttpOrigin,
        headers: &HeaderMap,
        response_delay: Duration,
        wall: SystemTime,
        now: Instant,
    ) {
        self.record_received(
            origin,
            headers,
            response_delay,
            AltSvcReceivedAt {
                instant: now,
                wall,
                ..AltSvcReceivedAt::now()
            },
        );
    }

    /// Record a response advertisement in transport receive order. Use the
    /// response's `AltSvcReceivedAt` when available so delayed header delivery
    /// cannot overwrite a newer HTTP/2 ALTSVC frame. The caller must first
    /// authorize this origin under the cache's shared trust policy.
    pub fn record_received(
        &self,
        origin: &HttpOrigin,
        headers: &HeaderMap,
        response_delay: Duration,
        received: AltSvcReceivedAt,
    ) {
        let bounded = headers
            .get_all(header::ALT_SVC)
            .iter()
            .try_fold(0usize, |size, value| {
                // Include a separator so arbitrarily many empty field lines are
                // bounded as well as large individual values.
                let size = size.checked_add(value.as_bytes().len())?.checked_add(1)?;
                (size <= self.max_advertisement_bytes).then_some(size)
            });
        if bounded.is_none() {
            return;
        }
        let Some(header) = headers.typed_get::<AltSvc>() else {
            return;
        };
        if header.is_clear() {
            self.record_advertisement(origin, &header, Duration::ZERO, received);
            return;
        }
        if headers.contains_key(header::AGE) && headers.typed_get::<Age>().is_none() {
            return;
        }
        let age = headers
            .typed_get::<Age>()
            .map_or(Duration::ZERO, Duration::from)
            .saturating_add(response_delay);
        let apparent_age = headers
            .typed_get::<Date>()
            .and_then(|date| received.wall.duration_since(SystemTime::from(date)).ok())
            .unwrap_or_default();
        let age = age.max(apparent_age);
        self.record_advertisement(origin, &header, age, received);
    }

    fn record_advertisement(
        &self,
        origin: &HttpOrigin,
        advertisement: &AltSvc,
        age: Duration,
        received: AltSvcReceivedAt,
    ) {
        let now = received.instant;
        let order = (now, received.sequence);
        let mut candidates = Vec::new();
        let mut availability = Vec::new();
        if let Some(alternatives) = advertisement.alternatives() {
            let capacity = alternatives.len().min(self.max_alternatives_per_origin);
            candidates.reserve_exact(capacity);
            availability.reserve_exact(capacity);
            for alternative in alternatives {
                if candidates.len() == self.max_alternatives_per_origin {
                    break;
                }
                let ttl = alternative.max_age().saturating_sub(age).min(self.max_age);
                if alternative.port() == 0 || ttl.is_zero() {
                    continue;
                }
                let host = alternative
                    .host()
                    .unwrap_or(&origin.authority().host)
                    .clone()
                    .canonicalize();
                if !matches!(host, Host::Name(_) | Host::Address(_)) {
                    continue;
                }
                let Some(expires) = now.checked_add(ttl) else {
                    continue;
                };
                let candidate = HttpServiceCandidate::new(
                    alternative.protocol().clone(),
                    HostWithPort::new(host, alternative.port()),
                )
                .with_source(HttpServiceSource::AltSvc);
                // Repeated advertisements must not consume the bounded attempt
                // budget with the same protocol/endpoint. First preference wins.
                if candidates.contains(&candidate) {
                    continue;
                }
                candidates.push(candidate);
                availability.push(Availability {
                    expires,
                    failure: None,
                    persist: alternative.persist(),
                    removed: false,
                });
            }
        }
        self.entries()
            .entry(origin.clone())
            .and_compute_with(|current| {
                if current
                    .as_ref()
                    .is_some_and(|entry| entry.value().received_at > order)
                {
                    return Op::Nop;
                }
                let network = self.network_epoch();
                for (candidate, availability) in candidates.iter().zip(&mut availability) {
                    availability.failure = self.storage.failures.get().and_then(|failures| {
                        failures.get(&(network, origin.clone(), candidate.clone()))
                    });
                }
                // Empty advertisements are bounded tombstones: a delayed response
                // must not resurrect a hint cleared by a later frame.
                Op::Put(Advertisement {
                    received_at: order,
                    services: Arc::new(HttpServiceCandidates::new(origin.clone(), candidates)),
                    availability: availability.into(),
                })
            });
    }

    /// Share a snapshot when at least one candidate is currently usable.
    ///
    /// The snapshot retains stable advertisement indices, including candidates
    /// that have expired or been suppressed. Call [`Self::is_usable`] before
    /// attempting each candidate. This avoids rebuilding a vector on every lookup.
    pub fn lookup(&self, origin: &HttpOrigin) -> Option<Arc<HttpServiceCandidates>> {
        self.lookup_at(origin, Instant::now())
    }

    /// Share a fresh snapshot without applying direct-path failure backoff.
    ///
    /// Proxy routes can reach alternatives unavailable on the direct path. Use
    /// this with [`Self::is_fresh`] for proxy route plans, and do not call
    /// [`Self::failed`] for those attempts.
    pub fn lookup_fresh(&self, origin: &HttpOrigin) -> Option<Arc<HttpServiceCandidates>> {
        self.lookup_with_policy(origin, Instant::now(), false)
    }

    fn lookup_at(&self, origin: &HttpOrigin, now: Instant) -> Option<Arc<HttpServiceCandidates>> {
        self.lookup_with_policy(origin, now, true)
    }

    fn lookup_with_policy(
        &self,
        origin: &HttpOrigin,
        now: Instant,
        apply_backoff: bool,
    ) -> Option<Arc<HttpServiceCandidates>> {
        let entry = self.storage.entries.get()?.get(origin)?;
        let network = self.network_epoch();
        if entry.availability.iter().any(|value| {
            if apply_backoff {
                value.usable_at(now, network)
            } else {
                value.fresh_at(now, network)
            }
        }) {
            return Some(entry.services);
        }
        None
    }

    /// Check current freshness and failure state for this exact advertisement.
    /// A replaced snapshot or out-of-range index is never usable.
    pub fn is_usable(&self, snapshot: &Arc<HttpServiceCandidates>, index: usize) -> bool {
        self.is_usable_at(snapshot, index, Instant::now())
    }

    /// Check advertisement freshness independently of direct-path failure state.
    /// Used with [`Self::lookup_fresh`] for proxy-routed establishment.
    pub fn is_fresh(&self, snapshot: &Arc<HttpServiceCandidates>, index: usize) -> bool {
        self.storage
            .entries
            .get()
            .and_then(|entries| entries.get(snapshot.origin()))
            .is_some_and(|entry| {
                Arc::ptr_eq(&entry.services, snapshot)
                    && entry
                        .availability
                        .get(index)
                        .is_some_and(|value| value.fresh_at(Instant::now(), self.network_epoch()))
            })
    }

    fn is_usable_at(
        &self,
        snapshot: &Arc<HttpServiceCandidates>,
        index: usize,
        now: Instant,
    ) -> bool {
        self.storage
            .entries
            .get()
            .and_then(|entries| entries.get(snapshot.origin()))
            .is_some_and(|entry| {
                Arc::ptr_eq(&entry.services, snapshot)
                    && entry
                        .availability
                        .get(index)
                        .is_some_and(|value| value.usable_at(now, self.network_epoch()))
            })
    }

    /// Temporarily suppress a candidate after direct-path establishment failure.
    ///
    /// Do not report proxy-route failures here: reachability can differ by route.
    /// Proxy selection uses [`Self::lookup_fresh`] instead of this direct-path
    /// backoff. Re-advertising an endpoint preserves its failure history.
    pub fn failed(&self, snapshot: &Arc<HttpServiceCandidates>, index: usize) {
        self.failed_at(snapshot, index, Instant::now());
    }

    fn failed_at(&self, snapshot: &Arc<HttpServiceCandidates>, index: usize, now: Instant) {
        self.suppress(snapshot, index, now, now, false, None);
    }

    /// Capture the current network generation before an attempt or dispatch.
    /// Reports from older generations are ignored after [`Self::network_changed`].
    pub fn network_epoch(&self) -> u64 {
        self.storage.network.load(Ordering::Acquire)
    }

    /// Record a completed attempt even when its endpoint was re-advertised
    /// during the dial. A network change invalidates the captured path context.
    pub fn failed_attempt(
        &self,
        snapshot: &Arc<HttpServiceCandidates>,
        index: usize,
        network: u64,
        started: Instant,
        terminal: bool,
    ) {
        self.suppress(
            snapshot,
            index,
            started,
            Instant::now(),
            terminal,
            Some(network),
        );
    }

    fn suppress(
        &self,
        snapshot: &Arc<HttpServiceCandidates>,
        index: usize,
        started: Instant,
        now: Instant,
        all_routes: bool,
        network: Option<u64>,
    ) {
        let Some(candidate) = snapshot.get(index) else {
            return;
        };
        self.entries()
            .entry(snapshot.origin().clone())
            .and_compute_with(|current| {
                let Some(current) = current else {
                    return Op::Nop;
                };
                let mut current = current.into_value();
                let current_network = self.network_epoch();
                if network.is_some_and(|network| network != current_network)
                    || (network.is_none() && !Arc::ptr_eq(&current.services, snapshot))
                {
                    return Op::Nop;
                }
                let key = (
                    current_network,
                    snapshot.origin().clone(),
                    candidate.clone(),
                );
                let previous = self.failures().get(&key);
                let Some(failure) =
                    self.next_failure(previous.as_ref(), current_network, started, now, all_routes)
                else {
                    return Op::Nop;
                };
                self.failures().insert(key, failure.clone());
                let index = current.services.iter().position(|item| item == candidate);
                if let Some(index) = index {
                    Arc::make_mut(&mut current.availability)[index].failure = Some(failure);
                    Op::Put(current)
                } else {
                    Op::Nop
                }
            });
    }

    /// Check freshness and backoff for a particular proxy route plan.
    pub fn route_usable(
        &self,
        snapshot: &Arc<HttpServiceCandidates>,
        index: usize,
        route: &RouteContext,
    ) -> bool {
        snapshot.get(index).is_some_and(|candidate| {
            self.is_fresh(snapshot, index)
                && (!route.cacheable()
                    || self
                        .storage
                        .route_failures
                        .get()
                        .and_then(|failures| {
                            failures.get(&(
                                self.network_epoch(),
                                snapshot.origin().clone(),
                                candidate.clone(),
                                route.clone(),
                            ))
                        })
                        .is_none_or(|failure| Instant::now() >= failure.until))
        })
    }

    /// Report an unsuccessful connection attempt on the captured route.
    pub fn failed_route(
        &self,
        snapshot: &Arc<HttpServiceCandidates>,
        index: usize,
        network: u64,
        started: Instant,
        route: &RouteContext,
    ) {
        let Some(candidate) = snapshot.get(index) else {
            return;
        };
        if self.network_epoch() != network || !route.cacheable() {
            return;
        }
        let key = (
            network,
            snapshot.origin().clone(),
            candidate.clone(),
            route.clone(),
        );
        self.route_failures()
            .entry(key)
            .and_compute_with(|previous| {
                match self.next_failure(
                    previous.as_ref().map(|entry| entry.value()),
                    network,
                    started,
                    Instant::now(),
                    false,
                ) {
                    Some(failure) => Op::Put(failure),
                    None => Op::Nop,
                }
            });
    }

    /// Requests already in flight belong to the same failed attempt window.
    /// Count a new failure only after a retry began beyond that window; late
    /// completions cannot stretch backoff or turn a burst into hours of delay.
    fn next_failure(
        &self,
        previous: Option<&Failure>,
        network: u64,
        started: Instant,
        now: Instant,
        all_routes: bool,
    ) -> Option<Failure> {
        if let Some(previous) = previous
            && started < previous.until
        {
            return (all_routes && !previous.all_routes).then(|| Failure {
                all_routes: true,
                ..previous.clone()
            });
        }
        let attempts = previous.map_or(1, |failure| failure.attempts.saturating_add(1));
        let backoff = self
            .failure_backoff
            .saturating_mul(2u32.saturating_pow(attempts.saturating_sub(1)))
            .min(self.max_age);
        Some(Failure {
            network,
            until: now.checked_add(backoff).unwrap_or(now),
            attempts,
            all_routes: all_routes || previous.is_some_and(|failure| failure.all_routes),
        })
    }

    /// Report a remote response failure under the shared connector policy.
    /// Caller cancellation, local body errors and request-only trust failures
    /// must not be reported as evidence that this endpoint is unavailable.
    pub fn failed_service(
        &self,
        service: &EstablishedHttpService,
        route: Option<&RouteContext>,
        network: u64,
        started: Instant,
    ) {
        // Only the error path needs a synthetic snapshot. Suppression resolves
        // the actual endpoint against the current advertisement, not its index
        // in the advertisement that originally established this connection.
        let snapshot = Arc::new(HttpServiceCandidates::new(
            service.origin.clone(),
            vec![service.candidate.clone()],
        ));
        if let Some(route) = route {
            self.failed_route(&snapshot, 0, network, started, route);
        } else {
            self.failed_attempt(&snapshot, 0, network, started, false);
        }
    }

    /// A complete response ends the selected path's failure streak. Merely
    /// connecting or receiving response headers does not establish stream health.
    pub fn succeeded_service(
        &self,
        service: &EstablishedHttpService,
        route: Option<&RouteContext>,
        network: u64,
    ) {
        self.succeeded(&service.origin, &service.candidate, route, network);
    }

    fn succeeded(
        &self,
        origin: &HttpOrigin,
        candidate: &HttpServiceCandidate,
        route: Option<&RouteContext>,
        network: u64,
    ) {
        if self.network_epoch() != network {
            return;
        }
        if let Some(route) = route {
            if !route.cacheable() {
                return;
            }
            let Some(failures) = self.storage.route_failures.get() else {
                return;
            };
            let key = (network, origin.clone(), candidate.clone(), route.clone());
            if failures.contains_key(&key) {
                failures.invalidate(&key);
            }
        } else {
            let Some(failures) = self.storage.failures.get() else {
                return;
            };
            let key = (network, origin.clone(), candidate.clone());
            if failures.contains_key(&key) {
                self.entries()
                    .entry(origin.clone())
                    .and_compute_with(|entry| {
                        if self.network_epoch() != network {
                            return Op::Nop;
                        }
                        failures.invalidate(&key);
                        let Some(entry) = entry else {
                            return Op::Nop;
                        };
                        let mut entry = entry.into_value();
                        let Some(index) = entry.services.iter().position(|item| item == candidate)
                        else {
                            return Op::Nop;
                        };
                        Arc::make_mut(&mut entry.availability)[index].failure = None;
                        Op::Put(entry)
                    });
            }
        }
    }

    /// Remove the alternative that returned 421 without replaying a request.
    /// Retain failure backoff across repeated advertisements of that endpoint;
    /// delayed responses from older discovery generations remain harmless.
    pub fn misdirected(&self, snapshot: &Arc<HttpServiceCandidates>, index: usize) {
        let now = Instant::now();
        self.suppress(snapshot, index, now, now, true, None);
        self.update_candidate(snapshot, index, |value| value.removed = true);
    }

    fn update_candidate(
        &self,
        snapshot: &Arc<HttpServiceCandidates>,
        index: usize,
        update: impl FnOnce(&mut Availability),
    ) {
        self.entries()
            .entry(snapshot.origin().clone())
            .and_compute_with(|entry| {
                let Some(entry) = entry else {
                    return Op::Nop;
                };
                let mut entry = entry.into_value();
                if !Arc::ptr_eq(&entry.services, snapshot) || index >= entry.availability.len() {
                    return Op::Nop;
                }
                update(&mut Arc::make_mut(&mut entry.availability)[index]);
                Op::Put(entry)
            });
    }

    /// Forget network-specific alternatives while retaining `persist=1` entries.
    ///
    /// Call this when the application's network changes (for example, switching
    /// interfaces or VPNs). Rama does not monitor operating-system connectivity.
    /// This also clears path failure backoff, including persistent alternatives,
    /// because reachability on the previous network does not describe the new one.
    pub fn network_changed(&self) {
        self.storage.network.fetch_add(1, Ordering::AcqRel);
        if let Some(failures) = self.storage.failures.get() {
            failures.invalidate_all();
        }
        if let Some(failures) = self.storage.route_failures.get() {
            failures.invalidate_all();
        }
        let Some(entries) = self.storage.entries.get() else {
            return;
        };
        for (origin, observed) in entries {
            self.entries()
                .entry(origin.as_ref().clone())
                .and_compute_with(|entry| {
                    let Some(entry) = entry else {
                        return Op::Nop;
                    };
                    let mut entry = entry.into_value();
                    if !Arc::ptr_eq(&entry.services, &observed.services) {
                        return Op::Nop;
                    }
                    let values = Arc::make_mut(&mut entry.availability);
                    for value in values.iter_mut() {
                        if value.persist {
                            // Old-network failures do not describe the new path.
                            value.failure = None;
                        } else {
                            value.removed = true;
                        }
                    }
                    if values.iter().all(|value| value.removed) {
                        Op::Remove
                    } else {
                        // Rotate generation so delayed old-network failures
                        // cannot suppress a recovered persistent alternative.
                        entry.services = Arc::new(HttpServiceCandidates::new(
                            entry.services.origin().clone(),
                            entry.services.iter().cloned().collect::<Vec<_>>(),
                        ));
                        Op::Put(entry)
                    }
                });
        }
    }

    /// Forget all advertisements and failure history, for example when clearing
    /// browsing data (RFC 7838 §9.4). Existing connections remain usable; later
    /// responses can advertise again. This does not allocate unused stores.
    pub fn clear_all(&self) {
        self.storage.network.fetch_add(1, Ordering::AcqRel);
        if let Some(entries) = self.storage.entries.get() {
            entries.invalidate_all();
        }
        if let Some(failures) = self.storage.failures.get() {
            failures.invalidate_all();
        }
        if let Some(failures) = self.storage.route_failures.get() {
            failures.invalidate_all();
        }
    }

    /// Explicitly invalidate this origin's advertisements.
    pub fn clear(&self, origin: &HttpOrigin) {
        self.record_advertisement(
            origin,
            &AltSvc::Clear,
            Duration::ZERO,
            AltSvcReceivedAt::now(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_net::{Protocol, tls::ApplicationProtocol};
    #[cfg(feature = "tls")]
    use {
        crate::{
            Body, Request, Response,
            body::util::BodyExt as _,
            layer::{alt_svc::AltSvcLayer, http_service::HttpServiceConnector},
        },
        parking_lot::Mutex,
        rama_core::{
            Layer as _, Service,
            error::{BoxError, BoxErrorExt as _},
            extensions::ExtensionsRef,
            futures::stream,
            service::service_fn,
        },
        rama_http_types::{Version, conn::TargetHttpVersion},
        rama_net::client::{
            ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectionPolicyScope,
            EstablishedClientConnection,
        },
        rama_tls::{
            ProtocolVersion,
            client::{NegotiatedTlsParameters, TlsServerAuthentication},
        },
    };

    fn origin() -> HttpOrigin {
        HttpOrigin::new(Protocol::HTTPS, "example.com:443".parse().unwrap()).unwrap()
    }

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::ALT_SVC, value.parse().unwrap());
        headers
    }

    fn record(cache: &AltSvcCache, value: &str, now: Instant) {
        cache.record_at(
            &origin(),
            &headers(value),
            Duration::ZERO,
            SystemTime::now(),
            now,
        );
    }

    #[cfg(feature = "tls")]
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ResponseKind {
        ResetBeforeHeaders,
        ResetDuringBody,
        Empty,
        Full,
    }

    #[cfg(feature = "tls")]
    #[derive(Clone)]
    struct ResponseConnection {
        extensions: Extensions,
        response: Arc<Mutex<ResponseKind>>,
    }

    #[cfg(feature = "tls")]
    impl ExtensionsRef for ResponseConnection {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    #[cfg(feature = "tls")]
    impl Service<Request> for ResponseConnection {
        type Output = Response;
        type Error = BoxError;

        async fn serve(&self, _: Request) -> Result<Response, BoxError> {
            let failure = || -> BoxError {
                Box::new(ConnectionError::application(
                    BoxError::from_static_str("peer reset response"),
                    ConnectionErrorKind::Unavailable,
                ))
            };
            let body = match *self.response.lock() {
                ResponseKind::ResetBeforeHeaders => return Err(failure()),
                ResponseKind::ResetDuringBody => Body::from_stream(stream::iter([
                    Ok(Bytes::from_static(b"partial")),
                    Err(failure()),
                ])),
                ResponseKind::Empty => Body::empty(),
                ResponseKind::Full => Body::from_stream(stream::iter([Ok::<_, BoxError>(
                    Bytes::from_static(b"complete"),
                )])),
            };
            Ok(Response::new(body))
        }
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn pooled_responses_reset_failure_streak_only_after_successful_completion() {
        for failure_response in [
            ResponseKind::ResetBeforeHeaders,
            ResponseKind::ResetDuringBody,
        ] {
            for success_response in [ResponseKind::Empty, ResponseKind::Full] {
                // Zero backoff permits deterministic immediate retries. Inspect
                // the streak itself rather than racing real-time sleeps.
                let cache = AltSvcCache::new(16, Duration::from_secs(60), Duration::ZERO);
                record(&cache, "h2=\":8443\"", Instant::now());
                let snapshot = cache.lookup(&origin()).unwrap();
                let key = (
                    cache.network_epoch(),
                    origin(),
                    snapshot.get(0).unwrap().clone(),
                );
                let response = Arc::new(Mutex::new(failure_response));
                let extensions = Extensions::new();
                extensions.insert(ConnectionPolicyScope::Connector);
                extensions.insert(TargetHttpVersion(Version::HTTP_2));
                extensions.insert(TlsServerAuthentication(Some(
                    origin().authority().host.clone(),
                )));
                extensions.insert(NegotiatedTlsParameters {
                    protocol_version: ProtocolVersion::TLSv1_3,
                    application_layer_protocol: Some(ApplicationProtocol::HTTP_2),
                    peer_certificate_chain: None,
                    server_name: None,
                    resumed: None,
                });
                let connection = ResponseConnection {
                    extensions,
                    response: response.clone(),
                };
                let connector =
                    HttpServiceConnector::new(service_fn(move |input: ConnectRequest| {
                        let conn = connection.clone();
                        async move {
                            Ok::<_, ConnectionError>(EstablishedClientConnection { conn, input })
                        }
                    }))
                    .with_cache(cache.clone());
                let input = || {
                    ConnectRequest::new(origin().authority().clone())
                        .with_application_protocol(Protocol::HTTPS)
                };
                let dispatch = |established: EstablishedClientConnection<
                    ResponseConnection,
                    ConnectRequest,
                >| {
                    let request =
                        Request::builder_with_extensions(established.input.extensions().clone())
                            .uri("https://example.com/")
                            .body(Body::empty())
                            .unwrap();
                    let service = AltSvcLayer::new(cache.clone()).layer(established.conn);
                    async move { service.serve(request).await }
                };

                for expected in 1..=3 {
                    let established = connector.serve(input()).await.unwrap();
                    assert_eq!(
                        cache
                            .storage
                            .failures
                            .get()
                            .and_then(|failures| failures.get(&key))
                            .map_or(0, |failure| failure.attempts),
                        expected - 1
                    );
                    let result = dispatch(established).await;
                    if failure_response == ResponseKind::ResetBeforeHeaders {
                        assert!(result.is_err());
                    } else {
                        _ = result.unwrap().into_body().collect().await.unwrap_err();
                    }
                    assert_eq!(cache.failures().get(&key).unwrap().attempts, expected);
                }

                // An unread response is not a successful retry, either.
                *response.lock() = ResponseKind::Full;
                let established = connector.serve(input()).await.unwrap();
                drop(dispatch(established).await.unwrap());
                assert_eq!(cache.failures().get(&key).unwrap().attempts, 3);

                *response.lock() = success_response;
                let established = connector.serve(input()).await.unwrap();
                assert_eq!(cache.failures().get(&key).unwrap().attempts, 3);
                let response_body = dispatch(established).await.unwrap().into_body();
                if success_response == ResponseKind::Full {
                    assert_eq!(cache.failures().get(&key).unwrap().attempts, 3);
                }
                response_body.collect().await.unwrap();
                assert!(cache.failures().get(&key).is_none());
                *response.lock() = failure_response;
                let established = connector.serve(input()).await.unwrap();
                let result = dispatch(established).await;
                if let Ok(response) = result {
                    _ = response.into_body().collect().await.unwrap_err();
                }
                assert_eq!(cache.failures().get(&key).unwrap().attempts, 1);
            }
        }
    }

    #[test]
    fn unused_cache_and_clones_allocate_no_backing_stores() {
        let cache = AltSvcCache::default();
        let shared = cache.clone();
        assert!(Arc::ptr_eq(&cache.storage, &shared.storage));
        assert!(shared.lookup(&origin()).is_none());
        cache.network_changed();
        assert_eq!(shared.network_epoch(), 1);
        assert!(cache.storage.entries.get().is_none());
        assert!(cache.storage.observers.lock().is_empty());
        assert!(cache.storage.failures.get().is_none());
        assert!(cache.storage.route_failures.get().is_none());

        record(&shared, "h2=\":443\"", Instant::now());
        assert!(cache.lookup(&origin()).is_some());
        assert!(cache.storage.entries.get().is_some());
        assert!(cache.storage.observers.lock().is_empty());
        assert!(cache.storage.failures.get().is_none());
        assert!(cache.storage.route_failures.get().is_none());

        let observing = AltSvcCache::default();
        let observing_clone = observing.clone();
        let observer = observing.frame_observer(origin());
        assert!(!observing.storage.observers.lock().is_empty());
        assert!(observing.storage.entries.get().is_none());
        assert!(observing.storage.failures.get().is_none());
        assert!(observing.storage.route_failures.get().is_none());
        assert!(Arc::ptr_eq(
            &observer,
            &observing_clone.frame_observer(origin())
        ));
    }

    #[test]
    fn frames_share_protocol_order_and_retention_policy_with_headers() {
        let cache = AltSvcCache::new(16, Duration::from_secs(30), Duration::ZERO)
            .with_max_alternatives_per_origin(2);
        let now = Instant::now();
        cache.record_frame(
            &origin(),
            Bytes::from_static(b"h2=\":8443\"; ma=5, h3=\":443\"; ma=60, future=\":9443\""),
            now,
        );
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(
            snapshot.get(0).unwrap().protocol,
            ApplicationProtocol::HTTP_2
        );
        assert_eq!(
            snapshot.get(1).unwrap().protocol,
            ApplicationProtocol::HTTP_3
        );
        assert!(!cache.is_usable_at(&snapshot, 0, now + Duration::from_secs(5)));
        assert!(cache.is_usable_at(&snapshot, 1, now + Duration::from_secs(29)));
        assert!(!cache.is_usable_at(&snapshot, 1, now + Duration::from_secs(30)));
    }

    #[test]
    fn delayed_frames_expire_from_reception_without_response_age() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        cache.record_frame(
            &origin(),
            Bytes::from_static(b"h3=\":443\"; ma=10"),
            now.checked_sub(Duration::from_secs(9)).unwrap(),
        );
        assert!(cache.lookup_at(&origin(), now).is_some());
        assert!(
            cache
                .lookup_at(&origin(), now + Duration::from_secs(1))
                .is_none()
        );
    }

    #[test]
    fn frame_clear_is_origin_scoped_and_invalid_values_preserve_advertisements() {
        let cache = AltSvcCache::default().with_max_advertisement_bytes(32);
        let now = Instant::now();
        let other = HttpOrigin::new(Protocol::HTTPS, "other.example:443".parse().unwrap()).unwrap();
        let field = Bytes::from_static(b"h3=\":443\"");
        cache.record_frame(&origin(), field.clone(), now);
        cache.record_frame(&other, field, now);
        let original = cache.lookup_at(&origin(), now).unwrap();
        for invalid in [
            Bytes::from_static(b"h3=\"unterminated"),
            Bytes::from_static(b"h3=\":443\"\r\n"),
            Bytes::from_static(b"h3=\":443\"; ignored=\"too long for the configured bound\""),
            Bytes::new(),
        ] {
            cache.record_frame(&origin(), invalid, now);
            assert!(Arc::ptr_eq(
                &original,
                &cache.lookup_at(&origin(), now).unwrap()
            ));
        }
        cache.record_frame(&origin(), Bytes::from_static(b"clear"), now);
        assert!(cache.lookup_at(&origin(), now).is_none());
        assert!(cache.lookup_at(&other, now).is_some());
    }

    #[test]
    fn all_protocols_and_advertised_preference_order_are_retained_without_lookup_copies() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(
            &cache,
            "h2=\":8443\", h3=\":443\", http%2F1.1=\"other.example:443\", future=\":9443\"",
            now,
        );
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        assert_eq!(snapshot.len(), 4);
        assert_eq!(
            &snapshot.get(0).unwrap().protocol,
            &ApplicationProtocol::HTTP_2
        );
        assert_eq!(
            &snapshot.get(1).unwrap().protocol,
            &ApplicationProtocol::HTTP_3
        );
        assert_eq!(
            &snapshot.get(2).unwrap().protocol,
            &ApplicationProtocol::HTTP_11
        );
        assert_eq!(snapshot.get(3).unwrap().target.port, 9443);
        assert!(Arc::ptr_eq(
            &snapshot,
            &cache.lookup_at(&origin(), now).unwrap()
        ));
        for index in 0..snapshot.len() {
            assert!(cache.is_usable_at(&snapshot, index, now));
        }
        assert!(!cache.is_usable_at(&snapshot, snapshot.len(), now));
    }

    #[test]
    fn individual_expiry_response_age_and_max_retention() {
        let cache = AltSvcCache::new(16, Duration::from_secs(30), Duration::ZERO);
        let now = Instant::now();
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut fields = headers("h2=\":8443\"; ma=60, h3=\":443\"; ma=120");
        fields.typed_insert(Age::from_seconds(20));
        fields.typed_insert(Date::from(wall - Duration::from_secs(50)));
        cache.record_at(&origin(), &fields, Duration::from_secs(5), wall, now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        assert!(cache.is_usable_at(&snapshot, 0, now + Duration::from_secs(9)));
        assert!(!cache.is_usable_at(&snapshot, 0, now + Duration::from_secs(10)));
        assert!(cache.is_usable_at(&snapshot, 1, now + Duration::from_secs(29)));
        assert!(
            cache
                .lookup_at(&origin(), now + Duration::from_secs(30))
                .is_none()
        );
    }

    #[test]
    fn age_includes_response_delay_and_invalid_age_cannot_replace_a_hint() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        let wall = SystemTime::now();
        let mut fields = headers("h2=\":8443\"; ma=60");
        fields.insert(header::AGE, "20".parse().unwrap());
        cache.record_at(&origin(), &fields, Duration::from_secs(5), wall, now);
        let old = cache.lookup_at(&origin(), now).unwrap();
        let mut invalid = headers("h3=\":9443\"; ma=120");
        invalid.insert(header::AGE, "invalid".parse().unwrap());
        cache.record_at(&origin(), &invalid, Duration::ZERO, wall, now);
        assert!(Arc::ptr_eq(&old, &cache.lookup_at(&origin(), now).unwrap()));
        assert!(
            cache
                .lookup_at(&origin(), now + Duration::from_secs(35))
                .is_none()
        );
    }

    #[test]
    fn schemes_hosts_and_effective_ports_have_distinct_cache_entries() {
        let cache = AltSvcCache::default();
        cache.record(&origin(), &headers("h2=\":8443\""), Duration::ZERO);
        for (scheme, authority) in [
            (Protocol::HTTP, "example.com:443"),
            (Protocol::HTTPS, "example.com:8443"),
            (Protocol::HTTPS, "other.example:443"),
        ] {
            let other = HttpOrigin::new(scheme, authority.parse().unwrap()).unwrap();
            assert!(cache.lookup(&other).is_none());
        }
        let uppercase =
            HttpOrigin::new(Protocol::HTTPS, "EXAMPLE.COM:443".parse().unwrap()).unwrap();
        assert!(cache.lookup(&uppercase).is_some());
    }

    #[test]
    fn readvertisement_and_temporary_removal_preserve_exponential_backoff() {
        let cache = AltSvcCache::new(16, Duration::from_secs(120), Duration::from_secs(5));
        let now = Instant::now();
        record(&cache, "h2=\":443\"", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        cache.failed_at(&snapshot, 0, now);
        record(&cache, "clear", now);
        record(&cache, "h2=\":443\"", now);
        assert!(cache.lookup_at(&origin(), now).is_none());
        let retry = now + Duration::from_secs(5);
        let snapshot = cache.lookup_at(&origin(), retry).unwrap();
        cache.failed_at(&snapshot, 0, retry);
        record(&cache, "h2=\":443\"", retry);
        assert!(
            cache
                .lookup_at(&origin(), retry + Duration::from_secs(5))
                .is_none()
        );
        assert!(
            cache
                .lookup_at(&origin(), retry + Duration::from_secs(10))
                .is_some()
        );
    }

    #[test]
    fn in_flight_failure_survives_readvertisement_but_not_a_network_change() {
        for network_changed in [false, true] {
            let cache = AltSvcCache::default();
            let now = Instant::now();
            record(&cache, "h3=\":443\"; persist=1", now);
            let snapshot = cache.lookup(&origin()).unwrap();
            let network = cache.network_epoch();
            record(&cache, "clear", Instant::now());
            record(&cache, "h3=\":443\"; persist=1", Instant::now());
            if network_changed {
                cache.network_changed();
            }
            cache.failed_attempt(&snapshot, 0, network, Instant::now(), true);
            assert_eq!(cache.lookup(&origin()).is_some(), network_changed);
        }
    }

    #[test]
    fn rejected_alternative_is_suppressed_on_every_route_and_after_readvertisement() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(&cache, "h2=\":443\"", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        cache.failed_attempt(&snapshot, 0, cache.network_epoch(), Instant::now(), true);
        assert!(!cache.is_fresh(&snapshot, 0));
        record(&cache, "h2=\":443\"", Instant::now());
        assert!(cache.lookup_fresh(&origin()).is_none());
    }

    #[test]
    fn delayed_headers_do_not_replace_newer_frames_or_clear_tombstones() {
        for (header, frame, expected_port) in [
            ("h3=\":8443\"", "clear", None),
            ("clear", "h3=\":9443\"", Some(9443)),
            ("h3=\":8443\"", "h3=\":9443\"", Some(9443)),
        ] {
            let cache = AltSvcCache::default();
            let first = Instant::now();
            let second = first + Duration::from_millis(1);
            cache.record_frame(&origin(), Bytes::from_static(frame.as_bytes()), second);
            record(&cache, header, first);
            let snapshot = cache.lookup_at(&origin(), second);
            assert_eq!(
                snapshot.map(|snapshot| snapshot.get(0).unwrap().target.port),
                expected_port
            );
        }
    }

    #[test]
    fn receive_sequence_breaks_clock_ties_without_processing_order_bias() {
        let first = AltSvcReceivedAt::now();
        let second = AltSvcReceivedAt {
            sequence: first.sequence + 1,
            ..first
        };
        for delayed_header in [false, true] {
            let cache = AltSvcCache::default();
            let record_header = || {
                cache.record_received(&origin(), &headers("h3=\":8443\""), Duration::ZERO, first)
            };
            let record_frame =
                || cache.record_frame_received(&origin(), Bytes::from_static(b"clear"), second);
            if delayed_header {
                record_frame();
                record_header();
            } else {
                record_header();
                record_frame();
            }
            assert!(cache.lookup(&origin()).is_none());
        }
    }

    #[test]
    fn failures_and_clear_tombstones_remain_bounded() {
        let cache = AltSvcCache::new(2, Duration::from_secs(60), Duration::from_secs(5));
        for port in 1..100 {
            let origin = HttpOrigin::new(
                Protocol::HTTPS,
                HostWithPort::new("example.com".parse().unwrap(), port),
            )
            .unwrap();
            cache.record(&origin, &headers("h3=\":443\""), Duration::ZERO);
            if let Some(snapshot) = cache.lookup(&origin) {
                cache.failed(&snapshot, 0);
            }
            cache.clear(&origin);
        }
        cache.entries().run_pending_tasks();
        cache.failures().run_pending_tasks();
        assert!(cache.entries().entry_count() <= 2);
        assert!(cache.failures().entry_count() <= 2 * DEFAULT_ALTERNATIVES_PER_ORIGIN as u64);
    }

    #[test]
    fn ignored_advertisements_do_not_advance_receive_order() {
        let cache = AltSvcCache::default().with_max_advertisement_bytes(16);
        let first = Instant::now();
        let second = first + Duration::from_millis(1);
        for ignored in ["invalid", "h3=\":9443\"; ignored=too-long"] {
            cache.record_frame(&origin(), Bytes::from_static(ignored.as_bytes()), second);
            record(&cache, "h3=\":8443\"", first);
            assert_eq!(
                cache
                    .lookup_at(&origin(), first)
                    .unwrap()
                    .get(0)
                    .unwrap()
                    .target
                    .port,
                8443
            );
        }
    }

    #[test]
    fn failures_are_per_candidate_and_backoff_expires() {
        let cache = AltSvcCache::new(16, Duration::from_secs(120), Duration::from_secs(5));
        let now = Instant::now();
        record(&cache, "h2=\":443\", h3=\":443\"", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        cache.failed_at(&snapshot, 0, now);
        assert!(!cache.is_usable_at(&snapshot, 0, now));
        assert!(cache.is_usable_at(&snapshot, 1, now));
        assert!(cache.is_usable_at(&snapshot, 0, now + Duration::from_secs(5)));
        cache.failed_at(&snapshot, 1, now);
        assert!(cache.lookup_at(&origin(), now).is_none());
        assert!(
            cache
                .lookup_at(&origin(), now + Duration::from_secs(5))
                .is_some()
        );
    }

    #[test]
    fn direct_failure_does_not_hide_a_fresh_proxy_candidate() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(&cache, "h2=\":443\"", now);
        let snapshot = cache.lookup(&origin()).unwrap();
        cache.failed(&snapshot, 0);
        assert!(cache.lookup(&origin()).is_none());
        assert!(!cache.is_usable(&snapshot, 0));
        assert!(cache.lookup_fresh(&origin()).is_some());
        assert!(cache.is_fresh(&snapshot, 0));
        cache.misdirected(&snapshot, 0);
        assert!(cache.lookup_fresh(&origin()).is_none());
        assert!(!cache.is_fresh(&snapshot, 0));
    }

    #[test]
    fn stale_failure_and_421_cannot_modify_a_new_advertisement_of_the_same_target() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(&cache, "h2=\":443\", h3=\":443\"", now);
        let old = cache.lookup_at(&origin(), now).unwrap();
        record(&cache, "h2=\":443\", h3=\":443\"", now);
        let new = cache.lookup_at(&origin(), now).unwrap();
        assert!(!Arc::ptr_eq(&old, &new));
        cache.failed_at(&old, 0, now);
        cache.misdirected(&old, 1);
        assert!(cache.is_usable_at(&new, 0, now));
        assert!(cache.is_usable_at(&new, 1, now));
        assert!(!cache.is_usable_at(&old, 0, now));
        cache.clear(&origin());
        cache.failed_at(&new, 0, now);
        cache.misdirected(&new, 1);
        assert!(cache.lookup_at(&origin(), now).is_none());
    }

    #[test]
    fn observer_registry_is_bounded_and_does_not_initialize_advertisement_stores() {
        let cache = AltSvcCache::new(1, Duration::from_hours(1), Duration::from_secs(30));
        let first = cache.frame_observer(origin());
        assert!(Arc::ptr_eq(&first, &cache.frame_observer(origin())));
        let other = HttpOrigin::new(Protocol::HTTPS, "other.example:443".parse().unwrap()).unwrap();
        let second = cache.frame_observer(other.clone());
        assert_eq!(cache.storage.observers.lock().len(), 1);
        assert!(cache.storage.entries.get().is_none());
        assert!(cache.storage.failures.get().is_none());
        assert!(cache.storage.route_failures.get().is_none());
        drop(first);
        let replacement = cache.frame_observer(other.clone());
        assert_eq!(cache.storage.observers.lock().len(), 1);
        assert!(Arc::ptr_eq(&replacement, &cache.frame_observer(other)));
        drop(second);
    }

    #[test]
    fn clear_all_forgets_advertisements_and_backoff() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(&cache, "h3=\":8443\"", now);
        let snapshot = cache.lookup(&origin()).unwrap();
        cache.misdirected(&snapshot, 0);
        cache.clear_all();
        assert!(cache.lookup(&origin()).is_none());
        record(&cache, "h3=\":8443\"", Instant::now());
        assert!(cache.is_usable(&cache.lookup(&origin()).unwrap(), 0));
    }

    #[test]
    fn misdirected_removes_only_the_selected_candidate() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(&cache, "h2=\":443\", h3=\":443\", h2=\":8443\"", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        cache.misdirected(&snapshot, 0);
        assert!(!cache.is_usable_at(&snapshot, 0, now));
        assert!(cache.is_usable_at(&snapshot, 1, now));
        assert!(cache.is_usable_at(&snapshot, 2, now));
    }

    #[test]
    fn network_change_preserves_only_persistent_candidates_in_a_mixed_advertisement() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(
            &cache,
            "h2=\":8443\", h3=\"alt.example:443\"; persist=1",
            now,
        );
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        cache.failed_at(&snapshot, 1, now);
        assert!(!cache.is_usable_at(&snapshot, 1, now));
        cache.network_changed();
        let current = cache.lookup_at(&origin(), now).unwrap();
        cache.failed_at(&snapshot, 1, now);
        assert!(!cache.is_usable_at(&current, 0, now));
        assert!(cache.is_usable_at(&current, 1, now));
        assert_eq!(
            current.get(1).unwrap().target.host.to_string(),
            "alt.example"
        );
        record(&cache, "h2=\":443\"", now);
        cache.network_changed();
        assert!(cache.lookup_at(&origin(), now).is_none());
    }

    #[test]
    fn invalid_targets_zero_age_clear_and_resource_bounds() {
        let cache = AltSvcCache::default().with_max_alternatives_per_origin(2);
        let now = Instant::now();
        record(
            &cache,
            "h3=\"[v1.fe80::a]:443\", h3=\":0\", h2=\":443\"; ma=0, h2=\":8443\", h3=\":443\", future=\":9443\"",
            now,
        );
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot.get(0).unwrap().target.port, 8443);
        record(&cache, "clear", now);
        assert!(cache.lookup_at(&origin(), now).is_none());
        record(&cache, "h3=\"[v1.fe80::a]:443\"", now);
        assert!(cache.lookup_at(&origin(), now).is_none());

        let disabled = AltSvcCache::default().with_max_alternatives_per_origin(0);
        record(&disabled, "h2=\":443\"", now);
        assert!(disabled.lookup_at(&origin(), now).is_none());
    }

    #[test]
    fn expired_or_removed_candidates_cannot_be_resurrected_by_failure() {
        let cache = AltSvcCache::new(16, Duration::from_secs(60), Duration::MAX);
        let now = Instant::now();
        record(&cache, "h2=\":443\"; ma=1, h3=\":443\"; ma=60", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        cache.failed_at(&snapshot, 0, now);
        assert!(!cache.is_usable_at(&snapshot, 0, now + Duration::from_secs(1)));
        cache.misdirected(&snapshot, 1);
        cache.failed_at(&snapshot, 1, now);
        assert!(!cache.is_usable_at(&snapshot, 1, now));
    }

    #[test]
    fn oversized_advertisements_are_ignored_before_parsing_and_duplicates_are_coalesced() {
        let cache = AltSvcCache::default().with_max_advertisement_bytes(128);
        let now = Instant::now();
        record(&cache, "h2=\":443\", h2=\":443\", h3=\":443\"", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        assert_eq!(snapshot.len(), 2);
        let mut fields = headers("h3=\":9443\"");
        fields.append(
            header::ALT_SVC,
            format!("future=\":443\"; p=\"{}\"", "x".repeat(128))
                .parse()
                .unwrap(),
        );
        cache.record_at(&origin(), &fields, Duration::ZERO, SystemTime::now(), now);
        assert!(Arc::ptr_eq(
            &snapshot,
            &cache.lookup_at(&origin(), now).unwrap()
        ));
    }

    #[test]
    fn entry_capacity_remains_bounded() {
        let cache = AltSvcCache::new(2, Duration::from_secs(60), Duration::ZERO);
        for port in 1..100 {
            let origin = HttpOrigin::new(
                Protocol::HTTPS,
                HostWithPort::new(Host::try_from("example.com").unwrap(), port),
            )
            .unwrap();
            cache.record(&origin, &headers("h2=\":443\""), Duration::ZERO);
        }
        cache.entries().run_pending_tasks();
        assert!(cache.entries().entry_count() <= 2);
    }

    #[test]
    fn concurrent_and_late_failures_share_one_backoff_window() {
        let cache = AltSvcCache::new(16, Duration::from_secs(60), Duration::from_secs(2));
        let now = Instant::now();
        record(&cache, "h2=\":443\"", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        let network = cache.network_epoch();
        std::thread::scope(|scope| {
            for _ in 0..32 {
                scope.spawn(|| cache.failed_attempt(&snapshot, 0, network, now, false));
            }
        });
        let failure = cache
            .failures()
            .get(&(network, origin(), snapshot.get(0).unwrap().clone()))
            .unwrap();
        assert_eq!(failure.attempts, 1);
        let late = failure.until + Duration::from_secs(1);
        cache.suppress(&snapshot, 0, now, late, false, Some(network));
        assert!(cache.is_usable_at(&snapshot, 0, late));
        cache.suppress(&snapshot, 0, late, late, false, Some(network));
        assert!(!cache.is_usable_at(&snapshot, 0, late + Duration::from_secs(3)));
        assert!(cache.is_usable_at(&snapshot, 0, late + Duration::from_secs(5)));

        let route = RouteContext::Route(Arc::new(ProxyRoute::Proxy(
            "http://proxy.example:3128".parse().unwrap(),
        )));
        for _ in 0..32 {
            cache.failed_route(&snapshot, 0, network, now, &route);
        }
        let failure = cache
            .route_failures()
            .get(&(network, origin(), snapshot.get(0).unwrap().clone(), route))
            .unwrap();
        assert_eq!(failure.attempts, 1);
    }

    #[test]
    fn identical_advertisements_refresh_generation_and_lifetime() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(&cache, "h2=\":443\"; ma=10", now);
        let first = cache.lookup_at(&origin(), now).unwrap();
        let later = now + Duration::from_secs(8);
        record(&cache, "h2=\":443\"; ma=10", later);
        let current = cache.lookup_at(&origin(), later).unwrap();
        assert!(!Arc::ptr_eq(&first, &current));
        cache.misdirected(&first, 0);
        assert!(cache.is_usable_at(&current, 0, later + Duration::from_secs(5)));
        assert!(!cache.is_usable_at(&current, 0, later + Duration::from_secs(11)));
    }

    #[test]
    fn validated_success_restarts_failure_backoff() {
        let cache = AltSvcCache::new(16, Duration::from_secs(60), Duration::from_secs(2));
        let now = Instant::now();
        record(&cache, "h2=\":443\"", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        cache.failed_at(&snapshot, 0, now);
        let retry = now + Duration::from_secs(3);
        cache.failed_at(&snapshot, 0, retry);
        assert!(!cache.is_usable_at(&snapshot, 0, retry + Duration::from_secs(3)));
        cache.succeeded(
            snapshot.origin(),
            snapshot.get(0).unwrap(),
            None,
            cache.network_epoch(),
        );
        cache.failed_at(&snapshot, 0, retry);
        assert!(cache.is_usable_at(&snapshot, 0, retry + Duration::from_secs(3)));
    }

    #[test]
    fn success_recovers_a_readvertised_endpoint_but_not_a_different_network() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(&cache, "h2=\":443\"; persist=1", now);
        let first = cache.lookup_at(&origin(), now).unwrap();
        let network = cache.network_epoch();
        cache.failed_at(&first, 0, now);
        record(&cache, "h2=\":443\"; persist=1", now);
        cache.succeeded(first.origin(), first.get(0).unwrap(), None, network);
        let current = cache.lookup_at(&origin(), now).unwrap();
        assert!(!Arc::ptr_eq(&first, &current));
        cache.network_changed();
        let current = cache.lookup_at(&origin(), now).unwrap();
        cache.failed_at(&current, 0, now);
        cache.succeeded(first.origin(), first.get(0).unwrap(), None, network);
        assert!(!cache.is_usable_at(&current, 0, now));
    }

    #[test]
    fn opaque_route_configuration_does_not_poison_another_plan() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(&cache, "h2=\":443\"", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        let proxy = ProxyRoute::Proxy("http://proxy.example:3128".parse().unwrap());
        let first = RouteContext::Routes(Arc::new(
            [(proxy.clone(), Extensions::new())].into_iter().collect(),
        ));
        let second = RouteContext::Routes(Arc::new(
            [(proxy.clone(), Extensions::new())].into_iter().collect(),
        ));
        cache.failed_route(&snapshot, 0, cache.network_epoch(), Instant::now(), &first);
        assert!(cache.route_usable(&snapshot, 0, &second));
        let plain = RouteContext::Route(Arc::new(proxy));
        assert!(cache.route_usable(&snapshot, 0, &plain));
        cache.failed_route(&snapshot, 0, cache.network_epoch(), Instant::now(), &plain);
        assert!(!cache.route_usable(&snapshot, 0, &plain));
        assert!(cache.route_usable(&snapshot, 0, &second));
    }

    #[test]
    fn direct_route_extensions_keep_their_policy_context() {
        let extensions = Extensions::new();
        extensions.insert(ProxyRoutes::from_iter([(
            ProxyRoute::Direct,
            Extensions::new(),
        )]));
        let context = RouteContext::for_request(&extensions).unwrap();
        assert!(!context.cacheable());
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(&cache, "h2=\":443\"", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        cache.failed_route(
            &snapshot,
            0,
            cache.network_epoch(),
            Instant::now(),
            &context,
        );
        assert!(cache.is_usable_at(&snapshot, 0, now));
    }
}
