//! Bounded, origin-scoped HTTP alternative-service advertisements.

use moka::{ops::compute::Op, policy::EvictionPolicy, sync::Cache};
use rama_core::bytes::Bytes;
use rama_http_headers::{Age, AltSvc, Date, HeaderDecode as _, HeaderMapExt as _};
use rama_http_types::{
    HeaderMap, HeaderValue,
    conn::{HttpOrigin, HttpServiceCandidate, HttpServiceCandidates, HttpServiceSource},
    header,
    proto::h2::alt_svc::AltSvcReceivedAt,
};
use rama_net::address::{Host, HostWithPort};
use rama_utils::macros::generate_set_and_with;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

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
#[derive(Clone, Debug)]
pub struct AltSvcCache {
    entries: Cache<HttpOrigin, Advertisement>,
    failures: Cache<(u64, HttpOrigin, HttpServiceCandidate), Failure>,
    network: Arc<AtomicU64>,
    max_age: Duration,
    failure_backoff: Duration,
    max_alternatives_per_origin: usize,
    max_advertisement_bytes: usize,
}

impl Default for AltSvcCache {
    fn default() -> Self {
        Self::new(1024, Duration::from_hours(24), Duration::from_secs(30))
    }
}

impl AltSvcCache {
    /// Set origin capacity, maximum retention and alternative failure backoff.
    pub fn new(capacity: u64, max_age: Duration, failure_backoff: Duration) -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(capacity)
                .eviction_policy(EvictionPolicy::lru())
                .time_to_live(max_age)
                .build(),
            failures: Cache::builder()
                .max_capacity(capacity.saturating_mul(DEFAULT_ALTERNATIVES_PER_ORIGIN as u64))
                .eviction_policy(EvictionPolicy::lru())
                .time_to_live(max_age)
                .build(),
            network: Arc::new(AtomicU64::new(0)),
            max_age,
            failure_backoff,
            max_alternatives_per_origin: DEFAULT_ALTERNATIVES_PER_ORIGIN,
            max_advertisement_bytes: DEFAULT_ADVERTISEMENT_BYTES,
        }
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

    pub(super) fn record_frame_received(
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

    pub(super) fn record_received(
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
        self.entries
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
                    availability.failure =
                        self.failures
                            .get(&(network, origin.clone(), candidate.clone()));
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
        let entry = self.entries.get(origin)?;
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
        self.entries.get(snapshot.origin()).is_some_and(|entry| {
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
        self.entries.get(snapshot.origin()).is_some_and(|entry| {
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
        self.suppress(snapshot, index, now, false, None);
    }

    pub(crate) fn network_epoch(&self) -> u64 {
        self.network.load(Ordering::Acquire)
    }

    /// Record a completed attempt even when its endpoint was re-advertised
    /// during the dial. A network change invalidates the captured path context.
    pub(crate) fn failed_attempt(
        &self,
        snapshot: &Arc<HttpServiceCandidates>,
        index: usize,
        network: u64,
        terminal: bool,
    ) {
        self.suppress(snapshot, index, Instant::now(), terminal, Some(network));
    }

    fn suppress(
        &self,
        snapshot: &Arc<HttpServiceCandidates>,
        index: usize,
        now: Instant,
        all_routes: bool,
        network: Option<u64>,
    ) {
        let Some(candidate) = snapshot.get(index) else {
            return;
        };
        self.entries
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
                let previous = self.failures.get(&key);
                let attempts = previous
                    .as_ref()
                    .map_or(1, |failure| failure.attempts.saturating_add(1));
                let backoff = self
                    .failure_backoff
                    .saturating_mul(2u32.saturating_pow(attempts.saturating_sub(1)))
                    .min(self.max_age);
                let failure = Failure {
                    network: current_network,
                    until: now.checked_add(backoff).unwrap_or(now),
                    attempts,
                    all_routes: all_routes || previous.is_some_and(|failure| failure.all_routes),
                };
                self.failures.insert(key, failure.clone());
                let index = current.services.iter().position(|item| item == candidate);
                if let Some(index) = index {
                    Arc::make_mut(&mut current.availability)[index].failure = Some(failure);
                    Op::Put(current)
                } else {
                    Op::Nop
                }
            });
    }

    /// Remove only the alternative that returned 421, without replaying a request.
    /// Delayed responses cannot invalidate a newer advertisement of that endpoint.
    pub fn misdirected(&self, snapshot: &Arc<HttpServiceCandidates>, index: usize) {
        self.update_candidate(snapshot, index, |value| value.removed = true);
    }

    fn update_candidate(
        &self,
        snapshot: &Arc<HttpServiceCandidates>,
        index: usize,
        update: impl FnOnce(&mut Availability),
    ) {
        self.entries
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
    pub fn network_changed(&self) {
        self.network.fetch_add(1, Ordering::AcqRel);
        self.failures.invalidate_all();
        for (origin, observed) in &self.entries {
            self.entries
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
            cache.failed_attempt(&snapshot, 0, network, true);
            assert_eq!(cache.lookup(&origin()).is_some(), network_changed);
        }
    }

    #[test]
    fn rejected_alternative_is_suppressed_on_every_route_and_after_readvertisement() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        record(&cache, "h2=\":443\"", now);
        let snapshot = cache.lookup_at(&origin(), now).unwrap();
        cache.failed_attempt(&snapshot, 0, cache.network_epoch(), true);
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
        cache.entries.run_pending_tasks();
        cache.failures.run_pending_tasks();
        assert!(cache.entries.entry_count() <= 2);
        assert!(cache.failures.entry_count() <= 2 * DEFAULT_ALTERNATIVES_PER_ORIGIN as u64);
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
        cache.entries.run_pending_tasks();
        assert!(cache.entries.entry_count() <= 2);
    }
}
