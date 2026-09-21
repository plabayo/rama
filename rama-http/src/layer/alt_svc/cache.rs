//! Authenticated, origin-scoped HTTP/3 alternatives with finite retention.

use moka::{ops::compute::Op, policy::EvictionPolicy, sync::Cache};
use rama_http_headers::{Age, AltSvc, Date, HeaderMapExt as _};
use rama_http_types::HeaderMap;
use rama_net::{
    address::{Host, HostWithPort},
    tls::ApplicationProtocol,
};
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Debug)]
struct Alternative {
    target: HostWithPort,
    expires: Instant,
    suppressed_until: Option<Instant>,
    persist: bool,
}

/// A bounded cache of H3 alternatives learned from authenticated HTTPS responses.
///
/// The cache stores one preferred H3 endpoint per logical origin. An alternative
/// changes only the dial target; requests, SNI and certificate checks use the origin.
#[derive(Clone, Debug)]
pub struct AltSvcCache {
    entries: Cache<HostWithPort, Alternative>,
    max_age: Duration,
    failure_backoff: Duration,
}

impl Default for AltSvcCache {
    fn default() -> Self {
        Self::new(1024, Duration::from_secs(86_400), Duration::from_secs(30))
    }
}

impl AltSvcCache {
    /// Set entry capacity, maximum retention and temporary alternative failure backoff.
    pub fn new(capacity: u64, max_age: Duration, failure_backoff: Duration) -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(capacity)
                .eviction_policy(EvictionPolicy::lru())
                .time_to_live(max_age)
                .build(),
            max_age,
            failure_backoff,
        }
    }

    /// Record an Alt-Svc header only after authenticating this logical HTTPS origin.
    /// `response_delay` is the time from request dispatch to response headers.
    pub fn record_authenticated(
        &self,
        origin: &HostWithPort,
        headers: &HeaderMap,
        response_delay: Duration,
    ) {
        self.record_at(
            origin,
            headers,
            response_delay,
            SystemTime::now(),
            Instant::now(),
        );
    }

    fn record_at(
        &self,
        origin: &HostWithPort,
        headers: &HeaderMap,
        response_delay: Duration,
        wall: SystemTime,
        now: Instant,
    ) {
        let Some(origin) = canonical(origin) else {
            return;
        };
        let Some(header) = headers.typed_get::<AltSvc>() else {
            return;
        };
        if header.is_clear() {
            self.remove(origin);
            return;
        }
        if headers.contains_key("age") && headers.typed_get::<Age>().is_none() {
            return;
        }
        let age = headers
            .typed_get::<Age>()
            .map_or(Duration::ZERO, Duration::from)
            .saturating_add(response_delay);
        let apparent_age = headers
            .typed_get::<Date>()
            .and_then(|date| wall.duration_since(SystemTime::from(date)).ok())
            .unwrap_or_default();
        let age = age.max(apparent_age);
        let alternative = header.alternatives().and_then(|mut values| {
            values.find_map(|value| {
                if value.protocol() != &ApplicationProtocol::HTTP_3
                    || value.port() == 0
                    || value.max_age() <= age
                {
                    return None;
                }
                let target = canonical(&HostWithPort {
                    host: value.host().cloned().unwrap_or_else(|| origin.host.clone()),
                    port: value.port(),
                })?;
                Some((value, target))
            })
        });
        let Some((alternative, target)) = alternative else {
            self.remove(origin);
            return;
        };
        let ttl = alternative.max_age().saturating_sub(age).min(self.max_age);
        if ttl.is_zero() {
            self.remove(origin);
            return;
        }
        let Some(expires) = now.checked_add(ttl) else {
            return;
        };
        self.entries.entry(origin).and_compute_with(|_| {
            Op::Put(Alternative {
                target,
                expires,
                suppressed_until: None,
                persist: alternative.persist(),
            })
        });
    }

    /// Return a fresh, currently usable H3 dial target for an HTTPS origin.
    pub fn lookup(&self, origin: &HostWithPort) -> Option<HostWithPort> {
        self.lookup_at(origin, Instant::now())
    }

    fn lookup_at(&self, origin: &HostWithPort, now: Instant) -> Option<HostWithPort> {
        let origin = canonical(origin)?;
        let entry = self.entries.get(&origin)?;
        if now >= entry.expires {
            self.entries.entry(origin).and_compute_with(|entry| {
                if entry.is_some_and(|entry| now >= entry.value().expires) {
                    Op::Remove
                } else {
                    Op::Nop
                }
            });
            return None;
        }
        if entry.suppressed_until.is_some_and(|until| now < until) {
            return None;
        }
        Some(entry.target)
    }

    /// Temporarily suppress the attempted target after an establishment failure.
    /// A different target learned while the connection was pending is unaffected.
    pub fn failed(&self, origin: &HostWithPort, attempted_target: &HostWithPort) {
        let Some(origin) = canonical(origin) else {
            return;
        };
        let Some(attempted_target) = canonical(attempted_target) else {
            return;
        };
        self.entries.entry(origin).and_compute_with(|entry| {
            let Some(entry) = entry else {
                return Op::Nop;
            };
            let mut entry = entry.into_value();
            if entry.target != attempted_target {
                return Op::Nop;
            }
            entry.suppressed_until = Instant::now().checked_add(self.failure_backoff);
            Op::Put(entry)
        });
    }

    /// Forget network-specific alternatives, retaining only entries with `persist=1`.
    pub fn network_changed(&self) {
        for (origin, alternative) in &self.entries {
            if !alternative.persist {
                self.entries
                    .entry(origin.as_ref().clone())
                    .and_compute_with(|entry| {
                        if entry.is_some_and(|entry| !entry.value().persist) {
                            Op::Remove
                        } else {
                            Op::Nop
                        }
                    });
            }
        }
    }

    /// Explicitly invalidate an origin's alternatives.
    pub fn clear(&self, origin: &HostWithPort) {
        if let Some(origin) = canonical(origin) {
            self.remove(origin);
        }
    }

    // Keep all mutations under Moka's per-key compute lock: a get/insert pair can
    // otherwise resurrect a cleared entry or overwrite a newer advertisement.
    fn remove(&self, origin: HostWithPort) {
        self.entries.entry(origin).and_compute_with(|_| Op::Remove);
    }
}

fn canonical(origin: &HostWithPort) -> Option<HostWithPort> {
    let host = if let Ok(ip) = origin.host.try_as_ip() {
        Host::from(ip)
    } else {
        Host::from(origin.host.try_as_domain().ok()?.into_owned())
    };
    Some(HostWithPort {
        host: host.canonicalize(),
        port: origin.port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn origin() -> HostWithPort {
        "example.com:443".parse().unwrap()
    }

    fn headers(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("alt-svc", value.parse().unwrap());
        headers
    }

    #[test]
    fn expiry_age_clear_and_failure_backoff() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        let mut fields = headers("h3=\":8443\"; ma=60");
        fields.insert("age", "20".parse().unwrap());
        cache.record_at(
            &origin(),
            &fields,
            Duration::from_secs(5),
            SystemTime::now(),
            now,
        );
        assert_eq!(cache.lookup_at(&origin(), now).unwrap().port, 8443);
        assert!(
            cache
                .lookup_at(&origin(), now + Duration::from_secs(35))
                .is_none()
        );
        cache.record_authenticated(&origin(), &headers("h3=\":443\"; ma=60"), Duration::ZERO);
        cache.failed(&origin(), &origin());
        assert!(cache.lookup(&origin()).is_none());
        cache.record_authenticated(&origin(), &headers("clear"), Duration::ZERO);
        assert!(cache.lookup(&origin()).is_none());
    }

    #[test]
    fn date_age_retention_and_origin_boundaries() {
        let cache = AltSvcCache::new(16, Duration::from_secs(30), Duration::ZERO);
        let now = Instant::now();
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut fields = headers("h3=\":8443\"; ma=120");
        fields.typed_insert(Date::from(wall - Duration::from_secs(100)));
        cache.record_at(&origin(), &fields, Duration::ZERO, wall, now);
        assert!(
            cache
                .lookup_at(&origin(), now + Duration::from_secs(19))
                .is_some()
        );
        assert!(
            cache
                .lookup_at(&origin(), now + Duration::from_secs(20))
                .is_none()
        );
        cache.record_at(
            &origin(),
            &headers("h3=\":8443\"; ma=120"),
            Duration::ZERO,
            wall,
            now,
        );
        assert!(
            cache
                .lookup_at(&origin(), now + Duration::from_secs(29))
                .is_some()
        );
        assert!(
            cache
                .lookup_at(&"example.com:8443".parse().unwrap(), now)
                .is_none()
        );
        assert!(
            cache
                .lookup_at(&"other.example:443".parse().unwrap(), now)
                .is_none()
        );
        assert!(
            cache
                .lookup_at(&origin(), now + Duration::from_secs(30))
                .is_none()
        );
    }

    #[test]
    fn invalid_age_cannot_extend_an_existing_alternative() {
        let cache = AltSvcCache::default();
        let now = Instant::now();
        let wall = SystemTime::now();
        cache.record_at(
            &origin(),
            &headers("h3=\":8443\"; ma=10"),
            Duration::ZERO,
            wall,
            now,
        );
        let mut invalid = headers("h3=\":9443\"; ma=120");
        invalid.insert("age", "invalid".parse().unwrap());
        cache.record_at(&origin(), &invalid, Duration::ZERO, wall, now);
        assert_eq!(cache.lookup_at(&origin(), now).unwrap().port, 8443);
        assert!(
            cache
                .lookup_at(&origin(), now + Duration::from_secs(10))
                .is_none()
        );
    }

    #[test]
    fn unsupported_hosts_do_not_keep_stale_alternatives_or_hide_usable_ones() {
        let cache = AltSvcCache::default();
        cache.record_authenticated(&origin(), &headers("h3=\":443\""), Duration::ZERO);
        cache.record_authenticated(
            &origin(),
            &headers("h3=\"[v1.fe80::a]:443\", h3=\":8443\""),
            Duration::ZERO,
        );
        assert_eq!(cache.lookup(&origin()).unwrap().port, 8443);
        cache.record_authenticated(
            &origin(),
            &headers("h3=\"[v1.fe80::a]:443\""),
            Duration::ZERO,
        );
        assert!(cache.lookup(&origin()).is_none());
    }

    #[test]
    fn failure_of_an_old_target_does_not_suppress_its_replacement() {
        let cache = AltSvcCache::default();
        cache.record_authenticated(&origin(), &headers("h3=\":8443\""), Duration::ZERO);
        let old_target = cache.lookup(&origin()).unwrap();
        cache.record_authenticated(&origin(), &headers("h3=\":9443\""), Duration::ZERO);
        cache.failed(&origin(), &old_target);
        assert_eq!(cache.lookup(&origin()).unwrap().port, 9443);
        cache.clear(&origin());
        cache.failed(&origin(), &old_target);
        assert!(cache.lookup(&origin()).is_none());
    }

    #[test]
    fn network_changes_only_keep_persistent_alternatives() {
        let cache = AltSvcCache::default();
        cache.record_authenticated(
            &origin(),
            &headers("h3=\"alt.example:443\"; persist=1"),
            Duration::ZERO,
        );
        cache.network_changed();
        assert_eq!(
            cache.lookup(&origin()).unwrap().host.to_string(),
            "alt.example"
        );
        cache.record_authenticated(&origin(), &headers("h3=\":443\""), Duration::ZERO);
        cache.network_changed();
        assert!(cache.lookup(&origin()).is_none());
    }
}
