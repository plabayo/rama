//! Authenticated, origin-scoped HTTP/3 alternatives with finite retention.

use moka::{policy::EvictionPolicy, sync::Cache};
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
            self.entries.invalidate(&origin);
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
            values.find(|value| {
                value.protocol() == &ApplicationProtocol::HTTP_3
                    && value.port() != 0
                    && value.max_age() > age
            })
        });
        let Some(alternative) = alternative else {
            self.entries.invalidate(&origin);
            return;
        };
        let ttl = alternative.max_age().saturating_sub(age).min(self.max_age);
        if ttl.is_zero() {
            self.entries.invalidate(&origin);
            return;
        }
        let target = HostWithPort {
            host: alternative
                .host()
                .cloned()
                .unwrap_or_else(|| origin.host.clone()),
            port: alternative.port(),
        };
        let Some(target) = canonical(&target) else {
            return;
        };
        let Some(expires) = now.checked_add(ttl) else {
            return;
        };
        self.entries.insert(
            origin,
            Alternative {
                target,
                expires,
                suppressed_until: None,
                persist: alternative.persist(),
            },
        );
    }
    /// Return a fresh, currently usable H3 dial target for an HTTPS origin.
    pub fn lookup(&self, origin: &HostWithPort) -> Option<HostWithPort> {
        self.lookup_at(origin, Instant::now())
    }
    fn lookup_at(&self, origin: &HostWithPort, now: Instant) -> Option<HostWithPort> {
        let origin = canonical(origin)?;
        let entry = self.entries.get(&origin)?;
        if now >= entry.expires {
            self.entries.invalidate(&origin);
            return None;
        }
        if entry.suppressed_until.is_some_and(|until| now < until) {
            return None;
        }
        Some(entry.target)
    }
    /// Temporarily suppress an alternative after an establishment failure.
    pub fn failed(&self, origin: &HostWithPort) {
        let Some(origin) = canonical(origin) else {
            return;
        };
        if let Some(mut entry) = self.entries.get(&origin) {
            entry.suppressed_until = Instant::now().checked_add(self.failure_backoff);
            self.entries.insert(origin, entry);
        }
    }
    /// Forget network-specific alternatives, retaining only entries with `persist=1`.
    pub fn network_changed(&self) {
        for (origin, alternative) in &self.entries {
            if !alternative.persist {
                self.entries.invalidate(origin.as_ref());
            }
        }
    }
    /// Explicitly invalidate an origin's alternatives.
    pub fn clear(&self, origin: &HostWithPort) {
        if let Some(origin) = canonical(origin) {
            self.entries.invalidate(&origin);
        }
    }
}
pub(crate) fn canonical(origin: &HostWithPort) -> Option<HostWithPort> {
    let host = if let Ok(ip) = origin.host.try_as_ip() {
        Host::from(ip)
    } else {
        Host::from(origin.host.try_as_domain().ok()?.into_owned())
    };
    Some(HostWithPort {
        host,
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
        cache.failed(&origin());
        assert!(cache.lookup(&origin()).is_none());
        cache.record_authenticated(&origin(), &headers("clear"), Duration::ZERO);
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
