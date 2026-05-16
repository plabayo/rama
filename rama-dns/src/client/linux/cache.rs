use std::{
    hash::{Hash, Hasher},
    sync::Arc,
    time::{Duration, Instant},
};

use moka::{Equivalent, Expiry, sync::Cache};
use rama_core::bytes::Bytes;
use rama_net::address::Domain;

/// Linux-only DNS response cache.
///
/// Stores positive and negative results keyed on `(domain, record-kind)`,
/// with per-entry expiry derived from the DNS response TTL (clamped to the
/// configured maxima).
#[derive(Debug, Clone)]
pub(super) struct LinuxDnsCache {
    entries: Cache<CacheKey, CacheEntry, ahash::RandomState>,
}

impl LinuxDnsCache {
    pub(super) fn new(max_capacity: u64, positive_ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(max_capacity)
                .expire_after(EntryExpiry {
                    positive_ttl,
                    negative_ttl,
                })
                .build_with_hasher(ahash::RandomState::default()),
        }
    }

    pub(super) fn get_ipv4(&self, domain: &Domain) -> Option<CacheLookup<std::net::Ipv4Addr>> {
        self.lookup(domain, RecordKind::Ipv4, |value| match value {
            CacheValue::Ipv4(values) => Some(values.clone()),
            _ => None,
        })
    }

    pub(super) fn insert_ipv4(
        &self,
        domain: Domain,
        values: Vec<std::net::Ipv4Addr>,
        ttl: Option<Duration>,
    ) {
        self.insert(
            domain,
            RecordKind::Ipv4,
            CacheValue::Ipv4(Arc::<[std::net::Ipv4Addr]>::from(values)),
            ttl,
        );
    }

    pub(super) fn get_ipv6(&self, domain: &Domain) -> Option<CacheLookup<std::net::Ipv6Addr>> {
        self.lookup(domain, RecordKind::Ipv6, |value| match value {
            CacheValue::Ipv6(values) => Some(values.clone()),
            _ => None,
        })
    }

    pub(super) fn insert_ipv6(
        &self,
        domain: Domain,
        values: Vec<std::net::Ipv6Addr>,
        ttl: Option<Duration>,
    ) {
        self.insert(
            domain,
            RecordKind::Ipv6,
            CacheValue::Ipv6(Arc::<[std::net::Ipv6Addr]>::from(values)),
            ttl,
        );
    }

    pub(super) fn get_txt(&self, domain: &Domain) -> Option<CacheLookup<Bytes>> {
        self.lookup(domain, RecordKind::Txt, |value| match value {
            CacheValue::Txt(values) => Some(values.clone()),
            _ => None,
        })
    }

    pub(super) fn insert_txt(&self, domain: Domain, values: Vec<Bytes>, ttl: Option<Duration>) {
        self.insert(
            domain,
            RecordKind::Txt,
            CacheValue::Txt(Arc::<[Bytes]>::from(values)),
            ttl,
        );
    }

    /// Insert a negative entry with an SOA-derived TTL.
    ///
    /// Per RFC 2308 §5 the caller must only invoke this when the response
    /// carries an SOA: there is no "default-TTL" fallback path here. The
    /// stored TTL is still clamped by the configured `negative_ttl` ceiling
    /// in [`EntryExpiry`].
    pub(super) fn insert_negative(&self, domain: Domain, kind: RecordKind, ttl: Duration) {
        self.entries.insert(
            CacheKey::new(domain, kind),
            CacheEntry {
                value: CacheValue::Negative,
                explicit_ttl: Some(ttl),
            },
        );
    }

    fn lookup<T, F>(&self, domain: &Domain, kind: RecordKind, extract: F) -> Option<CacheLookup<T>>
    where
        F: FnOnce(&CacheValue) -> Option<Arc<[T]>>,
    {
        let entry = self.entries.get(&CacheLookupKey::new(domain, kind))?;
        match &entry.value {
            CacheValue::Negative => Some(CacheLookup::Negative),
            value => extract(value).map(CacheLookup::Positive),
        }
    }

    fn insert(&self, domain: Domain, kind: RecordKind, value: CacheValue, ttl: Option<Duration>) {
        self.entries.insert(
            CacheKey::new(domain, kind),
            CacheEntry {
                value,
                explicit_ttl: ttl,
            },
        );
    }
}

pub(super) enum CacheLookup<T> {
    Positive(Arc<[T]>),
    Negative,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    domain: Domain,
    kind: RecordKind,
}

impl CacheKey {
    fn new(domain: Domain, kind: RecordKind) -> Self {
        Self { domain, kind }
    }
}

struct CacheLookupKey<'a> {
    domain: &'a Domain,
    kind: RecordKind,
}

impl<'a> CacheLookupKey<'a> {
    fn new(domain: &'a Domain, kind: RecordKind) -> Self {
        Self { domain, kind }
    }
}

impl Hash for CacheLookupKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let Self { domain, kind } = self;
        domain.hash(state);
        kind.hash(state);
    }
}

impl Equivalent<CacheKey> for CacheLookupKey<'_> {
    fn equivalent(&self, key: &CacheKey) -> bool {
        let Self {
            domain: lookup_domain,
            kind: lookup_kind,
        } = self;
        let CacheKey {
            domain: key_domain,
            kind: key_kind,
        } = key;

        lookup_kind == key_kind && *lookup_domain == key_domain
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub(super) enum RecordKind {
    Ipv4,
    Ipv6,
    Txt,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    value: CacheValue,
    /// Per-entry expiry derived from the DNS response TTL, capped at the
    /// configured positive max. `None` for negative entries or when the
    /// resolver back-end could not surface a TTL.
    explicit_ttl: Option<Duration>,
}

#[derive(Debug, Clone)]
enum CacheValue {
    Ipv4(Arc<[std::net::Ipv4Addr]>),
    Ipv6(Arc<[std::net::Ipv6Addr]>),
    Txt(Arc<[Bytes]>),
    Negative,
}

#[derive(Debug, Clone)]
struct EntryExpiry {
    positive_ttl: Duration,
    negative_ttl: Duration,
}

impl Expiry<CacheKey, CacheEntry> for EntryExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CacheEntry,
        _created_at: Instant,
    ) -> Option<Duration> {
        let bound = match value.value {
            CacheValue::Negative => self.negative_ttl,
            _ => self.positive_ttl,
        };
        let chosen = value
            .explicit_ttl
            .map_or(bound, |explicit| explicit.min(bound));
        Some(chosen)
    }
}
