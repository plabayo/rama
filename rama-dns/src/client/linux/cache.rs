use std::{
    hash::{Hash, Hasher},
    sync::Arc,
    time::Duration,
};

use moka::{Equivalent, sync::Cache};
use rama_core::bytes::Bytes;
use rama_net::address::Domain;

#[derive(Debug, Clone)]
pub(super) struct LinuxDnsCache {
    entries: Cache<CacheKey, CacheValue, ahash::RandomState>,
}

impl LinuxDnsCache {
    pub(super) fn new(max_capacity: u64, ttl: Duration) -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(ttl)
                .build_with_hasher(ahash::RandomState::default()),
        }
    }

    pub(super) fn get_ipv4(&self, domain: &Domain) -> Option<Arc<[std::net::Ipv4Addr]>> {
        match self
            .entries
            .get(&CacheLookupKey::new(domain, RecordKind::Ipv4))
        {
            Some(CacheValue::Ipv4(values)) => Some(values),
            _ => None,
        }
    }

    pub(super) fn insert_ipv4(&self, domain: Domain, values: Vec<std::net::Ipv4Addr>) {
        if values.is_empty() {
            return;
        }

        self.entries.insert(
            CacheKey::new(domain, RecordKind::Ipv4),
            CacheValue::Ipv4(Arc::<[std::net::Ipv4Addr]>::from(values)),
        );
    }

    pub(super) fn get_ipv6(&self, domain: &Domain) -> Option<Arc<[std::net::Ipv6Addr]>> {
        match self
            .entries
            .get(&CacheLookupKey::new(domain, RecordKind::Ipv6))
        {
            Some(CacheValue::Ipv6(values)) => Some(values),
            _ => None,
        }
    }

    pub(super) fn insert_ipv6(&self, domain: Domain, values: Vec<std::net::Ipv6Addr>) {
        if values.is_empty() {
            return;
        }

        self.entries.insert(
            CacheKey::new(domain, RecordKind::Ipv6),
            CacheValue::Ipv6(Arc::<[std::net::Ipv6Addr]>::from(values)),
        );
    }

    pub(super) fn get_txt(&self, domain: &Domain) -> Option<Arc<[Bytes]>> {
        match self
            .entries
            .get(&CacheLookupKey::new(domain, RecordKind::Txt))
        {
            Some(CacheValue::Txt(values)) => Some(values),
            _ => None,
        }
    }

    pub(super) fn insert_txt(&self, domain: Domain, values: Vec<Bytes>) {
        if values.is_empty() {
            return;
        }

        self.entries.insert(
            CacheKey::new(domain, RecordKind::Txt),
            CacheValue::Txt(Arc::<[Bytes]>::from(values)),
        );
    }
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
enum RecordKind {
    Ipv4,
    Ipv6,
    Txt,
}

#[derive(Debug, Clone)]
enum CacheValue {
    Ipv4(Arc<[std::net::Ipv4Addr]>),
    Ipv6(Arc<[std::net::Ipv6Addr]>),
    Txt(Arc<[Bytes]>),
}
