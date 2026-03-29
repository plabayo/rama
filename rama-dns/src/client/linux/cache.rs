use std::{hash::Hash, sync::Arc, time::Duration};

use moka::sync::Cache;
use rama_core::bytes::Bytes;
use rama_net::address::Domain;

#[derive(Debug, Clone)]
pub(super) struct LinuxDnsCache {
    pub(super) ipv4: RecordCache<std::net::Ipv4Addr>,
    pub(super) ipv6: RecordCache<std::net::Ipv6Addr>,
    pub(super) txt: RecordCache<Bytes>,
}

impl LinuxDnsCache {
    pub(super) fn new(max_capacity: u64, ttl: Duration) -> Self {
        Self {
            ipv4: RecordCache::new(max_capacity, ttl),
            ipv6: RecordCache::new(max_capacity, ttl),
            txt: RecordCache::new(max_capacity, ttl),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct RecordCache<T: Send + Sync + 'static> {
    entries: Cache<Domain, Arc<[T]>, ahash::RandomState>,
}

impl<T> RecordCache<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn new(max_capacity: u64, ttl: Duration) -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(ttl)
                .build_with_hasher(ahash::RandomState::default()),
        }
    }

    pub(super) fn get(&self, domain: &Domain) -> Option<Arc<[T]>>
    where
        Domain: Hash + Eq,
    {
        self.entries.get(domain)
    }

    pub(super) fn insert(&self, domain: Domain, values: Vec<T>)
    where
        Domain: Hash + Eq,
    {
        if values.is_empty() {
            return;
        }

        self.entries.insert(domain, Arc::<[T]>::from(values));
    }
}
