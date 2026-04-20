use std::hash::{BuildHasher as _, Hash as _, Hasher as _};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use ahash::RandomState;
use moka::sync::Cache;
use rama::{extensions::Extension, net::address::Host};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AppHostKeyHash(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Global,
    NonWeb,
    AppHost,
}

#[derive(Debug, Clone)]
pub struct ConcurrencyPolicy {
    pub global_limit: usize,
    pub web_reserved_limit: usize,
    pub per_app_host_limit: usize,
    pub app_host_cache_max_capacity: u64,
}

impl ConcurrencyPolicy {
    #[must_use]
    pub fn non_web_limit(&self) -> usize {
        self.global_limit.saturating_sub(self.web_reserved_limit)
    }
}

impl Default for ConcurrencyPolicy {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(8);
        let global_limit = (cpus * 128).max(2048);
        let web_reserved_limit = global_limit * 75 / 100;
        let per_app_host_limit = (global_limit / 32).clamp(16, 64);
        let app_host_cache_max_capacity = (global_limit.saturating_mul(8)).max(8192) as u64;

        Self {
            global_limit,
            web_reserved_limit,
            per_app_host_limit,
            app_host_cache_max_capacity,
        }
    }
}

#[derive(Debug, Extension)]
pub struct ConcurrencyPermit {
    global: Arc<AtomicUsize>,
    non_web: Option<Arc<AtomicUsize>>,
    app_host: Option<AppHostPermit>,
}

#[derive(Debug)]
struct AppHostPermit {
    key: AppHostKeyHash,
    ctr: Arc<AtomicUsize>,
    counters: Cache<AppHostKeyHash, Arc<AtomicUsize>>,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        self.global.fetch_sub(1, Ordering::AcqRel);

        if let Some(non_web) = &self.non_web {
            non_web.fetch_sub(1, Ordering::AcqRel);
        }

        if let Some(app_host) = self.app_host.take() {
            let prev = app_host.ctr.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(prev > 0, "app-host counter underflow");

            if prev == 1 {
                if let Some(current) = app_host.counters.get(&app_host.key) {
                    if Arc::ptr_eq(&current, &app_host.ctr) && current.load(Ordering::Acquire) == 0
                    {
                        app_host.counters.invalidate(&app_host.key);
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct ConcurrencyLimiter {
    global: Arc<AtomicUsize>,
    non_web: Arc<AtomicUsize>,
    app_host_counters: Cache<AppHostKeyHash, Arc<AtomicUsize>>,
    app_host_hasher: RandomState,
    policy: ConcurrencyPolicy,
}

impl ConcurrencyLimiter {
    #[must_use]
    pub fn new(policy: ConcurrencyPolicy) -> Self {
        Self {
            global: Arc::new(AtomicUsize::new(0)),
            non_web: Arc::new(AtomicUsize::new(0)),
            app_host_counters: Cache::builder()
                .max_capacity(policy.app_host_cache_max_capacity)
                .build(),
            app_host_hasher: RandomState::default(),
            policy,
        }
    }

    pub fn try_acquire(
        &self,
        port: u16,
        bundle_identifier: Option<&str>,
        host: Option<&Host>,
    ) -> Result<ConcurrencyPermit, RejectReason> {
        let global = self
            .try_acquire_counter(&self.global, self.policy.global_limit)
            .ok_or(RejectReason::Global)?;

        let non_web = if is_web_port(port) {
            None
        } else {
            match self.try_acquire_counter(&self.non_web, self.policy.non_web_limit()) {
                Some(counter) => Some(counter),
                None => {
                    global.fetch_sub(1, Ordering::AcqRel);
                    return Err(RejectReason::NonWeb);
                }
            }
        };

        let app_host = match (bundle_identifier, host) {
            (Some(bundle_identifier), Some(host)) => {
                match self.try_acquire_app_host(bundle_identifier, host) {
                    Some(permit) => Some(permit),
                    None => {
                        global.fetch_sub(1, Ordering::AcqRel);
                        if let Some(non_web) = &non_web {
                            non_web.fetch_sub(1, Ordering::AcqRel);
                        }
                        return Err(RejectReason::AppHost);
                    }
                }
            }
            _ => None,
        };

        Ok(ConcurrencyPermit {
            global,
            non_web,
            app_host,
        })
    }

    fn try_acquire_counter(
        &self,
        counter: &Arc<AtomicUsize>,
        limit: usize,
    ) -> Option<Arc<AtomicUsize>> {
        let mut current = counter.load(Ordering::Acquire);

        loop {
            if current >= limit {
                return None;
            }

            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(counter.clone()),
                Err(observed) => current = observed,
            }
        }
    }

    fn try_acquire_app_host(&self, bundle_identifier: &str, host: &Host) -> Option<AppHostPermit> {
        let key = AppHostKeyHash(self.hash_app_host(bundle_identifier, host));
        let counter = self
            .app_host_counters
            .get_with(key, || Arc::new(AtomicUsize::new(0)));

        self.try_acquire_counter(&counter, self.policy.per_app_host_limit)
            .map(|ctr| AppHostPermit {
                key,
                ctr,
                counters: self.app_host_counters.clone(),
            })
    }

    fn hash_app_host(&self, bundle_identifier: &str, host: &Host) -> u64 {
        let mut hasher = self.app_host_hasher.build_hasher();
        bundle_identifier.hash(&mut hasher);
        0xff_u8.hash(&mut hasher);
        host.hash(&mut hasher);
        hasher.finish()
    }
}

#[inline]
const fn is_web_port(port: u16) -> bool {
    matches!(port, 80 | 443)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_traffic_uses_reserved_headroom() {
        let limiter = ConcurrencyLimiter::new(ConcurrencyPolicy {
            global_limit: 4,
            web_reserved_limit: 2,
            per_app_host_limit: 4,
            app_host_cache_max_capacity: 128,
        });
        let host = Host::EXAMPLE_NAME;

        let _non_web_1 = limiter
            .try_acquire(22, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected non-web reject: {err:?}"));
        let _non_web_2 = limiter
            .try_acquire(25, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected non-web reject: {err:?}"));

        assert!(matches!(
            limiter.try_acquire(53, Some("com.example.app"), Some(&host)),
            Err(RejectReason::NonWeb)
        ));

        let _web_1 = limiter
            .try_acquire(443, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected web reject: {err:?}"));
        let _web_2 = limiter
            .try_acquire(80, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected web reject: {err:?}"));
    }

    #[test]
    fn app_host_limit_is_layered() {
        let limiter = ConcurrencyLimiter::new(ConcurrencyPolicy {
            global_limit: 8,
            web_reserved_limit: 2,
            per_app_host_limit: 2,
            app_host_cache_max_capacity: 128,
        });
        let host = Host::EXAMPLE_NAME;

        let _permit_1 = limiter
            .try_acquire(443, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected app-host reject: {err:?}"));
        let _permit_2 = limiter
            .try_acquire(443, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected app-host reject: {err:?}"));

        assert!(matches!(
            limiter.try_acquire(443, Some("com.example.app"), Some(&host)),
            Err(RejectReason::AppHost)
        ));

        let _other_app = limiter
            .try_acquire(443, Some("com.example.other"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected other-app reject: {err:?}"));
    }

    #[test]
    fn app_host_limit_is_skipped_without_domain_or_bundle_id() {
        let limiter = ConcurrencyLimiter::new(ConcurrencyPolicy {
            global_limit: 3,
            web_reserved_limit: 1,
            per_app_host_limit: 1,
            app_host_cache_max_capacity: 128,
        });

        let _permit_1 = limiter
            .try_acquire(443, None, None)
            .unwrap_or_else(|err| panic!("unexpected reject without scoped key: {err:?}"));
        let _permit_2 = limiter
            .try_acquire(443, None, None)
            .unwrap_or_else(|err| panic!("unexpected reject without scoped key: {err:?}"));
        let _permit_3 = limiter
            .try_acquire(443, None, None)
            .unwrap_or_else(|err| panic!("unexpected reject without scoped key: {err:?}"));

        assert!(matches!(
            limiter.try_acquire(443, None, None),
            Err(RejectReason::Global)
        ));
    }
}
