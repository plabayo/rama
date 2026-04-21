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

#[derive(Debug)]
struct AppHostReservation {
    key: AppHostKeyHash,
    reservation_ctr: Arc<AtomicUsize>,
    active_ctr: Arc<AtomicUsize>,
    reservation_counters: Cache<AppHostKeyHash, Arc<AtomicUsize>>,
    active_counters: Cache<AppHostKeyHash, Arc<AtomicUsize>>,
}

impl AppHostReservation {
    fn activate(&self) {
        self.active_ctr.fetch_add(1, Ordering::AcqRel);
    }

    fn drop_active(&self) {
        let prev = self.active_ctr.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "app-host active counter underflow");
        if prev == 1 {
            invalidate_if_zero(&self.active_counters, self.key, &self.active_ctr);
        }
    }
}

impl Drop for AppHostReservation {
    fn drop(&mut self) {
        let prev = self.reservation_ctr.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "app-host reservation counter underflow");
        if prev == 1 {
            invalidate_if_zero(&self.reservation_counters, self.key, &self.reservation_ctr);
        }
    }
}

#[derive(Debug)]
struct ConcurrencyReservationInner {
    reservation_global: Arc<AtomicUsize>,
    active_global: Arc<AtomicUsize>,
    reservation_non_web: Option<Arc<AtomicUsize>>,
    active_non_web: Option<Arc<AtomicUsize>>,
    app_host: Option<AppHostReservation>,
}

impl Drop for ConcurrencyReservationInner {
    fn drop(&mut self) {
        self.reservation_global.fetch_sub(1, Ordering::AcqRel);
        if let Some(counter) = &self.reservation_non_web {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConcurrencyReservation {
    inner: Arc<ConcurrencyReservationInner>,
}

impl ConcurrencyReservation {
    #[must_use]
    pub fn activate(&self) -> ConcurrencyPermit {
        self.inner.active_global.fetch_add(1, Ordering::AcqRel);
        if let Some(counter) = &self.inner.active_non_web {
            counter.fetch_add(1, Ordering::AcqRel);
        }
        if let Some(app_host) = &self.inner.app_host {
            app_host.activate();
        }

        ConcurrencyPermit {
            reservation: self.clone(),
        }
    }
}

#[derive(Debug, Extension)]
pub struct ConcurrencyPermit {
    reservation: ConcurrencyReservation,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        self.reservation
            .inner
            .active_global
            .fetch_sub(1, Ordering::AcqRel);
        if let Some(counter) = &self.reservation.inner.active_non_web {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
        if let Some(app_host) = &self.reservation.inner.app_host {
            app_host.drop_active();
        }
    }
}

#[derive(Debug)]
pub struct ConcurrencyLimiter {
    reserved_global: Arc<AtomicUsize>,
    active_global: Arc<AtomicUsize>,
    reserved_non_web: Arc<AtomicUsize>,
    active_non_web: Arc<AtomicUsize>,
    reserved_app_host_counters: Cache<AppHostKeyHash, Arc<AtomicUsize>>,
    active_app_host_counters: Cache<AppHostKeyHash, Arc<AtomicUsize>>,
    app_host_hasher: RandomState,
    policy: ConcurrencyPolicy,
}

impl ConcurrencyLimiter {
    #[must_use]
    pub fn new(policy: ConcurrencyPolicy) -> Self {
        Self {
            reserved_global: Arc::new(AtomicUsize::new(0)),
            active_global: Arc::new(AtomicUsize::new(0)),
            reserved_non_web: Arc::new(AtomicUsize::new(0)),
            active_non_web: Arc::new(AtomicUsize::new(0)),
            reserved_app_host_counters: Cache::builder()
                .max_capacity(policy.app_host_cache_max_capacity)
                .build(),
            active_app_host_counters: Cache::builder()
                .max_capacity(policy.app_host_cache_max_capacity)
                .build(),
            app_host_hasher: RandomState::default(),
            policy,
        }
    }

    pub fn try_reserve(
        &self,
        port: u16,
        bundle_identifier: Option<&str>,
        host: Option<&Host>,
    ) -> Result<ConcurrencyReservation, RejectReason> {
        let reservation_global =
            try_increment_counter(&self.reserved_global, self.policy.global_limit)
                .ok_or(RejectReason::Global)?;

        let reservation_non_web = if is_web_port(port) {
            None
        } else {
            if let Some(counter) =
                try_increment_counter(&self.reserved_non_web, self.policy.non_web_limit())
            {
                Some(counter)
            } else {
                reservation_global.fetch_sub(1, Ordering::AcqRel);
                return Err(RejectReason::NonWeb);
            }
        };

        let app_host = match (bundle_identifier, host) {
            (Some(bundle_identifier), Some(host)) => {
                if let Some(reservation) = self.try_reserve_app_host(bundle_identifier, host) {
                    Some(reservation)
                } else {
                    reservation_global.fetch_sub(1, Ordering::AcqRel);
                    if let Some(counter) = &reservation_non_web {
                        counter.fetch_sub(1, Ordering::AcqRel);
                    }
                    return Err(RejectReason::AppHost);
                }
            }
            _ => None,
        };

        Ok(ConcurrencyReservation {
            inner: Arc::new(ConcurrencyReservationInner {
                reservation_global,
                active_global: self.active_global.clone(),
                reservation_non_web,
                active_non_web: (!is_web_port(port)).then(|| self.active_non_web.clone()),
                app_host,
            }),
        })
    }

    fn try_reserve_app_host(
        &self,
        bundle_identifier: &str,
        host: &Host,
    ) -> Option<AppHostReservation> {
        let key = AppHostKeyHash(self.hash_app_host(bundle_identifier, host));
        let reservation_ctr = self
            .reserved_app_host_counters
            .get_with(key, || Arc::new(AtomicUsize::new(0)));

        try_increment_counter(&reservation_ctr, self.policy.per_app_host_limit).map(
            |reservation_ctr| AppHostReservation {
                key,
                reservation_ctr,
                active_ctr: self
                    .active_app_host_counters
                    .get_with(key, || Arc::new(AtomicUsize::new(0))),
                reservation_counters: self.reserved_app_host_counters.clone(),
                active_counters: self.active_app_host_counters.clone(),
            },
        )
    }

    fn hash_app_host(&self, bundle_identifier: &str, host: &Host) -> u64 {
        let mut hasher = self.app_host_hasher.build_hasher();
        bundle_identifier.hash(&mut hasher);
        0xff_u8.hash(&mut hasher);
        host.hash(&mut hasher);
        hasher.finish()
    }
}

fn try_increment_counter(counter: &Arc<AtomicUsize>, limit: usize) -> Option<Arc<AtomicUsize>> {
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

fn invalidate_if_zero(
    counters: &Cache<AppHostKeyHash, Arc<AtomicUsize>>,
    key: AppHostKeyHash,
    ctr: &Arc<AtomicUsize>,
) {
    if let Some(current) = counters.get(&key)
        && Arc::ptr_eq(&current, ctr)
        && current.load(Ordering::Acquire) == 0
    {
        counters.invalidate(&key);
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
            .try_reserve(22, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected non-web reject: {err:?}"));
        let _non_web_2 = limiter
            .try_reserve(25, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected non-web reject: {err:?}"));

        assert!(matches!(
            limiter.try_reserve(53, Some("com.example.app"), Some(&host)),
            Err(RejectReason::NonWeb)
        ));

        let _web_1 = limiter
            .try_reserve(443, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected web reject: {err:?}"));
        let _web_2 = limiter
            .try_reserve(80, Some("com.example.app"), Some(&host))
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
            .try_reserve(443, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected app-host reject: {err:?}"));
        let _permit_2 = limiter
            .try_reserve(443, Some("com.example.app"), Some(&host))
            .unwrap_or_else(|err| panic!("unexpected app-host reject: {err:?}"));

        assert!(matches!(
            limiter.try_reserve(443, Some("com.example.app"), Some(&host)),
            Err(RejectReason::AppHost)
        ));

        let _other_app = limiter
            .try_reserve(443, Some("com.example.other"), Some(&host))
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
            .try_reserve(443, None, None)
            .unwrap_or_else(|err| panic!("unexpected reject without scoped key: {err:?}"));
        let _permit_2 = limiter
            .try_reserve(443, None, None)
            .unwrap_or_else(|err| panic!("unexpected reject without scoped key: {err:?}"));
        let _permit_3 = limiter
            .try_reserve(443, None, None)
            .unwrap_or_else(|err| panic!("unexpected reject without scoped key: {err:?}"));

        assert!(matches!(
            limiter.try_reserve(443, None, None),
            Err(RejectReason::Global)
        ));
    }
}
