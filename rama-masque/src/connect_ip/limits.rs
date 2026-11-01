use super::{ConnectIpBudget, ConnectIpError, IpBudgetConfig};
use crate::connect_udp::{PrincipalKey, UserOrClientIpKey};
use ahash::HashMap;
use parking_lot::Mutex;
use rama_http::Request;
use rama_net::rate::InputToRateKey as _;
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;

/// Admission and principal accounting bounds, held for the whole tunnel lifetime.
#[derive(Debug, Clone, Copy)]
pub struct IpAdmissionLimits {
    /// Concurrent tunnels across all principals.
    pub max_tunnels: usize,
    /// Concurrent tunnels for one authenticated user, client-IP key or anonymous group.
    pub max_tunnels_per_principal: usize,
    /// Bound on retained principal accounting records.
    pub max_principals: usize,
    /// Minimum idle retention, extended as needed for rate refill. Lifetime quotas
    /// keep their record for the service lifetime and are never reset by eviction.
    pub principal_retention: Duration,
    /// Rates shared by every tunnel of one principal.
    pub budget: IpBudgetConfig,
}
impl Default for IpAdmissionLimits {
    fn default() -> Self {
        Self {
            max_tunnels: 128,
            max_tunnels_per_principal: 8,
            max_principals: 4096,
            principal_retention: Duration::from_secs(60),
            budget: IpBudgetConfig::default(),
        }
    }
}
#[derive(Debug)]
struct Principal {
    live: usize,
    idle_since: Instant,
    budget: ConnectIpBudget,
}
#[derive(Debug, Default)]
struct Counts {
    live: usize,
    principals: HashMap<PrincipalKey, Principal>,
}
/// Shared tunnel admission state. Clones count against the same bounds.
#[derive(Debug, Clone)]
pub struct ConnectIpLimits {
    config: IpAdmissionLimits,
    retention: Duration,
    counts: Arc<Mutex<Counts>>,
}
impl Default for ConnectIpLimits {
    fn default() -> Self {
        Self::from_validated(IpAdmissionLimits::default())
    }
}
impl ConnectIpLimits {
    /// Construct limits, refusing zero capacities or budget bursts.
    pub fn try_new(config: IpAdmissionLimits) -> Result<Self, ConnectIpError> {
        if config.max_tunnels == 0
            || config.max_tunnels_per_principal == 0
            || config.max_principals == 0
        {
            return Err(ConnectIpError::Config);
        }
        ConnectIpBudget::new(config.budget)?;
        Ok(Self::from_validated(config))
    }
    fn from_validated(config: IpAdmissionLimits) -> Self {
        let refill = |rate: rama_utils::rate::Rate, burst: u64| {
            let nanos = (rate.per().as_nanos().saturating_mul(u128::from(burst)))
                .div_ceil(u128::from(rate.units()));
            Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
        };
        let retention = config
            .principal_retention
            .max(refill(config.budget.packets, config.budget.packet_burst))
            .max(refill(config.budget.bytes, config.budget.byte_burst));
        Self {
            config,
            retention,
            counts: Arc::default(),
        }
    }
    /// Number of admitted, not-yet-ended tunnels (includes pending upgrades).
    #[must_use]
    pub fn live_tunnels(&self) -> usize {
        self.counts.lock().live
    }
    pub(super) fn admit(&self, request: &Request) -> Result<IpTunnelLease, ConnectIpError> {
        let key = UserOrClientIpKey::new()
            .rate_key(request)
            .map_err(|_error| ConnectIpError::Config)?
            .ok_or(ConnectIpError::Config)?;
        let mut counts = self.counts.lock();
        let now = Instant::now();
        if counts.live >= self.config.max_tunnels {
            return Err(ConnectIpError::Admission);
        }
        if !counts.principals.contains_key(&key) {
            if counts.principals.len() >= self.config.max_principals
                && self.config.budget.byte_quota.is_none()
            {
                counts.principals.retain(|_, p| {
                    p.live != 0 || now.duration_since(p.idle_since) < self.retention
                });
            }
            if counts.principals.len() >= self.config.max_principals {
                return Err(ConnectIpError::Admission);
            }
            counts.principals.insert(
                key.clone(),
                Principal {
                    live: 0,
                    idle_since: now,
                    budget: ConnectIpBudget::new(self.config.budget)?,
                },
            );
        }
        let p = counts
            .principals
            .get_mut(&key)
            .ok_or(ConnectIpError::Config)?;
        if p.live >= self.config.max_tunnels_per_principal {
            return Err(ConnectIpError::Admission);
        }
        p.live += 1;
        let budget = p.budget.clone();
        counts.live += 1;
        Ok(IpTunnelLease {
            limits: self.clone(),
            key,
            budget,
        })
    }
}
#[derive(Debug)]
pub(super) struct IpTunnelLease {
    limits: ConnectIpLimits,
    key: PrincipalKey,
    pub budget: ConnectIpBudget,
}
impl Drop for IpTunnelLease {
    fn drop(&mut self) {
        let mut counts = self.limits.counts.lock();
        counts.live -= 1;
        if let Some(p) = counts.principals.get_mut(&self.key) {
            p.live -= 1;
            p.idle_since = Instant::now();
        }
    }
}
