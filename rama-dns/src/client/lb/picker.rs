use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use rama_core::{error::BoxError, extensions::Extension};
use rama_net::address::Domain;
use rand::RngExt as _;

use super::HostResolution;

/// Strategy that selects one [`IpAddr`] from a [`HostResolution`].
///
/// Pickers should mostly be stateless themselves, any per-host state (e.g. a
/// round-robin cursor) should live in the [`HostResolution::state`] extensions
/// bag, which is scoped to the host and preserved across background DNS
/// refreshes.
pub trait DnsIpPicker: Send + Sync + 'static {
    /// Pick one address from `resolution`.
    ///
    /// Should return None if no IP has been picked. In that case the request
    /// will be forwarded to the inner service without any specific IP configured.
    fn pick(&self, host: &Domain, resolution: &HostResolution) -> Result<Option<IpAddr>, BoxError>;
}

impl<T> DnsIpPicker for Box<T>
where
    T: DnsIpPicker,
{
    fn pick(&self, host: &Domain, resolution: &HostResolution) -> Result<Option<IpAddr>, BoxError> {
        (**self).pick(host, resolution)
    }
}

impl<T> DnsIpPicker for Arc<T>
where
    T: DnsIpPicker,
{
    fn pick(&self, host: &Domain, resolution: &HostResolution) -> Result<Option<IpAddr>, BoxError> {
        (**self).pick(host, resolution)
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Round-robin IP picker
pub struct RoundRobinPicker;

impl RoundRobinPicker {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Default, Extension)]
struct RoundRobinCursor(AtomicUsize);

impl DnsIpPicker for RoundRobinPicker {
    fn pick(
        &self,
        _host: &Domain,
        resolution: &HostResolution,
    ) -> Result<Option<IpAddr>, BoxError> {
        let cursor = resolution
            .state
            .get_ref_or_insert(RoundRobinCursor::default);
        let idx = cursor.0.fetch_add(1, Ordering::Relaxed) % resolution.ips.len();

        // It is possible that resolution.ips has changed order because of dns refreshes.
        // We dont consider that a problem for this RoundRobinPicker, but if you need accurate
        // round robin, then you will also have to store a sorted listed of ips and keep track of this.
        Ok(Some(resolution.ips[idx]))
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Random IP picker
pub struct RandomPicker;

impl RandomPicker {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl DnsIpPicker for RandomPicker {
    fn pick(
        &self,
        _host: &Domain,
        resolution: &HostResolution,
    ) -> Result<Option<IpAddr>, BoxError> {
        let idx = rand::rng().random_range(0..resolution.ips.len());
        Ok(Some(resolution.ips[idx]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::Extensions;
    use rama_utils::collections::NonEmptyVec;
    use std::net::Ipv4Addr;
    use tokio::time::Instant;

    fn host() -> Domain {
        Domain::from_static("example.com")
    }

    fn ips() -> Vec<IpAddr> {
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        ]
    }

    fn resolution(ips: Vec<IpAddr>) -> HostResolution {
        HostResolution {
            ips: Arc::new(NonEmptyVec::from_vec(ips).expect("test ips must be non-empty")),
            fetched_at: Instant::now(),
            state: Extensions::new(),
        }
    }

    #[test]
    fn round_robin_cycles() {
        let picker = RoundRobinPicker::new();
        let host = host();
        let ips = ips();
        let res = resolution(ips.clone());
        let picks: Vec<_> = (0..7)
            .map(|_| picker.pick(&host, &res).unwrap().unwrap())
            .collect();
        assert_eq!(picks[0], ips[0]);
        assert_eq!(picks[1], ips[1]);
        assert_eq!(picks[2], ips[2]);
        assert_eq!(picks[3], ips[0]);
        assert_eq!(picks[6], ips[0]);
    }

    #[test]
    fn round_robin_state_is_scoped_per_host() {
        let picker = RoundRobinPicker::new();
        let host_a = Domain::from_static("a.example.com");
        let host_b = Domain::from_static("b.example.com");
        let ips = ips();
        let res_a = resolution(ips.clone());
        let res_b = resolution(ips.clone());
        assert_eq!(picker.pick(&host_a, &res_a).unwrap().unwrap(), ips[0]);
        assert_eq!(picker.pick(&host_b, &res_b).unwrap().unwrap(), ips[0]);
        assert_eq!(picker.pick(&host_a, &res_a).unwrap().unwrap(), ips[1]);
        assert_eq!(picker.pick(&host_b, &res_b).unwrap().unwrap(), ips[1]);
    }

    #[test]
    fn random_in_range() {
        let host = host();
        let ips = ips();
        let res = resolution(ips.clone());
        let picker = RandomPicker::new();
        for _ in 0..50 {
            let pick = picker.pick(&host, &res).unwrap().unwrap();
            assert!(ips.contains(&pick));
        }
    }
}
