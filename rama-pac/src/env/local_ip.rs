//! What `myIpAddress()` and `myIpAddressEx()` report.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rama_core::telemetry::tracing;
use rama_net::address::ip::IpScopes;

/// Where to ask the OS which source address it would route from; nothing is
/// sent, so any routable address answers the question.
const ROUTE_PROBES: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
    SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
        )),
        53,
    ),
];

/// Scopes a PAC script is shown by default: every address a proxy
/// decision can sensibly be based on, which is what browsers report.
/// Loopback and link-local are excluded, as they route nowhere useful.
pub const DEFAULT_LOCAL_IP_SCOPES: IpScopes = IpScopes::GLOBAL
    .union(IpScopes::PRIVATE)
    .union(IpScopes::SHARED);

/// Which local addresses `myIpAddress()` and `myIpAddressEx()` disclose.
///
/// A PAC script sees these, so a permissive setting hands the host's
/// network topology to script code. The default matches what browsers
/// do; tighten it when the script is less trusted than the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacLocalAddresses {
    /// Every address of every interface that is up, filtered to the given
    /// scopes: `myIpAddressEx()` lists them all, `myIpAddress()` reports
    /// the first IPv4. Browser behaviour, and the default with
    /// [`DEFAULT_LOCAL_IP_SCOPES`].
    Interfaces(IpScopes),
    /// Only the source address the OS would route from, asked once per
    /// call. Discloses a single address instead of the whole topology.
    Route,
    /// A fixed set of addresses, in preference order.
    Fixed(Vec<IpAddr>),
    /// Disclose nothing: always `127.0.0.1`, the address the PAC spec
    /// prescribes when none can be determined.
    Loopback,
}

impl Default for PacLocalAddresses {
    fn default() -> Self {
        Self::Interfaces(DEFAULT_LOCAL_IP_SCOPES)
    }
}

impl PacLocalAddresses {
    /// The addresses to report, most preferred first.
    ///
    /// Never empty: a failure to determine any address yields
    /// `127.0.0.1`, as the PAC spec requires.
    pub(super) fn resolve(&self, budget: &super::budget::PacBudgetState) -> Vec<IpAddr> {
        // enumerating interfaces is a syscall, so one evaluation pays for it
        // at most once however often the script asks
        budget.local_addresses(|| self.resolve_uncached())
    }

    fn resolve_uncached(&self) -> Vec<IpAddr> {
        let addresses = match self {
            Self::Interfaces(scopes) => match rama_net::socket::local_addresses(*scopes) {
                Ok(addresses) => addresses,
                Err(err) => {
                    tracing::debug!("could not enumerate local addresses for pac: {err}");
                    Vec::new()
                }
            },
            Self::Route => ROUTE_PROBES
                .into_iter()
                .find_map(rama_net::socket::route_source_address)
                .into_iter()
                .collect(),
            Self::Fixed(addresses) => addresses.clone(),
            Self::Loopback => Vec::new(),
        };

        if addresses.is_empty() {
            return vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        }
        addresses
    }

    /// The single address `myIpAddress()` reports: the first IPv4, since
    /// classic PAC callers expect a dotted quad.
    pub(super) fn resolve_ipv4(&self, budget: &super::budget::PacBudgetState) -> IpAddr {
        let addresses = self.resolve(budget);
        addresses
            .iter()
            .find(|address| address.is_ipv4())
            .copied()
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::env::budget::PacBudgetState;

    /// An unarmed state: these tests are about what is reported, not caching.
    fn budget() -> PacBudgetState {
        PacBudgetState::default()
    }

    use rama_net::address::ip::ip_scope;

    #[test]
    fn interfaces_default_excludes_loopback_and_link_local() {
        assert!(!DEFAULT_LOCAL_IP_SCOPES.contains(IpScopes::LOOPBACK));
        assert!(!DEFAULT_LOCAL_IP_SCOPES.contains(IpScopes::LINK_LOCAL));
        assert!(DEFAULT_LOCAL_IP_SCOPES.contains(IpScopes::GLOBAL));
        assert!(DEFAULT_LOCAL_IP_SCOPES.contains(IpScopes::PRIVATE));
        assert_eq!(
            PacLocalAddresses::default(),
            PacLocalAddresses::Interfaces(DEFAULT_LOCAL_IP_SCOPES),
        );
    }

    #[test]
    fn every_mode_yields_at_least_one_address() {
        for mode in [
            PacLocalAddresses::default(),
            PacLocalAddresses::Route,
            PacLocalAddresses::Loopback,
            PacLocalAddresses::Fixed(Vec::new()),
        ] {
            let addresses = mode.resolve(&budget());
            assert!(!addresses.is_empty(), "{mode:?}");
            assert!(
                addresses.iter().all(|address| !address.is_unspecified()),
                "{mode:?} -> {addresses:?}",
            );
            // and the classic accessor is always an ipv4 dotted quad
            assert!(mode.resolve_ipv4(&budget()).is_ipv4(), "{mode:?}");
        }
    }

    #[test]
    fn loopback_discloses_nothing() {
        assert_eq!(
            PacLocalAddresses::Loopback.resolve(&budget()),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );
    }

    #[test]
    fn fixed_addresses_are_reported_in_order() {
        let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let second = IpAddr::V6("2001:db8::1".parse().unwrap());
        let mode = PacLocalAddresses::Fixed(vec![second, first]);

        assert_eq!(mode.resolve(&budget()), vec![second, first]);
        // myIpAddress() skips the ipv6 entry
        assert_eq!(mode.resolve_ipv4(&budget()), first);
    }

    #[test]
    fn interface_addresses_are_within_the_configured_scopes() {
        let scopes = IpScopes::LOOPBACK;
        let addresses = PacLocalAddresses::Interfaces(scopes).resolve(&budget());
        // loopback is always present, so this never falls back
        assert!(
            addresses
                .iter()
                .all(|address| scopes.intersects(ip_scope(*address))),
            "{addresses:?}",
        );
    }
}
