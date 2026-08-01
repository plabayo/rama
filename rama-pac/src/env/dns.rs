//! Name resolution for the PAC host functions.
//!
//! PAC's `dnsResolve` and friends are synchronous, but rama resolvers are
//! async — and the script runs on a plain worker thread with no ambient
//! runtime. Each lookup therefore blocks that thread on the runtime handle
//! captured when the environment was built.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

use rama_core::telemetry::tracing;
use rama_dns::client::resolver::{BoxDnsAddressResolver, DnsAddressResolver as _};
use rama_net::address::{Domain, Host};

/// Resolves names for the PAC environment, bridging to async rama DNS.
#[derive(Debug, Clone)]
pub(super) struct PacDnsBridge {
    runtime: tokio::runtime::Handle,
    resolver: BoxDnsAddressResolver,
    timeout: Duration,
}

impl PacDnsBridge {
    pub(super) fn new(
        runtime: tokio::runtime::Handle,
        resolver: BoxDnsAddressResolver,
        timeout: Duration,
    ) -> Self {
        Self {
            runtime,
            resolver,
            timeout,
        }
    }

    /// All addresses for `host`, IPv4 first (what classic PAC exposes).
    ///
    /// An ip literal short-circuits; failures resolve to an empty list, as
    /// PAC host functions report "unresolvable" rather than throwing.
    pub(super) fn lookup(&self, host: &str, ipv6: bool) -> Vec<IpAddr> {
        let Ok(host) = Host::try_from(host) else {
            return Vec::new();
        };
        let domain = match host {
            Host::Address(ip) => {
                let keep = ipv6 || ip.is_ipv4();
                return if keep { vec![ip] } else { Vec::new() };
            }
            Host::Name(domain) => domain,
            Host::Uninterpreted(host) => {
                let Ok(domain) = Domain::try_from(host.as_str()) else {
                    return Vec::new();
                };
                domain
            }
            _ => return Vec::new(),
        };

        let resolver = self.resolver.clone();
        let timeout = self.timeout;
        let lookup = async move {
            let mut addresses = Vec::new();
            if let Some(Ok(ip)) = resolver.lookup_ipv4_first(domain.clone()).await {
                addresses.push(IpAddr::V4(ip));
            }
            if ipv6 && let Some(Ok(ip)) = resolver.lookup_ipv6_first(domain).await {
                addresses.push(IpAddr::V6(ip));
            }
            addresses
        };

        // a panic here would kill the worker and every job after it
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.runtime
                .block_on(async move { tokio::time::timeout(timeout, lookup).await })
        }));

        match result {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(_elapsed)) => {
                tracing::debug!("pac dns lookup timed out");
                Vec::new()
            }
            Err(_panic) => {
                tracing::error!("pac dns lookup panicked");
                Vec::new()
            }
        }
    }
}

/// The local address PAC's `myIpAddress()` reports.
///
/// Asks the OS which source address it would use to reach a public
/// address; no packet is sent, since connecting a UDP socket only sets
/// the peer. Falls back to `127.0.0.1`, which is what the PAC spec
/// prescribes when no address can be determined.
pub(super) fn detect_my_ip() -> IpAddr {
    // any routable address works: only the routing decision is used
    const PROBES: [&str; 2] = ["1.1.1.1:53", "[2606:4700:4700::1111]:53"];

    for probe in PROBES {
        let bind = if probe.starts_with('[') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        if let Ok(socket) = UdpSocket::bind(bind)
            && socket.connect(probe).is_ok()
            && let Ok(address) = socket.local_addr()
            && !address.ip().is_unspecified()
        {
            return address.ip();
        }
    }

    tracing::debug!("could not determine local ip for pac myIpAddress");
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rama_core::error::BoxError;
    use rama_core::futures::Stream;
    use rama_dns::client::resolver::DnsAddressResolver;

    /// Resolver with a fixed answer, so tests never touch the network.
    #[derive(Debug, Clone)]
    struct StaticResolver {
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    }

    impl DnsAddressResolver for StaticResolver {
        type Error = BoxError;

        fn lookup_ipv4(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            rama_core::futures::stream::iter(self.ipv4.map(Ok))
        }

        fn lookup_ipv6(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_ {
            rama_core::futures::stream::iter(self.ipv6.map(Ok))
        }
    }

    fn bridge(resolver: StaticResolver) -> PacDnsBridge {
        PacDnsBridge::new(
            tokio::runtime::Handle::current(),
            resolver.into_box_dns_address_resolver(),
            Duration::from_secs(5),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_resolves_from_worker_thread() {
        let bridge = bridge(StaticResolver {
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: Some("::1".parse().unwrap()),
        });

        // mirrors the real caller: a plain thread with no ambient runtime
        let addresses = std::thread::spawn(move || bridge.lookup("example.com", false))
            .join()
            .unwrap();
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_ex_includes_ipv6() {
        let bridge = bridge(StaticResolver {
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: Some("::1".parse().unwrap()),
        });
        let addresses = std::thread::spawn(move || bridge.lookup("example.com", true))
            .join()
            .unwrap();
        assert_eq!(addresses.len(), 2);
        assert!(addresses.contains(&IpAddr::V6("::1".parse().unwrap())));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unresolvable_host_yields_empty() {
        let bridge = bridge(StaticResolver {
            ipv4: None,
            ipv6: None,
        });
        let addresses = std::thread::spawn(move || bridge.lookup("example.com", true))
            .join()
            .unwrap();
        assert!(addresses.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ip_literals_short_circuit() {
        let bridge = bridge(StaticResolver {
            ipv4: None,
            ipv6: None,
        });
        let v4 = bridge.clone();
        let v6 = bridge.clone();
        let v6_v4_only = bridge;
        assert_eq!(
            std::thread::spawn(move || v4.lookup("10.0.0.7", false))
                .join()
                .unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))],
        );
        assert_eq!(
            std::thread::spawn(move || v6.lookup("::1", true))
                .join()
                .unwrap(),
            vec![IpAddr::V6("::1".parse().unwrap())],
        );
        // classic (v4-only) callers never see an ipv6 literal
        assert!(
            std::thread::spawn(move || v6_v4_only.lookup("::1", false))
                .join()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn my_ip_is_never_unspecified() {
        let ip = detect_my_ip();
        assert!(!ip.is_unspecified(), "{ip}");
    }
}
