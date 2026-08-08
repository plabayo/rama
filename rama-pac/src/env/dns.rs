//! Name resolution for the PAC host functions.
//!
//! PAC's `dnsResolve` and friends are synchronous, but rama resolvers are
//! async — and the script runs on a plain worker thread with no ambient
//! runtime. Each lookup therefore blocks that thread on the runtime handle
//! captured when the environment was built.

use std::net::IpAddr;
use std::time::Duration;

use rama_core::telemetry::tracing;
use rama_dns::client::resolver::{BoxDnsAddressResolver, DnsAddressResolver as _};
use rama_net::address::{Domain, Host};

/// Most addresses one lookup reports. A resolver that answers more is
/// truncated rather than handed to the script wholesale, since the script
/// chooses how often it asks.
const MAX_LOOKUP_ADDRESSES: usize = 64;

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

    /// Every address for `host`, IPv4 first: what the `*Ex` host
    /// functions expose.
    pub(super) fn lookup_all(&self, host: &Host) -> Vec<IpAddr> {
        self.resolve(host, true, true)
    }

    /// The first address per family for `host`, IPv4 first.
    ///
    /// An ip literal short-circuits; failures resolve to an empty list, as
    /// PAC host functions report "unresolvable" rather than throwing.
    pub(super) fn lookup(&self, host: &Host, ipv6: bool) -> Vec<IpAddr> {
        self.resolve(host, ipv6, false)
    }

    fn resolve(&self, host: &Host, ipv6: bool, all: bool) -> Vec<IpAddr> {
        let domain = match host {
            Host::Address(ip) => {
                let keep = ipv6 || ip.is_ipv4();
                return if keep { vec![*ip] } else { Vec::new() };
            }
            Host::Name(domain) => domain.clone(),
            Host::Uninterpreted(host) => {
                let Ok(domain) = Domain::try_from(host.as_str()) else {
                    return Vec::new();
                };
                domain
            }
            _ => return Vec::new(),
        };

        if !super::budget::take_lookup() {
            // "unresolvable" is the pac contract's way of saying no
            tracing::debug!("pac dns lookup budget exhausted for this evaluation");
            return Vec::new();
        }

        let resolver = self.resolver.clone();
        let timeout = self.timeout;
        let lookup = async move {
            use rama_core::futures::StreamExt as _;

            let mut addresses = Vec::new();
            if all {
                let mut stream = std::pin::pin!(
                    resolver
                        .lookup_ipv4(domain.clone())
                        .take(MAX_LOOKUP_ADDRESSES)
                );
                while let Some(Ok(ip)) = stream.next().await {
                    addresses.push(IpAddr::V4(ip));
                }
            } else if let Some(Ok(ip)) = resolver.lookup_ipv4_first(domain.clone()).await {
                addresses.push(IpAddr::V4(ip));
            }

            if ipv6 {
                if all {
                    let budget = MAX_LOOKUP_ADDRESSES.saturating_sub(addresses.len());
                    let mut stream = std::pin::pin!(resolver.lookup_ipv6(domain).take(budget));
                    while let Some(Ok(ip)) = stream.next().await {
                        addresses.push(IpAddr::V6(ip));
                    }
                } else if let Some(Ok(ip)) = resolver.lookup_ipv6_first(domain).await {
                    addresses.push(IpAddr::V6(ip));
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

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

    /// Resolver answering with more addresses than any real one would.
    #[derive(Debug, Clone)]
    struct FloodResolver(u32);

    impl DnsAddressResolver for FloodResolver {
        type Error = BoxError;

        fn lookup_ipv4(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            rama_core::futures::stream::iter((0..self.0).map(|index| Ok(Ipv4Addr::from(index))))
        }

        fn lookup_ipv6(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_ {
            rama_core::futures::stream::iter(
                (0..self.0).map(|index| Ok(std::net::Ipv6Addr::from(u128::from(index)))),
            )
        }
    }

    fn host(raw: &str) -> Host {
        Host::try_from(raw).unwrap_or_else(|err| panic!("`{raw}` must parse: {err}"))
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
        let addresses = std::thread::spawn(move || bridge.lookup(&host("example.com"), false))
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
        let addresses = std::thread::spawn(move || bridge.lookup(&host("example.com"), true))
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
        let addresses = std::thread::spawn(move || bridge.lookup(&host("example.com"), true))
            .join()
            .unwrap();
        assert!(addresses.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_all_is_capped() {
        let bridge = PacDnsBridge::new(
            tokio::runtime::Handle::current(),
            FloodResolver(10_000).into_box_dns_address_resolver(),
            Duration::from_secs(5),
        );
        let addresses = std::thread::spawn(move || bridge.lookup_all(&host("example.com")))
            .join()
            .unwrap();
        assert_eq!(addresses.len(), MAX_LOOKUP_ADDRESSES);
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
            std::thread::spawn(move || v4.lookup(&host("10.0.0.7"), false))
                .join()
                .unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))],
        );
        assert_eq!(
            std::thread::spawn(move || v6.lookup(&host("::1"), true))
                .join()
                .unwrap(),
            vec![IpAddr::V6("::1".parse().unwrap())],
        );
        // classic (v4-only) callers never see an ipv6 literal
        assert!(
            std::thread::spawn(move || v6_v4_only.lookup(&host("::1"), false))
                .join()
                .unwrap()
                .is_empty()
        );
    }
}
