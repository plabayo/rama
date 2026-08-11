//! Name resolution for the PAC host functions.
//!
//! PAC's `dnsResolve` and friends are synchronous, but rama resolvers are
//! async — and the script runs on a plain worker thread with no ambient
//! runtime. Each lookup therefore blocks that thread on the runtime handle
//! captured when the environment was built.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rama_core::telemetry::tracing;
use rama_dns::client::resolver::{BoxDnsAddressResolver, DnsAddressResolver as _};
use rama_net::address::{Domain, Host};

use super::budget::{LookupKind, PacBudgetState};
use std::sync::Arc;

/// Most addresses one lookup reports. A resolver that answers more is
/// truncated rather than handed to the script wholesale, since the script
/// chooses how often it asks.
const MAX_LOOKUP_ADDRESSES: usize = 64;

/// The evaluation spent its whole dns budget.
#[derive(Debug)]
pub(super) struct LookupBudgetExhausted;

impl std::fmt::Display for LookupBudgetExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("this evaluation exhausted its dns lookup budget")
    }
}

impl std::error::Error for LookupBudgetExhausted {}

/// Resolves names for the PAC environment, bridging to async rama DNS.
#[derive(Debug, Clone)]
pub(super) struct PacDnsBridge {
    runtime: tokio::runtime::Handle,
    resolver: BoxDnsAddressResolver,
    timeout: Duration,
    budget: Arc<PacBudgetState>,
}

impl PacDnsBridge {
    pub(super) fn new(
        runtime: tokio::runtime::Handle,
        resolver: BoxDnsAddressResolver,
        timeout: Duration,
        budget: Arc<PacBudgetState>,
    ) -> Self {
        Self {
            runtime,
            resolver,
            timeout,
            budget,
        }
    }

    /// Every address for `host`, IPv4 first: what the `*Ex` host
    /// functions expose.
    pub(super) fn lookup_all(&self, host: &Host) -> Result<Vec<IpAddr>, LookupBudgetExhausted> {
        self.resolve(host, LookupKind::Extended)
    }

    /// The first IPv4 address for `host`, without issuing an IPv6 lookup.
    ///
    /// An ip literal short-circuits; a failed lookup is no address, since
    /// PAC host functions report "unresolvable" rather than throwing. Running
    /// out of budget is not a failed lookup, though: answering "unresolvable"
    /// there would let a script turn a rule off by spending the budget first.
    pub(super) fn lookup_ipv4(
        &self,
        host: &Host,
    ) -> Result<Option<Ipv4Addr>, LookupBudgetExhausted> {
        self.resolve(host, LookupKind::Classic).map(|addresses| {
            addresses.into_iter().find_map(|address| match address {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            })
        })
    }

    fn resolve(&self, host: &Host, kind: LookupKind) -> Result<Vec<IpAddr>, LookupBudgetExhausted> {
        let domain = match host {
            Host::Address(ip) => {
                let keep = kind == LookupKind::Extended || ip.is_ipv4();
                return Ok(if keep { vec![*ip] } else { Vec::new() });
            }
            Host::Name(domain) => domain.clone(),
            Host::Uninterpreted(host) => {
                let Ok(domain) = Domain::try_from(host.as_str()) else {
                    return Ok(Vec::new());
                };
                domain
            }
            _ => return Ok(Vec::new()),
        };

        // repeats are free, as they are in the reference implementations:
        // only a host this evaluation has not seen costs budget
        if let Some(addresses) = self.budget.resolved(host, kind) {
            return Ok(addresses);
        }
        if !self.budget.take_lookup() {
            tracing::debug!("pac dns lookup budget exhausted for this evaluation");
            return Err(LookupBudgetExhausted);
        }

        // a lookup may not outlive what the evaluation has left to block for
        let timeout = match self.budget.blocking_left() {
            Some(left) if left.is_zero() => {
                tracing::debug!("pac evaluation exhausted its blocking budget");
                return Err(LookupBudgetExhausted);
            }
            Some(left) => self.timeout.min(left),
            None => self.timeout,
        };
        let resolver = self.resolver.clone();
        let lookup = async move {
            use rama_core::futures::StreamExt as _;

            let mut addresses = Vec::new();
            match kind {
                LookupKind::Classic => {
                    if let Some(Ok(ip)) = resolver.lookup_ipv4_first(domain).await {
                        addresses.push(IpAddr::V4(ip));
                    }
                }
                LookupKind::Extended => {
                    let mut stream = std::pin::pin!(
                        resolver
                            .lookup_ipv4(domain.clone())
                            .take(MAX_LOOKUP_ADDRESSES)
                    );
                    while let Some(Ok(ip)) = stream.next().await {
                        addresses.push(IpAddr::V4(ip));
                    }
                    let budget = MAX_LOOKUP_ADDRESSES.saturating_sub(addresses.len());
                    let mut stream = std::pin::pin!(resolver.lookup_ipv6(domain).take(budget));
                    while let Some(Ok(ip)) = stream.next().await {
                        addresses.push(IpAddr::V6(ip));
                    }
                }
            }
            addresses
        };

        // a panic here would kill the worker and every job after it
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.runtime
                .block_on(async move { tokio::time::timeout(timeout, lookup).await })
        }));

        let addresses = match result {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(_elapsed)) => {
                tracing::debug!("pac dns lookup timed out");
                Vec::new()
            }
            Err(_panic) => {
                tracing::error!("pac dns lookup panicked");
                Vec::new()
            }
        };

        self.budget.remember(host, kind, &addresses);
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

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

    #[derive(Debug, Clone)]
    struct QueryCountingResolver {
        ipv6_lookups: Arc<AtomicUsize>,
    }

    impl DnsAddressResolver for QueryCountingResolver {
        type Error = BoxError;

        fn lookup_ipv4(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            rama_core::futures::stream::iter([Ok(Ipv4Addr::new(10, 0, 0, 1))])
        }

        fn lookup_ipv6(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_ {
            self.ipv6_lookups.fetch_add(1, Ordering::Relaxed);
            rama_core::futures::stream::iter([Ok(std::net::Ipv6Addr::LOCALHOST)])
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
            Arc::new(PacBudgetState::default()),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_resolves_from_worker_thread() {
        let bridge = bridge(StaticResolver {
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: Some("::1".parse().unwrap()),
        });

        // mirrors the real caller: a plain thread with no ambient runtime
        let address = std::thread::spawn(move || bridge.lookup_ipv4(&host("example.com")))
            .join()
            .unwrap()
            .expect("an unarmed lookup cannot exhaust a budget");
        assert_eq!(address, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lookup_resolves_through_a_current_thread_runtime() {
        let bridge = bridge(StaticResolver {
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: Some("::1".parse().unwrap()),
        });

        let address = std::thread::spawn(move || bridge.lookup_ipv4(&host("example.com")))
            .join()
            .unwrap()
            .expect("an unarmed lookup cannot exhaust a budget");
        assert_eq!(address, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn classic_lookup_never_requests_ipv6() {
        let ipv6_lookups = Arc::new(AtomicUsize::new(0));
        let bridge = PacDnsBridge::new(
            tokio::runtime::Handle::current(),
            QueryCountingResolver {
                ipv6_lookups: ipv6_lookups.clone(),
            }
            .into_box_dns_address_resolver(),
            Duration::from_secs(5),
            Arc::new(PacBudgetState::default()),
        );

        let classic = bridge.clone();
        std::thread::spawn(move || classic.lookup_ipv4(&host("example.com")))
            .join()
            .unwrap()
            .expect("an unarmed lookup cannot exhaust a budget");
        assert_eq!(ipv6_lookups.load(Ordering::Relaxed), 0);

        std::thread::spawn(move || bridge.lookup_all(&host("example.com")))
            .join()
            .unwrap()
            .expect("an unarmed lookup cannot exhaust a budget");
        assert_eq!(ipv6_lookups.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_ex_includes_ipv6() {
        let bridge = bridge(StaticResolver {
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: Some("::1".parse().unwrap()),
        });
        let addresses = std::thread::spawn(move || bridge.lookup_all(&host("example.com")))
            .join()
            .unwrap()
            .expect("an unarmed lookup cannot exhaust a budget");
        assert_eq!(addresses.len(), 2);
        assert!(addresses.contains(&IpAddr::V6("::1".parse().unwrap())));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unresolvable_host_yields_empty() {
        let bridge = bridge(StaticResolver {
            ipv4: None,
            ipv6: None,
        });
        let addresses = std::thread::spawn(move || bridge.lookup_all(&host("example.com")))
            .join()
            .unwrap()
            .expect("an unarmed lookup cannot exhaust a budget");
        assert!(addresses.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_all_is_capped() {
        let bridge = PacDnsBridge::new(
            tokio::runtime::Handle::current(),
            FloodResolver(10_000).into_box_dns_address_resolver(),
            Duration::from_secs(5),
            Arc::new(PacBudgetState::default()),
        );
        let addresses = std::thread::spawn(move || bridge.lookup_all(&host("example.com")))
            .join()
            .unwrap()
            .expect("an unarmed lookup cannot exhaust a budget");
        assert_eq!(addresses.len(), MAX_LOOKUP_ADDRESSES);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn extended_cache_shape_is_independent_of_call_order() {
        fn armed_bridge() -> PacDnsBridge {
            let budget = Arc::new(PacBudgetState::default());
            budget.arm(crate::env::PacBudget {
                lookups: 4,
                glob_steps: 0,
                alerts: 0,
                blocking: Duration::from_secs(5),
            });
            PacDnsBridge::new(
                tokio::runtime::Handle::current(),
                FloodResolver(4).into_box_dns_address_resolver(),
                Duration::from_secs(5),
                budget,
            )
        }

        let all_first = armed_bridge();
        let (all, predicate) = std::thread::spawn(move || {
            let host = host("example.com");
            (all_first.lookup_all(&host), all_first.lookup_all(&host))
        })
        .join()
        .expect("join lookup thread");
        assert_eq!(
            all.expect("full lookup"),
            predicate.expect("predicate lookup")
        );

        let predicate_first = armed_bridge();
        let (predicate, all, classic) = std::thread::spawn(move || {
            let host = host("example.com");
            (
                predicate_first.lookup_all(&host),
                predicate_first.lookup_all(&host),
                predicate_first.lookup_ipv4(&host),
            )
        })
        .join()
        .expect("join lookup thread");
        assert_eq!(
            predicate.expect("predicate lookup"),
            all.expect("full lookup")
        );
        let classic = classic.expect("classic lookup");
        assert!(classic.is_some());
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
            std::thread::spawn(move || v4.lookup_ipv4(&host("10.0.0.7")))
                .join()
                .unwrap()
                .expect("an unarmed lookup cannot exhaust a budget"),
            Some(Ipv4Addr::new(10, 0, 0, 7)),
        );
        assert_eq!(
            std::thread::spawn(move || v6.lookup_all(&host("::1")))
                .join()
                .unwrap()
                .expect("an unarmed lookup cannot exhaust a budget"),
            vec![IpAddr::V6("::1".parse().unwrap())],
        );
        // classic (v4-only) callers never see an ipv6 literal
        assert!(
            std::thread::spawn(move || v6_v4_only.lookup_ipv4(&host("::1")))
                .join()
                .unwrap()
                .expect("an unarmed lookup cannot exhaust a budget")
                .is_none()
        );
    }
}
