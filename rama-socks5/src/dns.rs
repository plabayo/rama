//! Internal DNS resolution helpers shared between the SOCKS5 client connector
//! and the SOCKS5 UDP relay.

use std::{net::IpAddr, time::Duration};

use rama_core::telemetry::tracing;
use rama_dns::client::resolver::{BoxDnsAddressResolver, DnsAddressResolver as _};
use rama_net::{address::Domain, mode::DnsResolveIpMode};
use tokio::time::sleep;

const DNS_FAMILY_PREFERENCE_DELAY: Duration = Duration::from_micros(42);

/// Resolve `domain` to one address according to `mode`: a single-family mode
/// looks up only that family; a dual mode races an IPv4 and an IPv6 lookup
/// (random pick within each family) and returns whichever resolves first,
/// giving the preferred family a tiny head start.
///
/// The non-preferred family is delayed using the same preference delay as the
/// Happy Eyeballs resolver in `rama-dns`: [`DnsResolveIpMode::Dual`] prefers
/// IPv6 and [`DnsResolveIpMode::DualPreferIpV4`] prefers IPv4. Returns [`None`]
/// when nothing resolves to an address.
///
/// Both lookups run inside the caller's task, so dropping this future cancels
/// them and the losing lookup never keeps running detached.
pub(crate) async fn race_resolve_dual(
    dns_resolver: &BoxDnsAddressResolver,
    domain: Domain,
    mode: DnsResolveIpMode,
) -> Option<IpAddr> {
    use tracing::Instrument;

    let (delay_ipv4, delay_ipv6) = match mode {
        DnsResolveIpMode::Dual => (true, false),
        DnsResolveIpMode::DualPreferIpV4 => (false, true),
        DnsResolveIpMode::SingleIpV4 => {
            return lookup_ipv4(dns_resolver, domain, false)
                .instrument(tracing::trace_span!("dns::ipv4_lookup"))
                .await;
        }
        DnsResolveIpMode::SingleIpV6 => {
            return lookup_ipv6(dns_resolver, domain, false)
                .instrument(tracing::trace_span!("dns::ipv6_lookup"))
                .await;
        }
    };

    let ipv4 = lookup_ipv4(dns_resolver, domain.clone(), delay_ipv4)
        .instrument(tracing::trace_span!("dns::ipv4_lookup"));
    let ipv6 = lookup_ipv6(dns_resolver, domain, delay_ipv6)
        .instrument(tracing::trace_span!("dns::ipv6_lookup"));
    let mut ipv4 = std::pin::pin!(ipv4);
    let mut ipv6 = std::pin::pin!(ipv6);

    let mut ipv4_done = false;
    let mut ipv6_done = false;
    loop {
        tokio::select! {
            addr = &mut ipv4, if !ipv4_done => match addr {
                Some(addr) => return Some(addr),
                None => ipv4_done = true,
            },
            addr = &mut ipv6, if !ipv6_done => match addr {
                Some(addr) => return Some(addr),
                None => ipv6_done = true,
            },
            else => return None,
        }
    }
}

async fn lookup_ipv4(
    dns_resolver: &BoxDnsAddressResolver,
    domain: Domain,
    delay: bool,
) -> Option<IpAddr> {
    if delay {
        sleep(DNS_FAMILY_PREFERENCE_DELAY).await;
    }
    match dns_resolver.lookup_ipv4_rand(domain).await {
        Some(Ok(addr)) => Some(IpAddr::V4(addr)),
        Some(Err(err)) => {
            tracing::debug!("failed to lookup ipv4 addresses for domain: {err:?}");
            None
        }
        None => {
            tracing::debug!("failed to lookup ipv4 addresses for domain: no addresses found");
            None
        }
    }
}

async fn lookup_ipv6(
    dns_resolver: &BoxDnsAddressResolver,
    domain: Domain,
    delay: bool,
) -> Option<IpAddr> {
    if delay {
        sleep(DNS_FAMILY_PREFERENCE_DELAY).await;
    }
    match dns_resolver.lookup_ipv6_rand(domain).await {
        Some(Ok(addr)) => Some(IpAddr::V6(addr)),
        Some(Err(err)) => {
            tracing::debug!("failed to lookup ipv6 addresses for domain: {err:?}");
            None
        }
        None => {
            tracing::debug!("failed to lookup ipv6 addresses for domain: no addresses found");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };

    use rama_core::futures::{Stream, stream};
    use rama_dns::client::resolver::DnsAddressResolver;

    use super::*;

    struct ImmediateDualResolver;

    impl DnsAddressResolver for ImmediateDualResolver {
        type Error = Infallible;

        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Ok(Ipv4Addr::new(192, 0, 2, 4))))
        }

        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Ok(Ipv6Addr::LOCALHOST)))
        }
    }

    #[tokio::test]
    async fn race_resolve_dual_prefers_ipv6_for_dual_mode() {
        let resolver = BoxDnsAddressResolver::new(ImmediateDualResolver);

        let ip = race_resolve_dual(&resolver, Domain::example(), DnsResolveIpMode::Dual)
            .await
            .expect("dual resolver should return an address");

        assert!(matches!(ip, IpAddr::V6(_)));
    }

    /// Resolver that only answers for one family and fails the test if the
    /// other family is ever queried.
    struct SingleFamilyResolver(DnsResolveIpMode);

    impl DnsAddressResolver for SingleFamilyResolver {
        type Error = Infallible;

        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            assert_eq!(self.0, DnsResolveIpMode::SingleIpV4, "unexpected A lookup");
            stream::once(std::future::ready(Ok(Ipv4Addr::new(192, 0, 2, 4))))
        }

        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            assert_eq!(
                self.0,
                DnsResolveIpMode::SingleIpV6,
                "unexpected AAAA lookup"
            );
            stream::once(std::future::ready(Ok(Ipv6Addr::LOCALHOST)))
        }
    }

    #[tokio::test]
    async fn single_family_modes_only_query_their_own_family() {
        for (mode, want_v6) in [
            (DnsResolveIpMode::SingleIpV4, false),
            (DnsResolveIpMode::SingleIpV6, true),
        ] {
            let resolver = BoxDnsAddressResolver::new(SingleFamilyResolver(mode));
            let ip = race_resolve_dual(&resolver, Domain::example(), mode)
                .await
                .expect("single-family resolver should return an address");
            assert_eq!(ip.is_ipv6(), want_v6, "{mode:?}");
        }
    }

    #[tokio::test]
    async fn race_resolve_dual_prefers_ipv4_for_dual_prefer_ipv4_mode() {
        let resolver = BoxDnsAddressResolver::new(ImmediateDualResolver);

        let ip = race_resolve_dual(
            &resolver,
            Domain::example(),
            DnsResolveIpMode::DualPreferIpV4,
        )
        .await
        .expect("dual resolver should return an address");

        assert!(matches!(ip, IpAddr::V4(_)));
    }

    /// Answers for one family only, so the race has to keep waiting after the
    /// first lookup finishes empty-handed.
    struct OnlyIpv6Resolver;

    impl DnsAddressResolver for OnlyIpv6Resolver {
        type Error = Infallible;

        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            stream::empty()
        }

        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Ok(Ipv6Addr::LOCALHOST)))
        }
    }

    /// The preferred family is the one that has no answer, and it finishes
    /// first because it also gets the head start. Returning its `None` would
    /// fail a name the other family resolves perfectly well.
    #[tokio::test]
    async fn a_family_with_no_answer_leaves_the_race_to_the_other() {
        let resolver = BoxDnsAddressResolver::new(OnlyIpv6Resolver);

        let ip = race_resolve_dual(
            &resolver,
            Domain::example(),
            DnsResolveIpMode::DualPreferIpV4,
        )
        .await
        .expect("the answering family decides the race");

        assert!(matches!(ip, IpAddr::V6(_)));
    }

    struct NeitherFamilyResolver;

    impl DnsAddressResolver for NeitherFamilyResolver {
        type Error = Infallible;

        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            stream::empty()
        }

        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            stream::empty()
        }
    }

    /// Once both families are done with nothing to show, the race ends. A miss
    /// here hangs the caller on two futures that will never complete again.
    #[tokio::test]
    async fn a_dual_race_that_nobody_answers_resolves_to_nothing() {
        for mode in [DnsResolveIpMode::Dual, DnsResolveIpMode::DualPreferIpV4] {
            let resolver = BoxDnsAddressResolver::new(NeitherFamilyResolver);
            assert_eq!(
                race_resolve_dual(&resolver, Domain::example(), mode).await,
                None,
                "{mode:?}"
            );
        }
    }
}
