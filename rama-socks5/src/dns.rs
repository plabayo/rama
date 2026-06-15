//! Internal DNS resolution helpers shared between the SOCKS5 client connector
//! and the SOCKS5 UDP relay.

use std::{net::IpAddr, time::Duration};

use rama_core::telemetry::tracing;
use rama_dns::client::resolver::{BoxDnsAddressResolver, DnsAddressResolver as _};
use rama_net::{address::Domain, mode::DnsResolveIpMode};
use tokio::{sync::mpsc, time::sleep};

const DNS_FAMILY_PREFERENCE_DELAY: Duration = Duration::from_micros(42);

/// Race an IPv4 and IPv6 DNS lookup for `domain` against each other and return
/// whichever resolves first (random pick within each family), giving the
/// preferred family a tiny head start.
///
/// The non-preferred family is delayed using the same preference delay as the
/// Happy Eyeballs resolver in `rama-dns`: [`DnsResolveIpMode::Dual`] prefers
/// IPv6 and [`DnsResolveIpMode::DualPreferIpV4`] prefers IPv4. Returns [`None`]
/// when neither family resolves to an address.
pub(crate) async fn race_resolve_dual(
    dns_resolver: &BoxDnsAddressResolver,
    domain: Domain,
    mode: DnsResolveIpMode,
) -> Option<IpAddr> {
    use tracing::{Instrument, trace_span};

    let (tx, mut rx) = mpsc::unbounded_channel();
    let (delay_ipv4, delay_ipv6) = match mode {
        DnsResolveIpMode::Dual => (true, false),
        DnsResolveIpMode::DualPreferIpV4 => (false, true),
        DnsResolveIpMode::SingleIpV4 | DnsResolveIpMode::SingleIpV6 => (false, false),
    };

    tokio::spawn(
        {
            let tx = tx.clone();
            let domain = domain.clone();
            let dns_resolver = dns_resolver.clone();
            async move {
                if delay_ipv4 {
                    sleep(DNS_FAMILY_PREFERENCE_DELAY).await;
                }

                match dns_resolver.lookup_ipv4_rand(domain.clone()).await {
                    Some(Ok(addr)) => {
                        if let Err(err) = tx.send(IpAddr::V4(addr)) {
                            tracing::debug!(
                                "failed to send ipv4 lookup result for ip: {addr}; err = {err:?}"
                            )
                        }
                    }
                    Some(Err(err)) => {
                        tracing::debug!("failed to lookup ipv4 addresses for domain: {err:?}");
                    }
                    None => {
                        tracing::debug!(
                            "failed to lookup ipv4 addresses for domain: no addresses found"
                        );
                    }
                }
            }
        }
        .instrument(trace_span!("dns::ipv4_lookup")),
    );

    tokio::spawn(
        {
            let dns_resolver = dns_resolver.clone();
            async move {
                if delay_ipv6 {
                    sleep(DNS_FAMILY_PREFERENCE_DELAY).await;
                }

                match dns_resolver.lookup_ipv6_rand(domain.clone()).await {
                    Some(Ok(addr)) => {
                        if let Err(err) = tx.send(IpAddr::V6(addr)) {
                            tracing::debug!(
                                "failed to send ipv6 lookup result for ip: {addr}; err = {err:?}"
                            )
                        }
                    }
                    Some(Err(err)) => {
                        tracing::debug!("failed to lookup ipv6 addresses for domain: {err:?}");
                    }
                    None => {
                        tracing::debug!(
                            "failed to lookup ipv6 addresses for domain: no addresses found"
                        );
                    }
                }
            }
        }
        .instrument(trace_span!("dns::ipv6_lookup")),
    );

    rx.recv().await
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
}
