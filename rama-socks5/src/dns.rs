//! Internal DNS resolution helpers shared between the SOCKS5 client connector
//! and the SOCKS5 UDP relay.

use std::net::IpAddr;

use rama_core::telemetry::tracing;
use rama_dns::client::resolver::{BoxDnsAddressResolver, DnsAddressResolver as _};
use rama_net::address::Domain;
use tokio::sync::mpsc;

/// Race an IPv4 and IPv6 DNS lookup for `domain` against each other and return
/// whichever resolves first (random pick within each family).
///
/// Both lookups are spawned concurrently; the first successfully resolved
/// address (V4 or V6) wins. Returns [`None`] when neither family resolves to an
/// address.
pub(crate) async fn race_resolve_dual(
    dns_resolver: &BoxDnsAddressResolver,
    domain: Domain,
) -> Option<IpAddr> {
    use tracing::{Instrument, trace_span};

    let (tx, mut rx) = mpsc::unbounded_channel();

    tokio::spawn(
        {
            let tx = tx.clone();
            let domain = domain.clone();
            let dns_resolver = dns_resolver.clone();
            async move {
                match dns_resolver.lookup_ipv4_rand(domain.clone()).await {
                    Some(Ok(addr)) => {
                        if let Err(err) = tx.send(IpAddr::V4(addr)) {
                            tracing::debug!(
                                "failed to send ipv4 lookup result for ip: {addr}; err = {err:?}"
                            )
                        }
                    },
                    Some(Err(err)) => {
                        tracing::debug!(
                            "failed to lookup ipv4 addresses for domain: {err:?}"
                        );
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
                match dns_resolver.lookup_ipv6_rand(domain.clone()).await {
                    Some(Ok(addr)) => {
                        if let Err(err) = tx.send(IpAddr::V6(addr)) {
                            tracing::debug!(
                                "failed to send ipv6 lookup result for ip: {addr}; err = {err:?}"
                            )
                        }
                    },
                    Some(Err(err)) => {
                        tracing::debug!(
                            "failed to lookup ipv6 addresses for domain: {err:?}"
                        );
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
