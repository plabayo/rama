use crate::{
    error::{ErrorContext, OpaqueError},
    net::address::{Authority, Domain, Host},
    service::Context,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, Receiver},
};

/// Establish a TCP connection for the given authority.
///
/// In the case where the authority is already an IP address, we can directly connect to it.
/// Otherwise, we'll use [the Happy Eye Balls algorithm][`rfc8305`] to resolve the domain
/// to a valid IP address and establish a connection to it, with a bias towards IPv6.
///
/// [`rfc8305`]: https://datatracker.ietf.org/doc/html/rfc8305
pub async fn connect<State>(
    ctx: &Context<State>,
    authority: Authority,
) -> Result<(TcpStream, SocketAddr), OpaqueError>
where
    State: Send + Sync + 'static,
{
    let (host, port) = authority.into_parts();
    let domain = match host {
        Host::Name(domain) => domain,
        Host::Address(ip) => {
            // if the authority is already defined as an IP address, we can directly connect to it
            let addr = (ip, port).into();
            let stream = TcpStream::connect(&addr)
                .await
                .context("establish tcp client connection")?;
            return Ok((stream, addr));
        }
    };

    //... otherwise we'll use the Happy Eye Balls algorithm to
    // resolve the domain to a valid IP address and establish a connection to it.
    //
    // See <https://datatracker.ietf.org/doc/html/rfc8305> for more information.

    let mut resolver = HappyResolver::new(ctx, &domain);
    let mut delay = Duration::ZERO;
    while let Some(ip) = resolver.next_ip().await {
        let addr = (ip, port).into();

        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }

        match TcpStream::connect(&addr).await {
            Ok(stream) => return Ok((stream, addr)),
            Err(err) => {
                tracing::trace!(err = %err, "tcp connector failed to connect");
                delay = (delay + Duration::from_micros(250)) * 2;
                continue;
            }
        };
    }

    Err(OpaqueError::from_display(format!(
        "failed to connect to any resolved IP address for {domain} (port {port})"
    )))
}

#[derive(Debug)]
struct HappyResolver {
    ipv4_rx: Option<Receiver<Ipv4Addr>>,
    ipv6_rx: Option<Receiver<Ipv6Addr>>,
    last_ip_kind: IpKind,
}

#[derive(Debug)]
enum IpKind {
    Ipv4,
    Ipv6,
}

impl HappyResolver {
    fn new<State>(ctx: &Context<State>, domain: &Domain) -> Self {
        let ipv4_dns = ctx.dns().clone();
        let (ipv4_tx, ipv4_rx) = channel(1);
        let ipv4_domain = domain.clone();
        ctx.spawn(async move {
            tokio::time::sleep(Duration::from_micros(500)).await; // give Ipv6 a head start
            let ip_it = match ipv4_dns.ipv4_lookup(ipv4_domain).await {
                Ok(it) => it,
                Err(err) => {
                    tracing::trace!(err = %err, "failed to resolve domain to IPv4 addresses");
                    return;
                }
            };
            for ip in ip_it {
                if let Err(err) = ipv4_tx.send(ip).await {
                    tracing::trace!(err = %err, "failed to send resolved IPv4 address");
                    return;
                }
            }
        });

        let ipv6_dns = ctx.dns().clone();
        let (ipv6_tx, ipv6_rx) = channel(1);
        let ipv6_domain = domain.clone();
        ctx.spawn(async move {
            let ip_it = match ipv6_dns.ipv6_lookup(ipv6_domain).await {
                Ok(it) => it,
                Err(err) => {
                    tracing::trace!(err = %err, "failed to resolve domain to IPv6 addresses");
                    return;
                }
            };
            for ip in ip_it {
                if let Err(err) = ipv6_tx.send(ip).await {
                    tracing::trace!(err = %err, "failed to send resolved IPv6 address");
                    return;
                }
            }
        });

        Self {
            ipv4_rx: Some(ipv4_rx),
            ipv6_rx: Some(ipv6_rx),
            last_ip_kind: IpKind::Ipv6,
        }
    }

    async fn next_ip(&mut self) -> Option<IpAddr> {
        let (ipv4_rx, ipv6_rx) = (self.ipv4_rx.take(), self.ipv6_rx.take());
        match (ipv4_rx, ipv6_rx) {
            (None, None) => None,
            (Some(mut ipv4_rx), None) => match ipv4_rx.recv().await {
                Some(ip) => {
                    self.last_ip_kind = IpKind::Ipv4;
                    self.ipv4_rx = Some(ipv4_rx);
                    tracing::trace!("resolved IPv4 address: {ip}");
                    Some(IpAddr::V4(ip))
                }
                None => None,
            },
            (None, Some(mut ipv6_rx)) => match ipv6_rx.recv().await {
                Some(ip) => {
                    self.last_ip_kind = IpKind::Ipv6;
                    self.ipv6_rx = Some(ipv6_rx);
                    tracing::trace!("resolved IPv6 address: {ip}");
                    Some(IpAddr::V6(ip))
                }
                None => None,
            },
            (Some(mut ipv4_rx), Some(mut ipv6_rx)) => {
                let (maybe_ip, ip_kind) = match self.last_ip_kind {
                    IpKind::Ipv4 => {
                        tokio::select! {
                            biased;
                            ip = ipv6_rx.recv() => (ip.map(IpAddr::V6), IpKind::Ipv6),
                            ip = ipv4_rx.recv() => (ip.map(IpAddr::V4), IpKind::Ipv4),
                        }
                    }
                    IpKind::Ipv6 => {
                        tokio::select! {
                            biased;
                            ip = ipv4_rx.recv() => (ip.map(IpAddr::V4), IpKind::Ipv4),
                            ip = ipv6_rx.recv() => (ip.map(IpAddr::V6), IpKind::Ipv6),
                        }
                    }
                };
                match maybe_ip {
                    Some(ip) => {
                        tracing::trace!("resolved to {ip_kind:?} address: {ip}");
                        self.last_ip_kind = ip_kind;
                        self.ipv4_rx = Some(ipv4_rx);
                        self.ipv6_rx = Some(ipv6_rx);
                        Some(ip)
                    }
                    None => match ip_kind {
                        IpKind::Ipv4 => {
                            // drop Ipv4 receiver, since it's exhausted
                            // and try again with ipv6...
                            match ipv6_rx.recv().await {
                                Some(ip) => {
                                    self.last_ip_kind = IpKind::Ipv6;
                                    self.ipv6_rx = Some(ipv6_rx);
                                    tracing::trace!(
                                        "resolved to IPv6 address after exhausting IPv4: {ip}"
                                    );
                                    Some(IpAddr::V6(ip))
                                }
                                None => None, // X_X
                            }
                        }
                        IpKind::Ipv6 => {
                            // drop Ipv6 receiver, since it's exhausted
                            // and try again with ipv4...
                            match ipv4_rx.recv().await {
                                Some(ip) => {
                                    self.last_ip_kind = IpKind::Ipv4;
                                    self.ipv4_rx = Some(ipv4_rx);
                                    tracing::trace!(
                                        "resolved to IPv4 address after exhausting IPv6: {ip}"
                                    );
                                    Some(IpAddr::V4(ip))
                                }
                                None => None, // X_X
                            }
                        }
                    },
                }
            }
        }
    }
}
