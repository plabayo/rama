use crate::{
    dns::Dns,
    error::{ErrorContext, OpaqueError},
    net::address::{Authority, Domain, Host},
    service::Context,
    utils::combinators::Either,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{
        mpsc::{channel, Sender},
        Semaphore,
    },
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

    let (tx, mut rx) = channel(1);

    let connected = Arc::new(AtomicBool::new(false));

    // IPv6
    let ipv6_tx = tx.clone();
    let ipv6_domain = domain.clone();
    let ipv6_dns = ctx.dns().clone();
    let ipv6_connected = connected.clone();
    ctx.spawn(tcp_connect(
        ipv6_dns,
        IpKind::Ipv6,
        ipv6_domain,
        port,
        ipv6_tx,
        ipv6_connected,
    ));

    // IPv4
    let ipv4_tx = tx;
    let ipv4_domain = domain.clone();
    let ipv4_dns = ctx.dns().clone();
    let ipv4_connected = connected.clone();
    ctx.spawn(async move {
        // give Ipv6 a headstart
        tokio::time::sleep(Duration::from_micros(500)).await;
        tcp_connect(
            ipv4_dns,
            IpKind::Ipv4,
            ipv4_domain,
            port,
            ipv4_tx,
            ipv4_connected,
        )
        .await;
    });

    // wait for the first connection to succeed,
    // ignore the rest of the connections (sorry, but not sorry)
    if let Some((stream, addr)) = rx.recv().await {
        connected.store(true, Ordering::SeqCst);
        return Ok((stream, addr));
    }

    Err(OpaqueError::from_display(format!(
        "failed to connect to any resolved IP address for {domain} (port {port})"
    )))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum IpKind {
    Ipv4,
    Ipv6,
}

async fn tcp_connect(
    dns: Dns,
    ip_kind: IpKind,
    domain: Domain,
    port: u16,
    tx: Sender<(TcpStream, SocketAddr)>,
    connected: Arc<AtomicBool>,
) {
    let ip_it = match ip_kind {
        IpKind::Ipv4 => match dns.ipv4_lookup(domain).await {
            Ok(it) => Either::A(it.map(IpAddr::V4)),
            Err(err) => {
                tracing::trace!(err = %err, "[{ip_kind:?}] failed to resolve domain to IPv4 addresses");
                return;
            }
        },
        IpKind::Ipv6 => match dns.ipv6_lookup(domain).await {
            Ok(it) => Either::B(it.map(IpAddr::V6)),
            Err(err) => {
                tracing::trace!(err = %err, "[{ip_kind:?}] failed to resolve domain to IPv6 addresses");
                return;
            }
        },
    };

    const CONCURRENT_CONNECTIONS: usize = 2;

    let sem = Arc::new(Semaphore::new(CONCURRENT_CONNECTIONS));

    for (index, ip) in ip_it.enumerate() {
        let addr = (ip, port).into();

        let sem = sem.clone();
        let tx = tx.clone();
        let connected = connected.clone();

        // back off retries exponentially
        if index > 0 && index % CONCURRENT_CONNECTIONS == 0 {
            let multiplier = index / CONCURRENT_CONNECTIONS;
            let delay = Duration::from_micros((50 * 2 * multiplier) as u64);
            tokio::time::sleep(delay).await;
        }

        tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            if connected.load(Ordering::SeqCst) {
                tracing::trace!("[{ip_kind:?}] #{index}: abort attempt to {addr} (connection already established)");
                return;
            }

            tracing::trace!("[{ip_kind:?}] #{index}: tcp connect attempt to {addr}");

            match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    tracing::trace!("[{ip_kind:?}] #{index}: tcp connection stablished to {addr}");
                    if let Err(err) = tx.send((stream, addr)).await {
                        tracing::trace!(err = %err, "[{ip_kind:?}] #{index}: failed to send resolved IP address");
                    }
                }
                Err(err) => {
                    tracing::trace!(err = %err, "[{ip_kind:?}] #{index}: tcp connector failed to connect");
                }
            };
        });
    }
}
