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
/// Otherwise, we'll try to establish a connection with dual-stack parallel connections,
/// meaning that we'll try to connect to the domain using both IPv4 and IPv6,
/// with multiple concurrent connection attempts.
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

    //... otherwise we'll try to establish a connection,
    // with dual-stack parallel connections...

    let (tx, mut rx) = channel(1);

    let connected = Arc::new(AtomicBool::new(false));
    let sem = Arc::new(Semaphore::new(3));

    // IPv6
    let ipv6_tx = tx.clone();
    let ipv6_domain = domain.clone();
    let ipv6_dns = ctx.dns().clone();
    let ipv6_connected = connected.clone();
    let ipv6_sem = sem.clone();
    ctx.spawn(tcp_connect(
        ipv6_dns,
        IpKind::Ipv6,
        ipv6_domain,
        port,
        ipv6_tx,
        ipv6_connected,
        ipv6_sem,
    ));

    // IPv4
    let ipv4_tx = tx;
    let ipv4_domain = domain.clone();
    let ipv4_dns = ctx.dns().clone();
    let ipv4_connected = connected.clone();
    let ipv4_sem = sem;
    ctx.spawn(tcp_connect(
        ipv4_dns,
        IpKind::Ipv4,
        ipv4_domain,
        port,
        ipv4_tx,
        ipv4_connected,
        ipv4_sem,
    ));

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
    sem: Arc<Semaphore>,
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

    for (index, ip) in ip_it.enumerate() {
        let addr = (ip, port).into();

        let sem = sem.clone();
        let tx = tx.clone();
        let connected = connected.clone();

        // back off retries exponentially
        if index > 0 {
            let delay = match ip_kind {
                IpKind::Ipv4 => Duration::from_micros((35 * 2 * index) as u64),
                IpKind::Ipv6 => Duration::from_micros((21 * 2 * index) as u64),
            };
            tokio::time::sleep(delay).await;
        }

        if connected.load(Ordering::SeqCst) {
            tracing::trace!("[{ip_kind:?}] #{index}: abort connect loop to {addr} (connection already established)");
            return;
        }

        tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            if connected.load(Ordering::SeqCst) {
                tracing::trace!("[{ip_kind:?}] #{index}: abort spawned attempt to {addr} (connection already established)");
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
