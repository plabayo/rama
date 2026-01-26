use rama_core::extensions::Extensions;
use rama_core::telemetry::tracing::{self, Instrument, trace_span};
use rama_core::{
    combinators::Either,
    error::{BoxError, ErrorContext, OpaqueError},
    rt::Executor,
};
use rama_dns::{DnsOverwrite, DnsResolver, GlobalDnsResolver};
use rama_net::address::HostWithPort;
use rama_net::{
    address::{Domain, Host, SocketAddress},
    mode::{ConnectIpMode, DnsResolveIpMode},
    socket::SocketOptions,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{
    Semaphore,
    mpsc::{Sender, channel},
};

use crate::TcpStream;

/// Trait used internally by [`tcp_connect`] and the `TcpConnector`
/// to actually establish the [`TcpStream`]
pub trait TcpStreamConnector: Clone + Send + Sync + 'static {
    /// Type of error that can occurr when establishing the connection failed.
    type Error;

    /// Connect to the target via the given [`SocketAddr`]ess to establish a [`TcpStream`].
    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, Self::Error>> + Send + '_;
}

impl TcpStreamConnector for () {
    type Error = std::io::Error;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        Ok(stream.into())
    }
}

impl<T: TcpStreamConnector> TcpStreamConnector for Arc<T> {
    type Error = T::Error;

    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, Self::Error>> + Send + '_ {
        (**self).connect(addr)
    }
}

impl TcpStreamConnector for Arc<SocketOptions> {
    type Error = OpaqueError;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let opts = self.clone();
        tokio::task::spawn_blocking(move || tcp_connect_with_socket_opts(&opts, addr))
            .await
            .context("wait for blocking tcp bind using custom socket opts")?
    }
}

impl TcpStreamConnector for SocketAddress {
    type Error = OpaqueError;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let bind_addr = *self;
        let opts = match bind_addr.ip_addr {
            IpAddr::V4(_ip) => SocketOptions {
                address: Some(bind_addr),
                ..SocketOptions::default_tcp()
            },
            IpAddr::V6(_ip) => SocketOptions {
                address: Some(bind_addr),
                ..SocketOptions::default_tcp_v6()
            },
        };
        tokio::task::spawn_blocking(move || tcp_connect_with_socket_opts(&opts, addr))
            .await
            .context("wait for blocking tcp bind using provided Socket Address")?
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
impl TcpStreamConnector for rama_net::socket::DeviceName {
    type Error = OpaqueError;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let bind_interface = self.clone();
        tokio::task::spawn_blocking(move || {
            tcp_connect_with_socket_opts(
                &SocketOptions {
                    device: Some(bind_interface),
                    ..SocketOptions::default_tcp()
                },
                addr,
            )
        })
        .await
        .context("wait for blocking tcp bind using provided Socket Address")?
    }
}

fn tcp_connect_with_socket_opts(
    opts: &SocketOptions,
    addr: SocketAddr,
) -> Result<TcpStream, OpaqueError> {
    let socket = opts
        .try_build_socket()
        .context("try to build TCP socket's underlying OS socket")?;
    socket
        .connect(&addr.into())
        .context("connect to the provided socket addr")?;
    socket
        .set_nonblocking(true)
        .context("set socket non-blocking")?;
    let stream = tokio::net::TcpStream::from_std(std::net::TcpStream::from(socket))
        .context("create tokio tcp stream from created raw (tcp) socket")?;

    Ok(stream.into())
}

impl<ConnectFn, ConnectFnFut, ConnectFnErr> TcpStreamConnector for ConnectFn
where
    ConnectFn: Fn(SocketAddr) -> ConnectFnFut + Clone + Send + Sync + 'static,
    ConnectFnFut: Future<Output = Result<TcpStream, ConnectFnErr>> + Send + 'static,
    ConnectFnErr: Into<BoxError> + Send + 'static,
{
    type Error = ConnectFnErr;

    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, Self::Error>> + Send + '_ {
        (self)(addr)
    }
}

macro_rules! impl_stream_connector_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> TcpStreamConnector for ::rama_core::combinators::$id<$($param),+>
        where
            $(
                $param: TcpStreamConnector<Error: Into<BoxError>>,
            )+
        {
            type Error = BoxError;

            async fn connect(
                &self,
                addr: SocketAddr,
            ) -> Result<TcpStream, Self::Error> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(s) => s.connect(addr).await.map_err(Into::into),
                    )+
                }
            }
        }
    };
}

::rama_core::combinators::impl_either!(impl_stream_connector_either);

#[inline]
/// Establish a [`TcpStream`] connection for the given [`HostWithPort`],
/// using the default settings and no custom state.
///
/// Use [`tcp_connect`] in case you want to customise any of these settings,
/// or use a [`rama_net::client::ConnectorService`] for even more advanced possibilities.
pub async fn default_tcp_connect(
    extensions: &Extensions,
    address: HostWithPort,
    exec: Executor,
) -> Result<(TcpStream, SocketAddr), OpaqueError>
where
{
    tcp_connect(extensions, address, GlobalDnsResolver::default(), (), exec).await
}

/// Establish a [`TcpStream`] connection for the given [`HostWithPort`].
pub async fn tcp_connect<Dns, Connector>(
    extensions: &Extensions,
    address: HostWithPort,
    dns: Dns,
    connector: Connector,
    exec: Executor,
) -> Result<(TcpStream, SocketAddr), OpaqueError>
where
    Dns: DnsResolver + Clone,
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
{
    let ip_mode = extensions.get().copied().unwrap_or_default();
    let dns_mode = extensions.get().copied().unwrap_or_default();

    let HostWithPort { host, port } = address;
    let domain = match host {
        Host::Name(domain) => domain,
        Host::Address(ip) => {
            //check if IP Version is allowed
            match (ip, ip_mode) {
                (IpAddr::V4(_), ConnectIpMode::Ipv6) => {
                    return Err(OpaqueError::from_display("IPv4 address is not allowed"));
                }
                (IpAddr::V6(_), ConnectIpMode::Ipv4) => {
                    return Err(OpaqueError::from_display("IPv6 address is not allowed"));
                }
                _ => (),
            }

            // if the authority is already defined as an IP address, we can directly connect to it
            let addr = (ip, port).into();
            let stream = connector
                .connect(addr)
                .await
                .map_err(|err| OpaqueError::from_boxed(err.into()))
                .context("establish tcp client connection")?;
            return Ok((stream, addr));
        }
    };

    if let Some(dns_overwrite) = extensions.get::<DnsOverwrite>().cloned() {
        tcp_connect_inner(
            domain.clone(),
            port,
            dns_mode,
            (dns_overwrite, dns),
            connector.clone(),
            ip_mode,
            exec,
        )
        .await
    } else {
        tcp_connect_inner(domain, port, dns_mode, dns, connector, ip_mode, exec).await
    }
}

async fn tcp_connect_inner<Dns, Connector>(
    domain: Domain,
    port: u16,
    dns_mode: DnsResolveIpMode,
    dns: Dns,
    connector: Connector,
    connect_mode: ConnectIpMode,
    exec: Executor,
) -> Result<(TcpStream, SocketAddr), OpaqueError>
where
    Dns: DnsResolver + Clone,
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
{
    let (tx, mut rx) = channel(1);
    let connected = Arc::new(AtomicBool::new(false));
    let sem = Arc::new(Semaphore::new(3));

    if dns_mode.ipv4_supported() {
        exec.spawn_task(
            tcp_connect_inner_branch(
                dns_mode,
                dns.clone(),
                connect_mode,
                connector.clone(),
                IpKind::Ipv4,
                domain.clone(),
                port,
                tx.clone(),
                connected.clone(),
                sem.clone(),
            )
            .instrument(tracing::trace_span!(
                "tcp::connect::dns_v4",
                otel.kind = "client",
                network.protocol.name = "tcp",
            )),
        );
    }

    if dns_mode.ipv6_supported() {
        exec.into_spawn_task(
            tcp_connect_inner_branch(
                dns_mode,
                dns.clone(),
                connect_mode,
                connector.clone(),
                IpKind::Ipv6,
                domain.clone(),
                port,
                tx.clone(),
                connected.clone(),
                sem.clone(),
            )
            .instrument(tracing::trace_span!(
                "tcp::connect::dns_v6",
                otel.kind = "client",
                network.protocol.name = "tcp",
            )),
        );
    }

    drop(tx);
    if let Some((stream, addr)) = rx.recv().await {
        connected.store(true, Ordering::Release);
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

#[allow(clippy::too_many_arguments)]
async fn tcp_connect_inner_branch<Dns, Connector>(
    dns_mode: DnsResolveIpMode,
    dns: Dns,
    connect_mode: ConnectIpMode,
    connector: Connector,
    ip_kind: IpKind,
    domain: Domain,
    port: u16,
    tx: Sender<(TcpStream, SocketAddr)>,
    connected: Arc<AtomicBool>,
    sem: Arc<Semaphore>,
) where
    Dns: DnsResolver + Clone,
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
{
    let ip_it = match ip_kind {
        IpKind::Ipv4 => match dns.ipv4_lookup(domain.clone()).await {
            Ok(ips) => Either::A(ips.into_iter().map(IpAddr::V4)),
            Err(err) => {
                let err = OpaqueError::from_boxed(err.into());
                tracing::trace!(
                    "[{ip_kind:?}] failed to resolve domain to IPv4 addresses: {err:?}"
                );
                return;
            }
        },
        IpKind::Ipv6 => match dns.ipv6_lookup(domain.clone()).await {
            Ok(ips) => Either::B(ips.into_iter().map(IpAddr::V6)),
            Err(err) => {
                let err = OpaqueError::from_boxed(err.into());
                tracing::trace!(
                    "[{ip_kind:?}] failed to resolve domain to IPv6 addresses: {err:?}"
                );
                return;
            }
        },
    };

    let (ipv4_delay_scalar, ipv6_delay_scalar) = match dns_mode {
        DnsResolveIpMode::DualPreferIpV4 | DnsResolveIpMode::SingleIpV4 => (15 * 2, 21 * 2),
        _ => (21 * 2, 15 * 2),
    };
    for (index, ip) in ip_it.enumerate() {
        let addr = (ip, port).into();

        let sem = match (ip.is_ipv4(), connect_mode) {
            (true, ConnectIpMode::Ipv6) => {
                tracing::trace!(
                    "[{ip_kind:?}] #{index}: abort connect loop to {addr} (IPv4 address is not allowed)"
                );
                continue;
            }
            (false, ConnectIpMode::Ipv4) => {
                tracing::trace!(
                    "[{ip_kind:?}] #{index}: abort connect loop to {addr} (IPv6 address is not allowed)"
                );
                continue;
            }
            _ => sem.clone(),
        };

        let tx = tx.clone();
        let connected = connected.clone();

        // back off retries exponentially
        if index > 0 {
            let delay = match ip_kind {
                IpKind::Ipv4 => Duration::from_micros((ipv4_delay_scalar * index) as u64),
                IpKind::Ipv6 => Duration::from_micros((ipv6_delay_scalar * index) as u64),
            };
            tokio::time::sleep(delay).await;
        }

        if connected.load(Ordering::Acquire) {
            tracing::trace!(
                "[{ip_kind:?}] #{index}: abort connect loop to {addr} (connection already established)"
            );
            return;
        }

        let connector = connector.clone();
        tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(permit) => permit,
                Err(err) => {
                    tracing::trace!(
                        "[{ip_kind:?}] #{index}: abort conn; failed to acquire permit: {err}"
                    );
                    return;
                }
            };
            if connected.load(Ordering::Acquire) {
                tracing::trace!(
                    "[{ip_kind:?}] #{index}: abort spawned attempt to {addr} (connection already established)"
                );
                return;
            }

            tracing::trace!("[{ip_kind:?}] #{index}: tcp connect attempt to {addr}");

            match connector.connect(addr).await {
                Ok(stream) => {
                    tracing::trace!("[{ip_kind:?}] #{index}: tcp connection stablished to {addr}");
                    if let Err(err) = tx.send((stream, addr)).await {
                        tracing::trace!(
                            "[{ip_kind:?}] #{index}: failed to send resolved IP address {addr}: {err:?}"
                        );
                    }
                }
                Err(err) => {
                    let err = OpaqueError::from_boxed(err.into());
                    tracing::trace!("[{ip_kind:?}] #{index}: tcp connector failed to connect to {addr}: {err:?}");
                }
            };
        }.instrument(trace_span!(
            "tcp::connect",
            otel.kind = "client",
            network.protocol.name = "tcp",
            network.peer.address = %ip,
            server.address = %domain,
            %index,
        )));
    }
}
