use rama_core::combinators::Either;
use rama_core::error::ErrorExt as _;
use rama_core::extensions::Extensions;
use rama_core::stream::StreamExt;
use rama_core::stream::wrappers::ReceiverStream;
use rama_core::telemetry::tracing::{self, Instrument, trace_span};
use rama_core::{
    error::{BoxError, ErrorContext},
    rt::Executor,
};
use rama_dns::client::resolver::{DnsAddressResolver, HappyEyeballAddressResolverExt};
use rama_dns::client::{GlobalDnsResolver, resolver::DnsAddresssResolverOverwrite};
use rama_net::address::HostWithPort;
use rama_net::mode::ConnectIpMode;
use rama_net::{address::SocketAddress, socket::SocketOptions};
use rama_utils::macros::error::static_str_error;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// a [`TcpStreamConnector`] implementation which
/// denies all incoming tcp connector requests with a [`TcpConnectDeniedError`].
pub struct DenyTcpStreamConnector;

impl DenyTcpStreamConnector {
    #[inline(always)]
    /// Create a new [`Default`] [`DenyTcpStreamConnector`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

static_str_error! {
    #[doc = "TCP connect denied"]
    pub struct TcpConnectDeniedError;
}

impl TcpStreamConnector for DenyTcpStreamConnector {
    type Error = TcpConnectDeniedError;

    async fn connect(&self, _: SocketAddr) -> Result<TcpStream, Self::Error> {
        Err(TcpConnectDeniedError)
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
    type Error = BoxError;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let opts = self.clone();
        tokio::task::spawn_blocking(move || tcp_connect_with_socket_opts(&opts, addr))
            .await
            .context("wait for blocking tcp bind using custom socket opts")?
    }
}

impl TcpStreamConnector for SocketAddress {
    type Error = BoxError;

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
    type Error = BoxError;

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
) -> Result<TcpStream, BoxError> {
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
                        ::rama_core::combinators::$id::$param(s) => s.connect(addr).await.into_box_error(),
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
) -> Result<(TcpStream, SocketAddr), BoxError>
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
) -> Result<(TcpStream, SocketAddr), BoxError>
where
    Dns: DnsAddressResolver,
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
{
    let HostWithPort { host, port } = address;

    let maybe_dns_overwrite = extensions.get::<DnsAddresssResolverOverwrite>().cloned();
    let dns_resolver = (maybe_dns_overwrite, dns);

    let connect_ip_mode = extensions.get().copied().unwrap_or(ConnectIpMode::Dual);

    let ip_stream = dns_resolver
        .happy_eyeballs_resolver(host.clone())
        .with_extensions(extensions)
        .lookup_ip();

    let (tx, rx) = channel(1);
    let recv_stream = ReceiverStream::new(rx);

    let mut output_stream = std::pin::pin!(
        ip_stream
            .map({
                let tx = tx.clone();
                move |result| Either::A((tx.clone(), result))
            })
            .merge(recv_stream.map(Either::B))
    );

    drop(tx);

    let mut resolved_count = 0;
    let connected = Arc::new(AtomicBool::new(false));
    let sem = Arc::new(Semaphore::new(3));

    let mut index = 0;
    while let Some(output) = output_stream.next().await {
        index += 1;

        match output {
            Either::A((tx, ip_result)) => {
                let ip = match ip_result {
                    Ok(ip) => ip,
                    Err(err) => {
                        tracing::debug!("failed to resolve ip addr for host {host}: {err}");
                        continue;
                    }
                };
                resolved_count += 1;

                match (ip, connect_ip_mode) {
                    (IpAddr::V4(_), ConnectIpMode::Ipv6) => {
                        tracing::debug!(
                            "resolved to ipv4 addr {ip} for host {host}: ignored due to ConnectIpMode::Ipv6"
                        );
                        continue;
                    }
                    (IpAddr::V6(_), ConnectIpMode::Ipv4) => {
                        tracing::debug!(
                            "resolved to ipv6 addr {ip} for host {host}: ignored due to ConnectIpMode::Ipv4"
                        );
                        continue;
                    }
                    (IpAddr::V4(_), ConnectIpMode::Ipv4 | ConnectIpMode::Dual)
                    | (IpAddr::V6(_), ConnectIpMode::Ipv6 | ConnectIpMode::Dual) => (),
                };

                let connector = connector.clone();
                let connected = connected.clone();
                let sem = sem.clone();

                exec.spawn_task(
                    tcp_connect_inner_task(index, connector, ip, port, connected, tx, sem)
                        .instrument(trace_span!(
                            "tcp::connect",
                            otel.kind = "client",
                            network.protocol.name = "tcp",
                            network.peer.address = %ip,
                            server.host = %host,
                            %index,
                        )),
                );
            }
            Either::B(stream_and_addr) => {
                connected.store(true, Ordering::Release);
                return Ok(stream_and_addr);
            }
        }
    }

    if resolved_count > 0 {
        Err(
            BoxError::from("failed to (tcp) connect to any resolved IP address")
                .context_field("host", host)
                .context_field("port", port)
                .context_field("resolved_addr_count", resolved_count),
        )
    } else {
        Err(
            BoxError::from("failed to resolve into any IP address (as part of tcp connect)")
                .context_field("host", host)
                .context_field("port", port),
        )
    }
}

async fn tcp_connect_inner_task<Connector>(
    index: usize,
    connector: Connector,
    ip: IpAddr,
    port: u16,
    connected: Arc<AtomicBool>,
    tx: Sender<(TcpStream, SocketAddr)>,
    sem: Arc<Semaphore>,
) where
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
{
    let _permit = match sem.acquire().await {
        Ok(permit) => permit,
        Err(err) => {
            tracing::trace!("[IP | {ip}] #{index}: abort conn; failed to acquire permit: {err}");
            return;
        }
    };

    if connected.load(Ordering::Acquire) {
        tracing::trace!(
            "[IP | {ip}] #{index}: abort spawned attempt to port {port} (connection already established)"
        );
        return;
    }

    tracing::trace!("[IP | {ip}] #{index}: tcp connect attempt to port {port}");

    let addr = (ip, port).into();
    match connector.connect(addr).await {
        Ok(stream) => {
            tracing::trace!("[IP | {ip}] #{index}: tcp connection stablished to port {port}");
            if let Err(err) = tx.send((stream, addr)).await {
                tracing::trace!(
                    "[IP | {ip}] #{index}: failed to send connected stream with peer port {port}: {err:?}"
                );
            }
        }
        Err(err) => {
            let err = err.into_box_error();
            tracing::trace!(
                "[IP | {ip}] #{index}: tcp connector failed to connect to port {port}: {err:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use super::*;
    use rama_dns::client::{DenyAllDnsResolver, EmptyDnsResolver};
    use rama_net::mode::{ConnectIpMode, DnsResolveIpMode};

    async fn test_generic_err<Dns, Connector>(
        dns: Dns,
        connector: Connector,
        extensions: Option<Extensions>,
    ) where
        Dns: DnsAddressResolver,
        Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
    {
        let extensions = extensions.unwrap_or_default();

        let _ = tcp_connect(
            &extensions,
            HostWithPort::example_domain_http(),
            dns,
            connector,
            Executor::default(),
        )
        .await
        .unwrap_err();
    }

    #[tokio::test]
    async fn test_default_tcp_connect_with_dns_deny_and_connector_deny() {
        let dns = DenyAllDnsResolver::new();
        let connector = DenyTcpStreamConnector::new();
        test_generic_err(dns, connector, None).await;
    }

    #[tokio::test]
    async fn test_default_tcp_connect_with_dns_nop_and_connector_deny() {
        let dns = EmptyDnsResolver::new();
        let connector = DenyTcpStreamConnector::new();
        test_generic_err(dns, connector, None).await;
    }

    #[tokio::test]
    async fn test_default_tcp_connect_with_static_ip_and_connector_deny() {
        test_generic_err(Ipv4Addr::LOCALHOST, DenyTcpStreamConnector, None).await;
        test_generic_err(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DenyTcpStreamConnector,
            None,
        )
        .await;
        test_generic_err(Ipv6Addr::LOCALHOST, DenyTcpStreamConnector, None).await;
    }

    #[derive(Debug, Clone)]
    struct PanicTcpConnector;

    impl TcpStreamConnector for PanicTcpConnector {
        type Error = Infallible;

        async fn connect(&self, _: SocketAddr) -> Result<TcpStream, Self::Error> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn test_default_tcp_connect_with_incompatible_dns_mode_and_connector_return_dummy() {
        test_generic_err(Ipv4Addr::LOCALHOST, PanicTcpConnector, {
            let mut ext = Extensions::new();
            ext.insert(DnsResolveIpMode::SingleIpV6);
            Some(ext)
        })
        .await;
        test_generic_err(Ipv6Addr::LOCALHOST, PanicTcpConnector, {
            let mut ext = Extensions::new();
            ext.insert(DnsResolveIpMode::SingleIpV4);
            Some(ext)
        })
        .await;
    }

    #[tokio::test]
    async fn test_default_tcp_connect_with_incompatible_connect_ip_mode_and_connector_return_dummy()
    {
        test_generic_err(Ipv4Addr::LOCALHOST, PanicTcpConnector, {
            let mut ext = Extensions::new();
            ext.insert(ConnectIpMode::Ipv6);
            Some(ext)
        })
        .await;
        test_generic_err(Ipv6Addr::LOCALHOST, PanicTcpConnector, {
            let mut ext = Extensions::new();
            ext.insert(ConnectIpMode::Ipv4);
            Some(ext)
        })
        .await;
    }
}

#[cfg(all(test, any(target_os = "windows", target_family = "unix")))]
mod unix_windows_tests {
    use std::{
        convert::Infallible,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use rama_dns::client::DenyAllDnsResolver;
    use rama_net::{mode::DnsResolveIpMode, socket};

    use super::*;

    #[derive(Debug, Clone)]
    struct DummyTcpConnector;

    impl TcpStreamConnector for DummyTcpConnector {
        type Error = Infallible;

        async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
            let domain = match addr.ip() {
                IpAddr::V4(_) => socket::core::Domain::IPV4,
                IpAddr::V6(_) => socket::core::Domain::IPV6,
            };

            let socket = socket::core::Socket::new(
                domain,
                socket::core::Type::STREAM,
                Some(socket::core::Protocol::TCP),
            )
            .expect("create dummy tcp socket");

            let stream = TcpStream::try_from_socket(socket, Default::default()).unwrap();
            Ok(stream)
        }
    }

    async fn test_generic_ok<Dns>(dns: Dns, extensions: Option<Extensions>)
    where
        Dns: DnsAddressResolver,
    {
        let extensions = extensions.unwrap_or_default();

        let _ = tcp_connect(
            &extensions,
            HostWithPort::example_domain_http(),
            dns,
            DummyTcpConnector,
            Executor::default(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_default_tcp_connect_happy_path_no_extensions() {
        test_generic_ok(Ipv4Addr::LOCALHOST, None).await;
        test_generic_ok(IpAddr::V4(Ipv4Addr::LOCALHOST), None).await;
        test_generic_ok(Ipv6Addr::LOCALHOST, None).await;
    }

    #[tokio::test]
    async fn test_default_tcp_connect_happy_path_explicit_dns_mode() {
        for dns_resolve_ip_mode in [
            DnsResolveIpMode::SingleIpV4,
            DnsResolveIpMode::Dual,
            DnsResolveIpMode::DualPreferIpV4,
        ] {
            test_generic_ok(Ipv4Addr::LOCALHOST, {
                let mut ext = Extensions::new();
                ext.insert(dns_resolve_ip_mode);
                Some(ext)
            })
            .await;
        }

        for dns_resolve_ip_mode in [DnsResolveIpMode::SingleIpV6, DnsResolveIpMode::Dual] {
            test_generic_ok(Ipv6Addr::LOCALHOST, {
                let mut ext = Extensions::new();
                ext.insert(dns_resolve_ip_mode);
                Some(ext)
            })
            .await;
        }
    }

    #[tokio::test]
    async fn test_default_tcp_connect_happy_path_explicit_connect_ip_mode() {
        for connect_ip_mode in [ConnectIpMode::Ipv4, ConnectIpMode::Dual] {
            test_generic_ok(Ipv4Addr::LOCALHOST, {
                let mut ext = Extensions::new();
                ext.insert(connect_ip_mode);
                Some(ext)
            })
            .await;
        }

        for connect_ip_mode in [ConnectIpMode::Ipv6, ConnectIpMode::Dual] {
            test_generic_ok(Ipv6Addr::LOCALHOST, {
                let mut ext = Extensions::new();
                ext.insert(connect_ip_mode);
                Some(ext)
            })
            .await;
        }
    }

    #[tokio::test]
    async fn test_default_tcp_connect_happy_path_with_dns_overwrite() {
        test_generic_ok(DenyAllDnsResolver::new(), {
            let mut ext = Extensions::new();
            ext.insert(DnsAddresssResolverOverwrite::new(Ipv4Addr::LOCALHOST));
            Some(ext)
        })
        .await;

        test_generic_ok(DenyAllDnsResolver::new(), {
            let mut ext = Extensions::new();
            ext.insert(DnsAddresssResolverOverwrite::new(Ipv6Addr::LOCALHOST));
            Some(ext)
        })
        .await;
    }
}
