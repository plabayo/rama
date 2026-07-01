use rama_core::error::{BoxError, ErrorContext};
use rama_core::error::{BoxErrorExt as _, ErrorExt as _};
use rama_core::extensions::Extensions;
use rama_core::telemetry::tracing;
use rama_net::address::{HostWithPort, ip::IntoCanonicalIpAddr as _};
use rama_net::mode::ConnectIpMode;
use rama_net::{address::SocketAddress, socket::SocketOptions};
use rama_utils::macros::error::static_str_error;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use crate::TcpStream;

/// Trait used internally by [`tcp_connect`] and the `TcpConnector`
/// to actually establish the [`TcpStream`]
pub trait TcpStreamConnector: Send + Sync + 'static {
    /// Type of error that can occurr when establishing the connection failed.
    type Error: Send + 'static;

    /// Connect to the target via the given [`SocketAddr`]ess to establish a [`TcpStream`].
    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, Self::Error>> + Send + '_;
}

impl TcpStreamConnector for () {
    type Error = std::io::Error;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        // v4-mapped IPv6 is IPv4 wire traffic: dial it as such
        // (see `IntoCanonicalIpAddr`; RFC 4291, Section 2.5.5.2)
        let stream = tokio::net::TcpStream::connect(addr.into_canonical_ip_addr()).await?;
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
        tcp_connect_with_socket_opts_async(self, addr).await
    }
}

impl TcpStreamConnector for SocketAddress {
    type Error = BoxError;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let bind_addr = *self;
        let opts = SocketOptions {
            address: Some(bind_addr),
            ..SocketOptions::default_tcp()
        };
        tcp_connect_with_socket_opts_async(&opts, addr).await
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
)]
impl TcpStreamConnector for rama_net::socket::DeviceName {
    type Error = BoxError;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let bind_interface = self.clone();
        tcp_connect_with_socket_opts_async(
            &SocketOptions {
                device: Some(bind_interface),
                ..SocketOptions::default_tcp()
            },
            addr,
        )
        .await
    }
}

async fn tcp_connect_with_socket_opts_async(
    opts: &SocketOptions,
    addr: SocketAddr,
) -> Result<TcpStream, BoxError> {
    // dial canonical (RFC 4291, Section 2.5.5.2) — the socket family derives from it
    let addr = addr.into_canonical_ip_addr();
    let socket = opts
        .try_build_socket(addr.into())
        .context("try to build TCP socket's underlying OS socket")?;
    socket
        .set_nonblocking(true)
        .context("set socket non-blocking before connect")?;
    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(err) if nonblocking_connect_in_progress(&err) => {}
        Err(err) => {
            return Err(err)
                .context("connect to the provided socket addr")
                .into_box_error();
        }
    }
    let stream = TcpStream::try_from_connecting_socket(socket, Default::default())
        .await
        .context("complete nonblocking connect to the provided socket addr")?;

    Ok(stream)
}

fn nonblocking_connect_in_progress(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::AlreadyExists
    ) || nonblocking_connect_in_progress_os(err)
}

#[cfg(target_family = "unix")]
fn nonblocking_connect_in_progress_os(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EINPROGRESS | libc::EALREADY))
}

#[cfg(not(target_family = "unix"))]
fn nonblocking_connect_in_progress_os(_err: &std::io::Error) -> bool {
    false
}

impl<ConnectFn, ConnectFnFut, ConnectFnErr> TcpStreamConnector for ConnectFn
where
    ConnectFn: Fn(SocketAddr) -> ConnectFnFut + Send + Sync + 'static,
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
) -> Result<(TcpStream, SocketAddr), BoxError>
where
{
    tcp_connect(extensions, address, &()).await
}

/// Establish a [`TcpStream`] connection for the given [`HostWithPort`].
///
/// The host must be an IP address. Domain-name resolution belongs in
/// `rama-dns` connector middleware.
///
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are canonicalized to
/// the embedded IPv4 address, as they identify IPv4 wire traffic.
pub async fn tcp_connect<Connector>(
    extensions: &Extensions,
    address: HostWithPort,
    connector: &Connector,
) -> Result<(TcpStream, SocketAddr), BoxError>
where
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static>,
{
    let HostWithPort { host, port } = address;
    let connect_ip_mode = extensions.get_ref().copied().unwrap_or(ConnectIpMode::Dual);

    let ip = host
        .try_as_ip()
        .context("tcp connector target host is not an IP address")?
        .into_canonical_ip_addr();

    match (ip, connect_ip_mode) {
        (IpAddr::V4(_), ConnectIpMode::Ipv6) => {
            return Err(BoxError::from_static_str("IPv4 address is not allowed")
                .context_field("host", host)
                .context_field("port", port));
        }
        (IpAddr::V6(_), ConnectIpMode::Ipv4) => {
            return Err(BoxError::from_static_str("IPv6 address is not allowed")
                .context_field("host", host)
                .context_field("port", port));
        }
        (IpAddr::V4(_), ConnectIpMode::Ipv4 | ConnectIpMode::Dual)
        | (IpAddr::V6(_), ConnectIpMode::Ipv6 | ConnectIpMode::Dual) => (),
    }

    let addr = SocketAddr::from((ip, port));
    tracing::trace!(
        network.protocol.name = "tcp",
        network.peer.address = %ip,
        network.peer.port = port,
        "tcp connect attempt",
    );

    let stream = connector
        .connect(addr)
        .await
        .into_box_error()
        .context("tcp connector failed to connect to IP address")?;

    Ok((stream, addr))
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use super::*;
    use rama_net::mode::ConnectIpMode;

    #[tokio::test]
    async fn tcp_connect_rejects_domain_target_before_dialing() {
        let ext = Extensions::new();
        tcp_connect(
            &ext,
            HostWithPort::example_domain_http(),
            &PanicTcpConnector,
        )
        .await
        .unwrap_err();
    }

    #[tokio::test]
    async fn test_default_tcp_connect_with_incompatible_connect_ip_mode_and_connector_return_dummy()
    {
        test_generic_err((Ipv4Addr::LOCALHOST, 443).into(), &PanicTcpConnector, {
            let ext = Extensions::new();
            ext.insert(ConnectIpMode::Ipv6);
            Some(ext)
        })
        .await;
        test_generic_err((Ipv6Addr::LOCALHOST, 443).into(), &PanicTcpConnector, {
            let ext = Extensions::new();
            ext.insert(ConnectIpMode::Ipv4);
            Some(ext)
        })
        .await;
    }

    async fn test_generic_err<Connector>(
        address: HostWithPort,
        connector: &Connector,
        extensions: Option<Extensions>,
    ) where
        Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static>,
    {
        let extensions = extensions.unwrap_or_default();
        _ = tcp_connect(&extensions, address, connector)
            .await
            .unwrap_err();
    }

    #[derive(Debug, Clone)]
    struct PanicTcpConnector;

    impl TcpStreamConnector for PanicTcpConnector {
        type Error = Infallible;

        #[expect(
            clippy::unreachable,
            reason = "test fixture: this connector is wired up but the tested code path never invokes it"
        )]
        async fn connect(&self, _: SocketAddr) -> Result<TcpStream, Self::Error> {
            unreachable!()
        }
    }

    #[derive(Clone, Default)]
    struct RecordingDenyConnector {
        addrs: Arc<rama_utils::collections::AppendOnlyVec<SocketAddr>>,
    }

    impl RecordingDenyConnector {
        fn recorded_addrs(&self) -> Vec<SocketAddr> {
            self.addrs.iter().copied().collect()
        }
    }

    impl TcpStreamConnector for RecordingDenyConnector {
        type Error = TcpConnectDeniedError;

        async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
            self.addrs.push(addr);
            Err(TcpConnectDeniedError)
        }
    }

    #[tokio::test]
    async fn test_tcp_connect_canonicalizes_v4_mapped_ipv6_target() {
        // `::ffff:127.0.0.1` identifies IPv4 wire traffic (dual-stack
        // socket form, e.g. WFP redirect targets on Windows): the
        // connector must be asked to connect to the embedded IPv4
        // address, never to an (AF_INET6) v4-mapped one.
        let connector = RecordingDenyConnector::default();
        let ext = Extensions::new();
        let target: IpAddr = "::ffff:127.0.0.1".parse().unwrap();

        let result = tcp_connect(&ext, (target, 443).into(), &connector).await;
        assert!(result.is_err(), "deny connector: connect must fail");

        assert_eq!(
            connector.recorded_addrs(),
            vec![SocketAddr::from(([127, 0, 0, 1], 443))]
        );
    }

    #[tokio::test]
    async fn test_tcp_connect_v4_mapped_ipv6_target_counts_as_ipv4_for_connect_ip_mode() {
        let target: IpAddr = "::ffff:127.0.0.1".parse().unwrap();

        // allowed under IPv4-only connect mode (it IS IPv4 traffic)...
        let connector = RecordingDenyConnector::default();
        let ext = Extensions::new();
        ext.insert(ConnectIpMode::Ipv4);
        let result = tcp_connect(&ext, (target, 443).into(), &connector).await;
        assert!(result.is_err(), "deny connector: connect must fail");
        assert_eq!(
            connector.recorded_addrs(),
            vec![SocketAddr::from(([127, 0, 0, 1], 443))]
        );

        // ...and rejected under IPv6-only connect mode, without
        // ever reaching the connector.
        let ext = Extensions::new();
        ext.insert(ConnectIpMode::Ipv6);
        let result = tcp_connect(&ext, (target, 443).into(), &PanicTcpConnector).await;
        assert!(
            result.is_err(),
            "v4-mapped target must be rejected in IPv6-only mode"
        );
    }
}

#[cfg(all(test, any(target_os = "windows", target_family = "unix")))]
mod unix_windows_tests {
    use super::*;

    // The dial primitives canonicalize themselves, so even a raw
    // (resolver-bypassing) `TcpStreamConnector` call with a v4-mapped
    // target must dial the embedded IPv4 address.

    #[expect(
        clippy::unwrap_used,
        reason = "test helper: cfg(test) module, but clippy's allow-*-in-tests detection doesn't propagate through this generic test fn"
    )]
    async fn test_generic_connector_dials_v4_mapped_target_as_ipv4<C>(connector: C)
    where
        C: TcpStreamConnector<Error: std::fmt::Debug>,
    {
        use rama_net::stream::Socket as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let target: SocketAddr = format!("[::ffff:127.0.0.1]:{port}").parse().unwrap();
        let stream = connector.connect(target).await.unwrap();
        assert_eq!(
            stream.peer_addr().unwrap(),
            SocketAddress::from(([127, 0, 0, 1], port))
        );
    }

    #[tokio::test]
    async fn test_unit_connector_dials_v4_mapped_target_as_ipv4() {
        test_generic_connector_dials_v4_mapped_target_as_ipv4(()).await;
    }

    #[tokio::test]
    async fn test_socket_opts_connector_dials_v4_mapped_target_as_ipv4() {
        test_generic_connector_dials_v4_mapped_target_as_ipv4(Arc::new(
            SocketOptions::default_tcp(),
        ))
        .await;
    }
}
