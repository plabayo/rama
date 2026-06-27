use rama_core::error::BoxErrorExt as _;
use std::net::SocketAddr;

use rama_core::{
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::Extensions,
    telemetry::tracing,
};
use rama_net::{
    address::{HostWithPort, SocketAddress, ip::IntoCanonicalIpAddr as _},
    mode::ConnectIpMode,
};

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use rama_net::socket::{DeviceName, SocketOptions, opts::Domain};

pub use tokio::net::UdpSocket;

/// Bind a [`UdpSocket`] to the local interface and connect
/// to the given IP host and port.
///
/// The host must be an IP address. Domain-name resolution belongs in
/// `rama-dns` connector middleware.
///
/// This helper respects IP connect preferences (e.g. Ipv6 addresses won't
/// be allowed if running in Ipv4 only modes).
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are canonicalized to the embedded
/// IPv4 address, as they identify IPv4 wire traffic.
///
/// Connecting a UDP socket configures its default remote peer and
/// restricts incoming datagrams to that peer. It does not perform a
/// handshake or guarantee reachability.
pub async fn bind_udp_socket_with_connect(
    address: impl Into<HostWithPort>,
    extensions: Option<&Extensions>,
) -> Result<UdpSocket, BoxError> {
    let HostWithPort { host, port } = address.into();
    let ip = host
        .try_as_ip()
        .context("udp connector target host is not an IP address")?
        .into_canonical_ip_addr();

    let mode = extensions
        .and_then(|ext| ext.get_ref().copied())
        .unwrap_or(ConnectIpMode::Dual);
    match (ip, mode) {
        (std::net::IpAddr::V4(_), ConnectIpMode::Ipv6) => {
            return Err(BoxError::from_static_str("IPv4 address is not allowed")
                .context_field("host", host)
                .context_field("port", port));
        }
        (std::net::IpAddr::V6(_), ConnectIpMode::Ipv4) => {
            return Err(BoxError::from_static_str("IPv6 address is not allowed")
                .context_field("host", host)
                .context_field("port", port));
        }
        (std::net::IpAddr::V4(_), ConnectIpMode::Ipv4 | ConnectIpMode::Dual)
        | (std::net::IpAddr::V6(_), ConnectIpMode::Ipv6 | ConnectIpMode::Dual) => {}
    }

    let address: SocketAddr = (ip, port).into();
    let bind_address = if address.is_ipv4() {
        SocketAddress::default_ipv4(0)
    } else {
        SocketAddress::default_ipv6(0)
    };
    let socket = bind_udp_with_address(bind_address).await?;
    socket
        .connect(address)
        .await
        .with_context(|| format!("udp socket connect to IP address: {address}"))?;
    tracing::trace!("udp socket connected to IP address: {address}");
    Ok(socket)
}

/// Creates a new [`UdpSocket`], which will be bound to the specified address.
///
/// The returned socket is ready for accepting connections and connecting to others.
///
/// Binding with a port number of 0 will request that the OS assigns a port
/// to this listener. The port allocated can be queried via the `local_addr`
/// method.
pub async fn bind_udp_with_address<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
    addr: A,
) -> Result<UdpSocket, BoxError> {
    let socket_addr = addr.try_into().into_box_error()?;
    let tokio_socket_addr: SocketAddr = socket_addr.into();
    let socket = UdpSocket::bind(tokio_socket_addr)
        .await
        .context("bind to udp socket")?;
    Ok(socket)
}

#[cfg(any(target_os = "windows", target_family = "unix"))]
#[cfg_attr(docsrs, doc(cfg(any(target_os = "windows", target_family = "unix"))))]
/// Creates a new [`UdpSocket`], which will be bound to the specified socket.
///
/// The returned socket is ready for accepting connections and connecting to others.
pub async fn bind_udp_with_socket(
    socket: rama_net::socket::core::Socket,
) -> Result<UdpSocket, BoxError> {
    bind_socket_internal(socket)
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
)]
/// Creates a new [`UdpSocket`], which will be bound to the specified (interface) device name).
///
/// The returned socket is ready for accepting connections and connecting to others.
pub async fn bind_udp_with_device<
    N: TryInto<DeviceName, Error: Into<BoxError>> + Send + 'static,
>(
    name: N,
) -> Result<UdpSocket, BoxError> {
    let name = name.try_into().map_err(Into::<BoxError>::into)?;
    let socket = SocketOptions {
        device: Some(name),
        ..SocketOptions::default_udp()
    }
    .try_build_socket(Domain::Unix)
    .context("create udp ipv4 socket attached to device")?;
    bind_socket_internal(socket)
}

fn bind_socket_internal(socket: rama_net::socket::core::Socket) -> Result<UdpSocket, BoxError> {
    let socket = std::net::UdpSocket::from(socket);
    socket
        .set_nonblocking(true)
        .context("set socket as non-blocking")?;
    Ok(UdpSocket::from_std(socket)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_udp_socket_with_connect_canonicalizes_v4_mapped_ipv6_target() {
        let anchor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = anchor.local_addr().unwrap().port();

        // `::ffff:127.0.0.1` identifies IPv4 wire traffic (dual-stack
        // socket form, e.g. WFP redirect targets on Windows): an IPv4
        // socket must be bound and connected to the embedded IPv4
        // address, instead of attempting it as IPv6.
        let target: std::net::IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let socket = bind_udp_socket_with_connect((target, port), None)
            .await
            .unwrap();

        assert_eq!(
            socket.peer_addr().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], port))
        );
        assert!(socket.local_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn bind_udp_socket_with_connect_plain_ipv4_target() {
        let anchor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = anchor.local_addr().unwrap().port();

        let target: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let socket = bind_udp_socket_with_connect((target, port), None)
            .await
            .unwrap();

        assert_eq!(
            socket.peer_addr().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], port))
        );
    }
}
