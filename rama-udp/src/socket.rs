use std::net::SocketAddr;

use rama_core::{
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::Extensions,
    futures::StreamExt,
    telemetry::tracing,
};
use rama_dns::client::{
    GlobalDnsResolver,
    resolver::{DnsAddressResolver, HappyEyeballAddressResolverExt},
};
use rama_net::{
    address::{HostWithPort, SocketAddress},
    socket::Interface,
};

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use rama_net::socket::{DeviceName, SocketOptions};

pub use tokio::net::UdpSocket;

/// Bind a [`UdpSocket`] to the local interface and connect
/// to the given host and port using the global DNS resolver,
/// in case the host is a Domain, otherwise the IpAddr will be used as-is.
///
/// This is a convenience wrapper around [`bind_udp_socket_with_connect`] that uses
/// [`GlobalDnsResolver`].
///
/// Returns an error if the host is not compatible or cannot be resolve
/// or if all resolved addresses fail to connect.
///
/// Calling `connect` on a UDP socket does not establish a transport level
/// session. It sets the default remote peer and allows using `send` instead
/// of `send_to`.
#[inline(always)]
pub async fn bind_udp_socket_with_connect_default_dns(
    address: impl Into<HostWithPort>,
    extensions: Option<&Extensions>,
) -> Result<UdpSocket, BoxError> {
    bind_udp_socket_with_connect(address, GlobalDnsResolver::new(), extensions).await
}

/// Bind a [`UdpSocket`] to the local interface and connect
/// to the given host and port using the provided DNS resolver,
/// in case the host is a Domain, otherwise the IpAddr will be used as-is.
///
/// The host, if a domain, is resolved using a Happy Eyeballs strategy and each resolved IP
/// address is attempted in order until the socket successfully connects.
/// The first successful connection attempt completes the function. The strategy
/// also respects IP/Dns connect/resolve preferences (e.g. Ipv6 addresses won't
/// be allowed if running in Ipv4 only modes), even if host was an Ip to begin with.
///
/// Returns an error if the host is not compatible or
/// does not resolve to any IP address or
/// if all resolved addresses fail to connect.
///
/// Connecting a UDP socket configures its default remote peer and
/// restricts incoming datagrams to that peer. It does not perform a
/// handshake or guarantee reachability.
pub async fn bind_udp_socket_with_connect<Dns>(
    address: impl Into<HostWithPort>,
    dns: Dns,
    extensions: Option<&Extensions>,
) -> Result<UdpSocket, BoxError>
where
    Dns: DnsAddressResolver,
{
    let HostWithPort { host, port } = address.into();
    let mut ip_stream = std::pin::pin!(
        dns.happy_eyeballs_resolver(host.clone())
            .maybe_with_extensions(extensions)
            .lookup_ip()
    );

    let mut ipv4_socket = None;
    let mut ipv6_socket = None;

    let mut resolved_count = 0;

    while let Some(ip_result) = ip_stream.next().await {
        let ip = match ip_result {
            Ok(ip) => {
                resolved_count += 1;
                ip
            }
            Err(err) => {
                tracing::debug!("failed to resolve IP address for host {host}: {err}");
                continue;
            }
        };

        let address: SocketAddr = (ip, port).into();

        if address.is_ipv4() {
            let socket = if let Some(socket) = ipv4_socket.take() {
                socket
            } else {
                match bind_udp_with_address(SocketAddress::default_ipv4(0)).await {
                    Ok(socket) => socket,
                    Err(err) => {
                        tracing::debug!(
                            "failed to bind default Ipv4 socket.. ignore ipv4 address {address} (host = {host}): err = {err}"
                        );
                        continue;
                    }
                }
            };

            match socket.connect(address).await {
                Ok(()) => {
                    tracing::trace!(
                        "resolved#{resolved_count} udp socket connected to IpV4 address: {address} (resolved from host {host})"
                    );
                    return Ok(socket);
                }
                Err(err) => {
                    ipv4_socket = Some(socket);
                    tracing::trace!(
                        "resolved#{resolved_count} udp socket failed to connect to IpV4 address: {address} (resolved from host {host}): err = {err}"
                    );
                }
            }
        } else {
            let socket = if let Some(socket) = ipv6_socket.take() {
                socket
            } else {
                match bind_udp_with_address(SocketAddress::default_ipv6(0)).await {
                    Ok(socket) => socket,
                    Err(err) => {
                        tracing::debug!(
                            "failed to bind default Ipv6 socket.. ignore IpV4 address {address} (host = {host}): err = {err}"
                        );
                        continue;
                    }
                }
            };

            match socket.connect(address).await {
                Ok(()) => {
                    tracing::trace!(
                        "resolved#{resolved_count} udp socket connected to IpV6 address: {address} (resolved from host {host})"
                    );
                    return Ok(socket);
                }
                Err(err) => {
                    ipv6_socket = Some(socket);
                    tracing::trace!(
                        "resolved#{resolved_count} udp socket failed to connect to IpV6 address: {address} (resolved from host {host}): err = {err}"
                    );
                }
            }
        }
    }

    if resolved_count > 0 {
        Err(
            BoxError::from("failed to (udp) connect to any resolved IP address")
                .context_field("host", host)
                .context_field("port", port)
                .context_field("resolved_addr_count", resolved_count),
        )
    } else {
        Err(
            BoxError::from("failed to resolve into any IP address (as part of udp connect)")
                .context_field("host", host)
                .context_field("port", port),
        )
    }
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
    tokio::task::spawn_blocking(|| bind_socket_internal(socket))
        .await
        .context("await blocking bind socket task")?
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
    tokio::task::spawn_blocking(|| {
        let name = name.try_into().map_err(Into::<BoxError>::into)?;
        let socket = SocketOptions {
            device: Some(name),
            ..SocketOptions::default_udp()
        }
        .try_build_socket()
        .context("create udp ipv4 socket attached to device")?;
        bind_socket_internal(socket)
    })
    .await
    .context("await blocking bind socket task")?
}

/// Creates a new [`UdpSocket`], which will be bound to the specified [`Interface`].
///
/// The returned socket is ready for accepting connections and connecting to others.
pub async fn bind_udp<I: TryInto<Interface, Error: Into<BoxError>>>(
    interface: I,
) -> Result<UdpSocket, BoxError> {
    match interface.try_into().map_err(Into::<BoxError>::into)? {
        Interface::Address(addr) => bind_udp_with_address(addr).await,
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        Interface::Device(name) => bind_udp_with_device(name).await,
        Interface::Socket(opts) => {
            let socket = opts
                .try_build_socket()
                .context("build udp socket from options")?;
            bind_udp_with_socket(socket).await
        }
    }
}

fn bind_socket_internal(socket: rama_net::socket::core::Socket) -> Result<UdpSocket, BoxError> {
    let socket = std::net::UdpSocket::from(socket);
    socket
        .set_nonblocking(true)
        .context("set socket as non-blocking")?;
    Ok(UdpSocket::from_std(socket)?)
}
