use std::net::SocketAddr;

use rama_core::error::{BoxError, ErrorContext as _};

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use rama_net::socket::{DeviceName, SocketOptions};
use rama_net::{address::SocketAddress, socket::Interface};

pub use tokio::net::UdpSocket;

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
    let socket_addr = addr.try_into().map_err(Into::into)?;
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
