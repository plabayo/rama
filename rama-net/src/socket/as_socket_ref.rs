use super::core::SockRef;

/// Borrow a platform socket as a [`SockRef`].
///
/// Implementations are intentionally limited to socket types. A blanket over
/// `AsFd` would also admit regular files, terminals, and pipes even though
/// those descriptors cannot accept socket options.
pub trait AsSocketRef {
    /// Return a non-owning reference to this socket.
    fn as_socket_ref(&self) -> SockRef<'_>;
}

macro_rules! impl_as_socket_ref {
    ($($ty:ty),+ $(,)?) => {$ (
        impl AsSocketRef for $ty {
            #[inline]
            fn as_socket_ref(&self) -> SockRef<'_> {
                SockRef::from(self)
            }
        }
    )+ };
}

#[cfg(target_family = "unix")]
impl_as_socket_ref!(
    super::core::Socket,
    std::net::TcpStream,
    std::net::TcpListener,
    std::net::UdpSocket,
    tokio::net::TcpStream,
    tokio::net::TcpListener,
    tokio::net::UdpSocket,
);

#[cfg(target_os = "windows")]
impl_as_socket_ref!(
    super::core::Socket,
    std::net::TcpStream,
    std::net::TcpListener,
    std::net::UdpSocket,
    tokio::net::TcpStream,
    tokio::net::TcpListener,
    tokio::net::UdpSocket,
);
