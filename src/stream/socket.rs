use std::io::Result;
use std::net::SocketAddr;

/// Common information exposed by a Socket-like construct.
///
/// For now this is implemented for TCP and UDP, as these
/// are the types that are relevant to Rama.
pub trait Socket: Send + Sync + 'static {
    /// Try to get the local address of the socket.
    fn local_addr(&self) -> Result<SocketAddr>;

    /// Try to get the remote address of the socket.
    fn peer_addr(&self) -> Result<SocketAddr>;
}

impl Socket for std::net::TcpStream {
    #[inline]
    fn local_addr(&self) -> Result<SocketAddr> {
        self.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Result<SocketAddr> {
        self.peer_addr()
    }
}

impl Socket for tokio::net::TcpStream {
    #[inline]
    fn local_addr(&self) -> Result<SocketAddr> {
        self.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Result<SocketAddr> {
        self.peer_addr()
    }
}

impl Socket for std::net::UdpSocket {
    #[inline]
    fn local_addr(&self) -> Result<SocketAddr> {
        self.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Result<SocketAddr> {
        self.peer_addr()
    }
}

impl Socket for tokio::net::UdpSocket {
    #[inline]
    fn local_addr(&self) -> Result<SocketAddr> {
        self.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Result<SocketAddr> {
        self.peer_addr()
    }
}
