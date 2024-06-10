use std::io::Result;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
/// An address that can be set by any service or middleware,
/// to make connectors connect to the specified [`SocketAddr`],
/// instead of resolving it first (e.g. from the [`Request`] [`Uri`])
///
/// [`Request`]: crate::http::Request
/// [`Uri`]: crate::http::Uri
pub struct ServerSocketAddr(SocketAddr);

impl ServerSocketAddr {
    /// Create a new [`ServerSocketAddr`] for the given target [`SocketAddr`].
    pub fn new(target: SocketAddr) -> Self {
        Self(target)
    }

    /// Get the target [`SocketAddr`] of this [`ServerSocketAddr`].
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    pub fn addr(&self) -> &SocketAddr {
        &self.0
    }
}

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

#[derive(Debug, Clone)]
/// Connected socket information.
pub struct SocketInfo {
    local_addr: Option<SocketAddr>,
    peer_addr: SocketAddr,
}

impl SocketInfo {
    /// Create a new `SocketInfo`.
    pub fn new(local_addr: Option<SocketAddr>, peer_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            peer_addr,
        }
    }

    /// Get the local address of the socket.
    pub fn local_addr(&self) -> Option<&SocketAddr> {
        self.local_addr.as_ref()
    }

    /// Get the peer address of the socket.
    pub fn peer_addr(&self) -> &SocketAddr {
        &self.peer_addr
    }
}
