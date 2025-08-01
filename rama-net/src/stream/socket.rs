use std::io::Result;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};

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
/// Information about the socket on the egress end.
pub struct ClientSocketInfo(pub SocketInfo);

impl AsRef<SocketInfo> for ClientSocketInfo {
    fn as_ref(&self) -> &SocketInfo {
        &self.0
    }
}

impl AsMut<SocketInfo> for ClientSocketInfo {
    fn as_mut(&mut self) -> &mut SocketInfo {
        &mut self.0
    }
}

impl Deref for ClientSocketInfo {
    type Target = SocketInfo;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for ClientSocketInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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
    #[must_use]
    pub const fn new(local_addr: Option<SocketAddr>, peer_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            peer_addr,
        }
    }

    /// Get the local address of the socket.
    #[must_use]
    pub fn local_addr(&self) -> Option<&SocketAddr> {
        self.local_addr.as_ref()
    }

    /// Get the peer address of the socket.
    #[must_use]
    pub fn peer_addr(&self) -> &SocketAddr {
        &self.peer_addr
    }
}
