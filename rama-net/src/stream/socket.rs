use std::io::Result;
use std::ops::{Deref, DerefMut};

use rama_core::ServiceInput;

use crate::address::SocketAddress;

/// Common information exposed by a Socket-like construct.
///
/// For now this is implemented for TCP and UDP, as these
/// are the types that are relevant to Rama.
pub trait Socket: Send + Sync + 'static {
    /// Try to get the local address of the socket.
    fn local_addr(&self) -> Result<SocketAddress>;

    /// Try to get the remote address of the socket.
    fn peer_addr(&self) -> Result<SocketAddress>;
}

impl Socket for std::net::TcpStream {
    #[inline]
    fn local_addr(&self) -> Result<SocketAddress> {
        self.local_addr().map(Into::into)
    }

    #[inline]
    fn peer_addr(&self) -> Result<SocketAddress> {
        self.peer_addr().map(Into::into)
    }
}

impl Socket for tokio::net::TcpStream {
    #[inline]
    fn local_addr(&self) -> Result<SocketAddress> {
        self.local_addr().map(Into::into)
    }

    #[inline]
    fn peer_addr(&self) -> Result<SocketAddress> {
        self.peer_addr().map(Into::into)
    }
}

impl Socket for std::net::UdpSocket {
    #[inline]
    fn local_addr(&self) -> Result<SocketAddress> {
        self.local_addr().map(Into::into)
    }

    #[inline]
    fn peer_addr(&self) -> Result<SocketAddress> {
        self.peer_addr().map(Into::into)
    }
}

impl Socket for tokio::net::UdpSocket {
    #[inline]
    fn local_addr(&self) -> Result<SocketAddress> {
        self.local_addr().map(Into::into)
    }

    #[inline]
    fn peer_addr(&self) -> Result<SocketAddress> {
        self.peer_addr().map(Into::into)
    }
}

impl<T: Socket> Socket for ServiceInput<T> {
    #[inline]
    fn local_addr(&self) -> std::io::Result<SocketAddress> {
        self.input.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> std::io::Result<SocketAddress> {
        self.input.peer_addr()
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
    local_addr: Option<SocketAddress>,
    peer_addr: SocketAddress,
}

impl SocketInfo {
    /// Create a new `SocketInfo`.
    #[must_use]
    pub fn new(local_addr: Option<SocketAddress>, peer_addr: SocketAddress) -> Self {
        Self {
            local_addr,
            peer_addr,
        }
    }

    /// Get the local address of the socket.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddress> {
        self.local_addr
    }

    /// Get the peer address of the socket.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddress {
        self.peer_addr
    }
}
