//! TCP server module for Rama.

use std::net::SocketAddr;

mod listener;
pub use listener::{TcpListener, TcpListenerBuilder};

#[derive(Debug, Clone)]
/// TCP socket information of an incoming Tcp connection.
pub struct TcpSocketInfo {
    local_addr: Option<SocketAddr>,
    peer_addr: SocketAddr,
}

impl TcpSocketInfo {
    /// Create a new `TcpSocketInfo`.
    pub(crate) fn new(local_addr: Option<SocketAddr>, peer_addr: SocketAddr) -> Self {
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
