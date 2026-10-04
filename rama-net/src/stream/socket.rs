use std::io::Result;

use crate::address::SocketAddress;

use rama_core::ServiceInput;
use rama_core::extensions::{Extension, Extensions};

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

#[derive(Debug, Clone, Extension)]
#[extension(tags(net))]
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

    /// The [`SocketInfo`] of the connection `extensions` arrived on: from its
    /// ingress view, otherwise its own, never an outbound (egress) connection's.
    #[must_use]
    pub fn ingress(extensions: &Extensions) -> Option<&Self> {
        if let Some(info) = extensions.ingress().and_then(|ingress| ingress.get_ref()) {
            return Some(info);
        }
        let mut scope = Some(extensions);
        while let Some(current) = scope {
            if let Some(info) = current.self_get_ref() {
                return Some(info);
            }
            scope = current.parent();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::{Egress, Ingress};

    fn view(peer: &str) -> Extensions {
        let extensions = Extensions::new();
        extensions.insert(SocketInfo::new(None, peer.parse().unwrap()));
        extensions
    }

    #[test]
    fn the_ingress_socket_is_never_an_egress_one() {
        let client = "203.0.113.5:1000";
        let upstream = "198.51.100.7:443";

        let ingress_view = Extensions::new();
        ingress_view.insert(Ingress(view(client)));
        let own = view(client);
        let parent = view(client);
        let forked = parent.fork();
        let own_and_ingress = view("192.0.2.1:1");
        own_and_ingress.insert(Ingress(view(client)));

        for (name, extensions) in [
            ("ingress view", &ingress_view),
            ("own", &own),
            ("parent", &forked),
            ("ingress view over own", &own_and_ingress),
        ] {
            extensions.insert(Egress(view(upstream)));
            assert_eq!(
                SocketInfo::ingress(extensions).map(|info| info.peer_addr().to_string()),
                Some(client.to_owned()),
                "{name}"
            );
        }

        let egress_only = Extensions::new();
        egress_only.insert(Egress(view(upstream)));
        assert!(SocketInfo::ingress(&egress_only).is_none());
    }
}
