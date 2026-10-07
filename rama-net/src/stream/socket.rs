use std::io::Result;

use crate::address::SocketAddress;

use rama_core::ServiceInput;
use rama_core::extensions::{Egress, Extension, Extensions, Ingress};

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

    /// The [`SocketInfo`] of the connection `extensions` arrived on, never an outbound
    /// (egress) connection's, whatever the insertion order.
    ///
    /// The nearest ingress view of this store or its parents is resolved first, by the same
    /// rule; otherwise the nearest own [`SocketInfo`]. Egress views are never entered.
    #[must_use]
    pub fn ingress(extensions: &Extensions) -> Option<&Self> {
        let scopes = || core::iter::successors(Some(extensions), |scope| scope.parent());
        scopes()
            .find_map(|scope| scope.self_get_ref::<Ingress<Extensions>>())
            .and_then(|view| Self::ingress(&view.0))
            .or_else(|| scopes().find_map(|scope| scope.self_get_ref()))
    }

    /// The [`SocketInfo`] of the outbound (egress) connection `extensions` went out on,
    /// never the connection it arrived on, whatever the insertion order.
    ///
    /// The nearest egress view of this store or its parents decides: its own nearest egress
    /// view first, by the same rule, else its own [`SocketInfo`]. Ingress views are never
    /// entered, and a store without an egress view has none.
    #[must_use]
    pub fn egress(extensions: &Extensions) -> Option<&Self> {
        let view = core::iter::successors(Some(extensions), |scope| scope.parent())
            .find_map(|scope| scope.self_get_ref::<Egress<Extensions>>())?;
        Self::egress(&view.0).or_else(|| {
            core::iter::successors(Some(&view.0), |scope| scope.parent())
                .find_map(|scope| scope.self_get_ref())
        })
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

    /// Nested views: an egress view inside the ingress one, or an ingress view inside an
    /// egress one, never decide, whichever was inserted last.
    #[test]
    fn nested_egress_views_are_never_entered() {
        let client = "203.0.113.5:1000";
        let upstream = "127.0.0.1:9000";

        let egress_inside_ingress = Extensions::new();
        let ingress = view(client);
        ingress.insert(Egress(view(upstream)));
        egress_inside_ingress.insert(Ingress(ingress));

        let ingress_inside_egress = Extensions::new();
        ingress_inside_egress.insert(Ingress(view(client)));
        let egress = view("198.51.100.7:443");
        egress.insert(Ingress(view(upstream)));
        ingress_inside_egress.insert(Egress(egress));

        let parent_ingress = Extensions::new();
        parent_ingress.insert(Ingress(view(client)));
        let forked = parent_ingress.fork();
        forked.insert(Egress(view(upstream)));

        let nested_ingress = Extensions::new();
        let carrier = Extensions::new();
        carrier.insert(Ingress(view(client)));
        carrier.insert(Egress(view(upstream)));
        nested_ingress.insert(Ingress(carrier));

        for (name, extensions) in [
            ("egress inside ingress", &egress_inside_ingress),
            ("ingress inside egress", &ingress_inside_egress),
            ("parent ingress view", &forked),
            ("ingress inside ingress", &nested_ingress),
        ] {
            assert_eq!(
                SocketInfo::ingress(extensions).map(|info| info.peer_addr().to_string()),
                Some(client.to_owned()),
                "{name}"
            );
        }

        let egress_with_ingress_only = Extensions::new();
        let egress = Extensions::new();
        egress.insert(Ingress(view(upstream)));
        egress_with_ingress_only.insert(Egress(egress));
        assert!(SocketInfo::ingress(&egress_with_ingress_only).is_none());
    }

    #[test]
    fn the_egress_socket_is_never_an_ingress_one() {
        let client = "203.0.113.5:1000";
        let upstream = "198.51.100.7:443";

        let egress_view = Extensions::new();
        egress_view.insert(Egress(view(upstream)));
        let parent = Extensions::new();
        parent.insert(Egress(view(upstream)));
        let forked = parent.fork();
        let own_and_egress = view(client);
        own_and_egress.insert(Egress(view(upstream)));
        let egress_with_parent = Extensions::new();
        egress_with_parent.insert(Egress(view(upstream).fork()));

        for (name, extensions) in [
            ("egress view", &egress_view),
            ("parent egress view", &forked),
            ("egress view over own", &own_and_egress),
            ("egress view parent socket", &egress_with_parent),
        ] {
            // Inserted last, so a generic lookup would find the client.
            extensions.insert(Ingress(view(client)));
            extensions.insert(SocketInfo::new(None, client.parse().unwrap()));
            assert_eq!(
                SocketInfo::egress(extensions).map(|info| info.peer_addr().to_string()),
                Some(upstream.to_owned()),
                "{name}"
            );
        }

        for (name, extensions) in [
            ("own only", view(client)),
            ("ingress only", {
                let extensions = Extensions::new();
                extensions.insert(Ingress(view(client)));
                extensions
            }),
            ("ingress inside egress", {
                let egress = Extensions::new();
                egress.insert(Ingress(view(client)));
                let extensions = Extensions::new();
                extensions.insert(Egress(egress));
                extensions
            }),
        ] {
            assert!(SocketInfo::egress(&extensions).is_none(), "{name}");
        }
    }

    /// Nested views: an ingress view inside the egress one never decides; a nested egress
    /// view does, as for [`SocketInfo::ingress`].
    #[test]
    fn nested_ingress_views_are_never_entered() {
        let client = "203.0.113.5:1000";
        let upstream = "198.51.100.7:443";

        let ingress_inside_egress = Extensions::new();
        let egress = view(upstream);
        egress.insert(Ingress(view(client)));
        ingress_inside_egress.insert(Egress(egress));

        let egress_inside_ingress = Extensions::new();
        egress_inside_ingress.insert(Egress(view(upstream)));
        let ingress = view(client);
        ingress.insert(Egress(view(client)));
        egress_inside_ingress.insert(Ingress(ingress));

        let nested_egress = Extensions::new();
        let carrier = Extensions::new();
        carrier.insert(Egress(view(upstream)));
        carrier.insert(Ingress(view(client)));
        nested_egress.insert(Egress(carrier));

        for (name, extensions) in [
            ("ingress inside egress", &ingress_inside_egress),
            ("egress inside ingress", &egress_inside_ingress),
            ("egress inside egress", &nested_egress),
        ] {
            assert_eq!(
                SocketInfo::egress(extensions).map(|info| info.peer_addr().to_string()),
                Some(upstream.to_owned()),
                "{name}"
            );
        }
    }
}
