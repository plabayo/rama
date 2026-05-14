use std::net::SocketAddr;
use std::sync::{Arc, Once};

use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
};
use tokio::sync::mpsc;

/// One UDP datagram together with its peer endpoint.
///
/// `peer` is the *other end* of the wire relative to the proxy:
///
/// * For datagrams **flowing toward the wire** (`UdpFlow::recv`,
///   `NwUdpSocket::send`) it is the destination — the peer the
///   originating app wanted this datagram delivered to.
/// * For datagrams **flowing back from the wire** (`UdpFlow::send`,
///   `NwUdpSocket::recv`) it is the source — the peer the reply
///   came from, which then becomes the `sentBy` endpoint when the
///   transparent proxy delivers the datagram back to the kernel via
///   `NEAppProxyUDPFlow.writeDatagrams(_:sentBy:)`.
///
/// UDP is stateless and the kernel exposes per-datagram source /
/// destination endpoints on both `flow.readDatagrams` and
/// `flow.writeDatagrams`. Encoding that in the framework type means
/// multi-peer flows (DNS resolvers, NTP, mDNS, game protocols) are
/// faithfully proxied — every outbound datagram goes where the app
/// addressed it and every reply is tagged with the correct source.
///
/// `peer = None` is reserved for the edge case where the kernel
/// did not supply an endpoint (rare; mostly a safety valve). Real
/// production traffic always has a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// Payload bytes (may be empty — RFC 768 admits zero-length).
    pub payload: Bytes,
    /// Peer endpoint. See type docs for direction-dependent meaning.
    pub peer: Option<SocketAddr>,
}

impl Datagram {
    /// Construct a datagram with a known peer.
    #[inline]
    #[must_use]
    pub fn new(payload: Bytes, peer: SocketAddr) -> Self {
        Self {
            payload,
            peer: Some(peer),
        }
    }

    /// Construct a datagram whose peer is unknown.
    ///
    /// Used as a safety valve for paths that lack a per-datagram
    /// endpoint (e.g. tests, or NWConnection receives where Apple
    /// returns no source attribution).
    #[inline]
    #[must_use]
    pub fn without_peer(payload: Bytes) -> Self {
        Self {
            payload,
            peer: None,
        }
    }
}

/// A per-flow UDP datagram socket abstraction for transparent proxy services.
pub struct UdpFlow {
    incoming: mpsc::Receiver<Datagram>,
    outgoing: Arc<dyn Fn(Datagram) + Send + Sync + 'static>,
    extensions: Extensions,
    io_demand_once: Once,
    on_io_demand: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
}

impl UdpFlow {
    pub(crate) fn new_with_io_demand(
        incoming: mpsc::Receiver<Datagram>,
        outgoing: Arc<dyn Fn(Datagram) + Send + Sync + 'static>,
        on_io_demand: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            incoming,
            outgoing,
            extensions: Extensions::new(),
            io_demand_once: Once::new(),
            on_io_demand,
        }
    }

    #[inline(always)]
    fn signal_io_demand_once(&self) {
        if let Some(on_io_demand) = &self.on_io_demand {
            self.io_demand_once.call_once(|| on_io_demand());
        }
    }

    /// Receive one datagram from the intercepted client flow. The
    /// datagram's `peer` is the destination the originating app
    /// addressed it to.
    pub async fn recv(&mut self) -> Option<Datagram> {
        self.signal_io_demand_once();
        self.incoming.recv().await
    }

    /// Send one datagram back to the intercepted client flow. The
    /// datagram's `peer` is the source the reply came from; the
    /// kernel uses it as the `sentBy` endpoint when writing to
    /// `NEAppProxyUDPFlow`.
    pub fn send(&self, datagram: Datagram) {
        self.signal_io_demand_once();
        (self.outgoing)(datagram);
    }
}

impl ExtensionsRef for UdpFlow {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}
