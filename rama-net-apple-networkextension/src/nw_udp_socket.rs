use std::sync::Arc;

use tokio::sync::mpsc;

use crate::udp::Datagram;

/// Egress UDP socket backed by the per-flow set of `NWConnection`s.
///
/// Each `Datagram` on the egress side carries its peer:
///
/// * `recv` yields datagrams **from** the wire, tagged with the
///   per-peer NWConnection's bound endpoint as the `peer` field.
/// * `send` accepts datagrams **toward** the wire; the `peer` field
///   is the destination, used by Swift to route the datagram to (or
///   lazy-open) the per-peer `NWConnection`.
///
/// Unlike [`crate::UdpFlow`], this type carries no intercepted-flow
/// metadata. The proxy is responsible for honoring the destination
/// peer faithfully — UDP is stateless and pretending otherwise lost
/// fidelity for multi-peer apps (DNS resolvers, NTP, mDNS).
pub struct NwUdpSocket {
    incoming: mpsc::Receiver<Datagram>,
    outgoing: Arc<dyn Fn(Datagram) + Send + Sync + 'static>,
}

impl NwUdpSocket {
    pub(crate) fn new(
        incoming: mpsc::Receiver<Datagram>,
        outgoing: Arc<dyn Fn(Datagram) + Send + Sync + 'static>,
    ) -> Self {
        Self { incoming, outgoing }
    }

    /// Receive one datagram from the NWConnection set.
    ///
    /// Returns `None` when the bridge has been closed or cancelled.
    pub async fn recv(&mut self) -> Option<Datagram> {
        self.incoming.recv().await
    }

    /// Send one datagram to the wire. The datagram's `peer` is the
    /// destination Swift routes through the matching per-peer
    /// NWConnection.
    pub fn send(&self, datagram: Datagram) {
        (self.outgoing)(datagram);
    }
}
