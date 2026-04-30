use std::sync::Arc;

use rama_core::bytes::Bytes;
use tokio::sync::mpsc;

/// Egress UDP socket backed by a pre-established `NWConnection`.
///
/// Unlike [`crate::UdpFlow`], this type carries no intercepted-flow metadata.
/// Datagrams arriving from the NWConnection are delivered via [`recv`](Self::recv),
/// and datagrams to send to the NWConnection are dispatched via [`send`](Self::send).
pub struct NwUdpSocket {
    incoming: mpsc::Receiver<Bytes>,
    outgoing: Arc<dyn Fn(Bytes) + Send + Sync + 'static>,
}

impl NwUdpSocket {
    pub(crate) fn new(
        incoming: mpsc::Receiver<Bytes>,
        outgoing: Arc<dyn Fn(Bytes) + Send + Sync + 'static>,
    ) -> Self {
        Self { incoming, outgoing }
    }

    /// Receive one datagram from the NWConnection.
    ///
    /// Returns `None` when the NWConnection has been closed or cancelled.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.incoming.recv().await
    }

    /// Send one datagram to the NWConnection.
    pub fn send(&self, bytes: Bytes) {
        (self.outgoing)(bytes);
    }
}
