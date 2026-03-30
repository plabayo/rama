use std::sync::Arc;

use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsMut, ExtensionsRef},
};
use tokio::sync::mpsc;

/// A per-flow UDP datagram socket abstraction for transparent proxy services.
pub struct UdpFlow {
    incoming: mpsc::UnboundedReceiver<Bytes>,
    outgoing: Arc<dyn Fn(Bytes) + Send + Sync + 'static>,
    extensions: Extensions,
}

impl UdpFlow {
    pub(crate) fn new(
        incoming: mpsc::UnboundedReceiver<Bytes>,
        outgoing: Arc<dyn Fn(Bytes) + Send + Sync + 'static>,
    ) -> Self {
        Self {
            incoming,
            outgoing,
            extensions: Extensions::new(),
        }
    }

    /// Receive one datagram from the intercepted client flow.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.incoming.recv().await
    }

    /// Send one datagram back to the intercepted client flow.
    pub fn send(&self, bytes: Bytes) {
        (self.outgoing)(bytes);
    }
}

impl ExtensionsRef for UdpFlow {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl ExtensionsMut for UdpFlow {
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}
