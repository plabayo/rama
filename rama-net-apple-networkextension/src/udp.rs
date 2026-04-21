use std::sync::{Arc, Once};

use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
};
use tokio::sync::mpsc;

/// A per-flow UDP datagram socket abstraction for transparent proxy services.
pub struct UdpFlow {
    incoming: mpsc::UnboundedReceiver<Bytes>,
    outgoing: Arc<dyn Fn(Bytes) + Send + Sync + 'static>,
    extensions: Extensions,
    io_demand_once: Once,
    on_io_demand: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
}

impl UdpFlow {
    pub(crate) fn new_with_io_demand(
        incoming: mpsc::UnboundedReceiver<Bytes>,
        outgoing: Arc<dyn Fn(Bytes) + Send + Sync + 'static>,
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

    /// Receive one datagram from the intercepted client flow.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.signal_io_demand_once();
        self.incoming.recv().await
    }

    /// Send one datagram back to the intercepted client flow.
    pub fn send(&self, bytes: Bytes) {
        self.signal_io_demand_once();
        (self.outgoing)(bytes);
    }
}

impl ExtensionsRef for UdpFlow {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}
