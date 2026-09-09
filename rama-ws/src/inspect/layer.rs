use std::num::NonZeroUsize;

use rama_core::{Layer, Service, extensions::ExtensionsRef};
use rama_http::inspect::{
    capture::{CaptureStore, HttpExchangeId, HttpUpgradeCaptureGuard},
    control::HttpUpgradeContext,
};
use rama_utils::octets::kib;

use crate::handshake::mitm::{WebSocketBridge, WebSocketRelayReadAhead};

/// Bind an inspector exchange to the lifetime of the actual WebSocket relay.
///
/// Response-scoped metadata reaches the egress upgraded transport. This layer
/// copies only the inspector's typed exchange identifier to ingress so both
/// directional event streams can be associated without changing the generic
/// HTTP upgrade machinery. Completion follows the relay service future, which
/// also covers idle sockets and abnormal disconnects.
#[derive(Debug, Clone)]
pub struct CaptureWebSocketLayer {
    store: Option<CaptureStore>,
}

impl CaptureWebSocketLayer {
    pub fn new(store: Option<CaptureStore>) -> Self {
        Self { store }
    }
}

impl<S> Layer<S> for CaptureWebSocketLayer {
    type Service = CaptureWebSocketService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CaptureWebSocketService {
            inner,
            store: self.store.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaptureWebSocketService<S> {
    inner: S,
    store: Option<CaptureStore>,
}

impl<S, Ingress, Egress> Service<WebSocketBridge<Ingress, Egress>> for CaptureWebSocketService<S>
where
    S: Service<WebSocketBridge<Ingress, Egress>>,
    Ingress: ExtensionsRef + Send + 'static,
    Egress: ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(
        &self,
        bridge: WebSocketBridge<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        if let Some(context) = bridge
            .egress
            .extensions()
            .get_ref::<HttpUpgradeContext>()
            .cloned()
        {
            bridge.ingress.extensions().insert(context);
        }
        if self.store.is_some() {
            let limits = WebSocketRelayReadAhead {
                max_messages: NonZeroUsize::MIN.saturating_add(15),
                max_bytes: NonZeroUsize::MIN.saturating_add(kib(256) - 1),
            };
            bridge.ingress.extensions().insert(limits);
            bridge.egress.extensions().insert(limits);
        }
        let exchange_id = bridge
            .egress
            .extensions()
            .get_ref::<HttpExchangeId>()
            .copied();
        if let Some(exchange_id) = exchange_id {
            bridge.ingress.extensions().insert(exchange_id);
        }

        let _response_guard = bridge
            .egress
            .extensions()
            .get_arc::<HttpUpgradeCaptureGuard>();
        // Once the relay starts, its future owns completion independently of
        // incidental response-extension owners. Drop also covers cancellation;
        // the shared response guard still handles failures before relay startup.
        let _relay_guard = self
            .store
            .as_ref()
            .zip(exchange_id)
            .map(|(store, exchange_id)| store.upgrade_guard(exchange_id.0));
        self.inner.serve(bridge).await
    }
}
