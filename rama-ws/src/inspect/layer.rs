use rama_core::{Layer, Service};
use rama_http::inspect::capture::{CaptureStore, HttpExchangeId, HttpUpgradeCaptureGuard};

use crate::handshake::mitm::WebSocketBridge;

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
    Ingress: rama_core::extensions::ExtensionsRef + Send + 'static,
    Egress: rama_core::extensions::ExtensionsRef + Send + 'static,
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
            .get_ref::<rama_http::inspect::control::HttpUpgradeContext>()
            .cloned()
        {
            bridge.ingress.extensions().insert(context);
        }
        if self.store.is_some() {
            let limits = crate::handshake::mitm::WebSocketRelayReadAhead {
                max_messages: std::num::NonZeroUsize::MIN.saturating_add(15),
                max_bytes: std::num::NonZeroUsize::MIN
                    .saturating_add(rama_utils::octets::kib(256) - 1),
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

        let response_guard = bridge
            .egress
            .extensions()
            .get_arc::<HttpUpgradeCaptureGuard>();
        let fallback_guard = if response_guard.is_none() {
            self.store
                .as_ref()
                .zip(exchange_id)
                .map(|(store, exchange_id)| store.upgrade_guard(exchange_id.0))
        } else {
            None
        };
        let output = self.inner.serve(bridge).await;
        if let Some((store, exchange_id)) = self.store.as_ref().zip(exchange_id) {
            // Response extensions can have incidental owners beyond the
            // upgraded streams. The relay future itself is the authoritative
            // completion boundary once it starts, so finish eagerly here;
            // guard Drop remains the pre-relay failure fallback.
            store.finish_upgrade(exchange_id.0);
        }
        drop(response_guard);
        drop(fallback_guard);
        output
    }
}
