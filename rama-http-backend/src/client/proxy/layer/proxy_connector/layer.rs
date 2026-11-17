use super::HttpConnectProxyConnector;
use rama_core::Layer;
use rama_core::extensions::{NestedConnectionTransfer, SharedNestedConnectionTransfer};
use rama_net::stream::DefaultConnectionTransfer;
use rama_utils::macros::generate_set_and_with;

#[derive(Debug, Clone)]
/// A [`Layer`] which wraps the given connector towards the proxy with an
/// [`HttpConnectProxyConnector`], so a proxied [`ProxyRoute`] is required.
///
/// Wrap this layer in a [`MaybeProxiedConnectorLayer`](rama_net::client::MaybeProxiedConnectorLayer) to
/// connect directly instead when no proxy is requested.
///
/// [`ProxyRoute`]: rama_net::client::ProxyRoute
pub struct HttpConnectProxyConnectorLayer {
    nested_connection_transfer: SharedNestedConnectionTransfer,
}

impl Default for HttpConnectProxyConnectorLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpConnectProxyConnectorLayer {
    /// Create a new [`HttpConnectProxyConnectorLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            nested_connection_transfer: DefaultConnectionTransfer.into_shared(),
        }
    }

    generate_set_and_with! {
        /// Set what a CONNECT tunnel keeps from the proxy connection it is
        /// nested on.
        ///
        /// Defaults to [`DefaultConnectionTransfer`]. Chain transfers with
        /// [`NestedConnectionTransfer::and`] to also carry your own connection-scoped
        /// extension types across the tunnel.
        pub fn nested_connection_transfer(mut self, transfer: impl NestedConnectionTransfer) -> Self {
            self.nested_connection_transfer = transfer.into_shared();
            self
        }
    }
}

impl<S> Layer<S> for HttpConnectProxyConnectorLayer {
    type Service = HttpConnectProxyConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpConnectProxyConnector::new(inner)
            .with_nested_connection_transfer(self.nested_connection_transfer.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HttpConnectProxyConnector::new(inner)
            .with_nested_connection_transfer(self.nested_connection_transfer)
    }
}
