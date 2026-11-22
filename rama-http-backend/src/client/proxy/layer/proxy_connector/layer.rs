use super::HttpConnectProxyConnector;
use rama_core::Layer;
use rama_core::extensions::{ExtensionsTransfer, SharedExtensionsTransfer};
use rama_net::{client::ProxyDialer, stream::DefaultExtensionsTransfer};
use rama_utils::macros::generate_set_and_with;

#[derive(Debug, Clone)]
/// A [`Layer`] which wraps the given connector towards the proxy, dialed through a
/// [`ProxyDialer`], with an [`HttpConnectProxyConnector`], so a proxied [`ProxyRoute`] is
/// required.
///
/// Pair the connector it builds with a direct one in a
/// [`MaybeProxiedConnector`](rama_net::client::MaybeProxiedConnector) to connect directly instead
/// when no proxy is requested.
///
/// [`ProxyRoute`]: rama_net::client::ProxyRoute
/// [`ProxyDialer`]: rama_net::client::ProxyDialer
pub struct HttpConnectProxyConnectorLayer {
    extensions_transfer: SharedExtensionsTransfer,
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
            extensions_transfer: DefaultExtensionsTransfer::new().into_shared(),
        }
    }

    generate_set_and_with! {
        /// Set what a CONNECT tunnel keeps from the proxy connection it is
        /// nested on.
        ///
        /// Defaults to [`DefaultExtensionsTransfer`]. Chain transfers with
        /// [`ExtensionsTransfer::and`] to also carry your own connection-scoped
        /// extension types across the tunnel.
        pub fn extensions_transfer(mut self, transfer: impl ExtensionsTransfer) -> Self {
            self.extensions_transfer = transfer.into_shared();
            self
        }
    }
}

impl<S> Layer<S> for HttpConnectProxyConnectorLayer {
    type Service = HttpConnectProxyConnector<ProxyDialer<S>>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpConnectProxyConnector::new(inner)
            .with_extensions_transfer(self.extensions_transfer.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HttpConnectProxyConnector::new(inner).with_extensions_transfer(self.extensions_transfer)
    }
}
