use super::HttpProxyConnector;
use rama_core::Layer;

#[derive(Debug, Clone, Default)]
/// A [`Layer`] which wraps the given service with a [`HttpProxyConnector`].
///
/// See [`HttpProxyConnector`] for more information.
pub struct HttpProxyConnectorLayer {
    required: bool,
}

impl HttpProxyConnectorLayer {
    /// Create a new [`HttpProxyConnectorLayer`] which creates a [`HttpProxyConnector`]
    /// which will only connect via an http proxy in case the [`ProxyAddress`] is available
    /// in the [`Context`].
    ///
    /// [`Context`]: rama_core::Context
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn optional() -> Self {
        Self { required: false }
    }

    /// Create a new [`HttpProxyConnectorLayer`] which creates a [`HttpProxyConnector`]
    /// which will always connect via an http proxy, but fail in case the [`ProxyAddress`] is
    /// not available in the [`Context`].
    ///
    /// [`Context`]: rama_core::Context
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn required() -> Self {
        Self { required: true }
    }
}

impl<S> Layer<S> for HttpProxyConnectorLayer {
    type Service = HttpProxyConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpProxyConnector::new(inner, self.required)
    }
}
