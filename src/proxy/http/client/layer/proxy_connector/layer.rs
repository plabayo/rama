use super::HttpProxyConnectorService;
use crate::service::Layer;

#[derive(Debug, Clone, Default)]
/// A [`Layer`] which wraps the given service with a [`HttpProxyConnectorService`].
///
/// See [`HttpProxyConnectorService`] for more information.
pub struct HttpProxyConnectorLayer {
    required: bool,
}

impl HttpProxyConnectorLayer {
    /// Create a new [`HttpProxyConnectorLayer`] which creates a [`HttpProxyConnectorService`]
    /// which will only connect via an http proxy in case the [`ProxyAddress`] is available
    /// in the [`Context`].
    ///
    /// [`Context`]: crate::service::Context
    /// [`ProxyAddress`]: crate::net::address::ProxyAddress
    pub fn optional() -> Self {
        Self { required: false }
    }

    /// Create a new [`HttpProxyConnectorLayer`] which creates a [`HttpProxyConnectorService`]
    /// which will always connect via an http proxy, but fail in case the [`ProxyAddress`] is
    /// not available in the [`Context`].
    ///
    /// [`Context`]: crate::service::Context
    /// [`ProxyAddress`]: crate::net::address::ProxyAddress
    pub fn required() -> Self {
        Self { required: true }
    }
}

impl<S> Layer<S> for HttpProxyConnectorLayer {
    type Service = HttpProxyConnectorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpProxyConnectorService::new(inner, self.required)
    }
}
