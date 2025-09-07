use super::HttpProxyConnector;
use rama_core::Layer;
use rama_http_types::Version;

#[derive(Debug, Clone, Default)]
/// A [`Layer`] which wraps the given service with a [`HttpProxyConnector`].
///
/// See [`HttpProxyConnector`] for more information.
pub struct HttpProxyConnectorLayer {
    required: bool,
    version: Option<Version>,
}

impl HttpProxyConnectorLayer {
    /// Create a new [`HttpProxyConnectorLayer`] which creates a [`HttpProxyConnector`]
    /// which will only connect via an http proxy in case the [`ProxyAddress`] is available
    /// in the [`Context`].
    ///
    /// [`Context`]: rama_core::Context
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    #[must_use]
    pub fn optional() -> Self {
        Self {
            required: false,
            version: Some(Version::HTTP_11),
        }
    }

    /// Create a new [`HttpProxyConnectorLayer`] which creates a [`HttpProxyConnector`]
    /// which will always connect via an http proxy, but fail in case the [`ProxyAddress`] is
    /// not available in the [`Context`].
    ///
    /// [`Context`]: rama_core::Context
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    #[must_use]
    pub fn required() -> Self {
        Self {
            required: true,
            version: Some(Version::HTTP_11),
        }
    }

    /// Set the HTTP version to use for the CONNECT request.
    ///
    /// By default this is set to HTTP/1.1.
    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    /// Set the HTTP version to use for the CONNECT request.
    pub fn set_version(&mut self, version: Version) -> &mut Self {
        self.version = Some(version);
        self
    }

    /// Set the HTTP version to auto detect for the CONNECT request.
    #[must_use]
    pub fn with_auto_version(mut self) -> Self {
        self.version = None;
        self
    }

    /// Set the HTTP version to auto detect for the CONNECT request.
    pub fn set_auto_version(&mut self) -> &mut Self {
        self.version = None;
        self
    }
}

impl<S> Layer<S> for HttpProxyConnectorLayer {
    type Service = HttpProxyConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let mut svc = HttpProxyConnector::new(inner, self.required);
        match self.version {
            Some(version) => svc.set_version(version),
            None => svc.set_auto_version(),
        };
        svc
    }
}
