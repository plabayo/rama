use super::HttpProxyConnector;
use rama_core::Layer;
use rama_http::{HeaderMap, HeaderValue, header::IntoHeaderName};
use rama_http_types::Version;
use rama_utils::macros::generate_set_and_with;

#[derive(Debug, Clone)]
/// A [`Layer`] which wraps the given service with a [`HttpProxyConnector`].
///
/// See [`HttpProxyConnector`] for more information.
pub struct HttpProxyConnectorLayer {
    required: bool,
    tls_proxy_supported: bool,
    version: Option<Version>,
    headers: Option<HeaderMap>,
}

impl HttpProxyConnectorLayer {
    /// Create a new [`HttpProxyConnectorLayer`] which creates a [`HttpProxyConnector`]
    /// which will only connect via an HTTP proxy when a proxied [`ProxyRoute`] is available
    /// in the [`Extensions`].
    ///
    /// [`Extensions`]: rama_core::extensions::Extensions
    /// [`ProxyRoute`]: rama_net::client::ProxyRoute
    #[must_use]
    pub fn optional() -> Self {
        Self {
            required: false,
            tls_proxy_supported: true,
            version: Some(Version::HTTP_11),
            headers: None,
        }
    }

    /// Create a new [`HttpProxyConnectorLayer`] which creates a [`HttpProxyConnector`]
    /// which will always connect via an HTTP proxy, but fail when a proxied [`ProxyRoute`] is
    /// not available in the [`Extensions`].
    ///
    /// [`Extensions`]: rama_core::extensions::Extensions
    /// [`ProxyRoute`]: rama_net::client::ProxyRoute
    #[must_use]
    pub fn required() -> Self {
        Self {
            required: true,
            tls_proxy_supported: true,
            version: Some(Version::HTTP_11),
            headers: None,
        }
    }

    generate_set_and_with! {
        /// Set whether the inner connector supports TLS to an HTTPS proxy.
        pub fn tls_proxy_support(mut self, supported: bool) -> Self {
            self.tls_proxy_supported = supported;
            self
        }
    }

    generate_set_and_with! {
        /// Set the HTTP version to use for the CONNECT request.
        ///
        /// This also constrains HTTPS-proxy ALPN to the matching protocol.
        /// The `optional` and `required` constructors default to HTTP/1.1;
        /// [`Default`] follows the HTTPS proxy's negotiated ALPN and falls back
        /// to HTTP/1.1 when no version is negotiated.
        pub fn version(mut self, version: Version) -> Self {
            self.version = Some(version);
            self
        }
    }

    generate_set_and_with! {
        /// Append a custom header to use for the CONNECT request.
        pub fn custom_header(
            mut self,
            name: impl IntoHeaderName,
            value: HeaderValue,
        ) -> Self {
            self.headers.get_or_insert_default().append(name, value);
            self
        }
    }
}

impl<S> Layer<S> for HttpProxyConnectorLayer {
    type Service = HttpProxyConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpProxyConnector {
            inner,
            required: self.required,
            tls_proxy_supported: self.tls_proxy_supported,
            version: self.version,
            headers: self.headers.clone(),
        }
    }
}

impl Default for HttpProxyConnectorLayer {
    fn default() -> Self {
        Self {
            required: false,
            tls_proxy_supported: true,
            version: None,
            headers: None,
        }
    }
}
