use super::{HttpProxyConnector, HttpProxyVersionPolicy};
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
    version_policy: HttpProxyVersionPolicy,
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
            version_policy: HttpProxyVersionPolicy::Automatic {
                connect_fallback: Some(Version::HTTP_11),
            },
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
            version_policy: HttpProxyVersionPolicy::Automatic {
                connect_fallback: Some(Version::HTTP_11),
            },
            headers: None,
        }
    }

    generate_set_and_with! {
        /// Set whether the inner connector supports TLS to an HTTPS proxy.
        ///
        /// A custom TLS connector must publish
        /// `rama_tls::client::NegotiatedTlsParameters` on the established
        /// connection. The HTTP proxy connector requires that positive
        /// evidence before sending any bytes to an HTTPS proxy.
        pub fn tls_proxy_support(mut self, supported: bool) -> Self {
            self.tls_proxy_supported = supported;
            self
        }
    }

    generate_set_and_with! {
        /// Set the HTTP version used to communicate with the proxy.
        ///
        /// This pins plaintext forward-proxy requests and CONNECT requests to
        /// the given version, and constrains HTTPS-proxy ALPN accordingly.
        /// Without an explicit version, plaintext forward-proxy requests follow
        /// the target version. The `optional` and `required` constructors retain
        /// HTTP/1.1 as their CONNECT and HTTPS-proxy default; [`Default`] follows
        /// negotiated HTTPS-proxy ALPN and otherwise falls back to HTTP/1.1.
        pub fn version(mut self, version: Version) -> Self {
            self.version_policy = HttpProxyVersionPolicy::Fixed(version);
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
            version_policy: self.version_policy,
            headers: self.headers.clone(),
        }
    }
}

impl Default for HttpProxyConnectorLayer {
    fn default() -> Self {
        Self {
            required: false,
            tls_proxy_supported: true,
            version_policy: HttpProxyVersionPolicy::Automatic {
                connect_fallback: None,
            },
            headers: None,
        }
    }
}
