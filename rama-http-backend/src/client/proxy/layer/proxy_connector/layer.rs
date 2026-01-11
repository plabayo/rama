use super::HttpProxyConnector;
use rama_core::Layer;
use rama_http::{
    HeaderValue,
    proto::h1::{Http1HeaderMap, IntoHttp1HeaderName},
};
use rama_http_types::Version;
use rama_utils::macros::generate_set_and_with;

#[derive(Debug, Clone, Default)]
/// A [`Layer`] which wraps the given service with a [`HttpProxyConnector`].
///
/// See [`HttpProxyConnector`] for more information.
pub struct HttpProxyConnectorLayer {
    required: bool,
    version: Option<Version>,
    headers: Option<Http1HeaderMap>,
}

impl HttpProxyConnectorLayer {
    /// Create a new [`HttpProxyConnectorLayer`] which creates a [`HttpProxyConnector`]
    /// which will only connect via an http proxy in case the [`ProxyAddress`] is available
    /// in the [`Extensions`].
    ///
    /// [`Extensions`]: rama_core::extensions::Extensions
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    #[must_use]
    pub fn optional() -> Self {
        Self {
            required: false,
            version: Some(Version::HTTP_11),
            headers: None,
        }
    }

    /// Create a new [`HttpProxyConnectorLayer`] which creates a [`HttpProxyConnector`]
    /// which will always connect via an http proxy, but fail in case the [`ProxyAddress`] is
    /// not available in the [`Extensions`].
    ///
    /// [`Extensions`]: rama_core::extensions::Extensions
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    #[must_use]
    pub fn required() -> Self {
        Self {
            required: true,
            version: Some(Version::HTTP_11),
            headers: None,
        }
    }

    generate_set_and_with! {
        /// Set the HTTP version to use for the CONNECT request.
        ///
        /// By default this is set to HTTP/1.1.
        pub fn version(mut self, version: Version) -> Self {
            self.version = Some(version);
            self
        }
    }

    generate_set_and_with! {
        /// Append a custom header to use for the CONNECT request.
        pub fn custom_header(
            mut self,
            name: impl IntoHttp1HeaderName,
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
            version: self.version,
            headers: self.headers.clone(),
        }
    }
}
