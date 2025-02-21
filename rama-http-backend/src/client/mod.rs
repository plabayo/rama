//! Rama HTTP client module,
//! which provides the [`HttpClient`] type to serve HTTP requests.

#[cfg(any(feature = "rustls", feature = "boring"))]
use std::sync::Arc;

use proxy::layer::HttpProxyConnector;
use rama_core::{
    Context, Service,
    error::{BoxError, ErrorExt, OpaqueError},
};
use rama_http_types::{Request, Response, dep::http_body};
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_tcp::client::service::TcpConnector;

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_tls::std::client::{TlsConnector, TlsConnectorData};

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_net::tls::client::{ClientConfig, ProxyClientConfig};

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_core::error::ErrorContext;

mod svc;
#[doc(inline)]
pub use svc::HttpClientService;

mod conn;
#[doc(inline)]
pub use conn::{HttpConnector, HttpConnectorLayer};
use tracing::trace;

pub mod proxy;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// An opiniated http client that can be used to serve HTTP requests.
///
/// You can fork this http client in case you have use cases not possible with this service example.
/// E.g. perhaps you wish to have middleware in into outbound requests, after they
/// passed through your "connector" setup. All this and more is possible by defining your own
/// http client. Rama is here to empower you, the building blocks are there, go crazy
/// with your own service fork and use the full power of Rust at your fingertips ;)
pub struct HttpClient {
    #[cfg(any(feature = "rustls", feature = "boring"))]
    tls_config: Option<ClientConfig>,
    #[cfg(any(feature = "rustls", feature = "boring"))]
    proxy_tls_config: Option<ClientConfig>,
}

impl HttpClient {
    /// Create a new [`HttpClient`].
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Set the [`ClientConfig`] of this [`HttpClient`].
    pub fn set_tls_config(&mut self, cfg: ClientConfig) -> &mut Self {
        self.tls_config = Some(cfg);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`HttpClient`] with the [`ClientConfig`] set.
    pub fn with_tls_config(mut self, cfg: ClientConfig) -> Self {
        self.tls_config = Some(cfg);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`HttpClient`] with an option of [`ClientConfig`] set.
    pub fn maybe_with_tls_config(mut self, cfg: Option<ClientConfig>) -> Self {
        self.tls_config = cfg;
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Set the [`ClientConfig`] for the https proxy tunnel if needed within this [`HttpClient`].
    pub fn set_proxy_tls_config(&mut self, cfg: ClientConfig) -> &mut Self {
        self.proxy_tls_config = Some(cfg);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`HttpClient`] set for the https proxy tunnel if needed within this [`ClientConfig`].
    pub fn with_proxy_tls_config(mut self, cfg: ClientConfig) -> Self {
        self.proxy_tls_config = Some(cfg);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`HttpClient`] set for the https proxy tunnel if needed within this [`ClientConfig`].
    pub fn maybe_proxy_with_tls_config(mut self, cfg: Option<ClientConfig>) -> Self {
        self.proxy_tls_config = cfg;
        self
    }
}

impl<State, Body> Service<State, Request<Body>> for HttpClient
where
    State: Clone + Send + Sync + 'static,
    Body: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Response = Response;
    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let uri = req.uri().clone();

        // record original req version,
        // so we can put the response back
        let original_req_version = req.version();

        let tcp_connector = TcpConnector::new();

        #[cfg(any(feature = "rustls", feature = "boring"))]
        let connector = {
            let proxy_tls_connector_data = match (
                ctx.get::<ProxyClientConfig>(),
                &self.proxy_tls_config,
            ) {
                (Some(proxy_tls_config), _) => {
                    trace!("create proxy tls connector using rama tls client config from ontext");
                    proxy_tls_config
                        .0
                        .as_ref()
                        .clone()
                        .try_into()
                        .context(
                        "HttpClient: create proxy tls connector data from tls config found in context",
                    )?
                }
                (None, Some(proxy_tls_config)) => {
                    trace!("create proxy tls connector using pre-defined rama tls client config");
                    proxy_tls_config
                        .clone()
                        .try_into()
                        .context("HttpClient: create proxy tls connector data from tls config")?
                }
                (None, None) => {
                    trace!("create proxy tls connector using the 'new_http_auto' constructor");
                    TlsConnectorData::new().context(
                        "HttpClient: create proxy tls connector data with no application presets",
                    )?
                }
            };

            let transport_connector = HttpProxyConnector::optional(
                TlsConnector::tunnel(tcp_connector, None)
                    .with_connector_data(proxy_tls_connector_data),
            );
            let tls_connector_data = match (ctx.get::<Arc<ClientConfig>>(), &self.tls_config) {
                (Some(tls_config), _) => {
                    trace!("create tls connector using rama tls client config from ontext");
                    tls_config.as_ref().clone().try_into().context(
                        "HttpClient: create tls connector data from tls config found in context",
                    )?
                }
                (None, Some(tls_config)) => {
                    trace!("create tls connector using pre-defined rama tls client config");
                    tls_config.clone().try_into().context(
                        "HttpClient: create tls connector data from pre-defined tls config",
                    )?
                }
                (None, None) => {
                    trace!("create tls connector using the 'new_http_auto' constructor");
                    TlsConnectorData::new_http_auto()
                        .context("HttpClient: create tls connector data for http (auto)")?
                }
            };
            HttpConnector::new(
                TlsConnector::auto(transport_connector).with_connector_data(tls_connector_data),
            )
        };
        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        let connector = HttpConnector::new(HttpProxyConnector::optional(tcp_connector));

        // NOTE: stack might change request version based on connector data,
        // such as ALPN (tls), as such it is important to reset it back below,
        // so that the other end can read it... This might however give issues in
        // case switching http versions requires more work than version. If so,
        // your first place will be to check here and/or in the [`HttpConnector`].
        let EstablishedClientConnection { ctx, req, conn, .. } = connector
            .connect(ctx, req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err).with_context(|| uri.to_string()))?;

        trace!(uri = %uri, "send http req to connector stack");
        let mut resp = conn.serve(ctx, req).await.map_err(|err| {
            OpaqueError::from_boxed(err)
                .with_context(|| format!("http request failure for uri: {uri}"))
        })?;
        trace!(uri = %uri, "response received from connector stack");

        trace!(
            "incoming response version {:?}, normalizing to {:?}",
            resp.version(),
            original_req_version
        );
        // NOTE: in case http response writer does not handle possible conversion issues,
        // we might need to do more complex normalization here... Worries for the future, maybe
        *resp.version_mut() = original_req_version;

        Ok(resp)
    }
}
