//! Rama HTTP client module,
//! which provides the [`EasyHttpWebClient`] type to serve HTTP requests.

use std::fmt;
#[cfg(any(feature = "rustls", feature = "boring"))]
use std::sync::Arc;

use proxy::layer::HttpProxyConnector;
use rama_core::{
    Context, Service,
    error::{BoxError, ErrorExt, OpaqueError},
    inspect::RequestInspector,
};
use rama_http_types::{Request, Response, dep::http_body};
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_tcp::client::service::TcpConnector;

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_tls::std::client::{TlsConnector, TlsConnectorData};

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_net::tls::client::{ClientConfig, ProxyClientConfig, extract_client_config_from_ctx};

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_core::error::ErrorContext;

#[cfg(any(feature = "rustls", feature = "boring"))]
use http_inspector::HttpsAlpnModifier;

mod svc;
#[doc(inline)]
pub use svc::HttpClientService;

mod conn;
#[doc(inline)]
pub use conn::{HttpConnector, HttpConnectorLayer};
use tracing::trace;

pub mod http_inspector;
pub mod proxy;

/// An opiniated http client that can be used to serve HTTP requests.
///
/// You can fork this http client in case you have use cases not possible with this service example.
/// E.g. perhaps you wish to have middleware in into outbound requests, after they
/// passed through your "connector" setup. All this and more is possible by defining your own
/// http client. Rama is here to empower you, the building blocks are there, go crazy
/// with your own service fork and use the full power of Rust at your fingertips ;)
pub struct EasyHttpWebClient<I1 = (), I2 = ()> {
    #[cfg(any(feature = "rustls", feature = "boring"))]
    tls_config: Option<Arc<ClientConfig>>,
    #[cfg(any(feature = "rustls", feature = "boring"))]
    proxy_tls_config: Option<Arc<ClientConfig>>,

    http_req_inspector_jit: I1,
    http_req_inspector_svc: I2,
}

#[cfg(any(feature = "rustls", feature = "boring"))]
impl<I1: fmt::Debug, I2: fmt::Debug> fmt::Debug for EasyHttpWebClient<I1, I2> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHttpWebClient")
            .field("tls_config", &self.tls_config)
            .field("proxy_tls_config", &self.proxy_tls_config)
            .field("http_req_inspector_jit", &self.http_req_inspector_jit)
            .field("http_req_inspector_svc", &self.http_req_inspector_svc)
            .finish()
    }
}

#[cfg(not(any(feature = "rustls", feature = "boring")))]
impl<I1: fmt::Debug, I2: fmt::Debug> fmt::Debug for EasyHttpWebClient<I1, I2> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHttpWebClient")
            .field("http_req_inspector_jit", &self.http_req_inspector_jit)
            .field("http_req_inspector_svc", &self.http_req_inspector_svc)
            .finish()
    }
}

#[cfg(any(feature = "rustls", feature = "boring"))]
impl<I1: Clone, I2: Clone> Clone for EasyHttpWebClient<I1, I2> {
    fn clone(&self) -> Self {
        Self {
            tls_config: self.tls_config.clone(),
            proxy_tls_config: self.proxy_tls_config.clone(),
            http_req_inspector_jit: self.http_req_inspector_jit.clone(),
            http_req_inspector_svc: self.http_req_inspector_svc.clone(),
        }
    }
}

#[cfg(not(any(feature = "rustls", feature = "boring")))]
impl<I1: Clone, I2: Clone> Clone for EasyHttpWebClient<I1, I2> {
    fn clone(&self) -> Self {
        Self {
            http_req_inspector_jit: self.http_req_inspector_jit.clone(),
            http_req_inspector_svc: self.http_req_inspector_svc.clone(),
        }
    }
}

impl Default for EasyHttpWebClient {
    fn default() -> Self {
        Self {
            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_config: None,
            #[cfg(any(feature = "rustls", feature = "boring"))]
            proxy_tls_config: None,
            http_req_inspector_jit: (),
            http_req_inspector_svc: (),
        }
    }
}

impl EasyHttpWebClient {
    /// Create a new [`EasyHttpWebClient`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl<I1, I2> EasyHttpWebClient<I1, I2> {
    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Set the [`ClientConfig`] of this [`EasyHttpWebClient`].
    pub fn set_tls_config(&mut self, cfg: impl Into<Arc<ClientConfig>>) -> &mut Self {
        self.tls_config = Some(cfg.into());
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`EasyHttpWebClient`] with the [`ClientConfig`] set.
    pub fn with_tls_config(mut self, cfg: impl Into<Arc<ClientConfig>>) -> Self {
        self.tls_config = Some(cfg.into());
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`EasyHttpWebClient`] with an option of [`ClientConfig`] set.
    pub fn maybe_with_tls_config(mut self, cfg: Option<impl Into<Arc<ClientConfig>>>) -> Self {
        self.tls_config = cfg.map(Into::into);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Set the [`ClientConfig`] for the https proxy tunnel if needed within this [`EasyHttpWebClient`].
    pub fn set_proxy_tls_config(&mut self, cfg: impl Into<Arc<ClientConfig>>) -> &mut Self {
        self.proxy_tls_config = Some(cfg.into());
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`EasyHttpWebClient`] set for the https proxy tunnel if needed within this [`ClientConfig`].
    pub fn with_proxy_tls_config(mut self, cfg: impl Into<Arc<ClientConfig>>) -> Self {
        self.proxy_tls_config = Some(cfg.into());
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`EasyHttpWebClient`] set for the https proxy tunnel if needed within this [`ClientConfig`].
    pub fn maybe_proxy_with_tls_config(
        mut self,
        cfg: Option<impl Into<Arc<ClientConfig>>>,
    ) -> Self {
        self.proxy_tls_config = cfg.map(Into::into);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    pub fn with_http_conn_req_inspector<T>(
        self,
        http_req_inspector: T,
    ) -> EasyHttpWebClient<T, I2> {
        EasyHttpWebClient {
            tls_config: self.tls_config,
            proxy_tls_config: self.proxy_tls_config,
            http_req_inspector_jit: http_req_inspector,
            http_req_inspector_svc: self.http_req_inspector_svc,
        }
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    pub fn with_http_conn_req_inspector<T>(
        self,
        http_req_inspector: T,
    ) -> EasyHttpWebClient<T, I2> {
        EasyHttpWebClient {
            http_req_inspector_jit: http_req_inspector,
            http_req_inspector_svc: self.http_req_inspector_svc,
        }
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    pub fn with_http_serve_req_inspector<T>(
        self,
        http_req_inspector: T,
    ) -> EasyHttpWebClient<I1, T> {
        EasyHttpWebClient {
            tls_config: self.tls_config,
            proxy_tls_config: self.proxy_tls_config,
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: http_req_inspector,
        }
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    pub fn with_http_serve_req_inspector<T>(
        self,
        http_req_inspector: T,
    ) -> EasyHttpWebClient<I1, T> {
        EasyHttpWebClient {
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: http_req_inspector,
        }
    }
}

impl<State, BodyIn, BodyOut, I1, I2> Service<State, Request<BodyIn>> for EasyHttpWebClient<I1, I2>
where
    State: Clone + Send + Sync + 'static,
    BodyIn: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    BodyOut: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    I1: RequestInspector<
            State,
            Request<BodyIn>,
            Error: Into<BoxError>,
            StateOut = State,
            RequestOut = Request<BodyIn>,
        > + Clone,
    I2: RequestInspector<
            State,
            Request<BodyIn>,
            Error: Into<BoxError>,
            RequestOut = Request<BodyOut>,
        > + Clone,
{
    type Response = Response;
    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<BodyIn>,
    ) -> Result<Self::Response, Self::Error> {
        let uri = req.uri().clone();

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
                        "EasyHttpWebClient: create proxy tls connector data from tls config found in context",
                    )?
                }
                (None, Some(proxy_tls_config)) => {
                    trace!("create proxy tls connector using pre-defined rama tls client config");
                    proxy_tls_config.as_ref().clone().try_into().context(
                        "EasyHttpWebClient: create proxy tls connector data from tls config",
                    )?
                }
                (None, None) => {
                    trace!("create proxy tls connector using the 'new_http_auto' constructor");
                    TlsConnectorData::new().context(
                        "EasyHttpWebClient: create proxy tls connector data with no application presets",
                    )?
                }
            };

            let transport_connector = HttpProxyConnector::optional(
                TlsConnector::tunnel(tcp_connector, None)
                    .with_connector_data(proxy_tls_connector_data),
            );
            let tls_connector_data = match extract_client_config_from_ctx(&ctx) {
                Some(mut chain_ref) => {
                    trace!(
                        "create tls connector using rama tls client config(s) from context and/or the predefined one if defined"
                    );
                    if let Some(tls_config) = self.tls_config.clone() {
                        chain_ref.prepend(tls_config);
                    }
                    TlsConnectorData::try_from_multiple_client_configs(chain_ref.iter()).context(
                        "EasyHttpWebClient: create tls connector data from tls client config(s) from context and/or the predefined one if defined",
                    )?
                }
                None => match self.tls_config.as_deref() {
                    Some(tls_config) => {
                        trace!("create tls connector using pre-defined rama tls client config");
                        tls_config.clone().try_into().context(
                            "EasyHttpWebClient: create tls connector data from pre-defined tls config",
                        )?
                    }
                    None => {
                        trace!("create tls connector using the 'new_http_auto' constructor");
                        TlsConnectorData::new_http_auto().context(
                            "EasyHttpWebClient: create tls connector data for http (auto)",
                        )?
                    }
                },
            };
            HttpConnector::new(
                TlsConnector::auto(transport_connector).with_connector_data(tls_connector_data),
            )
            .with_jit_req_inspector((
                HttpsAlpnModifier::default(),
                self.http_req_inspector_jit.clone(),
            ))
        };
        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        let connector = HttpConnector::new(HttpProxyConnector::optional(tcp_connector))
            .with_jit_req_inspector(self.http_req_inspector_jit.clone());

        // set the runtime http req inspector
        let connector = connector.with_svc_req_inspector(self.http_req_inspector_svc.clone());

        // NOTE: stack might change request version based on connector data,
        // such as ALPN (tls), as such it is important to reset it back below,
        // so that the other end can read it... This might however give issues in
        // case switching http versions requires more work than version. If so,
        // your first place will be to check here and/or in the [`HttpConnector`].
        let EstablishedClientConnection { ctx, req, conn } = connector
            .connect(ctx, req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err).with_context(|| uri.to_string()))?;

        trace!(uri = %uri, "send http req to connector stack");
        let resp = conn.serve(ctx, req).await.map_err(|err| {
            OpaqueError::from_boxed(err)
                .with_context(|| format!("http request failure for uri: {uri}"))
        })?;
        trace!(uri = %uri, "response received from connector stack");

        Ok(resp)
    }
}
