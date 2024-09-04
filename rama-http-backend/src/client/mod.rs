//! Rama HTTP client module,
//! which provides the [`HttpClient`] type to serve HTTP requests.

use rama_core::{
    error::{BoxError, OpaqueError, ErrorExt},
    Context, Service,
};
use rama_http_types::{dep::http_body, Request, Response};
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use proxy::layer::HttpProxyConnector;
use rama_tcp::client::service::TcpConnector;

// TODO: also support client config in boring...
#[cfg(all(feature = "rustls", not(feature = "boring")))]
use rama_tls::rustls::dep::rustls::ClientConfig;
#[cfg(all(feature = "rustls", not(feature = "boring")))]
use std::sync::Arc;

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_tls::std::client::HttpsConnector;

mod svc;
#[doc(inline)]
pub use svc::HttpClientService;

mod conn;
#[doc(inline)]
pub use conn::{HttpConnector, HttpConnectorLayer};

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
    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    tls_config: Option<Arc<ClientConfig>>,
}

impl HttpClient {
    /// Create a new [`HttpClient`].
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    /// Set the [`ClientConfig`] of this [`HttpClient`].
    pub fn set_tls_config(&mut self, cfg: Arc<ClientConfig>) -> &mut Self {
        self.tls_config = Some(cfg);
        self
    }

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    /// Replace this [`HttpClient`] with the [`ClientConfig`] set.
    pub fn with_tls_config(mut self, cfg: Arc<ClientConfig>) -> Self {
        self.tls_config = Some(cfg);
        self
    }

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    /// Replace this [`HttpClient`] with an option of [`ClientConfig`] set.
    pub fn maybe_with_tls_config(mut self, cfg: Option<Arc<ClientConfig>>) -> Self {
        self.tls_config = cfg;
        self
    }
}

impl<State, Body> Service<State, Request<Body>> for HttpClient
where
    State: Send + Sync + 'static,
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

        #[cfg(all(feature = "rustls", not(feature = "boring")))]
        let connector = HttpConnector::new(
            HttpsConnector::auto(HttpProxyConnector::optional(HttpsConnector::tunnel(
                TcpConnector::new(),
            )))
            .maybe_with_config(self.tls_config.clone()),
        );
        #[cfg(feature = "boring")]
        let connector = HttpConnector::new(HttpsConnector::auto(HttpProxyConnector::optional(
            HttpsConnector::tunnel(TcpConnector::new()),
        )));
        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        let connector = HttpConnector::new(HttpProxyConnector::optional(TcpConnector::new()));

        let EstablishedClientConnection { ctx, req, conn, .. } = connector
            .connect(ctx, req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err).with_context(|| uri.to_string()))?;

        conn.serve(ctx, req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err).with_context(|| uri.to_string()))
    }
}
