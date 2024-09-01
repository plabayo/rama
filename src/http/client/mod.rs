//! Rama HTTP client module,
//! which provides the [`HttpClient`] type to serve HTTP requests.

use crate::{
    error::BoxError,
    http::{dep::http_body, Request, Response},
    net::client::{ConnectorService, EstablishedClientConnection},
    proxy::http::client::layer::HttpProxyConnector,
    tcp::client::service::TcpConnector,
    tls::rustls::{client::HttpsConnector, dep::rustls::ClientConfig}, // TODO: use default backend
    Context,
    Service,
};
use std::sync::Arc;

mod error;
#[doc(inline)]
pub use error::HttpClientError;

mod ext;
#[doc(inline)]
pub use ext::{HttpClientExt, IntoUrl, RequestBuilder};

mod svc;
#[doc(inline)]
pub use svc::HttpClientService;

mod conn;
#[doc(inline)]
pub use conn::{HttpConnector, HttpConnectorLayer};

#[derive(Debug, Clone, Default)]
/// An opiniated http client that can be used to serve HTTP requests.
///
/// You can fork this http client in case you have use cases not possible with this service example.
/// E.g. perhaps you wish to have middleware in into outbound requests, after they
/// passed through your "connector" setup. All this and more is possible by defining your own
/// http client. Rama is here to empower you, the building blocks are there, go crazy
/// with your own service fork and use the full power of Rust at your fingertips ;)
pub struct HttpClient {
    tls_config: Option<Arc<ClientConfig>>,
}

impl HttpClient {
    /// Create a new [`HttpClient`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [`ClientConfig`] of this [`HttpClient`].
    pub fn set_tls_config(&mut self, cfg: Arc<ClientConfig>) -> &mut Self {
        self.tls_config = Some(cfg);
        self
    }

    /// Replace this [`HttpClient`] with the [`ClientConfig`] set.
    pub fn with_tls_config(mut self, cfg: Arc<ClientConfig>) -> Self {
        self.tls_config = Some(cfg);
        self
    }

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
    type Error = HttpClientError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let uri = req.uri().clone();

        let connector = HttpConnector::new(
            HttpsConnector::auto(HttpProxyConnector::optional(HttpsConnector::tunnel(
                TcpConnector::new(),
            )))
            .maybe_with_config(self.tls_config.clone()),
        );

        let EstablishedClientConnection { ctx, req, conn, .. } = connector
            .connect(ctx, req)
            .await
            .map_err(|err| HttpClientError::from_boxed(err).with_uri(uri.clone()))?;

        conn.serve(ctx, req)
            .await
            .map_err(|err| HttpClientError::from_boxed(err).with_uri(uri))
    }
}
