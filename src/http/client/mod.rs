//! rama http client support
//!
//! Contains re-exports from `rama-http-backend::client`
//! and adds `EasyHttpWebClient`, an opiniated http web client which
//! supports most common use cases and provides sensible defaults.
use std::fmt;

use crate::{
    Context, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    http::{Request, Response, StreamingBody},
    net::client::EstablishedClientConnection,
    service::BoxService,
    telemetry::tracing,
};

#[doc(inline)]
pub use ::rama_http_backend::client::*;

pub mod builder;
#[doc(inline)]
pub use builder::EasyHttpWebClientBuilder;

#[cfg(feature = "socks5")]
mod proxy_connector;
#[cfg(feature = "socks5")]
#[doc(inline)]
pub use proxy_connector::{MaybeProxiedConnection, ProxyConnector, ProxyConnectorLayer};

/// An opiniated http client that can be used to serve HTTP requests.
///
/// Use [`EasyHttpWebClient::builder()`] to easily create a client with
/// a common Http connector setup (tcp + proxy + tls + http) or bring your
/// own http connector.
///
/// You can fork this http client in case you have use cases not possible with this service example.
/// E.g. perhaps you wish to have middleware in into outbound requests, after they
/// passed through your "connector" setup. All this and more is possible by defining your own
/// http client. Rama is here to empower you, the building blocks are there, go crazy
/// with your own service fork and use the full power of Rust at your fingertips ;)
pub struct EasyHttpWebClient<BodyIn, ConnResponse> {
    connector: BoxService<Request<BodyIn>, ConnResponse, BoxError>,
}

impl<BodyIn, ConnResponse> fmt::Debug for EasyHttpWebClient<BodyIn, ConnResponse> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHttpWebClient").finish()
    }
}

impl<BodyIn, ConnResponse> Clone for EasyHttpWebClient<BodyIn, ConnResponse> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
        }
    }
}

impl EasyHttpWebClient<(), ()> {
    /// Create a [`EasyHttpWebClientBuilder`] to easily create a [`EasyHttpWebClient`]
    #[must_use]
    pub fn builder() -> EasyHttpWebClientBuilder {
        EasyHttpWebClientBuilder::new()
    }
}

impl<Body> Default
    for EasyHttpWebClient<Body, EstablishedClientConnection<HttpClientService<Body>, Request<Body>>>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    #[cfg(feature = "boring")]
    fn default() -> Self {
        let tls_config =
            rama_tls_boring::client::TlsConnectorDataBuilder::new_http_auto().into_shared_builder();

        EasyHttpWebClientBuilder::new()
            .with_default_transport_connector()
            .with_tls_proxy_support_using_boringssl()
            .with_proxy_support()
            .with_tls_support_using_boringssl(Some(tls_config))
            .build()
    }

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    fn default() -> Self {
        let tls_config = rama_tls_rustls::client::TlsConnectorData::new_http_auto()
            .expect("connector data with http auto");

        EasyHttpWebClientBuilder::new()
            .with_default_transport_connector()
            .with_tls_proxy_support_using_rustls()
            .with_proxy_support()
            .with_tls_support_using_rustls(Some(tls_config))
            .build()
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    fn default() -> Self {
        EasyHttpWebClientBuilder::new()
            .with_default_transport_connector()
            .without_tls_proxy_support()
            .with_proxy_support()
            .without_tls_support()
            .build()
    }
}

impl<BodyIn, ConnResponse> EasyHttpWebClient<BodyIn, ConnResponse> {
    /// Create a new [`EasyHttpWebClient`] using the provided connector
    #[must_use]
    pub fn new(connector: BoxService<Request<BodyIn>, ConnResponse, BoxError>) -> Self {
        Self { connector }
    }

    /// Set the connector that this [`EasyHttpWebClient`] will use
    #[must_use]
    pub fn with_connector<BodyInNew, ConnResponseNew>(
        self,
        connector: BoxService<Request<BodyInNew>, ConnResponseNew, BoxError>,
    ) -> EasyHttpWebClient<BodyInNew, ConnResponseNew> {
        EasyHttpWebClient { connector }
    }
}

impl<Body, ModifiedBody, ConnResponse> Service<Request<Body>>
    for EasyHttpWebClient<Body, EstablishedClientConnection<ConnResponse, Request<ModifiedBody>>>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    ModifiedBody:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    ConnResponse: Service<Request<ModifiedBody>, Response = Response, Error = BoxError>,
{
    type Response = Response;

    type Error = OpaqueError;

    async fn serve(&self, ctx: Context, req: Request<Body>) -> Result<Self::Response, Self::Error> {
        let uri = req.uri().clone();

        let EstablishedClientConnection { ctx, req, conn } = self.connector.serve(ctx, req).await?;
        // NOTE: stack might change request version based on connector data,
        tracing::trace!(url.full = %uri, "send http req to connector stack");

        let result = conn.serve(ctx, req).await;

        let resp = result
            .map_err(OpaqueError::from_boxed)
            .with_context(|| format!("http request failure for uri: {uri}"))?;

        tracing::trace!(url.full = %uri, "response received from connector stack");

        Ok(resp)
    }
}
