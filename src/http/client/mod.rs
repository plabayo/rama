//! rama http client support
//!
//! Contains re-exports from `rama-http-backend::client`
//! and adds `EasyHttpWebClient`, an opiniated http web client which
//! supports most common use cases and provides sensible defaults.
use std::fmt;

use crate::{
    Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    extensions::{ExtensionsMut, ExtensionsRef},
    http::{Request, Response, StreamingBody},
    net::client::EstablishedClientConnection,
    rt::Executor,
    service::BoxService,
    telemetry::tracing,
};

#[doc(inline)]
pub use ::rama_http_backend::client::*;

pub mod builder;
#[doc(inline)]
pub use builder::EasyHttpConnectorBuilder;

#[cfg(feature = "socks5")]
mod proxy_connector;
#[cfg(feature = "socks5")]
#[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
#[doc(inline)]
pub use proxy_connector::{MaybeProxiedConnection, ProxyConnector, ProxyConnectorLayer};

/// An opiniated http client that can be used to serve HTTP requests.
///
/// Use [`EasyHttpWebClient::connector_builder()`] to easily create a client with
/// a common Http connector setup (tcp + proxy + tls + http) or bring your
/// own http connector.
///
/// You can fork this http client in case you have use cases not possible with this service example.
/// E.g. perhaps you wish to have middleware in into outbound requests, after they
/// passed through your "connector" setup. All this and more is possible by defining your own
/// http client. Rama is here to empower you, the building blocks are there, go crazy
/// with your own service fork and use the full power of Rust at your fingertips ;)
pub struct EasyHttpWebClient<BodyIn, ConnResponse, L> {
    connector: BoxService<Request<BodyIn>, ConnResponse, BoxError>,
    jit_layers: L,
}

impl<BodyIn, ConnResponse, L> fmt::Debug for EasyHttpWebClient<BodyIn, ConnResponse, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHttpWebClient").finish()
    }
}

impl<BodyIn, ConnResponse, L: Clone> Clone for EasyHttpWebClient<BodyIn, ConnResponse, L> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            jit_layers: self.jit_layers.clone(),
        }
    }
}

impl EasyHttpWebClient<(), (), ()> {
    /// Create a [`EasyHttpConnectorBuilder`] to easily create a [`EasyHttpWebClient`] with a custom connector
    #[must_use]
    pub fn connector_builder() -> EasyHttpConnectorBuilder {
        EasyHttpConnectorBuilder::new()
    }
}

impl<Body> Default
    for EasyHttpWebClient<
        Body,
        EstablishedClientConnection<HttpClientService<Body>, Request<Body>>,
        (),
    >
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    #[inline(always)]
    fn default() -> Self {
        Self::default_with_executor(Executor::default())
    }
}

impl<Body>
    EasyHttpWebClient<Body, EstablishedClientConnection<HttpClientService<Body>, Request<Body>>, ()>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    #[cfg(feature = "boring")]
    pub fn default_with_executor(exec: Executor) -> Self {
        let tls_config =
            rama_tls_boring::client::TlsConnectorDataBuilder::new_http_auto().into_shared_builder();

        EasyHttpConnectorBuilder::new()
            .with_default_transport_connector()
            .with_tls_proxy_support_using_boringssl()
            .with_proxy_support()
            .with_tls_support_using_boringssl(Some(tls_config))
            .with_default_http_connector(exec)
            .build_client()
    }

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    pub fn default_with_executor(exec: Executor) -> Self {
        let tls_config = rama_tls_rustls::client::TlsConnectorData::try_new_http_auto()
            .expect("connector data with http auto");

        EasyHttpConnectorBuilder::new()
            .with_default_transport_connector()
            .with_tls_proxy_support_using_rustls()
            .with_proxy_support()
            .with_tls_support_using_rustls(Some(tls_config))
            .with_default_http_connector(exec)
            .build_client()
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    pub fn default_with_executor(exec: Executor) -> Self {
        EasyHttpConnectorBuilder::new()
            .with_default_transport_connector()
            .without_tls_proxy_support()
            .with_proxy_support()
            .without_tls_support()
            .with_default_http_connector(exec)
            .build_client()
    }
}

impl<BodyIn, ConnResponse> EasyHttpWebClient<BodyIn, ConnResponse, ()> {
    /// Create a new [`EasyHttpWebClient`] using the provided connector
    #[must_use]
    pub fn new(connector: BoxService<Request<BodyIn>, ConnResponse, BoxError>) -> Self {
        Self {
            connector,
            jit_layers: (),
        }
    }
}

impl<BodyIn, ConnResponse, L> EasyHttpWebClient<BodyIn, ConnResponse, L> {
    /// Set the connector that this [`EasyHttpWebClient`] will use
    #[must_use]
    pub fn with_connector<BodyInNew, ConnResponseNew>(
        self,
        connector: BoxService<Request<BodyInNew>, ConnResponseNew, BoxError>,
    ) -> EasyHttpWebClient<BodyInNew, ConnResponseNew, L> {
        EasyHttpWebClient {
            connector,
            jit_layers: self.jit_layers,
        }
    }

    /// [`Layer`] which will be applied just in time (JIT) before the request is send, but after
    /// the connection has been established.
    ///
    /// Simplified flow of how the [`EasyHttpWebClient`] works:
    /// 1. External: let response = client.serve(request)
    /// 2. Internal: let http_connection = self.connector.serve(request)
    /// 3. Internal: let response = jit_layers.layer(http_connection).serve(request)
    pub fn with_jit_layer<T>(self, jit_layers: T) -> EasyHttpWebClient<BodyIn, ConnResponse, T> {
        EasyHttpWebClient {
            connector: self.connector,
            jit_layers,
        }
    }
}

impl<Body, ConnectionBody, Connection, L> Service<Request<Body>>
    for EasyHttpWebClient<Body, EstablishedClientConnection<Connection, Request<ConnectionBody>>, L>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    Connection:
        Service<Request<ConnectionBody>, Output = Response, Error = BoxError> + ExtensionsRef,
    // Body type this connection will be able to send, this is not necessarily the same one that
    // was used in the request that created this connection
    ConnectionBody:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    L: Layer<
            Connection,
            Service: Service<Request<ConnectionBody>, Output = Response, Error = BoxError>,
        > + Send
        + Sync
        + 'static,
{
    type Output = Response;
    type Error = OpaqueError;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        let uri = req.uri().clone();

        let EstablishedClientConnection {
            input: mut req,
            conn: http_connection,
        } = self.connector.serve(req).await?;

        req.extensions_mut()
            .extend(http_connection.extensions().clone());

        let http_connection = self.jit_layers.layer(http_connection);

        // NOTE: stack might change request version based on connector data,
        tracing::trace!(url.full = %uri, "send http req to connector stack");

        let result = http_connection.serve(req).await;

        let resp = result
            .map_err(OpaqueError::from_boxed)
            .with_context(|| format!("http request failure for uri: {uri}"))?;

        tracing::trace!(url.full = %uri, "response received from connector stack");

        Ok(resp)
    }
}
