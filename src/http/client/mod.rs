//! Rama HTTP client module,
//! which provides the [`HttpClient`] type to serve HTTP requests.

use crate::{
    error::BoxError,
    http::{dep::http_body, Request, Response},
    net::client::{ConnectorService, EstablishedClientConnection},
    tcp::client::service::TcpConnector,
    tls::rustls::client::HttpsConnector,
    Context, Layer, Service,
};
use std::fmt;

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

/// An http client that can be used to serve HTTP requests.
///
/// The underlying connections are established using the provided connection [`Service`],
/// which is a [`Service`] that is expected to return as output an [`EstablishedClientConnection`].
pub struct HttpClient<C, L> {
    connector: C,
    sender_layer_stack: L,
}

impl<C: fmt::Debug, L: fmt::Debug> fmt::Debug for HttpClient<C, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient")
            .field("connector", &self.connector)
            .field("sender_layer_stack", &self.sender_layer_stack)
            .finish()
    }
}

impl<C: Clone, L: Clone> Clone for HttpClient<C, L> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            sender_layer_stack: self.sender_layer_stack.clone(),
        }
    }
}

impl<C> HttpClient<C, ()> {
    /// Create a new [`HttpClient`] using the specified connection [`Service`]
    /// to establish connections to the server in the form of an [`EstablishedClientConnection`] as output.
    pub const fn new(connector: C) -> Self {
        Self {
            connector,
            sender_layer_stack: (),
        }
    }

    /// Define an [`Layer`] (stack) to create a [`Service`] stack
    /// through which the http [`Request`] will have to pass
    /// before actually being send of the the "target".
    pub fn layer<L>(self, layer_stack: L) -> HttpClient<C, L> {
        HttpClient {
            connector: self.connector,
            sender_layer_stack: layer_stack,
        }
    }
}

impl Default for HttpClient<HttpConnector<HttpsConnector<TcpConnector>>, ()> {
    fn default() -> Self {
        let connector = HttpConnector::new(HttpsConnector::auto(TcpConnector::default()));
        Self {
            connector,
            sender_layer_stack: (),
        }
    }
}

impl<State, Body, C, L> Service<State, Request<Body>> for HttpClient<C, L>
where
    State: Send + Sync + 'static,
    Body: http_body::Body<Data: Send + 'static, Error: Into<Box<dyn std::error::Error + Send + Sync>>>
        + Unpin
        + Send
        + 'static,
    C: ConnectorService<State, Request<Body>>,
    L: Layer<
            C::Connection,
            Service: Service<State, Request<Body>, Response = Response, Error: Into<BoxError>>,
        > + Send
        + Sync
        + 'static,
{
    type Response = Response;
    type Error = HttpClientError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let uri = req.uri().clone();

        let EstablishedClientConnection {
            ctx,
            req,
            conn: svc,
            ..
        } = self
            .connector
            .connect(ctx, req)
            .await
            .map_err(|err| HttpClientError::from_boxed(err.into()).with_uri(uri.clone()))?;

        let sender = self.sender_layer_stack.layer(svc);

        sender
            .serve(ctx, req)
            .await
            .map_err(|err| HttpClientError::from_boxed(err.into()).with_uri(uri))
    }
}
