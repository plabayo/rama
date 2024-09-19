use super::TlsConnectorData;
use crate::types::HttpsTunnel;
use pin_project_lite::pin_project;
use private::{ConnectorKindAuto, ConnectorKindSecure, ConnectorKindTunnel};
use rama_core::error::{BoxError, ErrorExt, OpaqueError};
use rama_core::{Context, Layer, Service};
use rama_net::address::Host;
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_net::stream::Stream;
use rama_net::tls::client::NegotiatedTlsParameters;
use rama_net::tls::ApplicationProtocol;
use rama_net::transport::TryRefIntoTransportContext;
use std::fmt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_boring::SslStream;

/// A [`Layer`] which wraps the given service with a [`HttpsConnector`].
///
/// See [`HttpsConnector`] for more information.
#[derive(Clone)]
pub struct HttpsConnectorLayer<K = ConnectorKindAuto> {
    connector_data: Option<TlsConnectorData>,
    _kind: std::marker::PhantomData<K>,
}

impl<K> std::fmt::Debug for HttpsConnectorLayer<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsConnectorLayer")
            .field("connector_data", &self.connector_data)
            .field("_kind", &format_args!("<{}>", std::any::type_name::<K>()))
            .finish()
    }
}

impl<K> HttpsConnectorLayer<K> {
    /// Attach [`TlsConnectorData`] to this [`HttpsConnectorLayer`],
    /// to be used instead of a globally shared [`TlsConnectorData::default`].
    pub fn with_connector_data(mut self, connector_data: TlsConnectorData) -> Self {
        self.connector_data = Some(connector_data);
        self
    }

    /// Maybe attach [`TlsConnectorData`] to this [`HttpsConnectorLayer`],
    /// to be used if `Some` instead of a globally shared [`TlsConnectorData::default`].
    pub fn maybe_with_connector_data(mut self, connector_data: Option<TlsConnectorData>) -> Self {
        self.connector_data = connector_data;
        self
    }

    /// Attach [`TlsConnectorData`] to this [`HttpsConnectorLayer`],
    /// to be used instead of a globally shared default client config.
    pub fn set_connector_data(&mut self, connector_data: TlsConnectorData) -> &mut Self {
        self.connector_data = Some(connector_data);
        self
    }
}

impl HttpsConnectorLayer<ConnectorKindAuto> {
    /// Creates a new [`HttpsConnectorLayer`] which will establish
    /// a secure connection if the request demands it,
    /// otherwise it will forward the pre-established inner connection.
    pub fn auto() -> Self {
        Self {
            connector_data: None,
            _kind: std::marker::PhantomData,
        }
    }
}

impl HttpsConnectorLayer<ConnectorKindSecure> {
    /// Creates a new [`HttpsConnectorLayer`] which will always
    /// establish a secure connection regardless of the request it is for.
    pub fn secure_only() -> Self {
        Self {
            connector_data: None,
            _kind: std::marker::PhantomData,
        }
    }
}

impl HttpsConnectorLayer<ConnectorKindTunnel> {
    /// Creates a new [`HttpsConnectorLayer`] which will establish
    /// a secure connection if the request is to be tunneled.
    pub fn tunnel() -> Self {
        Self {
            connector_data: None,
            _kind: std::marker::PhantomData,
        }
    }
}

impl<K, S> Layer<S> for HttpsConnectorLayer<K> {
    type Service = HttpsConnector<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpsConnector {
            inner,
            connector_data: self.connector_data.clone(),
            _kind: self._kind,
        }
    }
}

impl Default for HttpsConnectorLayer<ConnectorKindAuto> {
    fn default() -> Self {
        Self::auto()
    }
}

/// A connector which can be used to establish a connection to a server.
///
/// By default it will created in auto mode ([`HttpsConnector::auto`]),
/// which will perform the Tls handshake on the underlying stream,
/// only if the request requires a secure connection. You can instead use
/// [`HttpsConnector::secure_only`] to force the connector to always
/// establish a secure connection.
pub struct HttpsConnector<S, K = ConnectorKindAuto> {
    inner: S,
    connector_data: Option<TlsConnectorData>,
    _kind: std::marker::PhantomData<K>,
}

impl<S: fmt::Debug, K> fmt::Debug for HttpsConnector<S, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsConnector")
            .field("inner", &self.inner)
            .field("connector_data", &self.connector_data)
            .field("_kind", &format_args!("<{}>", std::any::type_name::<K>()))
            .finish()
    }
}

impl<S: Clone, K> Clone for HttpsConnector<S, K> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            connector_data: self.connector_data.clone(),
            _kind: std::marker::PhantomData,
        }
    }
}

impl<S, K> HttpsConnector<S, K> {
    /// Creates a new [`HttpsConnector`].
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            connector_data: None,
            _kind: std::marker::PhantomData,
        }
    }

    /// Attach [`TlsConnectorData`] to this [`HttpsConnector`],
    /// to be used instead of a globally shared [`TlsConnectorData::default`].
    ///
    /// NOTE: for a smooth interaction with HTTP you most likely do want to
    /// create tls connector data to at the very least define the ALPN's correctly.
    ///
    /// E.g. if you create an auto client, you want to make sure your ALPN can handle all.
    /// It will be then also be the [`HttpsConnector`] that sets the request http version correctly.
    pub fn with_connector_data(mut self, connector_data: TlsConnectorData) -> Self {
        self.connector_data = Some(connector_data);
        self
    }

    /// Maybe attach [`TlsConnectorData`] to this [`HttpsConnector`],
    /// to be used if `Some` instead of a globally shared [`TlsConnectorData::default`].
    pub fn maybe_with_connector_data(mut self, connector_data: Option<TlsConnectorData>) -> Self {
        self.connector_data = connector_data;
        self
    }

    /// Attach [`TlsConnectorData`] to this [`HttpsConnector`],
    /// to be used instead of a globally shared default client config.
    pub fn set_connector_data(&mut self, connector_data: TlsConnectorData) -> &mut Self {
        self.connector_data = Some(connector_data);
        self
    }
}

impl<S> HttpsConnector<S, ConnectorKindAuto> {
    /// Creates a new [`HttpsConnector`] which will establish
    /// a secure connection if the request demands it,
    /// otherwise it will forward the pre-established inner connection.
    pub const fn auto(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> HttpsConnector<S, ConnectorKindSecure> {
    /// Creates a new [`HttpsConnector`] which will always
    /// establish a secure connection regardless of the request it is for.
    pub const fn secure_only(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> HttpsConnector<S, ConnectorKindTunnel> {
    /// Creates a new [`HttpsConnector`] which will establish
    /// a secure connection if the request is to be tunneled.
    pub const fn tunnel(inner: S) -> Self {
        Self::new(inner)
    }
}

/// this way we do not need a hacky macro... however is there a way to do this without needing to hacK?!?!

impl<S, State, Request> Service<State, Request> for HttpsConnector<S, ConnectorKindAuto>
where
    S: ConnectorService<State, Request, Connection: Stream + Unpin, Error: Into<BoxError>>,
    State: Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State, Error: Into<BoxError> + Send + Sync + 'static>
        + Send
        + 'static,
{
    type Response = EstablishedClientConnection<AutoTlsStream<S::Connection>, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection {
            mut ctx,
            req,
            conn,
            addr,
        } = self.inner.connect(ctx, req).await.map_err(Into::into)?;

        let transport_ctx = ctx
            .get_or_try_insert_with_ctx(|ctx| req.try_ref_into_transport_ctx(ctx))
            .map_err(|err| {
                OpaqueError::from_boxed(err.into())
                    .context("HttpsConnector(auto): compute transport context")
            })?;

        if !transport_ctx
            .app_protocol
            .as_ref()
            .map(|p| p.is_secure())
            .unwrap_or_default()
        {
            tracing::trace!(
                authority = %transport_ctx.authority,
                "HttpsConnector(auto): protocol not secure, return inner connection",
            );
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn: AutoTlsStream {
                    inner: AutoTlsStreamData::Plain { inner: conn },
                },
                addr,
            });
        }

        let host = transport_ctx.authority.host().clone();

        let (stream, negotiated_params) = self.handshake(host, conn).await?;

        tracing::trace!(
            authority = %transport_ctx.authority,
            "HttpsConnector(auto): protocol secure, established tls connection",
        );

        ctx.insert(negotiated_params);

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: AutoTlsStream {
                inner: AutoTlsStreamData::Secure { inner: stream },
            },
            addr,
        })
    }
}

impl<S, State, Request> Service<State, Request> for HttpsConnector<S, ConnectorKindSecure>
where
    S: ConnectorService<State, Request, Connection: Stream + Unpin, Error: Into<BoxError>>,
    State: Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State, Error: Into<BoxError> + Send + Sync + 'static>
        + Send
        + 'static,
{
    type Response = EstablishedClientConnection<SslStream<S::Connection>, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection {
            mut ctx,
            req,
            conn,
            addr,
        } = self.inner.connect(ctx, req).await.map_err(Into::into)?;

        let transport_ctx = ctx
            .get_or_try_insert_with_ctx(|ctx| req.try_ref_into_transport_ctx(ctx))
            .map_err(|err| {
                OpaqueError::from_boxed(err.into())
                    .context("HttpsConnector(auto): compute transport context")
            })?;
        tracing::trace!(
            authority = %transport_ctx.authority,
            "HttpsConnector(secure): attempt to secure inner connection",
        );

        let host = transport_ctx.authority.host().clone();

        let (conn, negotiated_params) = self.handshake(host, conn).await?;
        ctx.insert(negotiated_params);

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn,
            addr,
        })
    }
}

impl<S, State, Request> Service<State, Request> for HttpsConnector<S, ConnectorKindTunnel>
where
    S: ConnectorService<State, Request, Connection: Stream + Unpin, Error: Into<BoxError>>,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Response = EstablishedClientConnection<AutoTlsStream<S::Connection>, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection {
            mut ctx,
            req,
            conn,
            addr,
        } = self.inner.connect(ctx, req).await.map_err(Into::into)?;

        let host = match ctx.get::<HttpsTunnel>() {
            Some(tunnel) => tunnel.server_host.clone(),
            None => {
                tracing::trace!(
                    "HttpsConnector(tunnel): return inner connection: no Https tunnel is requested"
                );
                return Ok(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: AutoTlsStream {
                        inner: AutoTlsStreamData::Plain { inner: conn },
                    },
                    addr,
                });
            }
        };

        let (stream, negotiated_params) = self.handshake(host, conn).await?;
        ctx.insert(negotiated_params);

        tracing::trace!("HttpsConnector(tunnel): connection secured");
        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: AutoTlsStream {
                inner: AutoTlsStreamData::Secure { inner: stream },
            },
            addr,
        })
    }
}

impl<S, K> HttpsConnector<S, K> {
    async fn handshake<T>(
        &self,
        server_host: Host,
        stream: T,
    ) -> Result<(SslStream<T>, NegotiatedTlsParameters), BoxError>
    where
        T: Stream + Unpin,
    {
        let (config, server_host) = match &self.connector_data {
            Some(connector_data) => {
                let client_config = connector_data.connect_config_input.try_to_build_config()?;
                let server_host = connector_data.server_name().cloned().unwrap_or(server_host);
                (client_config, server_host)
            }
            None => (
                TlsConnectorData::new_http_auto()?
                    .connect_config_input
                    .try_to_build_config()?,
                server_host,
            ),
        };
        let stream = tokio_boring::connect(config, server_host.to_string().as_str(), stream)
            .await
            .map_err(|err| match err.as_io_error() {
                Some(err) => OpaqueError::from_display(err.to_string())
                    .context("boring ssl connector: connect")
                    .into_boxed(),
                None => OpaqueError::from_display("boring ssl connector: connect").into_boxed(),
            })?;

        let params = match stream.ssl().session() {
            Some(ssl_session) => {
                let protocol_version = ssl_session.protocol_version().try_into().map_err(|v| {
                    OpaqueError::from_display(format!("protocol version {v}"))
                        .context("boring ssl connector: min proto version")
                })?;
                let application_layer_protocol = stream
                    .ssl()
                    .selected_alpn_protocol()
                    .map(ApplicationProtocol::from);
                NegotiatedTlsParameters {
                    protocol_version,
                    application_layer_protocol,
                }
            }
            None => {
                return Err(OpaqueError::from_display(
                    "boring ssl connector: failed to establish session...",
                )
                .into_boxed())
            }
        };

        Ok((stream, params))
    }
}

pin_project! {
    /// A stream which can be either a secure or a plain stream.
    pub struct AutoTlsStream<S> {
        #[pin]
        inner: AutoTlsStreamData<S>,
    }
}

impl<S: fmt::Debug> fmt::Debug for AutoTlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutoTlsStream")
            .field("inner", &self.inner)
            .finish()
    }
}

pin_project! {
    #[project = AutoTlsStreamDataProj]
    /// A stream which can be either a secure or a plain stream.
    enum AutoTlsStreamData<S> {
        /// A secure stream.
        Secure{ #[pin] inner: SslStream<S> },
        /// A plain stream.
        Plain { #[pin] inner: S },
    }
}

impl<S: fmt::Debug> fmt::Debug for AutoTlsStreamData<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AutoTlsStreamData::Secure { inner } => f.debug_tuple("Secure").field(inner).finish(),
            AutoTlsStreamData::Plain { inner } => f.debug_tuple("Plain").field(inner).finish(),
        }
    }
}

impl<S> AsyncRead for AutoTlsStream<S>
where
    S: Stream + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project().inner.project() {
            AutoTlsStreamDataProj::Secure { inner } => inner.poll_read(cx, buf),
            AutoTlsStreamDataProj::Plain { inner } => inner.poll_read(cx, buf),
        }
    }
}

impl<S> AsyncWrite for AutoTlsStream<S>
where
    S: Stream + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.project().inner.project() {
            AutoTlsStreamDataProj::Secure { inner } => inner.poll_write(cx, buf),
            AutoTlsStreamDataProj::Plain { inner } => inner.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            AutoTlsStreamDataProj::Secure { inner } => inner.poll_flush(cx),
            AutoTlsStreamDataProj::Plain { inner } => inner.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            AutoTlsStreamDataProj::Secure { inner } => inner.poll_shutdown(cx),
            AutoTlsStreamDataProj::Plain { inner } => inner.poll_shutdown(cx),
        }
    }
}

mod private {
    #[derive(Debug)]
    /// A connector which can be used to establish a connection to a server
    /// in function of the Request, meaning either it will be a seucre
    /// connector or it will be a plain connector.
    ///
    /// This connector can be handy as it allows to have a single layer
    /// which will work both for plain and secure connections.
    pub struct ConnectorKindAuto;

    #[derive(Debug)]
    /// A connector which can _only_ be used to establish a secure connection,
    /// regardless of the scheme of the request URI.
    pub struct ConnectorKindSecure;

    #[derive(Debug)]
    /// A connector which can be used to use this connector to support
    /// secure https tunnel connections.
    ///
    /// The connections will only be done if the [`HttpsTunnel`]
    /// is present in the context.
    ///
    /// [`HttpsTunnel`]: crate::HttpsTunnel
    pub struct ConnectorKindTunnel;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_send() {
        use rama_utils::test_helpers::assert_send;

        assert_send::<HttpsConnectorLayer>();
    }

    #[test]
    fn assert_sync() {
        use rama_utils::test_helpers::assert_sync;

        assert_sync::<HttpsConnectorLayer>();
    }
}
