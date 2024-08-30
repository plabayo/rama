use crate::error::{BoxError, ErrorContext, ErrorExt, OpaqueError};
use crate::net::client::{ConnectorService, EstablishedClientConnection};
use crate::net::stream::Stream;
use crate::net::transport::TryRefIntoTransportContext;
use crate::service::Layer;
use crate::service::{Context, Service};
use crate::tls::HttpsTunnel;
use pin_project_lite::pin_project;
use private::{ConnectorKindAuto, ConnectorKindSecure, ConnectorKindTunnel};
use std::fmt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_boring::SslStream;

/// A [`Layer`] which wraps the given service with a [`HttpsConnector`].
///
/// See [`HttpsConnector`] for more information.
#[derive(Clone)]
pub struct HttpsConnectorLayer<K = ConnectorKindAuto> {
    _kind: std::marker::PhantomData<K>,
}

impl<K> std::fmt::Debug for HttpsConnectorLayer<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsConnectorLayer").finish()
    }
}

impl HttpsConnectorLayer<ConnectorKindAuto> {
    /// Creates a new [`HttpsConnectorLayer`] which will establish
    /// a secure connection if the request demands it,
    /// otherwise it will forward the pre-established inner connection.
    pub fn auto() -> Self {
        Self {
            _kind: std::marker::PhantomData,
        }
    }
}

impl HttpsConnectorLayer<ConnectorKindSecure> {
    /// Creates a new [`HttpsConnectorLayer`] which will always
    /// establish a secure connection regardless of the request it is for.
    pub fn secure_only() -> Self {
        Self {
            _kind: std::marker::PhantomData,
        }
    }
}

impl HttpsConnectorLayer<ConnectorKindTunnel> {
    /// Creates a new [`HttpsConnectorLayer`] which will establish
    /// a secure connection if the request is to be tunneled.
    pub fn tunnel() -> Self {
        Self {
            _kind: std::marker::PhantomData,
        }
    }
}

impl<K, S> Layer<S> for HttpsConnectorLayer<K> {
    type Service = HttpsConnector<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpsConnector::new(inner)
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
    _kind: std::marker::PhantomData<K>,
}

impl<S: fmt::Debug, K> fmt::Debug for HttpsConnector<S, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsConnector")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Clone, K> Clone for HttpsConnector<S, K> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _kind: std::marker::PhantomData,
        }
    }
}

impl<S, K> HttpsConnector<S, K> {
    /// Creates a new [`HttpsConnector`].
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            _kind: std::marker::PhantomData,
        }
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
    S: ConnectorService<State, Request>,
    S::Connection: Stream + Unpin,
    S::Error: Into<BoxError>,
    State: Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State> + Send + 'static,
    Request::Error: Into<BoxError> + Send + Sync + 'static,
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

        let host = transport_ctx.authority.host().to_string();

        let stream = self.handshake(host, conn).await?;

        tracing::trace!(
            authority = %transport_ctx.authority,
            "HttpsConnector(auto): protocol secure, established tls connection",
        );
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
    S: ConnectorService<State, Request>,
    S::Connection: Stream + Unpin,
    S::Error: Into<BoxError>,
    State: Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State> + Send + 'static,
    Request::Error: Into<BoxError> + Send + Sync + 'static,
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

        let host = transport_ctx.authority.host().to_string();

        let conn = self.handshake(host, conn).await?;

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
    S: ConnectorService<State, Request>,
    S::Connection: Stream + Unpin,
    S::Error: Into<BoxError>,
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
            ctx,
            req,
            conn,
            addr,
        } = self.inner.connect(ctx, req).await.map_err(Into::into)?;

        let host = match ctx.get::<HttpsTunnel>() {
            Some(tunnel) => tunnel.server_name.clone(),
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

        let stream = self.handshake(host, conn).await?;

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
    async fn handshake<T>(&self, target_host: String, stream: T) -> Result<SslStream<T>, BoxError>
    where
        T: Stream + Unpin,
    {
        // TODO: make this configurable from "outside""...
        // - for emulation
        // - for obvious stuff like ALPN
        // - for client preferences/options
        let cfg = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls_client())
            .context("create ssl connector builder")?
            .build()
            .configure()
            .context("create ssl connector configuration")?
            .use_server_name_indication(true)
            .verify_hostname(false);
        tokio_boring::connect(cfg, target_host.as_str(), stream)
            .await
            .map_err(|err| match err.as_io_error() {
                Some(err) => OpaqueError::from_display(err.to_string())
                    .context("boring ssl acceptor: accept")
                    .into_boxed(),
                None => OpaqueError::from_display("boring ssl acceptor: accept").into_boxed(),
            })
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
    /// [`HttpsTunnel`]: crate::tls::HttpsTunnel
    pub struct ConnectorKindTunnel;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_send() {
        use crate::utils::test_helpers::assert_send;

        assert_send::<HttpsConnectorLayer>();
    }

    #[test]
    fn assert_sync() {
        use crate::utils::test_helpers::assert_sync;

        assert_sync::<HttpsConnectorLayer>();
    }
}
