use crate::{
    Layer, Service,
    error::{BoxError, OpaqueError},
    extensions::{Extensions, ExtensionsMut, ExtensionsRef},
    http::client::proxy::layer::{
        HttpProxyConnector, HttpProxyConnectorLayer, MaybeHttpProxiedConnection,
    },
    net::{
        Protocol,
        address::ProxyAddress,
        client::{ConnectorService, EstablishedClientConnection},
        transport::TryRefIntoTransportContext,
    },
    proxy::socks5::{Socks5ProxyConnector, Socks5ProxyConnectorLayer},
    stream::Stream,
    telemetry::tracing,
};
use pin_project_lite::pin_project;
use std::{
    fmt::Debug,
    pin::Pin,
    task::{self, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// Proxy connector which supports http(s) and socks5(h) proxy address
///
/// Connector will look at [`ProxyAddress`] to determine which proxy
/// connector to use if one is configured
#[derive(Debug, Clone)]
pub struct ProxyConnector<S> {
    inner: S,
    socks: Socks5ProxyConnector<S>,
    http: HttpProxyConnector<S>,
    required: bool,
}

impl<S: Clone> ProxyConnector<S> {
    /// Creates a new [`ProxyConnector`].
    fn new(
        inner: S,
        socks_proxy_layer: Socks5ProxyConnectorLayer,
        http_proxy_layer: HttpProxyConnectorLayer,
        required: bool,
    ) -> Self {
        Self {
            socks: socks_proxy_layer.into_layer(inner.clone()),
            http: http_proxy_layer.into_layer(inner.clone()),
            inner,
            required,
        }
    }

    #[inline]
    /// Creates a new required [`ProxyConnector`].
    ///
    /// This connector will fail if no [`ProxyAddress`] is configured
    pub fn required(
        inner: S,
        socks_proxy_layer: Socks5ProxyConnectorLayer,
        http_proxy_layer: HttpProxyConnectorLayer,
    ) -> Self {
        Self::new(inner, socks_proxy_layer, http_proxy_layer, true)
    }

    #[inline]
    /// Creates a new optional [`ProxyConnector`].
    ///
    /// This connector will forward to the inner connector if no [`ProxyAddress`] is configured
    pub fn optional(
        inner: S,
        socks_proxy_layer: Socks5ProxyConnectorLayer,
        http_proxy_layer: HttpProxyConnectorLayer,
    ) -> Self {
        Self::new(inner, socks_proxy_layer, http_proxy_layer, false)
    }
}

impl<Input, S> Service<Input> for ProxyConnector<S>
where
    S: ConnectorService<Input, Connection: Stream + Unpin>,
    Input: TryRefIntoTransportContext<Error: Into<BoxError> + Send + 'static>
        + Send
        + ExtensionsMut
        + 'static,
{
    type Output = EstablishedClientConnection<MaybeProxiedConnection<S::Connection>, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let proxy = input.extensions().get::<ProxyAddress>();

        match proxy {
            None => {
                if self.required {
                    return Err("proxy required but none is defined".into());
                }
                tracing::trace!("no proxy detected in ctx, using inner connector");
                let EstablishedClientConnection { input, conn } =
                    self.inner.connect(input).await.map_err(Into::into)?;

                let conn = MaybeProxiedConnection::direct(conn);
                Ok(EstablishedClientConnection { input, conn })
            }
            Some(proxy) => {
                let protocol = proxy.protocol.as_ref();
                tracing::trace!(?protocol, "proxy detected in ctx");

                let protocol = protocol.unwrap_or_else(|| {
                    tracing::trace!("no protocol detected, using http as protocol");
                    &Protocol::HTTP
                });

                if protocol.is_socks5() {
                    tracing::trace!("using socks proxy connector");
                    let EstablishedClientConnection { input, conn } =
                        self.socks.connect(input).await?;

                    let conn = MaybeProxiedConnection::socks(conn);
                    Ok(EstablishedClientConnection { input, conn })
                } else if protocol.is_http() {
                    tracing::trace!("using http proxy connector");
                    let EstablishedClientConnection { input, conn } =
                        self.http.connect(input).await?;

                    let conn = MaybeProxiedConnection::http(conn);
                    Ok(EstablishedClientConnection { input, conn })
                } else {
                    Err(OpaqueError::from_display(format!(
                        "received unsupport proxy protocol {protocol:?}"
                    ))
                    .into_boxed())
                }
            }
        }
    }
}

pin_project! {
    /// A connection which will be proxied if a [`ProxyAddress`] was configured
    pub struct MaybeProxiedConnection<S> {
        #[pin]
        inner: Connection<S>,
    }
}

impl<S: ExtensionsMut> MaybeProxiedConnection<S> {
    pub fn direct(conn: S) -> Self {
        Self {
            inner: Connection::Direct { conn },
        }
    }

    pub fn socks(conn: S) -> Self {
        Self {
            inner: Connection::Socks { conn },
        }
    }

    pub fn http(conn: MaybeHttpProxiedConnection<S>) -> Self {
        Self {
            inner: Connection::Http { conn },
        }
    }
}

impl<S: Debug> Debug for MaybeProxiedConnection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaybeProxiedConnection")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: ExtensionsRef> ExtensionsRef for MaybeProxiedConnection<S> {
    fn extensions(&self) -> &Extensions {
        match &self.inner {
            Connection::Direct { conn } | Connection::Socks { conn } => conn.extensions(),
            Connection::Http { conn } => conn.extensions(),
        }
    }
}

impl<S: ExtensionsMut> ExtensionsMut for MaybeProxiedConnection<S> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        match &mut self.inner {
            Connection::Direct { conn } | Connection::Socks { conn } => conn.extensions_mut(),
            Connection::Http { conn } => conn.extensions_mut(),
        }
    }
}

pin_project! {
    #[project = ConnectionProj]
    enum Connection<S> {
        Direct{ #[pin] conn: S },
        Socks{ #[pin] conn: S },
        Http{ #[pin] conn: MaybeHttpProxiedConnection<S> },

    }
}

impl<S: Debug> Debug for Connection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct { conn } => f.debug_struct("Direct").field("conn", conn).finish(),
            Self::Socks { conn } => f.debug_struct("Socks").field("conn", conn).finish(),
            Self::Http { conn } => f.debug_struct("Http").field("conn", conn).finish(),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<Conn: AsyncWrite> AsyncWrite for MaybeProxiedConnection<Conn> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Socks { conn } => {
                conn.poll_write(cx, buf)
            }
            ConnectionProj::Http { conn } => conn.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Socks { conn } => conn.poll_flush(cx),
            ConnectionProj::Http { conn } => conn.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Socks { conn } => {
                conn.poll_shutdown(cx)
            }
            ConnectionProj::Http { conn } => conn.poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            Connection::Direct { conn } | Connection::Socks { conn } => conn.is_write_vectored(),
            Connection::Http { conn } => conn.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Socks { conn } => {
                conn.poll_write_vectored(cx, bufs)
            }
            ConnectionProj::Http { conn } => conn.poll_write_vectored(cx, bufs),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<Conn: AsyncRead> AsyncRead for MaybeProxiedConnection<Conn> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Socks { conn } => {
                conn.poll_read(cx, buf)
            }
            ConnectionProj::Http { conn } => conn.poll_read(cx, buf),
        }
    }
}

/// Proxy connector layer which supports http(s) and socks5(h) proxy address
///
/// Connector will look at [`ProxyAddress`] to determine which proxy
/// connector to use if one is configured
pub struct ProxyConnectorLayer {
    socks_layer: Socks5ProxyConnectorLayer,
    http_layer: HttpProxyConnectorLayer,
    required: bool,
}

impl ProxyConnectorLayer {
    #[must_use]
    /// Creates a new required [`ProxyConnectorLayer`].
    ///
    /// This connector will fail if no [`ProxyAddress`] is configured
    pub fn required(
        socks_proxy_layer: Socks5ProxyConnectorLayer,
        http_proxy_layer: HttpProxyConnectorLayer,
    ) -> Self {
        Self {
            socks_layer: socks_proxy_layer,
            http_layer: http_proxy_layer,
            required: true,
        }
    }

    #[must_use]
    /// Creates a new optional [`ProxyConnectorLayer`].
    ///
    /// This connector will forward to the inner connector if no [`ProxyAddress`] is configured
    pub fn optional(
        socks_proxy_layer: Socks5ProxyConnectorLayer,
        http_proxy_layer: HttpProxyConnectorLayer,
    ) -> Self {
        Self {
            socks_layer: socks_proxy_layer,
            http_layer: http_proxy_layer,
            required: false,
        }
    }
}

impl<S: Clone> Layer<S> for ProxyConnectorLayer {
    type Service = ProxyConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyConnector::new(
            inner,
            self.socks_layer.clone(),
            self.http_layer.clone(),
            self.required,
        )
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyConnector::new(inner, self.socks_layer, self.http_layer, self.required)
    }
}
