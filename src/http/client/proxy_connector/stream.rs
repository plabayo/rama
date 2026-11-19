use crate::{
    Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
    http::io::upgrade::Upgraded,
    net::client::{
        ConnectionError, ConnectionErrorKind, ConnectorService, EstablishedClientConnection,
        ProxyRoute,
    },
    telemetry::tracing,
};
use pin_project_lite::pin_project;
use std::{
    fmt,
    pin::Pin,
    task::{self, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// Open a stream to the origin of a request through the proxy of its route: one a SOCKS5
/// proxy opens, or a tunnel an HTTP proxy opens with CONNECT.
///
/// Compose it with the direct stream connector in a [`MaybeProxiedConnector`] selecting by
/// [`HttpTunnelRoute`]: a request its HTTP proxy forwards has no tunnel to its origin, it
/// keeps the direct stream to the proxy.
///
/// [`MaybeProxiedConnector`]: crate::net::client::MaybeProxiedConnector
/// [`HttpTunnelRoute`]: crate::http::client::proxy::HttpTunnelRoute
#[derive(Debug, Clone)]
pub struct ProxyStreamConnector<S, C> {
    socks: S,
    connect: C,
}

impl<S, C> ProxyStreamConnector<S, C> {
    /// Create a new [`ProxyStreamConnector`] over the connector towards SOCKS5 proxies and
    /// the one opening CONNECT tunnels.
    pub const fn new(socks: S, connect: C) -> Self {
        Self { socks, connect }
    }
}

impl<S, C, Input, Socks> Service<Input> for ProxyStreamConnector<S, C>
where
    S: ConnectorService<Input, Connection = Socks>,
    C: ConnectorService<Input, Connection: Into<Upgraded>>,
    Socks: Send + ExtensionsRef + 'static,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<ProxyStream<Socks>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let Some(ProxyRoute::Proxy(proxy)) = input.extensions().get_ref::<ProxyRoute>() else {
            return Err(ConnectionError::local(
                BoxError::from_static_str("proxy stream connector: no proxied route is requested"),
                ConnectionErrorKind::InvalidInput,
            ));
        };
        let protocol = proxy.protocol.clone();
        if protocol.is_socks5() {
            tracing::trace!(?protocol, "proxy stream connector: socks5 proxy");
            let EstablishedClientConnection { input, conn } = self.socks.connect(input).await?;
            return Ok(EstablishedClientConnection {
                input,
                conn: ProxyStream::Socks { conn },
            });
        }
        if protocol.is_http() {
            tracing::trace!(?protocol, "proxy stream connector: connect tunnel");
            let EstablishedClientConnection { input, conn } = self.connect.connect(input).await?;
            return Ok(EstablishedClientConnection {
                input,
                conn: ProxyStream::Connect { conn: conn.into() },
            });
        }
        Err(ConnectionError::transport(
            BoxError::from_static_str("received unsupported proxy protocol"),
            ConnectionErrorKind::Protocol,
        )
        .context_debug_field("protocol", protocol))
    }
}

pin_project! {
    /// The byte stream a [`ProxyStreamConnector`] established.
    #[project = ProxyStreamProj]
    pub enum ProxyStream<S> {
        /// A stream a SOCKS5 proxy opened to the origin.
        Socks { #[pin] conn: S },
        /// A tunnel an HTTP proxy opened to the origin with CONNECT.
        Connect { #[pin] conn: Upgraded },
    }
}

impl<S: fmt::Debug> fmt::Debug for ProxyStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socks { conn } => f.debug_struct("Socks").field("conn", conn).finish(),
            Self::Connect { conn } => f.debug_struct("Connect").field("conn", conn).finish(),
        }
    }
}

impl<S: ExtensionsRef> ExtensionsRef for ProxyStream<S> {
    fn extensions(&self) -> &Extensions {
        match self {
            Self::Socks { conn } => conn.extensions(),
            Self::Connect { conn } => conn.extensions(),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S: AsyncRead> AsyncRead for ProxyStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project() {
            ProxyStreamProj::Socks { conn } => conn.poll_read(cx, buf),
            ProxyStreamProj::Connect { conn } => conn.poll_read(cx, buf),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S: AsyncWrite> AsyncWrite for ProxyStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project() {
            ProxyStreamProj::Socks { conn } => conn.poll_write(cx, buf),
            ProxyStreamProj::Connect { conn } => conn.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project() {
            ProxyStreamProj::Socks { conn } => conn.poll_flush(cx),
            ProxyStreamProj::Connect { conn } => conn.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project() {
            ProxyStreamProj::Socks { conn } => conn.poll_shutdown(cx),
            ProxyStreamProj::Connect { conn } => conn.poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Socks { conn } => conn.is_write_vectored(),
            Self::Connect { conn } => conn.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project() {
            ProxyStreamProj::Socks { conn } => conn.poll_write_vectored(cx, bufs),
            ProxyStreamProj::Connect { conn } => conn.poll_write_vectored(cx, bufs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client::proxy::HttpTunnelRoute;
    use crate::net::client::{EstablishedProxyRoute, MaybeProxied, MaybeProxiedConnector};
    use crate::{
        ServiceInput,
        http::proxy::PlaintextHttpProxyMode,
        net::{Protocol, address::HostWithPort, client::ConnectRequest},
        service::service_fn,
    };

    fn stream() -> ServiceInput<tokio::io::DuplexStream> {
        let (io, _peer) = tokio::io::duplex(64);
        ServiceInput::new(io)
    }

    fn streams<Input: Send + 'static>()
    -> impl ConnectorService<Input, Connection = ServiceInput<tokio::io::DuplexStream>> {
        service_fn(|input: Input| async move {
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: stream(),
            })
        })
    }

    fn tunnels<Input: Send + 'static>() -> impl ConnectorService<Input, Connection = Upgraded> {
        service_fn(|input: Input| async move {
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: Upgraded::new(stream(), Default::default()),
            })
        })
    }

    fn no_stream<Input: Send + 'static>()
    -> impl ConnectorService<Input, Connection = ServiceInput<tokio::io::DuplexStream>> {
        unreachable()
    }

    fn no_tunnel<Input: Send + 'static>() -> impl ConnectorService<Input, Connection = Upgraded> {
        unreachable()
    }

    fn unreachable<Input: Send + 'static, Conn: Send + ExtensionsRef + 'static>()
    -> impl ConnectorService<Input, Connection = Conn> {
        service_fn(|_: Input| async move {
            Err::<EstablishedClientConnection<Conn, Input>, _>(ConnectionError::local(
                BoxError::from_static_str("connector must not be used"),
                ConnectionErrorKind::Unavailable,
            ))
        })
    }

    fn transport<D, S, C>(
        direct: D,
        socks: S,
        connect: C,
    ) -> MaybeProxiedConnector<D, ProxyStreamConnector<S, C>, HttpTunnelRoute> {
        MaybeProxiedConnector::new(
            direct,
            ProxyStreamConnector::new(socks, connect),
            HttpTunnelRoute,
        )
    }

    fn plaintext(route: Option<&str>, mode: Option<PlaintextHttpProxyMode>) -> ConnectRequest {
        let input = ConnectRequest::new(HostWithPort::try_from("origin.example:80").unwrap())
            .with_application_protocol(Protocol::HTTP);
        if let Some(route) = route {
            input
                .extensions
                .insert(ProxyRoute::Proxy(route.parse().unwrap()));
        }
        if let Some(mode) = mode {
            input.extensions.insert(mode);
        }
        input
    }

    #[tokio::test]
    async fn a_request_without_a_route_takes_a_stream_of_its_own() {
        let connector = transport(streams(), no_stream(), no_tunnel());
        let established = connector.connect(plaintext(None, None)).await.unwrap();

        assert!(matches!(established.conn, MaybeProxied::Direct { .. }));
        assert!(
            !established
                .conn
                .extensions()
                .contains::<EstablishedProxyRoute>(),
            "no route was requested",
        );
    }

    #[tokio::test]
    async fn a_socks5_route_reaches_the_socks_connector() {
        let connector = transport(no_stream(), streams(), no_tunnel());
        let established = connector
            .connect(plaintext(Some("socks5://proxy.example:1080"), None))
            .await
            .unwrap();

        assert!(matches!(
            established.conn,
            MaybeProxied::Proxied {
                conn: ProxyStream::Socks { .. }
            }
        ));
    }

    #[tokio::test]
    async fn a_tunneled_http_route_reaches_the_connect_connector() {
        let connector = transport(no_stream(), no_stream(), tunnels());
        for input in [
            plaintext(
                Some("http://proxy.example:8080"),
                Some(PlaintextHttpProxyMode::Tunnel),
            ),
            ConnectRequest::new(HostWithPort::try_from("origin.example:443").unwrap())
                .with_application_protocol(Protocol::HTTPS),
        ] {
            input.extensions.insert(ProxyRoute::Proxy(
                "http://proxy.example:8080".parse().unwrap(),
            ));
            let established = connector.connect(input).await.unwrap();
            assert!(matches!(
                established.conn,
                MaybeProxied::Proxied {
                    conn: ProxyStream::Connect { .. }
                }
            ));
        }
    }

    #[tokio::test]
    async fn a_forwarded_request_keeps_the_stream_to_its_proxy_unclaimed() {
        let connector = transport(streams(), no_stream(), no_tunnel());
        let established = connector
            .connect(plaintext(Some("http://proxy.example:8080"), None))
            .await
            .unwrap();

        assert!(matches!(established.conn, MaybeProxied::Direct { .. }));
        assert!(
            !established
                .conn
                .extensions()
                .contains::<EstablishedProxyRoute>(),
            "the forward connector publishes the route of this connection",
        );
    }

    #[cfg(feature = "socks5")]
    #[test]
    fn eager_socks5_accepts_combined_proxy_connection() {
        use crate::{
            graceful::WeakScope,
            http::{
                Body,
                client::{ProxyConnector, ProxyConnectorParts},
            },
            net::{proxy::IoForwardService, test_utils::client::MockSocket},
            proxy::socks5::server::{Connector as EagerSocks5Connector, Socks5Connector},
        };

        fn assert_socks5_connector<S, C: Socks5Connector<S>>(_: &C) {}

        let scope = WeakScope::detached();
        let ProxyConnectorParts { socks, connect, .. } = ProxyConnector::builder(scope.clone())
            .with_default_tcp_connector()
            .without_dns_connector()
            .without_tls_support()
            .with_default_http_connector::<Body>()
            .without_connection_pool()
            .with_socks5()
            .with_http_connect()
            .build()
            .into_parts();
        let connector = EagerSocks5Connector::new(
            ProxyStreamConnector::new(socks, connect),
            IoForwardService::new(scope),
        );

        assert_socks5_connector::<MockSocket, _>(&connector);
    }

    #[tokio::test]
    async fn a_proxy_protocol_without_a_transport_is_refused() {
        let connector = transport(no_stream(), no_stream(), no_tunnel());
        let error = connector
            .connect(plaintext(Some("ftp://proxy.example:21"), None))
            .await
            .unwrap_err();

        assert!(
            format!("{error:?}").contains("unsupported proxy protocol"),
            "{error:?}"
        );
    }
}
