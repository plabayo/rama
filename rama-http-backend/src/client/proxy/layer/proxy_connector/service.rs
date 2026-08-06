use rama_core::error::BoxErrorExt as _;

use super::InnerHttpProxyConnector;
use pin_project_lite::pin_project;
use rama_core::{
    Service,
    error::BoxError,
    extensions::{Extension, Extensions, ExtensionsRef},
    io::Io,
    telemetry::tracing,
};
use rama_http::{
    HeaderMap, HeaderValue,
    header::{HOST, IntoHeaderName, PROXY_AUTHORIZATION},
    io::upgrade,
};
use rama_http_headers::ProxyAuthorization;
use rama_http_types::Version;
use rama_net::{
    AuthorityInputExt, Protocol, ProtocolInputExt,
    client::{
        ConnectionError, ConnectionErrorKind, ConnectorService, ConnectorTarget,
        EstablishedClientConnection, ProxyRoute,
    },
    user::ProxyCredential,
};
use rama_utils::macros::define_inner_service_accessors;
use rama_utils::macros::generate_set_and_with;
use std::fmt::Debug;
use std::pin::Pin;
use std::task::{self, Poll};
use std::{ops, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "tls")]
use rama_tls::TlsTunnel;

/// A connector which can be used to establish a connection over an HTTP Proxy.
///
/// This behaviour is optional and only triggered in case there
/// is a proxied [`ProxyRoute`] found in the [`Extensions`].
#[derive(Debug, Clone)]
pub struct HttpProxyConnector<S> {
    pub(super) inner: S,
    pub(super) required: bool,
    pub(super) version: Option<Version>,
    pub(super) headers: Option<HeaderMap>,
}

impl<S> HttpProxyConnector<S> {
    /// Creates a new [`HttpProxyConnector`].
    ///
    /// Protocol version is set to HTTP/1.1 by default.
    pub(super) fn new(inner: S, required: bool) -> Self {
        Self {
            inner,
            required,
            version: Some(Version::HTTP_11),
            headers: None,
        }
    }

    generate_set_and_with! {
        /// Set the HTTP version to use for the CONNECT request.
        ///
        /// By default this is set to HTTP/1.1.
        pub fn version(mut self, version: Version) -> Self {
            self.version = Some(version);
            self
        }
    }

    generate_set_and_with! {
        /// Append a custom header to use for the CONNECT request.
        pub fn custom_header(
            mut self,
            name: impl IntoHeaderName,
            value: HeaderValue,
        ) -> Self {
            self.headers.get_or_insert_default().append(name, value);
            self
        }
    }

    /// Create a new [`HttpProxyConnector`]
    /// which will only connect via an HTTP proxy when a proxied [`ProxyRoute`] is available
    /// in the [`Extensions`].
    #[must_use]
    pub fn optional(inner: S) -> Self {
        Self::new(inner, false)
    }

    /// Create a new [`HttpProxyConnector`]
    /// which will always connect via an HTTP proxy, but fail when a proxied [`ProxyRoute`] is
    /// not available in the [`Extensions`].
    #[must_use]
    pub fn required(inner: S) -> Self {
        Self::new(inner, true)
    }

    define_inner_service_accessors!();
}

impl<S, Input> Service<Input> for HttpProxyConnector<S>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: AuthorityInputExt + ProtocolInputExt + Send + ExtensionsRef + 'static,
{
    type Output = EstablishedClientConnection<MaybeHttpProxiedConnection<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let maybe_proxy_info = input
            .extensions()
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
            .cloned();

        let Some(proxy_info) = maybe_proxy_info else {
            // return early in case we did not use a proxy

            return if self.required {
                Err(ConnectionError::local(
                    BoxError::from_static_str("http proxy required but none is defined"),
                    ConnectionErrorKind::InvalidInput,
                ))
            } else {
                tracing::trace!(
                    "http proxy connector: no proxy required or set: proceed with direct connection"
                );
                let EstablishedClientConnection { input, conn } =
                    self.inner.connect(input).await.map_err(|error| {
                        error.context(
                            "establish direct connection (no http proxy given or required)",
                        )
                    })?;
                return Ok(EstablishedClientConnection {
                    input,
                    conn: MaybeHttpProxiedConnection::direct(conn),
                });
            };
        };

        if !proxy_info
            .protocol
            .as_ref()
            .map(|p| p.is_http())
            .unwrap_or(true)
        {
            return Err(ConnectionError::local(
                BoxError::from_static_str("http proxy connector can only serve http protocol"),
                ConnectionErrorKind::InvalidInput,
            ));
        }

        let authority = input.authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("http proxy connector: authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        let app_protocol = input.protocol().cloned();

        // insert target so that inner connector can use it instead of input's version
        input
            .extensions()
            .insert(ConnectorTarget(proxy_info.address.clone()));

        #[cfg(feature = "tls")]
        // in case the provider gave us a proxy info, we insert it into the context
        if proxy_info
            .protocol
            .as_ref()
            .map(|p| p.is_secure())
            .unwrap_or_default()
        {
            tracing::trace!(
                server.address = %proxy_info.address.host,
                server.port = proxy_info.address.port,
                "http proxy connector: preparing proxy connection for tls tunnel",
            );
            input.extensions().insert(TlsTunnel {
                sni: Some(proxy_info.address.host.clone()),
            });
        }

        let EstablishedClientConnection { input, conn } =
            self.inner.connect(input).await.map_err(|error| {
                error
                    .context("establish connection to proxy")
                    .context_field("address", proxy_info.address.clone())
                    .context_debug_field("protocol", proxy_info.protocol.clone())
            })?;

        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "http proxy connector: connected to proxy",
        );

        if !app_protocol
            .as_ref()
            .map(|p| p.is_secure())
            // TODO: re-evaluate this fallback at some point... seems pretty flawed to me
            .unwrap_or_else(|| authority.port.as_u16() == Some(Protocol::HTTPS_DEFAULT_PORT))
        {
            // unless the scheme is not secure, in such a case no handshake is required...
            // we do however need to add authorization headers if credentials are present
            // => for this the user has to use another middleware as we do not have access to that here
            return Ok(EstablishedClientConnection {
                input,
                conn: MaybeHttpProxiedConnection::proxied(conn),
            });
        }

        let mut connector =
            InnerHttpProxyConnector::new(authority.clone(), input.extensions().clone()).map_err(
                |error| {
                    ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                        .context("http proxy connector: build CONNECT request")
                },
            )?;

        if let Some(version) = self.version {
            if !matches!(
                version,
                Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2
            ) {
                return Err(ConnectionError::local(
                    BoxError::from_static_str("http proxy connector: unsupported HTTP version"),
                    ConnectionErrorKind::InvalidInput,
                )
                .context_debug_field("version", version));
            }
            connector.set_version(version);
        }

        if let Some(credential) = proxy_info.credential.clone() {
            match credential {
                ProxyCredential::Basic(basic) => {
                    connector.set_typed_header(ProxyAuthorization(basic));
                }
                ProxyCredential::Bearer(bearer) => {
                    connector.set_typed_header(ProxyAuthorization(bearer));
                }
            }
        }

        if let Some(headers) = self.headers.clone() {
            for (name, value) in headers.into_ordered_iter() {
                if name != PROXY_AUTHORIZATION && name != HOST {
                    connector.set_header(name, value);
                }
            }
        }

        let (headers, conn) = connector
            .handshake(conn)
            .await
            .map_err(ConnectionError::from)
            .map_err(|error| error.context("http proxy handshake"))?;

        let conn = MaybeHttpProxiedConnection::upgraded_proxy(conn);

        tracing::trace!("inserting HttpProxyHeaders in context");
        conn.extensions()
            .insert(HttpProxyConnectResponseHeaders::new(headers));

        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "http proxy connector: connected to proxy: ready secure request",
        );
        Ok(EstablishedClientConnection { input, conn })
    }
}

#[derive(Clone, Debug, Extension)]
#[extension(tags(http, proxy))]
/// Extension added to the [`Extensions`] by [`HttpProxyConnector`] to record the
/// headers from a successful CONNECT response.
///
/// This can be useful, for example, when the upstream proxy provider exposes
/// information in these headers about the connection to the final destination.
pub struct HttpProxyConnectResponseHeaders(Arc<HeaderMap>);

impl HttpProxyConnectResponseHeaders {
    fn new(headers: HeaderMap) -> Self {
        Self(Arc::new(headers))
    }
}

impl AsRef<HeaderMap> for HttpProxyConnectResponseHeaders {
    fn as_ref(&self) -> &HeaderMap {
        &self.0
    }
}

impl ops::Deref for HttpProxyConnectResponseHeaders {
    type Target = HeaderMap;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pin_project! {
    /// A connection which will be proxied if a proxied [`ProxyRoute`] was configured.
    pub struct MaybeHttpProxiedConnection<S> {
        #[pin]
        inner: Connection<S>,
    }
}

impl<S: ExtensionsRef + Unpin + Io> MaybeHttpProxiedConnection<S> {
    fn direct(conn: S) -> Self {
        Self {
            inner: Connection::Direct { conn },
        }
    }

    fn proxied(conn: S) -> Self {
        Self {
            inner: Connection::Proxied { conn },
        }
    }

    fn upgraded_proxy(conn: upgrade::Upgraded) -> Self {
        Self {
            inner: Connection::UpgradedProxy { conn },
        }
    }
}

impl<S: Debug> Debug for MaybeHttpProxiedConnection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaybeHttpProxiedConnection")
            .field("inner", &self.inner)
            .finish()
    }
}

pin_project! {
    #[project = ConnectionProj]
    enum Connection<S> {
        Direct{ #[pin] conn: S },
        Proxied{ #[pin] conn: S },
        UpgradedProxy{ #[pin] conn: upgrade::Upgraded },
    }
}

impl<S: Debug> Debug for Connection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct { conn } => f.debug_struct("Direct").field("conn", conn).finish(),
            Self::Proxied { conn } => f.debug_struct("Proxied").field("conn", conn).finish(),
            Self::UpgradedProxy { conn } => {
                f.debug_struct("UpgradedProxy").field("conn", conn).finish()
            }
        }
    }
}

impl<S: ExtensionsRef> ExtensionsRef for MaybeHttpProxiedConnection<S> {
    fn extensions(&self) -> &Extensions {
        match &self.inner {
            Connection::Direct { conn } | Connection::Proxied { conn } => conn.extensions(),
            Connection::UpgradedProxy { conn } => conn.extensions(),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<Conn: AsyncWrite> AsyncWrite for MaybeHttpProxiedConnection<Conn> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Proxied { conn } => {
                conn.poll_write(cx, buf)
            }
            ConnectionProj::UpgradedProxy { conn } => conn.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Proxied { conn } => {
                conn.poll_flush(cx)
            }
            ConnectionProj::UpgradedProxy { conn } => conn.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Proxied { conn } => {
                conn.poll_shutdown(cx)
            }
            ConnectionProj::UpgradedProxy { conn } => conn.poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            Connection::Direct { conn } | Connection::Proxied { conn } => conn.is_write_vectored(),
            Connection::UpgradedProxy { conn } => conn.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Proxied { conn } => {
                conn.poll_write_vectored(cx, bufs)
            }
            ConnectionProj::UpgradedProxy { conn } => conn.poll_write_vectored(cx, bufs),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<Conn: AsyncRead> AsyncRead for MaybeHttpProxiedConnection<Conn> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Proxied { conn } => {
                conn.poll_read(cx, buf)
            }
            ConnectionProj::UpgradedProxy { conn } => conn.poll_read(cx, buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{client::proxy::layer::HttpProxyConnectorLayer, server::HttpServer};
    use rama_core::{Layer, layer::MapOutputLayer, rt::Executor, service::service_fn};
    use rama_http_types::{Body, Request, Response};
    use rama_net::{
        Protocol,
        address::{HostWithPort, ProxyAddress},
        client::{
            ConnectRequest, ConnectionErrorDomain, ConnectionErrorKind, ConnectorService,
            ProxyRoute, ProxyRoutes, ProxyRoutesConnector,
        },
        test_utils::client::{MockConnectorService, MockSocket},
    };
    use rama_tcp::client::service::TcpConnector;
    use std::convert::Infallible;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[derive(Debug, Clone, Extension)]
    #[extension(tags(http))]
    struct ConnMarker(u32);

    #[tokio::test]
    async fn rejects_unsupported_proxy_http_version_as_local_input() {
        let http_server =
            HttpServer::auto(Executor::default()).service(service_fn(async |_req: Request| {
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let proxy_connector = HttpProxyConnectorLayer::required()
            .with_version(Version::HTTP_3)
            .into_layer(MockConnectorService::new(move || http_server.clone()));

        let req = Request::builder()
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();
        req.extensions().insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_http(),
            credential: None,
            protocol: Some(Protocol::HTTP),
        }));

        let error = proxy_connector
            .serve(req)
            .await
            .expect_err("HTTP/3 proxy configuration should be rejected");
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn connection_extensions_preserved_across_proxy_connect_upgrade() {
        let http_server =
            HttpServer::auto(Executor::default()).service(service_fn(async |_req: Request| {
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));

        let proxy_connector = (
            HttpProxyConnectorLayer::required(),
            MapOutputLayer::new(|out: EstablishedClientConnection<MockSocket, Request>| {
                out.conn.extensions().insert(ConnMarker(42));
                out
            }),
        )
            .into_layer(MockConnectorService::new(move || http_server.clone()));

        let req = Request::builder()
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();

        req.extensions().insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_http(),
            credential: None,
            protocol: Some(Protocol::HTTP),
        }));

        let EstablishedClientConnection { conn, .. } = proxy_connector
            .serve(req)
            .await
            .expect("proxy CONNECT handshake succeeds");

        let marker = conn
            .extensions()
            .get_ref::<ConnMarker>()
            .expect("ConnMarker set on the pre-CONNECT connection must survive the upgrade");
        assert_eq!(marker.0, 42);
    }

    #[tokio::test]
    async fn real_tcp_failure_falls_back_to_live_http_connect_proxy() {
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);

        let live_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = live_listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "CONNECT request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();

            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        });

        let inner = HttpProxyConnector::optional(TcpConnector::new());
        let connector = ProxyRoutesConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions.insert(ProxyRoutes::new([
            ProxyRoute::Proxy(
                format!("http://{dead_addr}")
                    .parse::<ProxyAddress>()
                    .unwrap(),
            ),
            ProxyRoute::Proxy(
                format!("http://{live_addr}")
                    .parse::<ProxyAddress>()
                    .unwrap(),
            ),
        ]));

        let established = Box::pin(connector.connect(input)).await.unwrap();
        assert_eq!(
            established
                .input
                .extensions
                .get_ref::<ProxyRoute>()
                .and_then(ProxyRoute::proxy_address)
                .map(|proxy| proxy.address.clone()),
            Some(live_addr.into()),
        );
        drop(established.conn);
        proxy_task.await.unwrap();
    }
}
