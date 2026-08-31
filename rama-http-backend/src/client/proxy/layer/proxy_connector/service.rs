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
use rama_net::tls::TlsAlpn;
#[cfg(feature = "tls")]
use rama_tls::{TlsTunnel, client::NegotiatedTlsParameters};

/// A connector which can be used to establish a connection over an HTTP Proxy.
///
/// This behaviour is optional and only triggered in case there
/// is a proxied [`ProxyRoute`] found in the [`Extensions`].
#[derive(Debug, Clone)]
pub struct HttpProxyConnector<S> {
    pub(super) inner: S,
    pub(super) required: bool,
    pub(super) tls_proxy_supported: bool,
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
            tls_proxy_supported: true,
            version: Some(Version::HTTP_11),
            headers: None,
        }
    }

    generate_set_and_with! {
        /// Set whether the inner connector supports TLS to an HTTPS proxy.
        ///
        /// When disabled, selecting an HTTPS proxy produces a route-specific
        /// protocol error instead of sending plaintext to it.
        pub fn tls_proxy_support(mut self, supported: bool) -> Self {
            self.tls_proxy_supported = supported;
            self
        }
    }

    generate_set_and_with! {
        /// Set the HTTP version to use for the CONNECT request.
        ///
        /// This also constrains HTTPS-proxy ALPN to the matching protocol.
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
            return Err(ConnectionError::transport(
                BoxError::from_static_str("http proxy connector can only serve http protocol"),
                ConnectionErrorKind::Protocol,
            )
            .context_debug_field("protocol", proxy_info.protocol.clone()));
        }

        if !self.tls_proxy_supported
            && proxy_info
                .protocol
                .as_ref()
                .is_some_and(Protocol::is_secure)
        {
            return Err(ConnectionError::transport(
                BoxError::from_static_str("https proxy selected without proxy-side TLS support"),
                ConnectionErrorKind::Protocol,
            ));
        }

        let authority = input.authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("http proxy connector: authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        let app_protocol = input.protocol().cloned();

        if let Some(version) = self.version {
            validate_connect_version(version)?;
        }

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
                server_identity: Some(proxy_info.address.host.clone()),
                application_protocol: Some(Protocol::HTTPS),
                alpn: self.version.and_then(connect_version_alpn),
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

        if app_protocol
            .as_ref()
            .is_some_and(|protocol| protocol.is_http_based() && !protocol.is_secure())
        {
            // Protocols supporting plaintext forward-proxy form can reuse the
            // proxy stream. Other byte-stream protocols require a tunnel.
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

        let proxy_is_secure = proxy_info
            .protocol
            .as_ref()
            .is_some_and(Protocol::is_secure);
        let negotiated_version = if proxy_is_secure {
            negotiated_proxy_http_version(conn.extensions())?
        } else {
            None
        };
        let connect_version =
            resolve_connect_version(self.version, negotiated_version, proxy_is_secure)?;
        connector.set_version(connect_version);

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

fn validate_connect_version(version: Version) -> Result<(), ConnectionError> {
    if matches!(
        version,
        Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2
    ) {
        Ok(())
    } else {
        Err(ConnectionError::local(
            BoxError::from_static_str("http proxy connector: unsupported HTTP version"),
            ConnectionErrorKind::InvalidInput,
        )
        .context_debug_field("version", version))
    }
}

fn resolve_connect_version(
    configured: Option<Version>,
    negotiated: Option<Version>,
    proxy_is_secure: bool,
) -> Result<Version, ConnectionError> {
    if let Some(configured) = configured {
        validate_connect_version(configured)?;
        if proxy_is_secure {
            match negotiated {
                Some(negotiated) if negotiated != configured => {
                    return Err(ConnectionError::transport(
                        BoxError::from_static_str(
                            "HTTPS proxy negotiated an incompatible HTTP version",
                        ),
                        ConnectionErrorKind::Protocol,
                    )
                    .context_debug_field("configured_version", configured)
                    .context_debug_field("negotiated_version", negotiated));
                }
                None if configured == Version::HTTP_2 => {
                    return Err(ConnectionError::transport(
                        BoxError::from_static_str(
                            "HTTPS proxy did not negotiate the required HTTP/2 ALPN",
                        ),
                        ConnectionErrorKind::Protocol,
                    ));
                }
                _ => {}
            }
        }
        return Ok(configured);
    }

    let Some(version) = negotiated else {
        return Ok(Version::HTTP_11);
    };
    if matches!(
        version,
        Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2
    ) {
        Ok(version)
    } else {
        Err(ConnectionError::transport(
            BoxError::from_static_str("HTTPS proxy negotiated an unsupported HTTP version"),
            ConnectionErrorKind::Protocol,
        )
        .context_debug_field("negotiated_version", version))
    }
}

#[cfg(feature = "tls")]
fn negotiated_proxy_http_version(
    extensions: &Extensions,
) -> Result<Option<Version>, ConnectionError> {
    let Some(protocol) = extensions
        .get_ref::<NegotiatedTlsParameters>()
        .and_then(|parameters| parameters.application_layer_protocol.clone())
    else {
        return Ok(None);
    };

    Version::try_from(protocol).map(Some).map_err(|error| {
        ConnectionError::transport(error, ConnectionErrorKind::Protocol)
            .context("HTTPS proxy negotiated an invalid HTTP ALPN")
    })
}

#[cfg(not(feature = "tls"))]
fn negotiated_proxy_http_version(_: &Extensions) -> Result<Option<Version>, ConnectionError> {
    Ok(None)
}

#[cfg(feature = "tls")]
fn connect_version_alpn(version: Version) -> Option<TlsAlpn> {
    match version {
        Version::HTTP_10 => Some(TlsAlpn::empty()),
        Version::HTTP_11 => Some(TlsAlpn::http_1()),
        Version::HTTP_2 => Some(TlsAlpn::http_2()),
        _ => None,
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
    async fn unsupported_proxy_routes_do_not_fall_back_to_direct() {
        for protocol in [Protocol::SOCKS5, Protocol::HTTPS] {
            let inner = MockConnectorService::new(|| {
                service_fn(async |_socket: MockSocket| Ok::<_, Infallible>(()))
            });
            let inner = HttpProxyConnector::optional(inner).with_tls_proxy_support(false);
            let connector = ProxyRoutesConnector::new(inner);
            let input = ConnectRequest::new(HostWithPort::example_domain_http());
            input.extensions.insert(ProxyRoutes::new([
                ProxyRoute::Proxy(ProxyAddress {
                    address: HostWithPort::example_domain_http(),
                    credential: None,
                    protocol: Some(protocol.clone()),
                }),
                ProxyRoute::Direct,
            ]));

            let error = Box::pin(connector.connect(input)).await.unwrap_err();
            assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
            assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
        }
    }

    #[tokio::test]
    async fn plaintext_non_http_protocol_uses_connect() {
        for protocol in [Protocol::ICAP, Protocol::from_static("custom")] {
            let http_server = HttpServer::auto(Executor::default()).service(service_fn(
                async move |req: Request| {
                    assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                },
            ));
            let proxy_connector = HttpProxyConnectorLayer::required()
                .into_layer(MockConnectorService::new(move || http_server.clone()));
            let request = ConnectRequest::new(HostWithPort::example_domain_http())
                .with_application_protocol(protocol.clone());
            request.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
                address: HostWithPort::example_domain_http(),
                credential: None,
                protocol: Some(Protocol::HTTP),
            }));

            let established = proxy_connector
                .serve(request)
                .await
                .expect("plaintext non-HTTP application uses CONNECT");
            assert!(matches!(
                established.conn.inner,
                Connection::UpgradedProxy { .. }
            ));
        }
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn https_proxy_tunnel_declares_http_as_its_tls_protocol() {
        let http_server =
            HttpServer::auto(Executor::default()).service(service_fn(async |req: Request| {
                assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let transport = MockConnectorService::new(move || http_server.clone());
        let transport = service_fn(move |input: ConnectRequest| {
            let transport = transport.clone();
            async move {
                let tunnel = input.extensions.get_ref::<TlsTunnel>().unwrap();
                assert_eq!(tunnel.application_protocol.as_ref(), Some(&Protocol::HTTPS),);
                assert_eq!(tunnel.alpn.as_ref(), Some(&TlsAlpn::http_1()));
                transport.serve(input).await
            }
        });
        let connector = HttpProxyConnectorLayer::required().into_layer(transport);
        let input = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::ICAPS);
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_https(),
            credential: None,
            protocol: Some(Protocol::HTTPS),
        }));

        connector.serve(input).await.unwrap();
    }

    #[cfg(feature = "tls")]
    #[test]
    fn explicit_connect_versions_define_matching_proxy_alpn() {
        for (version, expected) in [
            (Version::HTTP_10, TlsAlpn::empty()),
            (Version::HTTP_11, TlsAlpn::http_1()),
            (Version::HTTP_2, TlsAlpn::http_2()),
        ] {
            assert_eq!(connect_version_alpn(version), Some(expected));
        }
        assert_eq!(connect_version_alpn(Version::HTTP_3), None);

        assert_eq!(
            resolve_connect_version(Some(Version::HTTP_11), None, true).unwrap(),
            Version::HTTP_11
        );
        assert_eq!(
            resolve_connect_version(Some(Version::HTTP_10), None, true).unwrap(),
            Version::HTTP_10
        );
        let error = resolve_connect_version(Some(Version::HTTP_2), None, true).unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
        let error = resolve_connect_version(Some(Version::HTTP_11), Some(Version::HTTP_2), true)
            .unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
        assert_eq!(
            resolve_connect_version(None, Some(Version::HTTP_2), true).unwrap(),
            Version::HTTP_2
        );
        assert_eq!(
            resolve_connect_version(None, None, true).unwrap(),
            Version::HTTP_11
        );
        let error =
            resolve_connect_version(None, Some(Version::HTTP_3), true).expect_err("unsupported");
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn automatic_connect_version_follows_proxy_tls_negotiation() {
        let http_server =
            HttpServer::auto(Executor::default()).service(service_fn(async |req: Request| {
                assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                assert_eq!(req.version(), Version::HTTP_2);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let transport = MockConnectorService::new(move || http_server.clone());
        let transport = service_fn(move |input: ConnectRequest| {
            let transport = transport.clone();
            async move {
                let tunnel = input.extensions.get_ref::<TlsTunnel>().unwrap();
                assert!(tunnel.alpn.is_none());
                let established = transport.serve(input).await?;
                established
                    .conn
                    .extensions()
                    .insert(NegotiatedTlsParameters {
                        protocol_version: rama_tls::ProtocolVersion::TLSv1_3,
                        application_layer_protocol: Some(
                            rama_net::tls::ApplicationProtocol::HTTP_2,
                        ),
                        peer_certificate_chain: None,
                    });
                Ok::<_, Infallible>(established)
            }
        });
        let connector = HttpProxyConnectorLayer::default().into_layer(transport);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_https(),
            credential: None,
            protocol: Some(Protocol::HTTPS),
        }));

        connector.serve(input).await.unwrap();
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn plaintext_proxy_ignores_unrelated_tls_negotiation_metadata() {
        let http_server =
            HttpServer::auto(Executor::default()).service(service_fn(async |req: Request| {
                assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                assert_eq!(req.version(), Version::HTTP_11);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let transport = MockConnectorService::new(move || http_server.clone());
        let transport = MapOutputLayer::new(
            |established: EstablishedClientConnection<MockSocket, ConnectRequest>| {
                established
                    .conn
                    .extensions()
                    .insert(NegotiatedTlsParameters {
                        protocol_version: rama_tls::ProtocolVersion::TLSv1_3,
                        application_layer_protocol: Some(
                            rama_net::tls::ApplicationProtocol::HTTP_2,
                        ),
                        peer_certificate_chain: None,
                    });
                established
            },
        )
        .into_layer(transport);
        let connector = HttpProxyConnectorLayer::default().into_layer(transport);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_http(),
            credential: None,
            protocol: Some(Protocol::HTTP),
        }));

        connector.serve(input).await.unwrap();
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
