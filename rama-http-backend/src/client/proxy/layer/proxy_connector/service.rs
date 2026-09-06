use rama_core::error::BoxErrorExt as _;

use super::{HttpProxyVersionPolicy, InnerHttpProxyConnector};
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
    header::{IntoHeaderName, proxy_connect::is_managed_proxy_connect_request_header},
    io::upgrade,
};
use rama_http_headers::ProxyAuthorization;
use rama_http_types::{Version, proxy::PlaintextHttpProxyMode};
use rama_net::{
    AuthorityInputExt, HttpVersionInputExt, Protocol, ProtocolInputExt, TargetHttpVersionInputExt,
    client::{
        ConnectionError, ConnectionErrorKind, ConnectorService, ConnectorTarget,
        ConnectorTransportProtocol, EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute,
    },
    http::TargetHttpVersion,
    transport::TransportProtocol,
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
    pub(super) version_policy: HttpProxyVersionPolicy,
    pub(super) headers: Option<HeaderMap>,
}

impl<S> HttpProxyConnector<S> {
    /// Creates a new [`HttpProxyConnector`].
    ///
    /// CONNECT and HTTPS-proxy protocol versions default to HTTP/1.1.
    /// Plaintext forward-proxy requests follow the target HTTP version.
    pub(super) fn new(inner: S, required: bool) -> Self {
        Self {
            inner,
            required,
            tls_proxy_supported: true,
            version_policy: HttpProxyVersionPolicy::Automatic {
                connect_fallback: Some(Version::HTTP_11),
            },
            headers: None,
        }
    }

    generate_set_and_with! {
        /// Set whether the inner connector supports TLS to an HTTPS proxy.
        ///
        /// When enabled, the connector must attach
        /// `rama_tls::client::NegotiatedTlsParameters` to the established
        /// connection as positive evidence that TLS was negotiated.
        ///
        /// When disabled, selecting an HTTPS proxy produces a route-specific
        /// protocol error instead of sending plaintext to it.
        pub fn tls_proxy_support(mut self, supported: bool) -> Self {
            self.tls_proxy_supported = supported;
            self
        }
    }

    generate_set_and_with! {
        /// Set the HTTP version used to communicate with the proxy.
        ///
        /// This pins plaintext forward-proxy requests and CONNECT requests to
        /// the given version, and constrains HTTPS-proxy ALPN accordingly.
        /// Without an explicit version, plaintext forward-proxy requests follow
        /// the target version. Connectors created with [`Self::optional`] or
        /// [`Self::required`] default CONNECT and HTTPS-proxy traffic to
        /// HTTP/1.1; [`HttpProxyConnectorLayer::default`] instead follows
        /// negotiated HTTPS-proxy ALPN and otherwise falls back to HTTP/1.1.
        ///
        /// [`HttpProxyConnectorLayer::default`]: super::HttpProxyConnectorLayer
        pub fn version(mut self, version: Version) -> Self {
            self.version_policy = HttpProxyVersionPolicy::Fixed(version);
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
    Input: AuthorityInputExt
        + ProtocolInputExt
        + HttpVersionInputExt
        + TargetHttpVersionInputExt
        + Send
        + ExtensionsRef
        + 'static,
{
    type Output = EstablishedClientConnection<MaybeHttpProxiedConnection<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let route_configured = input.extensions().contains::<ProxyRoute>();
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
                if route_configured {
                    conn.extensions().insert(EstablishedProxyRoute::Direct);
                }
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

        if proxy_info
            .protocol
            .as_ref()
            .is_some_and(Protocol::is_secure)
            && (!self.tls_proxy_supported || !cfg!(feature = "tls"))
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
        let app_is_http = app_protocol.as_ref().is_some_and(Protocol::is_http_based);
        let app_is_plaintext_http = app_protocol
            .as_ref()
            .is_some_and(|protocol| protocol.is_http_based() && !protocol.is_secure());
        let use_forward_proxy = input
            .extensions()
            .get_ref::<PlaintextHttpProxyMode>()
            .copied()
            .unwrap_or_default()
            .should_forward(app_protocol.as_ref());
        let proxy_is_secure = proxy_info
            .protocol
            .as_ref()
            .is_some_and(Protocol::is_secure);
        let requested_http_version = crate::client::conn::resolve_input_target_http_version(&input);

        if app_is_http && !use_forward_proxy && requested_http_version == Some(Version::HTTP_3) {
            return Err(ConnectionError::local(
                BoxError::from_static_str(
                    "http proxy connector: HTTP/3 tunneling requires CONNECT-UDP",
                ),
                ConnectionErrorKind::InvalidInput,
            ));
        }

        let plaintext_forward_version = if use_forward_proxy && !proxy_is_secure {
            resolve_forward_proxy_version(self.version_policy, requested_http_version, None, false)?
        } else {
            None
        };

        if let Some(version) = self.version_policy.connect_version() {
            validate_connect_version(version)?;
        }

        // insert target so that inner connector can use it instead of input's version
        input
            .extensions()
            .insert(ConnectorTarget(proxy_info.address.clone()));
        input
            .extensions()
            .insert(ConnectorTransportProtocol(TransportProtocol::Tcp));

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
                alpn: self
                    .version_policy
                    .connect_version()
                    .and_then(connect_version_alpn),
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

        let negotiated_version = if proxy_is_secure {
            negotiated_proxy_http_version(conn.extensions())?
        } else {
            None
        };
        if use_forward_proxy {
            // Protocols supporting plaintext forward-proxy form can reuse the
            // proxy stream. Other byte-stream protocols require a tunnel.
            let proxy_http_version = if proxy_is_secure {
                resolve_forward_proxy_version(
                    self.version_policy,
                    requested_http_version,
                    negotiated_version,
                    true,
                )?
            } else {
                plaintext_forward_version
            };
            if let Some(proxy_http_version) = proxy_http_version {
                conn.extensions()
                    .insert(TargetHttpVersion(proxy_http_version));
            }
            return Ok(EstablishedClientConnection {
                input,
                conn: MaybeHttpProxiedConnection::proxied(conn, proxy_info),
            });
        }

        // CONNECT is a separate proxy exchange: deliberately omit request
        // extensions, including telemetry, so origin Protocol/TargetHttpVersion
        // metadata cannot change the proxy handshake.
        let mut connector = InnerHttpProxyConnector::new(authority.clone(), Extensions::new())
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("http proxy connector: build CONNECT request")
            })?;

        let proxy_http_version = resolve_connect_version(
            self.version_policy.connect_version(),
            negotiated_version,
            proxy_is_secure,
        )?;
        connector.set_version(proxy_http_version);

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
                if !is_managed_proxy_connect_request_header(&name) {
                    connector.set_header(name, value);
                }
            }
        }

        let (headers, conn) = connector
            .handshake(conn)
            .await
            .map_err(ConnectionError::from)
            .map_err(|error| error.context("http proxy handshake"))?;

        let conn = MaybeHttpProxiedConnection::upgraded_proxy(conn, proxy_info);

        // A CONNECT upgrade inherits proxy-leg connection metadata. Shadow the
        // proxy's wire version before the outer origin HTTP connector runs.
        // A plaintext origin needs an explicit HTTP/1.1 default; for a TLS
        // origin without a requested version, leave selection to origin ALPN.
        if app_is_plaintext_http || (app_is_http && requested_http_version.is_some()) {
            conn.extensions().insert(TargetHttpVersion(
                requested_http_version.unwrap_or(Version::HTTP_11),
            ));
        }

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

fn resolve_forward_proxy_version(
    policy: HttpProxyVersionPolicy,
    requested: Option<Version>,
    negotiated: Option<Version>,
    proxy_is_secure: bool,
) -> Result<Option<Version>, ConnectionError> {
    // A request's explicit target version is also the wire version for a
    // plaintext forward proxy. It must never configure an HTTPS proxy, whose
    // ALPN (or explicit connector policy) describes the physical connection.
    if proxy_is_secure {
        return resolve_connect_version(policy.connect_version(), negotiated, true).map(Some);
    }

    policy
        .forward_version(requested)
        .map(|version| {
            validate_connect_version(version)?;
            Ok(version)
        })
        .transpose()
}

#[cfg(feature = "tls")]
fn negotiated_proxy_http_version(
    extensions: &Extensions,
) -> Result<Option<Version>, ConnectionError> {
    let parameters = extensions
        .get_ref::<NegotiatedTlsParameters>()
        .ok_or_else(|| {
            ConnectionError::transport(
                BoxError::from_static_str(
                    "HTTPS proxy connection is missing negotiated TLS parameters",
                ),
                ConnectionErrorKind::Protocol,
            )
        })?;
    let Some(protocol) = parameters.application_layer_protocol.clone() else {
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

#[derive(Clone, Extension)]
#[extension(tags(http, proxy))]
/// Extension added to the [`Extensions`] by [`HttpProxyConnector`] to record the
/// headers from a successful CONNECT response.
///
/// This can be useful, for example, when the upstream proxy provider exposes
/// information in these headers about the connection to the final destination.
pub struct HttpProxyConnectResponseHeaders(Arc<HeaderMap>);

impl Debug for HttpProxyConnectResponseHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpProxyConnectResponseHeaders")
            .field("header_names", &self.0.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

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

    fn proxied(conn: S, proxy: rama_net::address::ProxyAddress) -> Self {
        conn.extensions()
            .insert(EstablishedProxyRoute::Forward(proxy));
        Self {
            inner: Connection::Proxied { conn },
        }
    }

    fn upgraded_proxy(conn: upgrade::Upgraded, proxy: rama_net::address::ProxyAddress) -> Self {
        conn.extensions()
            .insert(EstablishedProxyRoute::Tunnel(proxy));
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
    use rama_core::{
        Layer,
        futures::{Stream, stream},
        layer::MapOutputLayer,
        rt::Executor,
        service::service_fn,
    };
    use rama_http_types::{Body, Request, Response, StatusCode, conn::FallbackHttpVersion};
    use rama_net::{
        Protocol,
        address::{Domain, HostWithPort, ProxyAddress},
        client::{
            AddressCandidates, ConnectRequest, ConnectionErrorDomain, ConnectionErrorKind,
            ConnectorService, ConnectorTargetStream, ProxyRoute, ProxyRoutes, ProxyRoutesConnector,
        },
        http::HttpRequestVersion,
        test_utils::client::{MockConnectorService, MockSocket},
    };
    use rama_tcp::client::service::TcpConnector;
    use std::{
        convert::Infallible,
        net::{IpAddr, SocketAddr},
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[derive(Debug, Clone, Extension)]
    #[extension(tags(http))]
    struct ConnMarker(u32);

    struct OneCandidate {
        domain: Domain,
        ip_addr: IpAddr,
    }

    impl AddressCandidates for OneCandidate {
        fn domain(&self) -> &Domain {
            &self.domain
        }

        fn stream<'a>(
            &'a self,
            _: &'a Extensions,
        ) -> core::pin::Pin<Box<dyn Stream<Item = Result<IpAddr, BoxError>> + Send + 'a>> {
            Box::pin(stream::iter([Ok(self.ip_addr)]))
        }
    }

    #[tokio::test]
    async fn optional_direct_connection_records_only_the_original_route_selection() {
        for route_configured in [false, true] {
            for rewrite_input in [false, true] {
                let transport = service_fn(move |mut input: ConnectRequest| async move {
                    if rewrite_input {
                        input.extensions = Extensions::new();
                        if !route_configured {
                            input.extensions.insert(ProxyRoute::Direct);
                        }
                    }
                    let (stream, _peer) = tokio::io::duplex(64);
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        input,
                        conn: MockSocket::new(stream),
                    })
                });
                let connector = HttpProxyConnector::optional(transport);
                let input = ConnectRequest::new(HostWithPort::example_domain_http())
                    .with_application_protocol(Protocol::HTTP);
                if route_configured {
                    input.extensions.insert(ProxyRoute::Direct);
                }

                let established = connector.serve(input).await.unwrap();
                assert_eq!(
                    established
                        .conn
                        .extensions()
                        .get_ref::<EstablishedProxyRoute>(),
                    route_configured.then_some(&EstablishedProxyRoute::Direct),
                    "route configured: {route_configured}, input rewritten: {rewrite_input}",
                );
                assert!(!established.conn.extensions().contains::<ProxyRoute>());
            }
        }
    }

    #[tokio::test]
    async fn established_http_route_distinguishes_forward_and_tunnel_for_the_same_proxy() {
        for protocol in [None, Some(Protocol::HTTP)] {
            let mut proxy = "http://alice:private-password@proxy.example:8080"
                .parse::<ProxyAddress>()
                .unwrap();
            proxy.protocol = protocol;

            for mode in [
                PlaintextHttpProxyMode::Forward,
                PlaintextHttpProxyMode::Tunnel,
            ] {
                let http_server = HttpServer::auto(Executor::default()).service(service_fn(
                    async |req: Request| {
                        assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    },
                ));
                let connector =
                    HttpProxyConnector::required(MockConnectorService::new(move || {
                        http_server.clone()
                    }));
                let input = ConnectRequest::new(HostWithPort::example_domain_http())
                    .with_application_protocol(Protocol::HTTP);
                input.extensions.insert(ProxyRoute::Proxy(proxy.clone()));
                input.extensions.insert(mode);

                let established = connector.serve(input).await.unwrap();
                let expected = match mode {
                    PlaintextHttpProxyMode::Forward => {
                        EstablishedProxyRoute::Forward(proxy.clone())
                    }
                    PlaintextHttpProxyMode::Tunnel => EstablishedProxyRoute::Tunnel(proxy.clone()),
                };
                assert_eq!(
                    established
                        .conn
                        .extensions()
                        .get_ref::<EstablishedProxyRoute>(),
                    Some(&expected),
                );
                assert!(!established.conn.extensions().contains::<ProxyRoute>());
                assert_eq!(
                    established.input.extensions.get_ref::<ProxyRoute>(),
                    Some(&ProxyRoute::Proxy(proxy.clone())),
                );
            }
        }
    }

    #[tokio::test]
    async fn proxy_route_ignores_stale_origin_candidates() {
        let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 8080));
        let origin_ip = IpAddr::from([127, 0, 0, 1]);
        let recorded = Arc::new(rama_utils::collections::AppendOnlyVec::<SocketAddr>::new());
        let transport = TcpConnector::new().with_connector({
            let recorded = Arc::clone(&recorded);
            move |addr| {
                recorded.push(addr);
                async { Err::<rama_tcp::TcpStream, _>(std::io::Error::other("denied")) }
            }
        });
        let connector = HttpProxyConnector::required(transport);
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input
            .extensions
            .insert(ConnectorTargetStream::new(OneCandidate {
                domain: Domain::example(),
                ip_addr: origin_ip,
            }));
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: proxy_addr.into(),
            credential: None,
            protocol: Some(Protocol::HTTP),
        }));

        let error = connector.serve(input).await.unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(recorded.iter().copied().collect::<Vec<_>>(), [proxy_addr]);
    }

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
    async fn https_proxy_without_available_tls_support_is_rejected_before_dial() {
        let dials = Arc::new(AtomicUsize::new(0));
        let observed_dials = dials.clone();
        let inner = MockConnectorService::new(move || {
            observed_dials.fetch_add(1, Ordering::Relaxed);
            service_fn(async |_socket: MockSocket| Ok::<_, Infallible>(()))
        });
        let connector = HttpProxyConnector::required(inner);
        #[cfg(feature = "tls")]
        let connector = connector.with_tls_proxy_support(false);

        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_https(),
            credential: None,
            protocol: Some(Protocol::HTTPS),
        }));

        let error = connector.serve(input).await.unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
        assert_eq!(dials.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn connect_custom_headers_cannot_override_managed_fields() {
        let http_server =
            HttpServer::auto(Executor::default()).service(service_fn(async move |req: Request| {
                assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                assert_eq!(
                    req.headers()[rama_http_types::header::HOST],
                    "example.com:443"
                );
                assert_eq!(
                    req.headers()[rama_http_types::header::PROXY_AUTHORIZATION],
                    "Basic dXBzdHJlYW06c2VjcmV0"
                );
                assert!(
                    !req.headers()
                        .contains_key(rama_http_types::header::CONTENT_LENGTH)
                );
                assert!(
                    !req.headers()
                        .contains_key(rama_http_types::header::TRANSFER_ENCODING)
                );
                assert_eq!(req.headers()["x-kept"], "yes");
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let connector = HttpProxyConnectorLayer::required()
            .with_custom_header(
                rama_http_types::header::HOST,
                rama_http_types::HeaderValue::from_static("evil.example"),
            )
            .with_custom_header(
                rama_http_types::header::PROXY_AUTHORIZATION,
                rama_http_types::HeaderValue::from_static("Basic ZXZpbA=="),
            )
            .with_custom_header(
                rama_http_types::header::CONTENT_LENGTH,
                rama_http_types::HeaderValue::from_static("999"),
            )
            .with_custom_header(
                rama_http_types::header::TRANSFER_ENCODING,
                rama_http_types::HeaderValue::from_static("chunked"),
            )
            .with_custom_header("x-kept", rama_http_types::HeaderValue::from_static("yes"))
            .into_layer(MockConnectorService::new(move || http_server.clone()));
        let input = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_http(),
            credential: Some(rama_net::user::ProxyCredential::Basic(
                rama_net::user::Basic::try_from("upstream:secret").unwrap(),
            )),
            protocol: Some(Protocol::HTTP),
        }));

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn connect_statuses_establish_tunnels_only_for_success() {
        for version in [Version::HTTP_11, Version::HTTP_2] {
            for status in [
                StatusCode::OK,
                StatusCode::CREATED,
                StatusCode::NO_CONTENT,
                StatusCode::from_u16(299).unwrap(),
            ] {
                let http_server = HttpServer::auto(Executor::default()).service(service_fn(
                    move |_req: Request| async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Body::empty())
                                .unwrap(),
                        )
                    },
                ));
                let connector = HttpProxyConnectorLayer::required()
                    .with_version(version)
                    .into_layer(MockConnectorService::new(move || http_server.clone()));
                let input = ConnectRequest::new(HostWithPort::example_domain_https())
                    .with_application_protocol(Protocol::HTTPS);
                input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
                    address: HostWithPort::example_domain_http(),
                    credential: None,
                    protocol: Some(Protocol::HTTP),
                }));

                tokio::time::timeout(Duration::from_secs(2), connector.serve(input))
                    .await
                    .expect("successful CONNECT must not wait indefinitely for an upgraded tunnel")
                    .expect("every successful CONNECT response establishes a tunnel");
            }
        }

        for (status, expected_domain, expected_kind) in [
            (
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::Authentication,
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::Unavailable,
            ),
            (
                StatusCode::BAD_GATEWAY,
                ConnectionErrorDomain::Application,
                ConnectionErrorKind::Unavailable,
            ),
            (
                StatusCode::GATEWAY_TIMEOUT,
                ConnectionErrorDomain::Application,
                ConnectionErrorKind::Unavailable,
            ),
            (
                StatusCode::FORBIDDEN,
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::Rejected,
            ),
        ] {
            let http_server = HttpServer::auto(Executor::default()).service(service_fn(
                move |_req: Request| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Body::from("not a tunnel"))
                            .unwrap(),
                    )
                },
            ));
            let connector = HttpProxyConnectorLayer::required()
                .into_layer(MockConnectorService::new(move || http_server.clone()));
            let input = ConnectRequest::new(HostWithPort::example_domain_https())
                .with_application_protocol(Protocol::HTTPS);
            input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
                address: HostWithPort::example_domain_http(),
                credential: None,
                protocol: Some(Protocol::HTTP),
            }));

            let error = tokio::time::timeout(Duration::from_secs(2), connector.serve(input))
                .await
                .expect("CONNECT rejection must not wait for an upgraded tunnel")
                .expect_err("a rejected CONNECT must not establish a tunnel");
            assert_eq!(error.domain(), expected_domain, "status: {status}");
            assert_eq!(error.kind(), expected_kind, "status: {status}");
        }
    }

    #[tokio::test]
    async fn connect_protocol_errors_never_fall_back_to_direct() {
        for version in [Version::HTTP_11, Version::HTTP_2] {
            let dials = Arc::new(AtomicUsize::new(0));
            let transport = MockConnectorService::new({
                let dials = dials.clone();
                move || {
                    dials.fetch_add(1, Ordering::Relaxed);
                    service_fn(move |mut socket: MockSocket| async move {
                        if version == Version::HTTP_2 {
                            let mut conn =
                                rama_http_core::h2::server::handshake(socket).await.unwrap();
                            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
                            assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                            respond.send_reset(rama_http_core::h2::Reason::PROTOCOL_ERROR);
                            _ = std::future::poll_fn(|cx| conn.poll_closed(cx)).await;
                        } else {
                            let mut request = Vec::new();
                            while !request.ends_with(b"\r\n\r\n") {
                                request.push(socket.read_u8().await.unwrap());
                            }
                            assert!(request.starts_with(b"CONNECT "));
                            socket.write_all(b"HTTP/1.1 INVALID\r\n\r\n").await.unwrap();
                        }
                        Ok::<_, Infallible>(())
                    })
                }
            });
            let connector = ProxyRoutesConnector::new(
                HttpProxyConnector::optional(transport).with_version(version),
            );
            let input = ConnectRequest::new(HostWithPort::example_domain_https())
                .with_application_protocol(Protocol::HTTPS);
            input.extensions.insert(ProxyRoutes::new([
                ProxyRoute::Proxy("http://proxy.example:8080".parse().unwrap()),
                ProxyRoute::Direct,
            ]));

            let error = tokio::time::timeout(Duration::from_secs(2), connector.serve(input))
                .await
                .expect("CONNECT protocol error must complete promptly")
                .expect_err("CONNECT protocol error must not establish a direct connection");
            assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
            assert_eq!(
                error.kind(),
                ConnectionErrorKind::Protocol,
                "{version:?}: {error:?}"
            );
            assert_eq!(dials.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn connect_closed_proxy_may_fall_back_to_direct() {
        for version in [Version::HTTP_11, Version::HTTP_2] {
            let dials = Arc::new(AtomicUsize::new(0));
            let transport = MockConnectorService::new({
                let dials = dials.clone();
                move || {
                    dials.fetch_add(1, Ordering::Relaxed);
                    service_fn(move |mut socket: MockSocket| async move {
                        if version == Version::HTTP_2 {
                            let mut conn =
                                rama_http_core::h2::server::handshake(socket).await.unwrap();
                            let (req, _) = conn.accept().await.unwrap().unwrap();
                            assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                        } else {
                            let mut request = Vec::new();
                            while !request.ends_with(b"\r\n\r\n") {
                                request.push(socket.read_u8().await.unwrap());
                            }
                            assert!(request.starts_with(b"CONNECT "));
                        }
                        Ok::<_, Infallible>(())
                    })
                }
            });
            let connector = ProxyRoutesConnector::new(
                HttpProxyConnector::optional(transport).with_version(version),
            );
            let input = ConnectRequest::new(HostWithPort::example_domain_https())
                .with_application_protocol(Protocol::HTTPS);
            input.extensions.insert(ProxyRoutes::new([
                ProxyRoute::Proxy("http://proxy.example:8080".parse().unwrap()),
                ProxyRoute::Direct,
            ]));

            let established = tokio::time::timeout(Duration::from_secs(2), connector.serve(input))
                .await
                .unwrap()
                .expect("transport closure permits direct fallback");
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<EstablishedProxyRoute>(),
                Some(&EstablishedProxyRoute::Direct)
            );
            assert!(!established.conn.extensions().contains::<ProxyRoute>());
            assert_eq!(dials.load(Ordering::Relaxed), 2);
        }
    }

    #[tokio::test]
    async fn plaintext_non_http_protocol_uses_connect() {
        for protocol in [Protocol::ICAP, Protocol::from_static("custom")] {
            let http_server = HttpServer::auto(Executor::default()).service(service_fn(
                async move |req: Request| {
                    assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                    assert!(
                        !req.extensions()
                            .contains::<rama_http_types::proto::h2::ext::Protocol>()
                    );
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(rama_http_types::StatusCode::CREATED)
                            .body(Body::empty())
                            .unwrap(),
                    )
                },
            ));
            let proxy_connector = HttpProxyConnectorLayer::required()
                .into_layer(MockConnectorService::new(move || http_server.clone()));
            let request = ConnectRequest::new(HostWithPort::example_domain_http())
                .with_application_protocol(protocol.clone());
            request
                .extensions
                .insert(rama_http_types::proto::h2::ext::Protocol::from_static(
                    "websocket",
                ));
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

    #[tokio::test]
    async fn plaintext_http_tunnel_restores_origin_version_after_connect() {
        let http_server =
            HttpServer::auto(Executor::default()).service(service_fn(async move |req: Request| {
                assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                assert_eq!(req.version(), Version::HTTP_11);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let connector = HttpProxyConnectorLayer::required()
            .into_layer(MockConnectorService::new(move || http_server.clone()));
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(HttpRequestVersion(Version::HTTP_2));
        input.extensions.insert(PlaintextHttpProxyMode::Tunnel);
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_http(),
            credential: None,
            protocol: Some(Protocol::HTTP),
        }));

        let established = connector.serve(input).await.unwrap();
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|version| version.0),
            Some(Version::HTTP_2)
        );
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<EstablishedProxyRoute>(),
            Some(&EstablishedProxyRoute::Tunnel(ProxyAddress {
                address: HostWithPort::example_domain_http(),
                credential: None,
                protocol: Some(Protocol::HTTP),
            }))
        );
    }

    #[tokio::test]
    async fn plaintext_http_tunnel_defaults_missing_origin_version() {
        let http_server =
            HttpServer::auto(Executor::default()).service(service_fn(async move |req: Request| {
                assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let transport = MockConnectorService::new(move || http_server.clone());
        let transport = service_fn(move |input: ConnectRequest| {
            let transport = transport.clone();
            async move {
                let established = transport.serve(input).await?;
                established
                    .conn
                    .extensions()
                    .insert(TargetHttpVersion(Version::HTTP_2));
                Ok::<_, Infallible>(established)
            }
        });
        let connector = HttpProxyConnectorLayer::required().into_layer(transport);
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(PlaintextHttpProxyMode::Tunnel);
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_http(),
            credential: None,
            protocol: Some(Protocol::HTTP),
        }));

        let established = connector.serve(input).await.unwrap();
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|version| version.0),
            Some(Version::HTTP_11),
        );
    }

    #[tokio::test]
    async fn non_http_tunnel_does_not_inherit_incidental_http_version() {
        let http_server =
            HttpServer::auto(Executor::default()).service(service_fn(async move |req: Request| {
                assert_eq!(req.method(), rama_http_types::Method::CONNECT);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let connector = HttpProxyConnectorLayer::required()
            .into_layer(MockConnectorService::new(move || http_server.clone()));
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::from_static("custom"));
        input.extensions.insert(HttpRequestVersion(Version::HTTP_2));
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_http(),
            credential: None,
            protocol: Some(Protocol::HTTP),
        }));

        let established = connector.serve(input).await.unwrap();
        assert!(
            established
                .conn
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .is_none()
        );
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
                let established = transport.serve(input).await?;
                established
                    .conn
                    .extensions()
                    .insert(NegotiatedTlsParameters {
                        protocol_version: rama_tls::ProtocolVersion::TLSv1_3,
                        application_layer_protocol: None,
                        peer_certificate_chain: None,
                    });
                Ok::<_, Infallible>(established)
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
    #[tokio::test]
    async fn https_proxy_requires_positive_tls_evidence() {
        let connector =
            HttpProxyConnectorLayer::required().into_layer(MockConnectorService::new(|| {
                service_fn(async |_socket: MockSocket| Ok::<_, Infallible>(()))
            }));
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_https(),
            credential: None,
            protocol: Some(Protocol::HTTPS),
        }));

        let error = connector
            .serve(input)
            .await
            .expect_err("an HTTPS proxy cannot silently use a plaintext connection");
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
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

    #[test]
    fn forward_proxy_version_uses_only_physical_connection_signals() {
        assert_eq!(
            resolve_forward_proxy_version(
                HttpProxyVersionPolicy::Automatic {
                    connect_fallback: Some(Version::HTTP_11),
                },
                Some(Version::HTTP_2),
                None,
                false,
            )
            .unwrap(),
            Some(Version::HTTP_2)
        );
        assert_eq!(
            resolve_forward_proxy_version(
                HttpProxyVersionPolicy::Automatic {
                    connect_fallback: Some(Version::HTTP_11),
                },
                None,
                None,
                false,
            )
            .unwrap(),
            None,
        );
        assert_eq!(
            resolve_forward_proxy_version(
                HttpProxyVersionPolicy::Fixed(Version::HTTP_11),
                Some(Version::HTTP_2),
                None,
                false,
            )
            .unwrap(),
            Some(Version::HTTP_11)
        );
        assert_eq!(
            resolve_forward_proxy_version(
                HttpProxyVersionPolicy::Automatic {
                    connect_fallback: None,
                },
                Some(Version::HTTP_2),
                Some(Version::HTTP_11),
                true,
            )
            .unwrap(),
            Some(Version::HTTP_11)
        );
    }

    #[tokio::test]
    async fn automatic_plaintext_forward_proxy_preserves_requested_version() {
        for (target, fallback, requested, expected) in [
            (None, None, None, None),
            (None, None, Some(Version::HTTP_2), Some(Version::HTTP_2)),
            (
                None,
                Some(Version::HTTP_2),
                Some(Version::HTTP_11),
                Some(Version::HTTP_2),
            ),
            (
                Some(Version::HTTP_2),
                Some(Version::HTTP_11),
                Some(Version::HTTP_10),
                Some(Version::HTTP_2),
            ),
            (
                Some(Version::HTTP_11),
                None,
                Some(Version::HTTP_3),
                Some(Version::HTTP_11),
            ),
            (
                None,
                Some(Version::HTTP_11),
                Some(Version::HTTP_3),
                Some(Version::HTTP_11),
            ),
        ] {
            let connector =
                HttpProxyConnectorLayer::required().into_layer(MockConnectorService::new(|| {
                    service_fn(async |_socket: MockSocket| Ok::<_, Infallible>(()))
                }));
            let input = ConnectRequest::new(HostWithPort::example_domain_http())
                .with_application_protocol(Protocol::HTTP);
            if let Some(target) = target {
                input.extensions.insert(TargetHttpVersion(target));
            }
            if let Some(fallback) = fallback {
                input.extensions.insert(FallbackHttpVersion(fallback));
            }
            if let Some(requested) = requested {
                input
                    .extensions
                    .insert(rama_net::http::HttpRequestVersion(requested));
            }
            input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
                address: HostWithPort::example_domain_http(),
                credential: None,
                protocol: Some(Protocol::HTTP),
            }));

            let established = connector.serve(input).await.unwrap();
            assert!(matches!(established.conn.inner, Connection::Proxied { .. }));
            assert_eq!(
                rama_net::ConnectorTransportProtocolInputExt::connector_transport_protocol(
                    &established.input,
                ),
                Some(TransportProtocol::Tcp),
            );
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<TargetHttpVersion>()
                    .map(|target| target.0),
                expected,
            );
        }
    }

    #[tokio::test]
    async fn explicit_plaintext_forward_proxy_version_overrides_request() {
        let connector = HttpProxyConnectorLayer::required()
            .with_version(Version::HTTP_11)
            .into_layer(MockConnectorService::new(|| {
                service_fn(async |_socket: MockSocket| Ok::<_, Infallible>(()))
            }));
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input
            .extensions
            .insert(rama_net::http::HttpRequestVersion(Version::HTTP_3));
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_http(),
            credential: None,
            protocol: Some(Protocol::HTTP),
        }));

        let established = connector.serve(input).await.unwrap();
        assert_eq!(
            rama_net::ConnectorTransportProtocolInputExt::connector_transport_protocol(
                &established.input,
            ),
            Some(TransportProtocol::Tcp),
        );
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|target| target.0),
            Some(Version::HTTP_11),
        );
    }

    #[tokio::test]
    async fn effective_http3_proxy_target_is_rejected_before_dial() {
        for (app_protocol, target, fallback, requested) in [
            (Protocol::HTTP, Some(Version::HTTP_3), None, None),
            (
                Protocol::HTTP,
                None,
                Some(Version::HTTP_3),
                Some(Version::HTTP_11),
            ),
            (Protocol::HTTP, None, None, Some(Version::HTTP_3)),
            (Protocol::HTTPS, Some(Version::HTTP_3), None, None),
        ] {
            let dials = Arc::new(AtomicUsize::new(0));
            let observed_dials = dials.clone();
            let connector = HttpProxyConnectorLayer::required().into_layer(
                MockConnectorService::new(move || {
                    observed_dials.fetch_add(1, Ordering::Relaxed);
                    service_fn(async |_socket: MockSocket| Ok::<_, Infallible>(()))
                }),
            );
            let input = ConnectRequest::new(HostWithPort::example_domain_http())
                .with_application_protocol(app_protocol);
            if let Some(target) = target {
                input.extensions.insert(TargetHttpVersion(target));
            }
            if let Some(fallback) = fallback {
                input.extensions.insert(FallbackHttpVersion(fallback));
            }
            if let Some(requested) = requested {
                input
                    .extensions
                    .insert(rama_net::http::HttpRequestVersion(requested));
            }
            input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
                address: HostWithPort::example_domain_http(),
                credential: None,
                protocol: Some(Protocol::HTTP),
            }));

            let error = connector
                .serve(input)
                .await
                .expect_err("effective HTTP/3 requires a datagram proxy protocol");
            assert_eq!(error.domain(), ConnectionErrorDomain::Local);
            assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
            assert_eq!(dials.load(Ordering::Relaxed), 0);
        }
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
        input
            .extensions
            .insert(HttpRequestVersion(Version::HTTP_11));
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: HostWithPort::example_domain_https(),
            credential: None,
            protocol: Some(Protocol::HTTPS),
        }));

        connector.serve(input).await.unwrap();
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn forward_proxy_version_follows_proxy_tls_negotiation() {
        for (negotiated, expected) in [
            (None, Version::HTTP_11),
            (
                Some(rama_net::tls::ApplicationProtocol::HTTP_2),
                Version::HTTP_2,
            ),
        ] {
            let transport = MockConnectorService::new(|| {
                service_fn(async |_socket: MockSocket| Ok::<_, Infallible>(()))
            });
            let transport = MapOutputLayer::new(
                move |established: EstablishedClientConnection<MockSocket, ConnectRequest>| {
                    established
                        .conn
                        .extensions()
                        .insert(NegotiatedTlsParameters {
                            protocol_version: rama_tls::ProtocolVersion::TLSv1_3,
                            application_layer_protocol: negotiated.clone(),
                            peer_certificate_chain: None,
                        });
                    established
                },
            )
            .into_layer(transport);
            let connector = HttpProxyConnectorLayer::default().into_layer(transport);
            let input = ConnectRequest::new(HostWithPort::example_domain_http())
                .with_application_protocol(Protocol::HTTP);
            input
                .extensions
                .insert(HttpRequestVersion(if expected == Version::HTTP_11 {
                    Version::HTTP_2
                } else {
                    Version::HTTP_11
                }));
            input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
                address: HostWithPort::example_domain_https(),
                credential: None,
                protocol: Some(Protocol::HTTPS),
            }));

            let established = connector.serve(input).await.unwrap();
            assert!(matches!(established.conn.inner, Connection::Proxied { .. }));
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<TargetHttpVersion>()
                    .map(|target| target.0),
                Some(expected),
            );
        }
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

    #[test]
    fn connect_response_header_debug_does_not_include_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "proxy-authentication-info",
            "nextnonce=private-upstream-token".parse().unwrap(),
        );
        headers.insert("x-proxy-id", "private-account-id".parse().unwrap());

        let debug = format!("{:?}", HttpProxyConnectResponseHeaders::new(headers));
        assert!(debug.contains("proxy-authentication-info"));
        assert!(debug.contains("x-proxy-id"));
        assert!(!debug.contains("private-upstream-token"));
        assert!(!debug.contains("private-account-id"));
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
