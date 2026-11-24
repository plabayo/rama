use rama_core::error::BoxErrorExt as _;

use super::{HttpProxyError, connect_request, upgrade_connect_response};
use crate::client::conn::resolve_input_target_http_version;
use rama_core::{
    Service,
    error::BoxError,
    extensions::{Extension, ExtensionsRef, ExtensionsTransfer, SharedExtensionsTransfer},
    telemetry::tracing,
};
use rama_http::{
    HeaderMap, HeaderValue,
    header::{IntoHeaderName, proxy_connect::is_managed_proxy_connect_request_header},
    io::upgrade::Upgraded,
};
use rama_http_types::{Body, Request, Response, Version, proxy::ProxyRequestBody};
use rama_net::{
    ConnectorTargetInputExt, HttpVersionInputExt, Protocol, ProtocolInputExt,
    TargetHttpVersionInputExt,
    client::{
        ConnectionError, ConnectionErrorKind, ConnectorService, EstablishedClientConnection,
        EstablishedProxyRoute, ProxyDialRequest, ProxyDialer, ProxyRoute,
    },
    http::TargetHttpVersion,
    stream::DefaultExtensionsTransfer,
};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::fmt::Debug;
use std::{marker::PhantomData, ops, sync::Arc};

/// A connector which establishes a tunnel over an HTTP proxy with CONNECT.
///
/// A proxy is required: a request without a proxied [`ProxyRoute`] fails. Pair it with
/// [`MaybeProxiedConnector`] to connect directly instead when no proxy is requested.
///
/// The inner service dials the HTTP connection to the proxy, such as a [`ProxyDialer`]
/// over the connector towards proxies, and CONNECT is exchanged over it. The version
/// spoken is the one on the [`ProxyAddress`], or the one negotiated when it names none,
/// and TLS to the proxy is the connector towards proxies' business.
///
/// `B` is the body type of the connections towards the proxy: the CONNECT request carries
/// its empty [`Default`] value.
///
/// [`MaybeProxiedConnector`]: rama_net::client::MaybeProxiedConnector
/// [`ProxyDialer`]: rama_net::client::ProxyDialer
/// [`ProxyAddress`]: rama_net::address::ProxyAddress
#[derive(ExtensionsRef)]
pub struct HttpConnectProxyConnector<S, B = ProxyRequestBody<Body>> {
    inner: S,
    headers: Option<HeaderMap>,
    extensions_transfer: SharedExtensionsTransfer,
    _phantom: PhantomData<fn() -> B>,
}

impl<S: Debug, B> Debug for HttpConnectProxyConnector<S, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConnectProxyConnector")
            .field("inner", &self.inner)
            .field("headers", &self.headers)
            .finish()
    }
}

impl<S: Clone, B> Clone for HttpConnectProxyConnector<S, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            headers: self.headers.clone(),
            extensions_transfer: self.extensions_transfer.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S, B> HttpConnectProxyConnector<ProxyDialer<S>, B> {
    /// Creates a new [`HttpConnectProxyConnector`] over the given connector towards the proxy.
    pub fn new(inner: S) -> Self {
        Self::from_dialer(ProxyDialer::new(inner))
    }
}

impl<S, B> HttpConnectProxyConnector<S, B> {
    /// Creates a new [`HttpConnectProxyConnector`] over the connections to the proxy that
    /// `dialer` dials, see [`ProxyDialer`].
    pub fn from_dialer(dialer: S) -> Self {
        Self {
            inner: dialer,
            headers: None,
            extensions_transfer: DefaultExtensionsTransfer::new().into_shared(),
            _phantom: PhantomData,
        }
    }

    generate_set_and_with! {
        /// Set a header on every CONNECT request this connector sends.
        ///
        /// A name set more than once keeps the last value.
        pub fn custom_header(mut self, name: impl IntoHeaderName, value: HeaderValue) -> Self {
            self.headers.get_or_insert_default().append(name, value);
            self
        }
    }

    generate_set_and_with! {
        /// Set what a CONNECT tunnel keeps from the proxy connection it is
        /// nested on.
        ///
        /// Defaults to [`DefaultExtensionsTransfer`]. Chain transfers with
        /// [`ExtensionsTransfer::and`] to also carry your own connection-scoped
        /// extension types across the tunnel.
        pub fn extensions_transfer(mut self, transfer: impl ExtensionsTransfer) -> Self {
            self.extensions_transfer = transfer.into_shared();
            self
        }
    }

    define_inner_service_accessors!();
}

impl<S, B, Input> Service<Input> for HttpConnectProxyConnector<S, B>
where
    S: ConnectorService<
            ProxyDialRequest,
            Connection: Service<Request<B>, Output = Response, Error: Into<BoxError>> + 'static,
        >,
    B: Default + Send + 'static,
    Input: ConnectorTargetInputExt
        + ProtocolInputExt
        + HttpVersionInputExt
        + TargetHttpVersionInputExt
        + Send
        + 'static,
{
    type Output = EstablishedClientConnection<Upgraded, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let proxy = match input.extensions().get_ref::<ProxyRoute>() {
            Some(ProxyRoute::Proxy(proxy)) => proxy.clone(),
            None | Some(ProxyRoute::Direct) => {
                return Err(ConnectionError::local(
                    BoxError::from_static_str(
                        "http proxy connector: no proxied route is requested",
                    ),
                    ConnectionErrorKind::InvalidInput,
                ));
            }
        };

        if !proxy.protocol.is_http() {
            return Err(ConnectionError::local(
                BoxError::from_static_str("http proxy connector can only serve http protocol"),
                ConnectionErrorKind::InvalidInput,
            )
            .context_debug_field("protocol", proxy.protocol.clone()));
        }

        let target = input.connector_target().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("http proxy connector: destination missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;

        let requested_http_version = resolve_input_target_http_version(&input);
        let app_protocol = input.target_protocol().cloned();
        let app_is_http = app_protocol.as_ref().is_some_and(Protocol::is_http_based);
        let app_is_plaintext_http = app_protocol
            .as_ref()
            .is_some_and(|protocol| protocol.is_http_based() && !protocol.is_secure());
        if app_is_http {
            match requested_http_version {
                None
                | Some(Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2) => {
                }
                Some(Version::HTTP_3) => {
                    return Err(ConnectionError::local(
                        BoxError::from_static_str(
                            "http proxy connector: HTTP/3 tunneling requires CONNECT-UDP",
                        ),
                        ConnectionErrorKind::InvalidInput,
                    ));
                }
            }
        }

        let conn = self
            .inner
            .connect(ProxyDialRequest {
                proxy: proxy.clone(),
                origin: input.extensions().clone(),
            })
            .await?
            .conn;
        let proxy_version = conn
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .map(|version| version.0)
            .unwrap_or(Version::HTTP_11);

        let mut request = connect_request(target, proxy.credential.as_ref(), proxy_version)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("http proxy connector: build CONNECT request")
            })?;
        if let Some(headers) = &self.headers {
            for (name, value) in headers {
                if !is_managed_proxy_connect_request_header(name) {
                    request.headers_mut().insert(name, value.clone());
                }
            }
        }
        let response = conn
            .serve(request)
            .await
            .map_err(|error| ConnectionError::from(HttpProxyError::Transport(error.into())))
            .map_err(|error| error.context("http proxy CONNECT exchange"))?;
        let (headers, tunnel) = upgrade_connect_response(response)
            .await
            .map_err(ConnectionError::from)
            .map_err(|error| error.context("http proxy handshake"))?;
        // The tunnel holds the connection to the proxy, so its pool counts it until the end.
        let mut tunnel = tunnel.with_guard(conn);
        let tunnel_extensions = tunnel
            .extensions()
            .fork_connection(&self.extensions_transfer);
        tunnel.set_extensions(tunnel_extensions);

        tracing::trace!(
            server.address = %proxy.address.host,
            server.port = proxy.address.port,
            "http proxy connector: tunnel established",
        );

        let extensions = tunnel.extensions();
        extensions.insert(EstablishedProxyRoute::Tunnel(proxy));
        extensions.insert(HttpProxyConnectResponseHeaders::new(headers));
        // A plaintext origin has no ALPN to select its wire version with, and the
        // tunnel inherits none from the connection to the proxy.
        if app_is_plaintext_http {
            extensions.insert(TargetHttpVersion(
                requested_http_version.unwrap_or(Version::HTTP_11),
            ));
        }

        Ok(EstablishedClientConnection {
            input,
            conn: tunnel,
        })
    }
}

#[derive(Clone, Extension)]
#[extension(tags(http, proxy))]
/// Extension added to the [`Extensions`](rama_core::extensions::Extensions) by
/// [`HttpConnectProxyConnector`] to record the
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::HttpConnectorLayer;
    use crate::client::conn::http_connect;
    use crate::client::proxy::{HttpTunnelRoute, forwarding_proxy};
    use crate::server::HttpServer;
    use rama_core::{
        Layer,
        extensions::Extensions,
        futures::{Stream, stream},
        graceful::WeakScope,
        io::AbortIo,
        layer::MapOutputLayer,
        service::service_fn,
    };
    use rama_http::io::upgrade::handle_upgrade;
    use rama_http_types::StatusCode;
    use rama_http_types::{
        Method,
        header::{CONTENT_LENGTH, HOST, PROXY_AUTHORIZATION, TRANSFER_ENCODING},
        proxy::PlaintextHttpProxyMode,
    };
    use rama_net::client::ConnectionErrorDomain;
    #[cfg(feature = "tls")]
    use rama_net::tls::{ApplicationProtocol, TlsAlpn};
    use rama_net::{
        Protocol,
        address::{Domain, HostWithPort, ProxyAddress, ProxyProtocol},
        client::{
            AddressCandidates, ConnectRequest, ConnectorService, ConnectorTarget,
            ConnectorTargetStream, MaybeProxied, MaybeProxiedConnector, PlaintextProxyOnly,
            ProxiedRoute, ProxyRoute, ProxyRoutes, ProxyRoutesConnector, ProxySelector as _,
            pool::{ConnectionReuse, ConnectionReusePolicy, ReuseKey},
        },
        http::{FallbackHttpVersion, HttpRequestVersion},
        test_utils::client::{MockConnectorService, MockSocket},
    };
    use rama_tcp::client::service::TcpConnector;
    #[cfg(feature = "tls")]
    use rama_tls::client::NegotiatedTlsParameters;
    use std::{
        convert::Infallible,
        net::{IpAddr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[derive(Debug, Clone, Extension)]
    #[extension(tags(http))]
    struct ConnMarker(u32);

    #[derive(Debug)]
    struct FixedProxyPolicy;

    impl ConnectionReusePolicy for FixedProxyPolicy {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }

        fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
    #[extension(scope(connection))]
    struct ProxyLegFact(u8);

    #[cfg(feature = "tls")]
    fn negotiated_tls(
        application_layer_protocol: Option<ApplicationProtocol>,
    ) -> NegotiatedTlsParameters {
        NegotiatedTlsParameters {
            protocol_version: rama_tls::ProtocolVersion::TLSv1_3,
            application_layer_protocol,
            peer_certificate_chain: None,
            server_name: None,
            resumed: None,
            algorithms: Default::default(),
            server_hello: None,
        }
    }

    fn never_forwards() -> impl ConnectorService<ConnectRequest, Connection = MockSocket> {
        service_fn(async |_: ConnectRequest| {
            Err::<EstablishedClientConnection<MockSocket, ConnectRequest>, _>(
                ConnectionError::local(
                    BoxError::from_static_str("a tunneled route must not be forwarded"),
                    ConnectionErrorKind::InvalidInput,
                ),
            )
        })
    }

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

    fn mock_connect_proxy(
        fact: Option<ProxyLegFact>,
    ) -> impl ConnectorService<
        ConnectRequest,
        Connection: Service<Request<Body>, Output = Response, Error: Into<BoxError>>
                        + ExtensionsRef,
    > {
        let transport = MapOutputLayer::new(
            move |established: EstablishedClientConnection<MockSocket, ConnectRequest>| {
                if let Some(fact) = fact {
                    established.conn.extensions().insert(fact);
                }
                established
                    .conn
                    .extensions()
                    .insert(ConnectionReuse::new(FixedProxyPolicy));
                established
            },
        )
        .into_layer(MockConnectorService::new(|| {
            HttpServer::auto(WeakScope::detached()).service(service_fn(async |request: Request| {
                assert_eq!(request.method(), Method::CONNECT);
                let tunnel = handle_upgrade(&request);
                tokio::spawn(async move {
                    drop(tunnel.await);
                });
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
        }));
        HttpConnectorLayer::default().into_layer(transport)
    }

    fn connect_request() -> ConnectRequest {
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions.insert(ProxyRoute::Proxy(
            "http://proxy.example:8080".parse::<ProxyAddress>().unwrap(),
        ));
        input
    }

    #[tokio::test]
    async fn a_custom_transfer_carries_a_connection_scoped_type_across_connect() {
        let carry_fact = |outer: &Extensions, nested: &Extensions| {
            if let Some(fact) = outer.get_ref::<ProxyLegFact>() {
                nested.insert(*fact);
            }
        };
        let connector =
            HttpConnectProxyConnector::<_, Body>::new(mock_connect_proxy(Some(ProxyLegFact(7))))
                .with_extensions_transfer(DefaultExtensionsTransfer::new().and(carry_fact));

        let EstablishedClientConnection { conn, .. } = connector
            .connect(connect_request())
            .await
            .expect("proxy CONNECT handshake succeeds");

        assert_eq!(
            conn.extensions().get_ref::<ProxyLegFact>(),
            Some(&ProxyLegFact(7)),
            "the configured transfer carries it onto the tunnel"
        );
        let reuse = conn
            .extensions()
            .get_ref::<ConnectionReuse>()
            .expect("the default transfer still runs");
        assert!(!reuse.is_complete());
    }

    #[tokio::test]
    async fn without_a_transfer_a_connection_scoped_type_stops_at_the_tunnel() {
        let connector =
            HttpConnectProxyConnector::<_, Body>::new(mock_connect_proxy(Some(ProxyLegFact(7))));

        let EstablishedClientConnection { conn, .. } = connector
            .connect(connect_request())
            .await
            .expect("proxy CONNECT handshake succeeds");

        assert_eq!(conn.extensions().get_ref::<ProxyLegFact>(), None);
    }

    #[tokio::test]
    async fn connect_custom_headers_cannot_override_managed_fields() {
        let proxy = HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
            HttpServer::auto(WeakScope::detached()).service(service_fn(async |request: Request| {
                assert_eq!(request.method(), Method::CONNECT);
                let headers = request.headers();
                assert_eq!(headers[HOST], "example.com:80");
                assert_eq!(headers[PROXY_AUTHORIZATION], "Basic dXBzdHJlYW06c2VjcmV0");
                assert!(!headers.contains_key(CONTENT_LENGTH));
                assert!(!headers.contains_key(TRANSFER_ENCODING));
                assert_eq!(headers["x-kept"], "yes");
                let tunnel = handle_upgrade(&request);
                tokio::spawn(async move {
                    drop(tunnel.await);
                });
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
        }));
        let connector = HttpConnectProxyConnector::<_, Body>::new(proxy)
            .with_custom_header(HOST, HeaderValue::from_static("evil.example"))
            .with_custom_header(
                PROXY_AUTHORIZATION,
                HeaderValue::from_static("Basic ZXZpbA=="),
            )
            .with_custom_header(CONTENT_LENGTH, HeaderValue::from_static("999"))
            .with_custom_header(TRANSFER_ENCODING, HeaderValue::from_static("chunked"))
            .with_custom_header("x-kept", HeaderValue::from_static("yes"));
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions.insert(ProxyRoute::Proxy(
            "http://upstream:secret@proxy.example:8080"
                .parse::<ProxyAddress>()
                .unwrap(),
        ));

        connector
            .connect(input)
            .await
            .expect("proxy CONNECT handshake succeeds");
    }

    #[tokio::test]
    async fn a_repeated_custom_connect_header_is_sent_once() {
        let proxy = HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
            HttpServer::auto(WeakScope::detached()).service(service_fn(async |request: Request| {
                assert_eq!(
                    request
                        .headers()
                        .get_all("x-route")
                        .into_iter()
                        .collect::<Vec<_>>(),
                    ["second"],
                );
                let tunnel = handle_upgrade(&request);
                tokio::spawn(async move {
                    drop(tunnel.await);
                });
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
        }));
        let connector = HttpConnectProxyConnector::<_, Body>::new(proxy)
            .with_custom_header("x-route", HeaderValue::from_static("first"))
            .with_custom_header("x-route", HeaderValue::from_static("second"));

        connector
            .connect(proxied_https("http://proxy.example:8080"))
            .await
            .expect("proxy CONNECT handshake succeeds");
    }

    fn proxied_https(proxy: &str) -> ConnectRequest {
        let input = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions
            .insert(ProxyRoute::Proxy(proxy.parse::<ProxyAddress>().unwrap()));
        input
    }

    #[tokio::test]
    async fn connect_statuses_establish_tunnels_only_for_success() {
        for proxy in ["http://proxy.example:8080", "h2c://proxy.example:8080"] {
            for status in [
                StatusCode::OK,
                StatusCode::CREATED,
                StatusCode::NO_CONTENT,
                StatusCode::from_u16(299).unwrap(),
            ] {
                let connection = HttpConnectorLayer::default().into_layer(
                    MockConnectorService::new(move || {
                        HttpServer::auto(WeakScope::detached()).service(service_fn(
                            move |request: Request| async move {
                                let tunnel = handle_upgrade(&request);
                                tokio::spawn(async move {
                                    drop(tunnel.await);
                                });
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(status)
                                        .body(Body::empty())
                                        .unwrap(),
                                )
                            },
                        ))
                    }),
                );
                let connector = HttpConnectProxyConnector::<_, Body>::new(connection);

                tokio::time::timeout(
                    Duration::from_secs(2),
                    connector.connect(proxied_https(proxy)),
                )
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
            let connection = HttpConnectorLayer::default().into_layer(MockConnectorService::new(
                HttpServer::auto(WeakScope::detached()).service(service_fn(
                    move |_request: Request| async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Body::from("not a tunnel"))
                                .unwrap(),
                        )
                    },
                )),
            ));
            let connector = HttpConnectProxyConnector::<_, Body>::new(connection);

            let error = tokio::time::timeout(
                Duration::from_secs(2),
                connector.connect(proxied_https("http://proxy.example:8080")),
            )
            .await
            .expect("CONNECT rejection must not wait for an upgraded tunnel")
            .expect_err("a rejected CONNECT must not establish a tunnel");
            assert_eq!(error.domain(), expected_domain, "status: {status}");
            assert_eq!(error.kind(), expected_kind, "status: {status}");
        }
    }

    #[tokio::test]
    async fn connect_protocol_errors_never_fall_back_to_direct() {
        for (version, proxy) in [
            (Version::HTTP_11, "http://proxy.example:8080"),
            (Version::HTTP_2, "h2c://proxy.example:8080"),
        ] {
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
                            assert_eq!(req.method(), Method::CONNECT);
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
            let direct = MockConnectorService::new({
                let dials = dials.clone();
                move || {
                    dials.fetch_add(1, Ordering::Relaxed);
                    service_fn(|_: MockSocket| async { Ok::<_, Infallible>(()) })
                }
            });
            let connector = ProxyRoutesConnector::new(MaybeProxiedConnector::new(
                direct,
                HttpConnectProxyConnector::<_, Body>::new(
                    HttpConnectorLayer::default().into_layer(transport),
                ),
                ProxiedRoute::new(),
            ));
            let input = ConnectRequest::new(HostWithPort::example_domain_https())
                .with_application_protocol(Protocol::HTTPS);
            input.extensions.insert(ProxyRoutes::new([
                ProxyRoute::Proxy(proxy.parse().unwrap()),
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
    async fn connect_tunnel_keeps_bytes_sent_along_with_the_proxy_response() {
        let connection =
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
                service_fn(move |mut socket: MockSocket| async move {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(socket.read_u8().await.unwrap());
                    }
                    assert!(request.starts_with(b"CONNECT "));
                    socket
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nserver-first")
                        .await
                        .unwrap();
                    let mut rest = Vec::new();
                    _ = socket.read_to_end(&mut rest).await;
                    Ok::<_, Infallible>(())
                })
            }));
        let connector = HttpConnectProxyConnector::<_, Body>::new(connection);

        let mut established = tokio::time::timeout(
            Duration::from_secs(2),
            connector.connect(proxied_https("http://proxy.example:8080")),
        )
        .await
        .expect("a complete response head establishes the tunnel without waiting for more")
        .expect("200 establishes the tunnel");
        let mut first = [0u8; 12];
        established.conn.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"server-first");
    }

    #[tokio::test]
    async fn a_non_http_proxy_is_refused_locally() {
        let connector = HttpConnectProxyConnector::<_, Body>::new(mock_connect_proxy(None));
        let error = connector
            .connect(proxied_https("socks5://proxy.example:1080"))
            .await
            .unwrap_err();
        assert_eq!(
            (error.domain(), error.kind()),
            (
                ConnectionErrorDomain::Local,
                ConnectionErrorKind::InvalidInput
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn https_proxy_requires_positive_tls_evidence() {
        let connection = HttpConnectorLayer::default().into_layer(PlaintextProxyOnly::new(
            MockConnectorService::new(service_fn(async |_socket: MockSocket| {
                Ok::<_, Infallible>(())
            })),
        ));
        let connector = HttpConnectProxyConnector::<_, Body>::new(connection);

        let error = connector
            .connect(proxied_https("https://proxy.example:8443"))
            .await
            .expect_err("an HTTPS proxy cannot silently use a plaintext connection");
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
    }

    #[tokio::test]
    async fn the_connect_tunnel_aborts_the_upgraded_transport() {
        let aborted = Arc::new(AtomicBool::new(false));
        let transport = MapOutputLayer::new({
            let aborted = aborted.clone();
            move |established: EstablishedClientConnection<MockSocket, ConnectRequest>| {
                let aborted = aborted.clone();
                established.conn.extensions().insert(AbortIo::new(move || {
                    aborted.store(true, Ordering::Release);
                }));
                established
            }
        })
        .into_layer(MockConnectorService::new(|| {
            HttpServer::auto(WeakScope::detached()).service(service_fn(async |request: Request| {
                let tunnel = handle_upgrade(&request);
                tokio::spawn(async move {
                    drop(tunnel.await);
                });
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
        }));
        let connector = HttpConnectProxyConnector::<_, Body>::new(
            HttpConnectorLayer::default().into_layer(transport),
        );

        let input = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions.insert(ProxyRoute::Proxy(
            "http://proxy.example:8080".parse::<ProxyAddress>().unwrap(),
        ));
        let EstablishedClientConnection { conn, .. } = connector
            .connect(input)
            .await
            .expect("proxy CONNECT handshake succeeds");

        conn.extensions()
            .get_arc::<AbortIo>()
            .expect("the tunnel fronts the upgraded transport")
            .abort();
        assert!(aborted.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn connect_closed_proxy_may_fall_back_to_direct() {
        for (version, proxy) in [
            (Version::HTTP_11, "http://proxy.example:8080"),
            (Version::HTTP_2, "h2c://proxy.example:8080"),
        ] {
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
                            assert_eq!(req.method(), Method::CONNECT);
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
            let direct = MockConnectorService::new({
                let dials = dials.clone();
                move || {
                    dials.fetch_add(1, Ordering::Relaxed);
                    service_fn(|_: MockSocket| async { Ok::<_, Infallible>(()) })
                }
            });
            let connector = ProxyRoutesConnector::new(MaybeProxiedConnector::new(
                direct,
                HttpConnectProxyConnector::<_, Body>::new(
                    HttpConnectorLayer::default().into_layer(transport),
                ),
                ProxiedRoute::new(),
            ));
            let input = ConnectRequest::new(HostWithPort::example_domain_https())
                .with_application_protocol(Protocol::HTTPS);
            input.extensions.insert(ProxyRoutes::new([
                ProxyRoute::Proxy(proxy.parse().unwrap()),
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
    async fn established_http_route_distinguishes_forward_and_tunnel_for_the_same_proxy() {
        let proxy = "http://alice:private-password@proxy.example:8080"
            .parse::<ProxyAddress>()
            .unwrap();
        let connector = HttpConnectProxyConnector::<_, Body>::new(
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
                HttpServer::auto(WeakScope::detached()).service(service_fn(
                    async |request: Request| {
                        assert_eq!(request.method(), Method::CONNECT);
                        let tunnel = handle_upgrade(&request);
                        tokio::spawn(async move {
                            drop(tunnel.await);
                        });
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    },
                ))
            })),
        );
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(ProxyRoute::Proxy(proxy.clone()));
        input.extensions.insert(PlaintextHttpProxyMode::Tunnel);

        let established = connector.serve(input).await.unwrap();
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<EstablishedProxyRoute>(),
            Some(&EstablishedProxyRoute::Tunnel(proxy.clone())),
        );
        assert!(!established.conn.extensions().contains::<ProxyRoute>());
        assert_eq!(
            established.input.extensions.get_ref::<ProxyRoute>(),
            Some(&ProxyRoute::Proxy(proxy)),
        );
    }

    #[tokio::test]
    async fn selected_service_is_tunneled_without_changing_the_origin() {
        for protocol in [Protocol::HTTP, Protocol::HTTPS] {
            let origin = if protocol.is_secure() {
                HostWithPort::example_domain_https()
            } else {
                HostWithPort::example_domain_http()
            };
            let destination = "alternative.example:8443";
            let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
            let connector = MaybeProxiedConnector::new(
                never_forwards(),
                HttpConnectProxyConnector::<_, Body>::new(
                    HttpConnectorLayer::default().into_layer(MockConnectorService::new(
                        move || {
                            HttpServer::auto(WeakScope::detached()).service(service_fn(
                                move |request: Request| async move {
                                    assert_eq!(request.method(), Method::CONNECT);
                                    assert_eq!(request.uri().to_string(), destination);
                                    assert_eq!(request.headers()[HOST], destination);
                                    let tunnel = handle_upgrade(&request);
                                    tokio::spawn(async move {
                                        drop(tunnel.await);
                                    });
                                    Ok::<_, Infallible>(Response::new(Body::empty()))
                                },
                            ))
                        },
                    )),
                ),
                HttpTunnelRoute::new(),
            );
            let input =
                ConnectRequest::new(origin.clone()).with_application_protocol(protocol.clone());
            input.extensions.insert(ProxyRoute::Proxy(proxy.clone()));
            input.extensions.insert(PlaintextHttpProxyMode::Forward);
            input
                .extensions
                .insert(ConnectorTarget(destination.parse().unwrap()));
            assert!(forwarding_proxy(&input).is_none());
            assert!(HttpTunnelRoute::new().is_proxied(&input));

            let established = connector.serve(input).await.unwrap();
            assert!(
                matches!(established.conn, MaybeProxied::Proxied { .. }),
                "an explicitly selected endpoint is tunneled, never forwarded"
            );
            assert_eq!(established.input.target_protocol(), Some(&protocol));
            assert_eq!(established.input.authority, origin);
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<EstablishedProxyRoute>(),
                Some(&EstablishedProxyRoute::Tunnel(proxy)),
            );
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
        let connector = HttpConnectProxyConnector::<_, Body>::new(
            HttpConnectorLayer::default().into_layer(transport),
        );
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(ConnectorTargetStream::new(
            input.authority.clone(),
            OneCandidate {
                domain: Domain::example(),
                ip_addr: origin_ip,
            },
        ));
        input.extensions.insert(ProxyRoute::Proxy(ProxyAddress {
            address: proxy_addr.into(),
            credential: None,
            protocol: ProxyProtocol::HTTP,
        }));

        let error = connector.serve(input).await.unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(recorded.iter().copied().collect::<Vec<_>>(), [proxy_addr]);
    }

    #[tokio::test]
    async fn plaintext_non_http_protocol_uses_connect() {
        for protocol in [Protocol::ICAP, Protocol::from_static("custom")] {
            let connector = MaybeProxiedConnector::new(
                never_forwards(),
                HttpConnectProxyConnector::<_, Body>::new(
                    HttpConnectorLayer::default().into_layer(MockConnectorService::new(
                        move || {
                            HttpServer::auto(WeakScope::detached()).service(service_fn(
                                async move |request: Request| {
                                    assert_eq!(request.method(), Method::CONNECT);
                                    assert!(
                                        !request
                                            .extensions()
                                            .contains::<rama_http_types::proto::ext::Protocol>()
                                    );
                                    let tunnel = handle_upgrade(&request);
                                    tokio::spawn(async move {
                                        drop(tunnel.await);
                                    });
                                    Ok::<_, Infallible>(
                                        Response::builder()
                                            .status(StatusCode::CREATED)
                                            .body(Body::empty())
                                            .unwrap(),
                                    )
                                },
                            ))
                        },
                    )),
                ),
                HttpTunnelRoute::new(),
            );
            let request = ConnectRequest::new(HostWithPort::example_domain_http())
                .with_application_protocol(protocol.clone());
            request
                .extensions
                .insert(rama_http_types::proto::ext::Protocol::from_static(
                    "websocket",
                ));
            request.extensions.insert(ProxyRoute::Proxy(
                "http://proxy.example:8080".parse().unwrap(),
            ));
            request.extensions.insert(PlaintextHttpProxyMode::Forward);
            assert!(forwarding_proxy(&request).is_none(), "{protocol}");
            assert!(HttpTunnelRoute::new().is_proxied(&request), "{protocol}");

            let established = connector
                .serve(request)
                .await
                .expect("plaintext non-HTTP application uses CONNECT");
            assert!(
                matches!(established.conn, MaybeProxied::Proxied { .. }),
                "{protocol}"
            );
            assert!(matches!(
                established
                    .conn
                    .extensions()
                    .get_ref::<EstablishedProxyRoute>(),
                Some(EstablishedProxyRoute::Tunnel(_)),
            ));
        }
    }

    #[tokio::test]
    async fn plaintext_http_tunnel_restores_origin_version_after_connect() {
        let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        let connector = HttpConnectProxyConnector::<_, Body>::new(
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
                HttpServer::auto(WeakScope::detached()).service(service_fn(
                    async move |request: Request| {
                        assert_eq!(request.method(), Method::CONNECT);
                        assert_eq!(request.version(), Version::HTTP_11);
                        let tunnel = handle_upgrade(&request);
                        tokio::spawn(async move {
                            drop(tunnel.await);
                        });
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    },
                ))
            })),
        );
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(HttpRequestVersion(Version::HTTP_2));
        input.extensions.insert(PlaintextHttpProxyMode::Tunnel);
        input.extensions.insert(ProxyRoute::Proxy(proxy.clone()));

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
            Some(&EstablishedProxyRoute::Tunnel(proxy))
        );
    }

    #[tokio::test]
    async fn plaintext_http_tunnel_defaults_missing_origin_version() {
        let connector = HttpConnectProxyConnector::<_, Body>::new(
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
                HttpServer::auto(WeakScope::detached()).service(service_fn(
                    async move |request: Request| {
                        assert_eq!(request.method(), Method::CONNECT);
                        assert_eq!(request.version(), Version::HTTP_2);
                        let tunnel = handle_upgrade(&request);
                        tokio::spawn(async move {
                            drop(tunnel.await);
                        });
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    },
                ))
            })),
        );
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(PlaintextHttpProxyMode::Tunnel);
        input.extensions.insert(ProxyRoute::Proxy(
            "h2c://proxy.example:8080".parse().unwrap(),
        ));

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
        let connector = HttpConnectProxyConnector::<_, Body>::new(
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
                HttpServer::auto(WeakScope::detached()).service(service_fn(
                    async move |request: Request| {
                        assert_eq!(request.method(), Method::CONNECT);
                        let tunnel = handle_upgrade(&request);
                        tokio::spawn(async move {
                            drop(tunnel.await);
                        });
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    },
                ))
            })),
        );
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::from_static("custom"));
        input.extensions.insert(HttpRequestVersion(Version::HTTP_2));
        input.extensions.insert(ProxyRoute::Proxy(
            "http://proxy.example:8080".parse().unwrap(),
        ));

        let established = connector.serve(input).await.unwrap();
        assert!(
            established
                .conn
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .is_none()
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
            let connector = HttpConnectProxyConnector::<_, Body>::new(
                HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
                    observed_dials.fetch_add(1, Ordering::Relaxed);
                    service_fn(async |_socket: MockSocket| Ok::<_, Infallible>(()))
                })),
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
                input.extensions.insert(HttpRequestVersion(requested));
            }
            input.extensions.insert(ProxyRoute::Proxy(
                "http://proxy.example:8080".parse().unwrap(),
            ));

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
        let transport = MockConnectorService::new(|| {
            HttpServer::auto(WeakScope::detached()).service(service_fn(async |request: Request| {
                assert_eq!(request.method(), Method::CONNECT);
                assert_eq!(request.version(), Version::HTTP_2);
                let tunnel = handle_upgrade(&request);
                tokio::spawn(async move {
                    drop(tunnel.await);
                });
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
        });
        let transport = service_fn(move |input: ConnectRequest| {
            let transport = transport.clone();
            async move {
                assert!(!input.extensions.contains::<TargetHttpVersion>());
                assert!(!input.extensions.contains::<TlsAlpn>());
                let established = transport.serve(input).await?;
                established
                    .conn
                    .extensions()
                    .insert(negotiated_tls(Some(ApplicationProtocol::HTTP_2)));
                established
                    .conn
                    .extensions()
                    .insert(TargetHttpVersion(Version::HTTP_2));
                Ok::<_, Infallible>(established)
            }
        });
        let connector = HttpConnectProxyConnector::<_, Body>::new(
            HttpConnectorLayer::default().into_layer(transport),
        );
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(HttpRequestVersion(Version::HTTP_11));
        input.extensions.insert(ProxyRoute::Proxy(
            "https://proxy.example:8443".parse().unwrap(),
        ));

        connector.serve(input).await.unwrap();
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn plaintext_proxy_ignores_unrelated_tls_negotiation_metadata() {
        let transport = MapOutputLayer::new(
            |established: EstablishedClientConnection<MockSocket, ConnectRequest>| {
                established
                    .conn
                    .extensions()
                    .insert(negotiated_tls(Some(ApplicationProtocol::HTTP_2)));
                established
            },
        )
        .into_layer(MockConnectorService::new(|| {
            HttpServer::auto(WeakScope::detached()).service(service_fn(async |request: Request| {
                assert_eq!(request.method(), Method::CONNECT);
                assert_eq!(request.version(), Version::HTTP_11);
                let tunnel = handle_upgrade(&request);
                tokio::spawn(async move {
                    drop(tunnel.await);
                });
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
        }));
        let connector = HttpConnectProxyConnector::<_, Body>::new(
            HttpConnectorLayer::default().into_layer(transport),
        );
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoute::Proxy(
            "http://proxy.example:8080".parse().unwrap(),
        ));

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn connection_extensions_preserved_across_proxy_connect_upgrade() {
        let transport = MapOutputLayer::new(
            |established: EstablishedClientConnection<MockSocket, ConnectRequest>| {
                established.conn.extensions().insert(ConnMarker(42));
                established
                    .conn
                    .extensions()
                    .insert(ConnectionReuse::new(FixedProxyPolicy));
                established
            },
        )
        .into_layer(MockConnectorService::new(|| {
            HttpServer::auto(WeakScope::detached()).service(service_fn(async |request: Request| {
                let tunnel = handle_upgrade(&request);
                tokio::spawn(async move {
                    drop(tunnel.await);
                });
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
        }));
        let proxy_connector = HttpConnectProxyConnector::<_, Body>::new(
            HttpConnectorLayer::default().into_layer(transport),
        );

        let request = Request::builder()
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ProxyRoute::Proxy(
            "http://proxy.example:8080".parse().unwrap(),
        ));

        let EstablishedClientConnection { conn, input } = proxy_connector
            .connect(request)
            .await
            .expect("proxy CONNECT handshake succeeds");

        let marker = conn
            .extensions()
            .get_ref::<ConnMarker>()
            .expect("ConnMarker set on the pre-CONNECT connection must survive the upgrade");
        assert_eq!(marker.0, 42);
        let reuse = conn.extensions().get_ref::<ConnectionReuse>().unwrap();
        assert!(reuse.is_reusable());
        assert!(
            !reuse.is_complete(),
            "proxy policy cannot classify the origin"
        );

        let established = http_connect::<_, _, Body>(conn, input, WeakScope::detached())
            .await
            .expect("HTTP connector accepts the custom transport");
        assert!(
            !established
                .conn
                .extensions()
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .is_reusable(),
            "an unclassified secure origin must not borrow the proxy's complete policy"
        );
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

        let connector = ProxyRoutesConnector::new(MaybeProxiedConnector::new(
            TcpConnector::new(),
            HttpConnectProxyConnector::<_, Body>::new(
                HttpConnectorLayer::default().into_layer(TcpConnector::new()),
            ),
            ProxiedRoute::new(),
        ));
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
