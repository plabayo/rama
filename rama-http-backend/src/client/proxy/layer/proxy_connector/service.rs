use rama_core::error::BoxErrorExt as _;

use super::{connect_request, upgrade_connect_response};
use crate::client::proxy::verify_proxy_tls;
use rama_core::{
    Service,
    error::BoxError,
    extensions::{
        Extension, ExtensionsRef, NestedConnectionTransfer, SharedNestedConnectionTransfer,
    },
    telemetry::tracing,
};
use rama_http::{
    HeaderMap, HeaderValue,
    header::{IntoHeaderName, proxy_connect::is_managed_proxy_connect_request_header},
    io::upgrade::Upgraded,
};
use rama_http_types::{Body, Request, Response, Version};
use rama_net::{
    ConnectorTargetInputExt, HttpVersionInputExt, Protocol, ProtocolInputExt,
    TargetHttpVersionInputExt,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService,
        EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute, connect_to_proxy,
        proxy_http_version,
    },
    http::TargetHttpVersion,
    stream::DefaultConnectionTransfer,
};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::{fmt, marker::PhantomData, ops, sync::Arc};

/// A connector which establishes a tunnel over an HTTP proxy with CONNECT.
///
/// A proxy is required: a request without a proxied [`ProxyRoute`] fails. Pair it with
/// [`MaybeProxiedConnector`] to connect directly instead when no proxy is requested.
///
/// The inner service is the connector towards the proxy: it receives its own
/// [`ConnectRequest`] addressed at the proxy and answers with an HTTP connection to it,
/// over which CONNECT is exchanged. The version spoken is the one on the
/// [`ProxyAddress`], or the one negotiated when it names none, and TLS to the proxy is the
/// inner connector's business.
///
/// `B` is the body type of the connections towards the proxy, in which the CONNECT request
/// is built: a client reaches its proxies with the body type it serves origins with.
///
/// [`MaybeProxiedConnector`]: rama_net::client::MaybeProxiedConnector
/// [`ProxyAddress`]: rama_net::address::ProxyAddress
#[derive(ExtensionsRef)]
pub struct HttpConnectProxyConnector<S, B = Body> {
    inner: S,
    headers: Option<HeaderMap>,
    nested_connection_transfer: SharedNestedConnectionTransfer,
    _phantom: PhantomData<fn() -> B>,
}

impl<S: fmt::Debug, B> fmt::Debug for HttpConnectProxyConnector<S, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            nested_connection_transfer: self.nested_connection_transfer.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S, B> HttpConnectProxyConnector<S, B> {
    /// Creates a new [`HttpConnectProxyConnector`] over the given connector towards the proxy.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            headers: None,
            nested_connection_transfer: DefaultConnectionTransfer.into_shared(),
            _phantom: PhantomData,
        }
    }

    generate_set_and_with! {
        /// Append a header to every CONNECT request this connector sends.
        pub fn custom_header(mut self, name: impl IntoHeaderName, value: HeaderValue) -> Self {
            self.headers.get_or_insert_default().append(name, value);
            self
        }
    }

    generate_set_and_with! {
        /// Set what a CONNECT tunnel keeps from the proxy connection it is
        /// nested on.
        ///
        /// Defaults to [`DefaultConnectionTransfer`]. Chain transfers with
        /// [`NestedConnectionTransfer::and`] to also carry your own connection-scoped
        /// extension types across the tunnel.
        pub fn nested_connection_transfer(mut self, transfer: impl NestedConnectionTransfer) -> Self {
            self.nested_connection_transfer = transfer.into_shared();
            self
        }
    }

    define_inner_service_accessors!();
}

impl<S, B, Input> Service<Input> for HttpConnectProxyConnector<S, B>
where
    S: ConnectorService<
            ConnectRequest,
            Connection: Service<Request<B>, Output = Response, Error: Into<BoxError>>
                            + ExtensionsRef
                            + 'static,
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
            return Err(ConnectionError::transport(
                BoxError::from_static_str("http proxy connector can only serve http protocol"),
                ConnectionErrorKind::Protocol,
            )
            .context_debug_field("protocol", proxy.protocol.clone()));
        }

        let target = input.connector_target().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("http proxy connector: destination missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;

        let requested_http_version = crate::client::conn::resolve_input_target_http_version(&input);
        let app_protocol = input.target_protocol().cloned();
        let app_is_http = app_protocol.as_ref().is_some_and(Protocol::is_http_based);
        let app_is_plaintext_http = app_protocol
            .as_ref()
            .is_some_and(|protocol| protocol.is_http_based() && !protocol.is_secure());
        if app_is_http && requested_http_version == Some(Version::HTTP_3) {
            return Err(ConnectionError::local(
                BoxError::from_static_str(
                    "http proxy connector: HTTP/3 tunneling requires CONNECT-UDP",
                ),
                ConnectionErrorKind::InvalidInput,
            ));
        }

        let conn = connect_to_proxy(&self.inner, &proxy, input.extensions()).await?;
        verify_proxy_tls(&proxy, conn.extensions())?;
        let proxy_version = proxy_http_version(&proxy, &conn);

        let mut request = connect_request(target, proxy.credential.as_ref(), proxy_version)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("http proxy connector: build CONNECT request")
            })?;
        if let Some(headers) = &self.headers {
            for (name, value) in headers {
                if !is_managed_proxy_connect_request_header(name) {
                    request.headers_mut().append(name, value.clone());
                }
            }
        }
        let response = conn
            .serve(request)
            .await
            .map_err(|error| {
                ConnectionError::transport(error.into(), ConnectionErrorKind::Unavailable)
            })
            .map_err(|error| error.context("http proxy CONNECT exchange"))?;
        let (headers, tunnel) = upgrade_connect_response(response)
            .await
            .map_err(ConnectionError::from)
            .map_err(|error| error.context("http proxy handshake"))?;
        // The tunnel holds the connection to the proxy, so its pool counts it until the end.
        let mut tunnel = tunnel.with_guard(conn);
        let tunnel_extensions = tunnel
            .extensions()
            .fork_nested_connection(&self.nested_connection_transfer);
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
        // tunnel inherits none from the proxy leg.
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

impl fmt::Debug for HttpProxyConnectResponseHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    use crate::server::HttpServer;
    use rama_core::{
        Layer, extensions::Extensions, graceful::WeakScope, io::AbortIo, layer::MapOutputLayer,
        service::service_fn,
    };
    use rama_http::io::upgrade::handle_upgrade;
    use rama_http_types::StatusCode;
    use rama_http_types::{
        Method,
        header::{CONTENT_LENGTH, HOST, PROXY_AUTHORIZATION, TRANSFER_ENCODING},
    };
    use rama_net::client::ConnectionErrorDomain;
    use rama_net::{
        Protocol,
        address::{HostWithPort, ProxyAddress},
        client::{
            ConnectRequest,
            pool::{ConnectionReuse, ConnectionReusePolicy, ReuseKey},
        },
        test_utils::client::{MockConnectorService, MockSocket},
    };
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
                .with_nested_connection_transfer(DefaultConnectionTransfer.and(carry_fact));

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
            let connection =
                HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
                    HttpServer::auto(WeakScope::detached()).service(service_fn(
                        move |_request: Request| async move {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Body::from("not a tunnel"))
                                    .unwrap(),
                            )
                        },
                    ))
                }));
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
    async fn https_proxy_requires_positive_tls_evidence() {
        let connection =
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
                service_fn(async |_socket: MockSocket| Ok::<_, Infallible>(()))
            }));
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
}
