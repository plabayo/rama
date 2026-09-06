//! HTTP connection pool: connection identity and connector assembly.

use std::{num::NonZeroUsize, time::Duration};

use rama_core::error::BoxError;
use rama_core::{Layer, extensions::ExtensionsRef};
use rama_http_types::{Version, conn::FallbackHttpVersion, proxy::PlaintextHttpProxyMode};
use rama_net::client::pool::{
    BasicConnId, BasicConnIdentifier, ConnID, MultiplexPool, MuxSelection, PooledConnector,
    ReqToConnID,
};
use rama_net::client::{ConnectRequest, ConnectorService, ProxyRoute};
use rama_net::{
    HttpVersionInputExt, ProtocolInputExt, TargetHttpVersionInputExt, transport::TransportProtocol,
};

use super::{BindBodyToConnLayer, BindBodyToConnector};

/// Default HTTP pooled connector assembled by
/// [`HttpPooledConnectorConfig::try_build_connector`].
pub type HttpPooledConnector<S> = BindBodyToConnector<
    PooledConnector<
        S,
        MultiplexPool<<S as ConnectorService<ConnectRequest>>::Connection, HttpConnId>,
        HttpConnIdentifier,
    >,
>;

/// HTTP connection-pool identifier derived from the network route, any version
/// requirement that constrains the physical connection, and whether plaintext
/// HTTP uses forward-proxy or CONNECT-tunnel semantics.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct HttpConnIdentifier;

impl HttpConnIdentifier {
    /// Create an HTTP connection-pool identifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Connection identity produced by [`HttpConnIdentifier`].
///
/// Besides physical route and HTTP-version requirements, this identity keeps
/// plaintext forward-proxy connections separate from plaintext CONNECT
/// tunnels. Those connections address the same proxy socket but use different
/// HTTP request semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpConnId {
    network: BasicConnId,
    required_version: Option<Version>,
    http_proxy_mode: Option<HttpProxyModeRequirement>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpProxyModeRequirement {
    Forward,
    Tunnel,
}

impl ConnID for HttpConnId {
    #[cfg(feature = "opentelemetry")]
    fn attributes(&self) -> impl Iterator<Item = rama_core::telemetry::opentelemetry::KeyValue> {
        self.network.attributes()
    }
}

impl ReqToConnID<ConnectRequest> for HttpConnIdentifier {
    type ID = HttpConnId;

    fn id(&self, input: &ConnectRequest) -> Result<Self::ID, BoxError> {
        let mut network = BasicConnIdentifier::new().id(input)?;
        if input
            .extensions()
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
            .is_some_and(|proxy| {
                proxy
                    .protocol
                    .as_ref()
                    .is_none_or(|protocol| protocol.is_http() || protocol.is_socks5())
            })
        {
            // Rama's supported HTTP(S) and SOCKS proxy connectors establish a
            // TCP connection to the proxy, irrespective of the origin's
            // logical transport.
            network.connector_transport_protocol = Some(TransportProtocol::Tcp);
        }

        Ok(HttpConnId {
            network,
            required_version: connection_version_requirement(input),
            http_proxy_mode: http_proxy_mode_requirement(input),
        })
    }
}

fn http_proxy_mode_requirement(input: &ConnectRequest) -> Option<HttpProxyModeRequirement> {
    let is_http_proxy = input
        .extensions()
        .get_ref::<ProxyRoute>()
        .and_then(ProxyRoute::proxy_address)
        .is_some_and(|proxy| {
            proxy
                .protocol
                .as_ref()
                .is_none_or(|protocol| protocol.is_http())
        });
    if !is_http_proxy {
        return None;
    }

    Some(
        if input
            .extensions()
            .get_ref::<PlaintextHttpProxyMode>()
            .copied()
            .unwrap_or_default()
            .should_forward(input.protocol())
        {
            HttpProxyModeRequirement::Forward
        } else {
            HttpProxyModeRequirement::Tunnel
        },
    )
}

fn connection_version_requirement(input: &ConnectRequest) -> Option<Version> {
    let plaintext_http = input
        .protocol()
        .is_some_and(|protocol| protocol.is_http_based() && !protocol.is_secure());
    let secure_forward_proxy = input
        .extensions()
        .get_ref::<PlaintextHttpProxyMode>()
        .copied()
        .unwrap_or_default()
        .should_forward(input.protocol())
        && input
            .extensions()
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
            .and_then(|proxy| proxy.protocol.as_ref())
            .is_some_and(|protocol| protocol.is_secure());

    // HTTPS forward-proxy wire versions come from proxy-side ALPN or an
    // explicit connector policy, never from origin request metadata.
    if secure_forward_proxy {
        return None;
    }

    let fallback = input
        .extensions()
        .get_ref::<FallbackHttpVersion>()
        .map(|fallback| fallback.0);
    input
        .target_http_version_with_fallback(fallback)
        .or_else(|| {
            let requested = input.http_version();
            (plaintext_http || requested == Some(Version::HTTP_3))
                .then_some(requested)
                .flatten()
        })
}

#[derive(Debug, Clone)]
/// Config used to create a multiplexing http connection pool ([`MultiplexPool`]).
///
/// The per-connection concurrency comes from the connection's
/// [`MaxConcurrency`](rama_net::conn::MaxConcurrency) extension (set by the http
/// connectors: 1 for http/1, the stream capacity for http/2), clamped to
/// `max_concurrent_streams` as an upper bound.
pub struct HttpPooledConnectorConfig {
    /// Set the max amount of connections that this connection pool will contain
    ///
    /// This is the sum of active connections and idle connections. When this limit
    /// is hit idle connections will be replaced with new ones.
    pub max_total: usize,
    /// Upper bound on the concurrent requests a single connection may serve.
    ///
    /// Acts as a ceiling for each connection, each connection also figures
    /// it's own max concurrency out by itself
    pub max_concurrent_streams: usize,
    /// How a connection is chosen among several that can serve a request.
    pub selection: MuxSelection,
    /// If connections have been idle (no active streams) for longer than this
    /// timeout they are dropped. Only checked when a connection is requested.
    pub idle_timeout: Option<Duration>,
    /// How long to wait for the pool to hand out a connection before timing out.
    pub wait_for_pool_timeout: Option<Duration>,
}

const DEFAULT_MAX_TOTAL: NonZeroUsize = NonZeroUsize::new(50).unwrap();
const DEFAULT_MAX_CONCURRENT_STREAMS: NonZeroUsize = NonZeroUsize::new(100).unwrap();

impl Default for HttpPooledConnectorConfig {
    fn default() -> Self {
        Self {
            max_total: DEFAULT_MAX_TOTAL.get(),
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS.get(),
            selection: MuxSelection::default(),
            idle_timeout: Some(Duration::from_secs(300)),
            wait_for_pool_timeout: Some(Duration::from_secs(120)),
        }
    }
}

impl HttpPooledConnectorConfig {
    /// Build a pooled HTTP connector using Rama's known-valid default limits.
    ///
    /// Unlike [`Self::try_build_connector`], this constructor is infallible because
    /// its connection and concurrency limits are non-zero constants owned by
    /// Rama.
    pub fn build_default_connector<S>(inner: S) -> HttpPooledConnector<S>
    where
        S: ConnectorService<ConnectRequest>,
    {
        let config = Self::default();
        let pool = MultiplexPool::new(DEFAULT_MAX_CONCURRENT_STREAMS, DEFAULT_MAX_TOTAL)
            .with_selection(config.selection)
            .maybe_with_idle_timeout(config.idle_timeout);

        let connector = PooledConnector::new(inner, pool, HttpConnIdentifier::new())
            .maybe_with_wait_for_pool_timeout(config.wait_for_pool_timeout);

        BindBodyToConnLayer::new().into_layer(connector)
    }

    /// Build a pooled HTTP connector around `inner`.
    ///
    /// The connector only adds body binding and pool lookup. HTTP request
    /// adaptation and proxy-route selection remain independently composable
    /// services and can be layered around the returned connector when needed.
    ///
    /// The returned connector wraps each pooled connection in
    /// [`BindBodyToConn`](super::BindBodyToConn), so the pool only frees/reuses a
    /// connection once its response body has been consumed, not at response
    /// headers.
    ///
    /// Warning: the connection returned by this pool should only be used for a single
    /// request. Every request should go through the connector stack again, and will
    /// receive a new or reused connection (maybe multiplexed) of its own.
    pub fn try_build_connector<S>(self, inner: S) -> Result<HttpPooledConnector<S>, BoxError>
    where
        S: ConnectorService<ConnectRequest>,
    {
        let pool = MultiplexPool::try_new(self.max_concurrent_streams, self.max_total)?
            .with_selection(self.selection)
            .maybe_with_idle_timeout(self.idle_timeout);

        let connector = PooledConnector::new(inner, pool, HttpConnIdentifier::new())
            .maybe_with_wait_for_pool_timeout(self.wait_for_pool_timeout);

        Ok(BindBodyToConnLayer::new().into_layer(connector))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rama_core::bytes::Bytes;
    use rama_core::error::{BoxError, BoxErrorExt as _};
    use rama_core::extensions::ExtensionsRef;
    use rama_core::futures::stream;
    use rama_core::rt::Executor;
    use rama_core::service::service_fn;
    use rama_core::{Layer, Service, ServiceInput};
    use rama_http_types::body::util::BodyExt as _;
    use rama_http_types::proxy::PlaintextHttpProxyMode;
    use rama_http_types::{Body, HeaderValue, Method, Request, Response, StatusCode, Version};
    use rama_net::address::{HostWithPort, ProxyAddress};
    use rama_net::client::pool::{
        BasicConnIdentifier, MultiplexPool, PooledConnector, ReqToConnID,
    };
    use rama_net::client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService,
        EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute, ProxyRoutes,
        ProxyRoutesConnector,
    };
    use rama_net::conn::{ConnectionHealth, ConnectionHealthWatcher};
    use rama_net::http::{HttpRequestVersion, TargetHttpVersion};
    use rama_net::test_utils::client::MockConnectorService;
    use rama_net::{HttpVersionInputExt, Protocol, transport::TransportProtocol};
    use rama_utils::octets::kib;
    use tokio::time::sleep;

    use super::{
        HttpConnIdentifier, HttpPooledConnector, HttpPooledConnectorConfig,
        HttpProxyModeRequirement, connection_version_requirement, http_proxy_mode_requirement,
    };
    use crate::client::proxy::layer::HttpProxyConnectorLayer;
    use crate::client::{HttpConnectRequestAdapter, HttpConnectorLayer};
    use crate::server::HttpServer;

    fn create_test_request(version: Version) -> Request {
        Request::builder()
            .uri("https://www.example.com")
            .version(version)
            .body(Body::from("a random request body"))
            .unwrap()
    }

    fn build_test_connector<S>(
        config: HttpPooledConnectorConfig,
        inner: S,
    ) -> HttpConnectRequestAdapter<HttpPooledConnector<S>>
    where
        S: ConnectorService<ConnectRequest>,
    {
        HttpConnectRequestAdapter::new(config.try_build_connector(inner).unwrap())
    }

    #[test]
    fn connection_id_uses_only_the_selected_proxy_route() {
        let request = Request::builder()
            .uri("https://example.com")
            .body(())
            .unwrap();

        let unconfigured_id = BasicConnIdentifier::new().id(&request).unwrap();
        assert_eq!(unconfigured_id.proxy_address, None);

        request.extensions().insert(ProxyRoute::Direct);
        let direct_id = BasicConnIdentifier::new().id(&request).unwrap();
        assert_eq!(direct_id.proxy_address, None);
        assert_ne!(unconfigured_id, direct_id);

        let proxy_address = ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: HostWithPort::example_domain_http(),
            credential: None,
        };
        request
            .extensions()
            .insert(ProxyRoute::Proxy(proxy_address.clone()));

        let proxied_id = BasicConnIdentifier::new().id(&request).unwrap();
        assert_eq!(proxied_id.proxy_address, Some(proxy_address));
    }

    #[test]
    fn http_connection_id_separates_plaintext_wire_versions() {
        for proxy in [
            None,
            Some("http://proxy.example:8080".parse::<ProxyAddress>().unwrap()),
            Some(
                "socks5://proxy.example:1080"
                    .parse::<ProxyAddress>()
                    .unwrap(),
            ),
        ] {
            let ids = [Version::HTTP_11, Version::HTTP_2].map(|version| {
                let input = ConnectRequest::new(HostWithPort::example_domain_http())
                    .with_application_protocol(Protocol::HTTP);
                input.extensions.insert(HttpRequestVersion(version));
                if let Some(proxy) = proxy.clone() {
                    input.extensions.insert(ProxyRoute::Proxy(proxy));
                }
                HttpConnIdentifier::new().id(&input).unwrap()
            });
            assert_ne!(ids[0], ids[1]);
        }
    }

    #[test]
    fn http_connection_id_uses_only_physical_version_requirements() {
        let secure_proxy: ProxyAddress = "https://proxy.example:8443".parse().unwrap();
        let secure_forward_ids = [
            (Version::HTTP_11, TransportProtocol::Tcp),
            (Version::HTTP_2, TransportProtocol::Tcp),
            (Version::HTTP_3, TransportProtocol::Udp),
        ]
        .map(|(version, transport)| {
            let input = ConnectRequest::new(HostWithPort::example_domain_http())
                .with_application_protocol(Protocol::HTTP)
                .with_transport_protocol(transport);
            input.extensions.insert(HttpRequestVersion(version));
            input
                .extensions
                .insert(ProxyRoute::Proxy(secure_proxy.clone()));
            HttpConnIdentifier::new().id(&input).unwrap()
        });
        assert_eq!(secure_forward_ids[0], secure_forward_ids[1]);
        assert_eq!(secure_forward_ids[1], secure_forward_ids[2]);

        let explicit_ids = [Version::HTTP_11, Version::HTTP_2].map(|version| {
            let input = ConnectRequest::new(HostWithPort::example_domain_https())
                .with_application_protocol(Protocol::HTTPS);
            input.extensions.insert(TargetHttpVersion(version));
            HttpConnIdentifier::new().id(&input).unwrap()
        });
        assert_ne!(explicit_ids[0], explicit_ids[1]);
    }

    #[test]
    fn http_connection_id_separates_forward_and_forced_tunnel_modes() {
        for proxy in [
            "http://proxy.example:8080".parse::<ProxyAddress>().unwrap(),
            "https://proxy.example:8443"
                .parse::<ProxyAddress>()
                .unwrap(),
        ] {
            let make_id = |tunnel| {
                let input = ConnectRequest::new(HostWithPort::example_domain_http())
                    .with_application_protocol(Protocol::HTTP);
                input
                    .extensions
                    .insert(HttpRequestVersion(Version::HTTP_11));
                input.extensions.insert(ProxyRoute::Proxy(proxy.clone()));
                if tunnel {
                    input.extensions.insert(PlaintextHttpProxyMode::Tunnel);
                }
                HttpConnIdentifier::new().id(&input).unwrap()
            };

            assert_ne!(make_id(false), make_id(true));
        }
    }

    #[test]
    fn http_proxy_mode_requirement_covers_every_route_kind() {
        let make_input = |application: Protocol, proxy: Option<&str>, tunnel: bool| {
            let input = ConnectRequest::new(HostWithPort::example_domain_http())
                .with_application_protocol(application);
            if let Some(proxy) = proxy {
                input
                    .extensions
                    .insert(ProxyRoute::Proxy(proxy.parse::<ProxyAddress>().unwrap()));
            }
            if tunnel {
                input.extensions.insert(PlaintextHttpProxyMode::Tunnel);
            }
            input
        };

        assert_eq!(
            http_proxy_mode_requirement(&make_input(
                Protocol::HTTP,
                Some("http://proxy.example:8080"),
                false,
            )),
            Some(HttpProxyModeRequirement::Forward)
        );
        assert_eq!(
            http_proxy_mode_requirement(&make_input(
                Protocol::HTTP,
                Some("http://proxy.example:8080"),
                true,
            )),
            Some(HttpProxyModeRequirement::Tunnel)
        );
        for application in [Protocol::HTTPS, Protocol::from_static("custom")] {
            assert_eq!(
                http_proxy_mode_requirement(&make_input(
                    application,
                    Some("http://proxy.example:8080"),
                    false,
                )),
                Some(HttpProxyModeRequirement::Tunnel)
            );
        }
        assert_eq!(
            http_proxy_mode_requirement(&make_input(
                Protocol::HTTP,
                Some("socks5://proxy.example:1080"),
                false,
            )),
            None
        );
        assert_eq!(
            http_proxy_mode_requirement(&make_input(Protocol::HTTP, None, false)),
            None
        );
    }

    #[test]
    fn connection_version_requirement_uses_only_physical_wire_constraints() {
        for application in [Protocol::HTTPS, Protocol::from_static("custom")] {
            let input = ConnectRequest::new(HostWithPort::example_domain_http())
                .with_application_protocol(application);
            input.extensions.insert(HttpRequestVersion(Version::HTTP_2));
            assert_eq!(connection_version_requirement(&input), None);
        }

        let secure_forward = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        secure_forward
            .extensions
            .insert(HttpRequestVersion(Version::HTTP_2));
        secure_forward.extensions.insert(ProxyRoute::Proxy(
            "https://proxy.example:8443"
                .parse::<ProxyAddress>()
                .unwrap(),
        ));
        assert_eq!(connection_version_requirement(&secure_forward), None);

        for version in [Version::HTTP_11, Version::HTTP_2] {
            let tunnel = ConnectRequest::new(HostWithPort::example_domain_http())
                .with_application_protocol(Protocol::HTTP);
            tunnel.extensions.insert(PlaintextHttpProxyMode::Tunnel);
            tunnel.extensions.insert(TargetHttpVersion(version));
            tunnel.extensions.insert(ProxyRoute::Proxy(
                "https://proxy.example:8443"
                    .parse::<ProxyAddress>()
                    .unwrap(),
            ));
            assert_eq!(connection_version_requirement(&tunnel), Some(version));
        }
    }

    fn proxy_route(name: &str) -> ProxyRoute {
        ProxyRoute::Proxy(
            format!("http://{name}.example:8080")
                .parse::<ProxyAddress>()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn route_order_checks_pool_per_selected_route() {
        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                async move {
                    let route = input.extensions.get_ref::<ProxyRoute>().unwrap();
                    let name = route
                        .proxy_address()
                        .map(|proxy| proxy.address.host.to_string())
                        .unwrap_or_else(|| "DIRECT".to_owned());
                    attempts.lock().push(name.clone());

                    if name == "c.example" {
                        Ok(EstablishedClientConnection {
                            input,
                            conn: ServiceInput::new(()),
                        })
                    } else {
                        Err(ConnectionError::transport(
                            BoxError::from_static_str("route unavailable"),
                            ConnectionErrorKind::Unavailable,
                        ))
                    }
                }
            }
        });
        let pool = MultiplexPool::try_new(10, 10).unwrap();
        let pooled = PooledConnector::new(inner, pool, BasicConnIdentifier::new());
        let connector = ProxyRoutesConnector::new(pooled);

        let first = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS);
        first.extensions.insert(ProxyRoutes::new([
            proxy_route("a"),
            proxy_route("b"),
            proxy_route("c"),
        ]));
        let established = connector.serve(first).await.unwrap();
        assert_eq!(
            established
                .input
                .extensions
                .get_ref::<ProxyRoute>()
                .unwrap(),
            &proxy_route("c")
        );
        drop(established.conn);

        // Route a is still preferred and attempted first. Route c then reuses
        // the existing pooled connection instead of calling the inner connector.
        let second = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS);
        second
            .extensions
            .insert(ProxyRoutes::new([proxy_route("a"), proxy_route("c")]));
        drop(connector.serve(second).await.unwrap().conn);

        // A later request selecting only c shares the exact same pool identity.
        let third = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS);
        third.extensions.insert(proxy_route("c"));
        drop(connector.serve(third).await.unwrap().conn);

        assert_eq!(
            attempts.lock().as_slice(),
            ["a.example", "b.example", "c.example", "a.example"]
        );
    }

    #[tokio::test]
    async fn pooled_tunnel_does_not_reuse_http2_for_http3() {
        for proxy in [
            "http://proxy.example:8080",
            "https://proxy.example:8443",
            "socks5://proxy.example:1080",
        ] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let inner = service_fn({
                let attempts = Arc::clone(&attempts);
                move |input: ConnectRequest| {
                    let attempts = Arc::clone(&attempts);
                    async move {
                        attempts.fetch_add(1, Ordering::Relaxed);
                        if input.http_version() == Some(Version::HTTP_3) {
                            Err(ConnectionError::local(
                                BoxError::from_static_str("HTTP/3 tunnel unsupported"),
                                ConnectionErrorKind::InvalidInput,
                            ))
                        } else {
                            Ok(EstablishedClientConnection {
                                input,
                                conn: ServiceInput::new(()),
                            })
                        }
                    }
                }
            });
            let pool = MultiplexPool::try_new(10, 10).unwrap();
            let connector = PooledConnector::new(inner, pool, HttpConnIdentifier::new());
            let proxy: ProxyAddress = proxy.parse().unwrap();

            let first = ConnectRequest::new(HostWithPort::example_domain_https())
                .with_application_protocol(Protocol::HTTPS)
                .with_transport_protocol(TransportProtocol::Tcp);
            first.extensions.insert(HttpRequestVersion(Version::HTTP_2));
            first.extensions.insert(ProxyRoute::Proxy(proxy.clone()));
            drop(connector.serve(first).await.unwrap().conn);

            let second = ConnectRequest::new(HostWithPort::example_domain_https())
                .with_application_protocol(Protocol::HTTPS)
                .with_transport_protocol(TransportProtocol::Udp);
            second
                .extensions
                .insert(HttpRequestVersion(Version::HTTP_3));
            second.extensions.insert(ProxyRoute::Proxy(proxy));
            let error = connector.serve(second).await.unwrap_err();

            assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
            assert_eq!(attempts.load(Ordering::Relaxed), 2);
        }
    }

    /// A mock connector whose every backend connection runs an `HttpServer` that
    /// tags each response with `x-conn-id` (which backend connection served it) and
    /// `x-resp-id` (how many requests that connection has served so far). The
    /// per-connection id is read from a header, so it can be asserted without
    /// draining the (possibly still in-flight) response body.
    fn tagging_mock_connector() -> impl ConnectorService<
        ConnectRequest,
        Connection: Service<Request, Output = Response, Error = BoxError> + ExtensionsRef,
    > {
        let conns = Arc::new(AtomicUsize::new(0));
        HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
            let conn_id = conns.fetch_add(1, Ordering::Relaxed);
            let resps = Arc::new(AtomicUsize::new(0));
            HttpServer::auto(Executor::default()).service(service_fn(move |_req: Request| {
                let resps = resps.clone();
                async move {
                    let resp_id = resps.fetch_add(1, Ordering::Relaxed);
                    let mut resp = Response::new(Body::from("ok"));
                    let headers = resp.headers_mut();
                    headers.insert("x-conn-id", HeaderValue::from(conn_id as u64));
                    headers.insert("x-resp-id", HeaderValue::from(resp_id as u64));
                    Ok::<_, Infallible>(resp)
                }
            }))
        }))
    }

    fn conn_id(resp: &Response) -> u64 {
        resp.headers()
            .get("x-conn-id")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn pool_keeps_h2_connection_in_use_until_response_body_consumed() {
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_concurrent_streams: 1,
                max_total: 4,
                ..Default::default()
            },
            tagging_mock_connector(),
        );

        let req = || create_test_request(Version::HTTP_2);

        // Serve req1 but hold its (still-streaming) response body: the connection is
        // moved into that body, so it is logically still in use.
        let est1 = connector.serve(req()).await.unwrap();
        let resp1 = est1.conn.serve(req()).await.unwrap();
        drop(est1);

        // req2 must therefore land on a NEW connection (cap = 1, conn 0 busy).
        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();

        assert_eq!(conn_id(&resp1), 0);
        assert_eq!(
            conn_id(&resp2),
            1,
            "second request must not reuse a connection whose response body is still in flight"
        );
    }

    #[tokio::test]
    async fn pool_keeps_h1_connection_in_use_until_response_body_consumed() {
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_concurrent_streams: 1,
                max_total: 4,
                ..Default::default()
            },
            tagging_mock_connector(),
        );

        let req = || create_test_request(Version::HTTP_11);

        let est1 = connector.serve(req()).await.unwrap();
        let resp1 = est1.conn.serve(req()).await.unwrap();
        drop(est1);

        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();

        assert_eq!(conn_id(&resp1), 0);
        assert_eq!(
            conn_id(&resp2),
            1,
            "h1: second request must not reuse a connection whose response body is still in flight"
        );
    }

    /// An h1 connection the server closed (`Connection: close`) must not be handed
    /// back out by the pool. Multiplex storage keeps the connection after a handout
    /// drops, so this relies on `ConnectionHealthWatcher` being marked broken and
    /// swept, the multiplex equivalent of the exclusive pool's `drop_connection_if_no_response`.
    #[tokio::test(start_paused = true)]
    async fn pool_does_not_reuse_h1_connection_after_server_close() {
        let conns = Arc::new(AtomicUsize::new(0));
        let inner =
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
                let conn_id = conns.fetch_add(1, Ordering::Relaxed);
                HttpServer::auto(Executor::default()).service(service_fn(
                    move |_req: Request| async move {
                        let mut resp = Response::new(Body::from("ok"));
                        let headers = resp.headers_mut();
                        headers.insert("x-conn-id", HeaderValue::from(conn_id as u64));
                        headers.insert("connection", HeaderValue::from_static("close"));
                        Ok::<_, Infallible>(resp)
                    },
                ))
            }));
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_total: 4,
                ..Default::default()
            },
            inner,
        );

        let req = || create_test_request(Version::HTTP_11);

        // Serve and fully drain req1 so the h1 connection processes the close and
        // (should) get marked broken before it could be reused.
        let est1 = connector.serve(req()).await.unwrap();
        let resp1 = est1.conn.serve(req()).await.unwrap();
        drop(est1);
        let id1 = conn_id(&resp1);
        resp1.into_body().collect().await.unwrap();

        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();

        assert_eq!(id1, 0);
        assert_ne!(
            conn_id(&resp2),
            id1,
            "must not reuse an h1 connection the server closed"
        );
    }

    #[tokio::test]
    async fn pool_does_not_reuse_h1_connection_after_upgrade() {
        let conns = Arc::new(AtomicUsize::new(0));
        let inner =
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
                let conn_id = conns.fetch_add(1, Ordering::Relaxed);
                HttpServer::auto(Executor::default()).service(service_fn(
                    move |req: Request| async move {
                        let is_upgrade = req.uri().path().is_some_and(|path| path == "/upgrade");
                        if is_upgrade {
                            let on_upgrade = rama_http::io::upgrade::handle_upgrade(&req);
                            _ = tokio::spawn(async move {
                                _ = on_upgrade.await;
                            });
                        }

                        let mut resp = if is_upgrade {
                            Response::builder()
                                .status(StatusCode::SWITCHING_PROTOCOLS)
                                .header("connection", "upgrade")
                                .header("upgrade", "test")
                                .body(Body::empty())
                                .unwrap()
                        } else {
                            Response::new(Body::from("ok"))
                        };
                        resp.headers_mut()
                            .insert("x-conn-id", HeaderValue::from(conn_id as u64));
                        Ok::<_, Infallible>(resp)
                    },
                ))
            }));
        let connector = build_test_connector(HttpPooledConnectorConfig::default(), inner);

        let upgrade_request = Request::builder()
            .uri("https://www.example.com/upgrade")
            .version(Version::HTTP_11)
            .header("connection", "upgrade")
            .header("upgrade", "test")
            .body(Body::empty())
            .unwrap();
        let established = connector.serve(upgrade_request).await.unwrap();
        let response = established.conn.serve(established.input).await.unwrap();
        let first_conn_id = conn_id(&response);
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<ConnectionHealthWatcher>()
                .expect("pooled h1 connection health watcher")
                .health(),
            ConnectionHealth::Broken,
            "an h1 upgrade must be marked broken before returning its response"
        );
        let on_upgrade = rama_http::io::upgrade::handle_upgrade(&response);
        let body = response.into_body();
        drop(body);

        let request = create_test_request(Version::HTTP_11);
        let established = connector.serve(request).await.unwrap();
        let response = established.conn.serve(established.input).await.unwrap();
        assert_ne!(
            conn_id(&response),
            first_conn_id,
            "an upgraded h1 connection must be evicted before the next request"
        );
        drop(on_upgrade.await.unwrap());
    }

    /// An h1 response body abandoned before end-of-stream leaves the connection
    /// mid-message, the pool must not reuse it. Uses a large body so the response is
    /// genuinely still on the wire when dropped (a tiny fully-buffered body could be
    /// drained and legitimately reused).
    #[tokio::test(start_paused = true)]
    async fn pool_does_not_reuse_h1_connection_after_body_dropped_early() {
        let conns = Arc::new(AtomicUsize::new(0));
        let inner =
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
                let conn_id = conns.fetch_add(1, Ordering::Relaxed);
                HttpServer::auto(Executor::default()).service(service_fn(
                    move |_req: Request| async move {
                        let mut resp = Response::new(Body::from(vec![0u8; kib(1024)]));
                        resp.headers_mut()
                            .insert("x-conn-id", HeaderValue::from(conn_id as u64));
                        Ok::<_, Infallible>(resp)
                    },
                ))
            }));
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_total: 4,
                ..Default::default()
            },
            inner,
        );

        let req = || create_test_request(Version::HTTP_11);

        // Take the response (headers) but drop it without reading the body.
        let est1 = connector.serve(req()).await.unwrap();
        let resp1 = est1.conn.serve(req()).await.unwrap();
        drop(est1);
        let id1 = conn_id(&resp1);
        drop(resp1);

        // Let the connection task observe the abandoned read and update health.
        sleep(Duration::from_millis(50)).await;

        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();

        assert_eq!(id1, 0);
        assert_ne!(
            conn_id(&resp2),
            id1,
            "must not reuse an h1 connection whose response body was abandoned mid-stream"
        );
    }

    /// Regression test: the h1 dispatcher also evicts a connection whose response
    /// body was abandoned, but it runs on the spawned connection task. An immediate
    /// follow-up request used to win that race and get handed the dead connection,
    /// failing with a closed-channel error. Eviction must be synchronous with
    /// abandoning the body: no sleeps/yields between the drop and the next request.
    #[tokio::test]
    async fn pool_evicts_h1_connection_the_moment_its_streaming_body_is_abandoned() {
        let conns = Arc::new(AtomicUsize::new(0));
        let inner =
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
                let conn_id = conns.fetch_add(1, Ordering::Relaxed);
                HttpServer::auto(Executor::default()).service(service_fn(
                    move |_req: Request| async move {
                        // infinite SSE-like stream: never reaches end-of-stream
                        let stream = stream::repeat_with(|| {
                            Ok::<_, Infallible>(Bytes::from_static(b"data: ping\n\n"))
                        });
                        let mut resp = Response::new(Body::from_stream(stream));
                        resp.headers_mut()
                            .insert("x-conn-id", HeaderValue::from(conn_id as u64));
                        Ok::<_, Infallible>(resp)
                    },
                ))
            }));
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_total: 4,
                ..Default::default()
            },
            inner,
        );

        let req = || create_test_request(Version::HTTP_11);

        let est1 = connector.serve(req()).await.unwrap();
        let resp1 = est1.conn.serve(req()).await.unwrap();
        drop(est1);
        let id1 = conn_id(&resp1);

        // Read a few chunks mid-stream, then abandon the body.
        let mut body1 = resp1.into_body();
        for _ in 0..2 {
            body1.frame().await.unwrap().unwrap();
        }
        drop(body1);

        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();

        assert_eq!(id1, 0);
        assert_ne!(
            conn_id(&resp2),
            id1,
            "an h1 connection whose streaming body was just abandoned must not serve the next request"
        );
    }

    /// Dropping an in-flight h1 request future closes the shared connection: the
    /// connection must be evicted synchronously with the cancellation, before a
    /// follow-up request can check it out of the pool.
    #[tokio::test(start_paused = true)]
    async fn pool_evicts_h1_connection_when_inflight_request_cancelled() {
        let conns = Arc::new(AtomicUsize::new(0));
        let inner =
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
                let conn_id = conns.fetch_add(1, Ordering::Relaxed);
                HttpServer::auto(Executor::default()).service(service_fn(
                    move |_req: Request| async move {
                        sleep(Duration::from_secs(60)).await;
                        let mut resp = Response::new(Body::from("ok"));
                        resp.headers_mut()
                            .insert("x-conn-id", HeaderValue::from(conn_id as u64));
                        Ok::<_, Infallible>(resp)
                    },
                ))
            }));
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_total: 4,
                ..Default::default()
            },
            inner,
        );

        let req = || create_test_request(Version::HTTP_11);

        let est1 = connector.serve(req()).await.unwrap();
        let send = est1.conn.serve(req());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), send)
                .await
                .is_err(),
            "request should still be in flight when cancelled"
        );
        drop(est1);

        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();
        assert_eq!(
            conn_id(&resp2),
            1,
            "a cancelled in-flight h1 request must evict its connection; the next request dials fresh"
        );
    }

    /// A connection tunneled through an HTTP CONNECT proxy must be reusable: the
    /// consumed h1 proxy hop is marked broken on upgrade, but the tunnel built on
    /// top forks that state instead of inheriting it. It used to inherit the
    /// broken mark (and the hop's MaxConcurrency of 1), evicting every proxied
    /// connection from the pool after a single request.
    #[tokio::test]
    async fn pool_reuses_connection_tunneled_through_connect_proxy() {
        let tunnels = Arc::new(AtomicUsize::new(0));
        let mock = MockConnectorService::new({
            let tunnels = tunnels.clone();
            move || {
                let tunnels = tunnels.clone();
                // CONNECT proxy: reply 200 and serve the "origin" server over the tunnel
                HttpServer::auto(Executor::default()).service(service_fn(move |req: Request| {
                    let tunnels = tunnels.clone();
                    async move {
                        assert_eq!(req.method(), Method::CONNECT);
                        let on_upgrade = rama_http::io::upgrade::handle_upgrade(&req);
                        let conn_id = tunnels.fetch_add(1, Ordering::Relaxed);
                        _ = tokio::spawn(async move {
                            let tunnel = on_upgrade.await.unwrap();
                            let origin = HttpServer::auto(Executor::default()).service(service_fn(
                                move |_req: Request| async move {
                                    let mut resp = Response::new(Body::from("ok"));
                                    resp.headers_mut()
                                        .insert("x-conn-id", HeaderValue::from(conn_id as u64));
                                    Ok::<_, Infallible>(resp)
                                },
                            ));
                            _ = origin.serve(tunnel).await;
                        });
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    }
                }))
            }
        });
        let inner = HttpConnectorLayer::default()
            .into_layer(HttpProxyConnectorLayer::required().into_layer(mock));
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_total: 4,
                ..Default::default()
            },
            inner,
        );

        let proxy_address = "http://alice:private-password@proxy.example:8080"
            .parse::<ProxyAddress>()
            .unwrap();
        let proxy = ProxyRoute::Proxy(proxy_address.clone());
        let req = || {
            let req = create_test_request(Version::HTTP_11);
            req.extensions().insert(proxy.clone());
            req
        };

        let est1 = connector.serve(req()).await.unwrap();
        assert_eq!(
            est1.conn.extensions().get_ref::<EstablishedProxyRoute>(),
            Some(&EstablishedProxyRoute::Tunnel(proxy_address.clone())),
        );
        assert!(!est1.conn.extensions().contains::<ProxyRoute>());
        let resp1 = est1.conn.serve(req()).await.unwrap();
        assert_eq!(conn_id(&resp1), 0);
        // Drain to end-of-stream so the tunneled connection returns to the pool.
        resp1.into_body().collect().await.unwrap();

        let est2 = connector.serve(req()).await.unwrap();
        assert_eq!(
            est2.conn.extensions().get_ref::<EstablishedProxyRoute>(),
            Some(&EstablishedProxyRoute::Tunnel(proxy_address)),
        );
        assert!(!est2.conn.extensions().contains::<ProxyRoute>());
        let resp2 = est2.conn.serve(req()).await.unwrap();
        assert_eq!(
            conn_id(&resp2),
            0,
            "second request must reuse the CONNECT tunnel"
        );
        assert_eq!(
            tunnels.load(Ordering::Relaxed),
            1,
            "a reused tunnel means a single proxy dial"
        );
    }

    /// An h1 chunked response consumed through its terminal trailers frame is
    /// complete even though the body never reports `is_end_stream`: dropping it
    /// without polling the final `None` must not poison the connection, and the
    /// pool must reuse it.
    #[tokio::test]
    async fn pool_reuses_h1_connection_after_body_consumed_through_trailers() {
        let conns = Arc::new(AtomicUsize::new(0));
        let inner =
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
                let conn_id = conns.fetch_add(1, Ordering::Relaxed);
                HttpServer::auto(Executor::default()).service(service_fn(
                    move |_req: Request| async move {
                        let mut trailers = rama_http_types::HeaderMap::new();
                        trailers.insert("x-trailer", HeaderValue::from_static("yes"));
                        // unknown length -> chunked, so the trailers actually go on the wire
                        let stream =
                            stream::iter([Ok::<_, Infallible>(Bytes::from_static(b"hello"))]);
                        let body = Body::from_stream(stream)
                            .with_trailers(std::future::ready(Some(Ok(trailers))));
                        let mut resp = Response::new(Body::new(body));
                        let headers = resp.headers_mut();
                        headers.insert("x-conn-id", HeaderValue::from(conn_id as u64));
                        // the h1 encoder only sends trailer fields declared here
                        headers.insert("trailer", HeaderValue::from_static("x-trailer"));
                        Ok::<_, Infallible>(resp)
                    },
                ))
            }));
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_total: 4,
                ..Default::default()
            },
            inner,
        );

        let req = || {
            let mut req = create_test_request(Version::HTTP_11);
            // the h1 server only encodes trailers when the request allows them
            req.headers_mut()
                .insert("te", HeaderValue::from_static("trailers"));
            req
        };

        let est1 = connector.serve(req()).await.unwrap();
        let resp1 = est1.conn.serve(req()).await.unwrap();
        let id1 = conn_id(&resp1);
        let mut body1 = resp1.into_body();
        let mut saw_trailers = false;
        while !saw_trailers {
            let frame = body1
                .frame()
                .await
                .expect("the response must yield frames up to its trailers")
                .unwrap();
            saw_trailers = frame.is_trailers();
        }
        // Consumed through the terminal trailers frame; drop before the final `None`.
        drop(body1);

        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();
        assert_eq!(id1, 0);
        assert_eq!(
            conn_id(&resp2),
            id1,
            "a connection whose response was consumed through trailers must be reused"
        );
    }

    #[tokio::test]
    async fn pool_reuses_connection_after_body_consumed() {
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_concurrent_streams: 1,
                max_total: 4,
                ..Default::default()
            },
            tagging_mock_connector(),
        );

        let req = || create_test_request(Version::HTTP_2);

        let resp1 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        assert_eq!(conn_id(&resp1), 0);
        // Drain to end-of-stream: releases connection 0 back to the pool.
        resp1.into_body().collect().await.unwrap();

        let resp2 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        assert_eq!(
            conn_id(&resp2),
            0,
            "connection must be reused once its response body is consumed"
        );
    }

    #[tokio::test]
    async fn pool_multiplexes_on_h2() {
        let connector = build_test_connector(
            HttpPooledConnectorConfig::default(),
            tagging_mock_connector(),
        );

        let req = || create_test_request(Version::HTTP_2);

        // Hold resp1 (body unconsumed) so connection 0 stays in use.
        let resp1 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        let resp2 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();

        assert_eq!(conn_id(&resp1), 0);
        assert_eq!(
            conn_id(&resp2),
            0,
            "h2: a second in-flight request multiplexes onto the same connection"
        );
    }

    #[tokio::test]
    async fn pool_does_not_multiplex_on_h1() {
        let connector = build_test_connector(
            HttpPooledConnectorConfig::default(),
            tagging_mock_connector(),
        );

        let req = || create_test_request(Version::HTTP_11);

        let resp1 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        let resp2 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();

        assert_eq!(conn_id(&resp1), 0);
        assert_eq!(
            conn_id(&resp2),
            1,
            "h1 does not multiplex: a second in-flight request needs a new connection"
        );
    }

    #[tokio::test]
    async fn pool_respects_max_concurrent_streams() {
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_concurrent_streams: 2,
                max_total: 4,
                ..Default::default()
            },
            tagging_mock_connector(),
        );

        let req = || create_test_request(Version::HTTP_2);

        // Three in-flight (bodies unconsumed) requests: two fit on connection 0.
        let resp1 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        let resp2 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        let resp3 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();

        assert_eq!(conn_id(&resp1), 0);
        assert_eq!(conn_id(&resp2), 0, "second request fits on connection 0");
        assert_eq!(
            conn_id(&resp3),
            1,
            "third request exceeds the per-connection limit, needs a new connection"
        );
    }

    /// Like [`tagging_mock_connector`] but each response carries a large body, so
    /// it genuinely streams over multiple frames rather than a single buffered one.
    fn large_body_mock_connector() -> impl ConnectorService<
        ConnectRequest,
        Connection: Service<Request, Output = Response, Error = BoxError> + ExtensionsRef,
    > {
        let conns = Arc::new(AtomicUsize::new(0));
        HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
            let conn_id = conns.fetch_add(1, Ordering::Relaxed);
            HttpServer::auto(Executor::default()).service(service_fn(
                move |_req: Request| async move {
                    let mut resp = Response::new(Body::from(vec![0u8; kib(1024)]));
                    resp.headers_mut()
                        .insert("x-conn-id", HeaderValue::from(conn_id as u64));
                    Ok::<_, Infallible>(resp)
                },
            ))
        }))
    }

    /// A connection stays bound for the whole of a *streaming* response body: it
    /// is not reusable while frames are still arriving, and is released precisely
    /// at end-of-stream (exercising `GuardedBody`'s `poll_frame -> Ready(None)`
    /// over real multi-frame h2 streaming).
    #[tokio::test]
    async fn pool_binds_connection_across_streaming_body() {
        let connector = build_test_connector(
            HttpPooledConnectorConfig {
                max_concurrent_streams: 1,
                max_total: 4,
                ..Default::default()
            },
            large_body_mock_connector(),
        );

        let req = || create_test_request(Version::HTTP_2);

        // Read the headers and a single body frame: the stream is not yet at
        // end-of-stream, so connection 0 is still in use.
        let resp1 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        let id1 = conn_id(&resp1);
        let mut body1 = resp1.into_body();
        assert!(
            body1.frame().await.is_some(),
            "streaming body should yield at least one frame"
        );

        // Mid-stream: connection 0 must not be reused.
        let resp2 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        assert_eq!(id1, 0);
        assert_ne!(
            conn_id(&resp2),
            id1,
            "a connection still streaming its response body must not be reused"
        );

        // Drain body 1 to end-of-stream. `GuardedBody` releases the connection
        // right here (at `poll_frame -> Ready(None)`), not on drop.
        while let Some(frame) = body1.frame().await {
            frame.unwrap();
        }

        // `body1` is still in scope (not dropped), yet connection 0 is reused.
        // Proving the release happens at end-of-stream, not when the body drops.
        let resp3 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        assert_eq!(
            conn_id(&resp3),
            id1,
            "a connection is reused once its streaming body reaches end-of-stream"
        );
    }
}
