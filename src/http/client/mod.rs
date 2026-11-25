//! rama http client support
//!
//! Contains re-exports from `rama-http-backend::client`
//! and adds `EasyHttpWebClient`, an opiniated http web client which
//! supports most common use cases and provides sensible defaults.
use std::{fmt, io};

use crate::{
    Layer, Service,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef},
    graceful::WeakScope,
    http::{Body as ResponseBody, Request, Response, StreamingBody},
    net::client::{
        ConnectRequest, ConnectorService, EstablishedClientConnection, EstablishedProxyRoute,
        ProxyDialer,
    },
    service::BoxService,
    tcp::client::service::TcpConnector,
    telemetry::tracing,
};

#[doc(inline)]
pub use ::rama_http::service::client::blocking::{
    Body as BlockingBody, Client as BlockingHttpClient, Response as BlockingResponse,
};
#[doc(inline)]
pub use ::rama_http_backend::client::*;
use rama_core::{
    error::{ErrorContext, ErrorExt as _, extra::OpaqueError},
    extensions::Egress,
    layer::MapErr,
};
use rama_http::{
    layer::{map_response_body::MapResponseBody, remove_header::remove_proxy_auth_request_headers},
    proxy::PlaintextHttpProxyMode,
};

#[cfg(any(feature = "boring", feature = "rustls"))]
use crate::tls::client::TlsClientConfig;

#[cfg(feature = "boring")]
use crate::tls::boring::client::TlsClientSessionCache;

#[cfg(any(feature = "boring", all(feature = "quic", feature = "rustls")))]
use std::sync::Arc;

#[cfg(all(feature = "quic", any(feature = "boring", feature = "rustls")))]
use crate::quic::tls::QuicClientConfigProvider;

#[cfg(all(feature = "masque", feature = "quic"))]
use crate::{
    proxy::masque::connect_udp::{OUTER_IDLE_TIMEOUT, OUTER_INITIAL_MTU},
    quic::{IdleTimeout, TransportConfig, proto::VarInt},
};

pub mod builder;
#[doc(inline)]
pub use builder::EasyHttpConnectorBuilder;

mod proxy_connector;
use proxy_connector::DefaultProxyHttpConnector;
#[doc(inline)]
pub use proxy_connector::{
    DefaultProxyConnector, MaybeForwardedConnection, MaybeForwardedConnector, NoProxyConnection,
    ProxyAltSvcConnectionLayer, ProxyConnectUdpMethod, ProxyConnectUdpNotEnabled, ProxyConnector,
    ProxyConnectorBuilder, ProxyConnectorParts, ProxyHttpStage, ProxyMethodBuilder,
    ProxyMethodNotEnabled, ProxyServiceConnector, ProxySocksMethod, ProxyStream,
    ProxyStreamConnector,
};

/// An opiniated http client that can be used to serve HTTP requests.
///
/// Use [`EasyHttpWebClient::connector_builder`] to easily create a client with
/// a common Http connector setup (tcp + proxy + tls + http) or bring your
/// own http connector.
///
/// [`Default`] uses Rama's default multiplexing connection pool. Build the
/// connector explicitly with
/// [`EasyHttpConnectorBuilder::without_connection_pool`] when connection reuse
/// is unwanted.
///
/// You can fork this http client in case you have use cases not possible with this service example.
/// E.g. perhaps you wish to have middleware in into outbound requests, after they
/// passed through your "connector" setup. All this and more is possible by defining your own
/// http client. Rama is here to empower you, the building blocks are there, go crazy
/// with your own service fork and use the full power of Rust at your fingertips ;)
pub struct EasyHttpWebClient<BodyIn, ConnResponse, L> {
    connector: BoxService<Request<BodyIn>, ConnResponse, OpaqueError>,
    plaintext_http_proxy_mode: Option<PlaintextHttpProxyMode>,
    jit_layers: L,
}

impl<BodyIn, ConnResponse, L> fmt::Debug for EasyHttpWebClient<BodyIn, ConnResponse, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHttpWebClient").finish()
    }
}

impl<BodyIn, ConnResponse, L: Clone> Clone for EasyHttpWebClient<BodyIn, ConnResponse, L> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            plaintext_http_proxy_mode: self.plaintext_http_proxy_mode,
            jit_layers: self.jit_layers.clone(),
        }
    }
}

impl EasyHttpWebClient<(), (), ()> {
    /// Create a [`EasyHttpConnectorBuilder`] to easily create a [`EasyHttpWebClient`] with a
    /// custom connector, whose connections and tunnels run in `scope`.
    #[must_use]
    pub fn connector_builder(scope: impl Into<WeakScope>) -> EasyHttpConnectorBuilder {
        EasyHttpConnectorBuilder::new(scope)
    }

    /// Create a cloneable blocking HTTP(S) client with its own dedicated
    /// runtime thread and Rama's default web connector stack.
    ///
    /// ```no_run
    /// use rama::http::client::EasyHttpWebClient;
    ///
    /// # fn main() -> Result<(), rama::error::BoxError> {
    /// let client = EasyHttpWebClient::try_blocking()?;
    /// let client_for_worker = client.clone();
    ///
    /// let text = client_for_worker
    ///     .get("https://example.com/")
    ///     .send()?
    ///     .try_into_string()?;
    /// # _ = text;
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_blocking() -> io::Result<BlockingHttpWebClient> {
        BlockingHttpClient::try_new(EasyHttpWebClient::default())
    }
}

/// Rama's default asynchronous HTTP(S) client, including its default
/// multiplexing connection pool.
///
/// With BoringSSL or Rustls plus `ring`/`aws-lc`, HTTP/3 is available through
/// alternative-service discovery or an explicit HTTP/3 request. Its shared UDP
/// endpoint is bound lazily, so constructing the client requires no runtime.
///
/// Like a browser it resumes TLS sessions (with BoringSSL, also over TCP), which
/// lets servers link the connections of one client. It acts for a single user:
/// proxies relay traffic instead of sharing one client between their users.
pub type DefaultHttpWebClient<Body = crate::http::Body> = EasyHttpWebClient<
    Body,
    EstablishedClientConnection<
        rama_http::layer::alt_svc::AltSvc<
            BindBodyToConn<
                crate::net::client::pool::MultiplexedConnection<
                    MaybeForwardedConnection<
                        HttpClientService<Body>,
                        DefaultForwardConnection<Body>,
                    >,
                    HttpConnId,
                >,
            >,
        >,
        Request<Body>,
    >,
    (),
>;

type DefaultForwardConnection<Body> = <proxy::HttpForwardProxyConnector<
    ProxyDialer<DefaultProxyHttpConnector<TcpConnector, Body>>,
> as ConnectorService<ConnectRequest>>::Connection;

/// A blocking HTTP(S) client using Rama's default pooled web connector stack.
pub type BlockingHttpWebClient = BlockingHttpClient<DefaultHttpWebClient>;

impl<Body> Default for DefaultHttpWebClient<Body>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    #[inline(always)]
    fn default() -> Self {
        Self::default_with_scope(WeakScope::detached())
    }
}

impl<Body> DefaultHttpWebClient<Body>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    /// Rama's default client stack, with its connections and tunnels in `scope`.
    pub fn default_with_scope(scope: impl Into<WeakScope>) -> Self {
        let scope = scope.into();
        let proxies = ProxyConnector::default_with_scope(scope.clone());
        Self::default_using_proxies(scope, proxies)
    }

    core::cfg_select! {
        feature = "boring" => {
            /// Rama's default client stack over `proxies`, the connector towards proxies,
            /// such as a [`ProxyConnector`] which isolates the `407` of an upstream proxy
            /// for the client of a proxy.
            pub fn default_using_proxies(
                scope: impl Into<WeakScope>,
                proxies: DefaultProxyConnector<TcpConnector, Body>,
            ) -> Self {
                EasyHttpWebClient::connector_builder(scope.into())
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_proxy_support(proxies)
                    .with_tls_support_using_boringssl(TlsClientConfig::default_http())
                    .with_tls_session_store(Arc::new(TlsClientSessionCache::default()))
                    .with_default_http_connector()
                    .with_default_connection_pool()
                    .build_client()
            }
        }
        feature = "rustls" => {
            /// Rama's default client stack over `proxies`, the connector towards proxies,
            /// such as a [`ProxyConnector`] which isolates the `407` of an upstream proxy
            /// for the client of a proxy.
            pub fn default_using_proxies(
                scope: impl Into<WeakScope>,
                proxies: DefaultProxyConnector<TcpConnector, Body>,
            ) -> Self {
                EasyHttpWebClient::connector_builder(scope.into())
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_proxy_support(proxies)
                    .with_tls_support_using_rustls(TlsClientConfig::default_http())
                    .with_default_http_connector()
                    .with_default_connection_pool()
                    .build_client()
            }
        }
        _ => {
            /// Rama's default client stack over `proxies`, the connector towards proxies,
            /// such as a [`ProxyConnector`] which isolates the `407` of an upstream proxy
            /// for the client of a proxy.
            pub fn default_using_proxies(
                scope: impl Into<WeakScope>,
                proxies: DefaultProxyConnector<TcpConnector, Body>,
            ) -> Self {
                EasyHttpWebClient::connector_builder(scope.into())
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_proxy_support(proxies)
                    .without_tls_support()
                    .with_default_http_connector()
                    .with_default_connection_pool()
                    .build_client()
            }
        }
    }
}

#[cfg(all(feature = "masque", feature = "quic"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "masque", feature = "quic"))))]
/// The QUIC transport for HTTP/3 connections that carry MASQUE tunnels, for both the proxy
/// and its clients: room for a tunneled QUIC packet in each datagram ([`OUTER_INITIAL_MTU`]),
/// and an idle timeout that leaves quiet tunnels to their own policy
/// ([`OUTER_IDLE_TIMEOUT`]).
#[must_use]
pub fn masque_quic_transport() -> TransportConfig {
    let idle = u32::try_from(OUTER_IDLE_TIMEOUT.as_millis()).unwrap_or(u32::MAX);
    TransportConfig::default()
        .with_initial_mtu(OUTER_INITIAL_MTU)
        .with_max_idle_timeout(IdleTimeout::from(VarInt::from_u32(idle)))
}

#[cfg(all(feature = "quic", any(feature = "boring", feature = "rustls")))]
pub(crate) fn default_http3_builder(
    scope: impl Into<WeakScope>,
    tls: TlsClientConfig,
    provider: Arc<dyn QuicClientConfigProvider>,
) -> Http3ConnectorBuilder {
    Http3Connector::builder(scope)
        .with_tls_config(tls)
        .with_tls_provider(provider)
}

impl<BodyIn, ConnResponse> EasyHttpWebClient<BodyIn, ConnResponse, ()>
where
    BodyIn: Send + 'static,
{
    /// Create a new [`EasyHttpWebClient`] using the provided connector.
    ///
    /// Custom proxy connectors must honor [`PlaintextHttpProxyMode`] and publish
    /// [`EstablishedProxyRoute`].
    /// Connection wrappers must preserve that metadata through [`ExtensionsRef`].
    /// Forward credentials and challenge isolation come from [`ProxyConnector`]: a
    /// connection which does not report [`EstablishedProxyRoute::Forward`] carries no
    /// `Proxy-Authorization` at all.
    #[must_use]
    pub fn new<S>(connector: S) -> Self
    where
        S: Service<Request<BodyIn>, Output = ConnResponse, Error: Into<BoxError>>,
    {
        Self {
            connector: MapErr::into_opaque_error(connector).boxed(),
            plaintext_http_proxy_mode: None,
            jit_layers: (),
        }
    }
}

impl<BodyIn, ConnResponse, L> EasyHttpWebClient<BodyIn, ConnResponse, L> {
    /// Convert this asynchronous web client into a cloneable blocking client
    /// with its own dedicated runtime thread.
    pub fn try_into_blocking(self) -> io::Result<BlockingHttpClient<Self>> {
        BlockingHttpClient::try_new(self)
    }

    /// Convert this asynchronous web client into a blocking client using a
    /// caller-supplied runtime.
    #[must_use]
    pub fn into_blocking_with_runtime(
        self,
        runtime: &crate::rt::blocking::Runtime,
    ) -> BlockingHttpClient<Self> {
        BlockingHttpClient::with_runtime(self, runtime)
    }

    /// Set the connector that this [`EasyHttpWebClient`] will use.
    ///
    /// Custom proxy connectors follow the metadata contract described in [`Self::new`].
    #[must_use]
    pub fn with_connector<S, BodyInNew, ConnResponseNew>(
        self,
        connector: S,
    ) -> EasyHttpWebClient<BodyInNew, ConnResponseNew, L>
    where
        S: Service<Request<BodyInNew>, Output = ConnResponseNew, Error: Into<BoxError>>,
        BodyInNew: Send + 'static,
    {
        EasyHttpWebClient {
            connector: MapErr::into_opaque_error(connector).boxed(),
            plaintext_http_proxy_mode: self.plaintext_http_proxy_mode,
            jit_layers: self.jit_layers,
        }
    }

    /// [`Layer`] which will be applied just in time (JIT) before the request is sent, but after
    /// the connection has been established. A forwarded request's proxy policy (credentials,
    /// challenge isolation) is part of that connection, so it runs inside these layers: after
    /// caller middleware has processed the request, and before it sees the response.
    ///
    /// That credential is the one of the request's own [`ProxyRoute`], which has to name the
    /// proxy its connection reaches. A layer here which rewrites that route leaves the
    /// request without credentials, rather than sending another proxy's.
    ///
    /// [`ProxyRoute`]: rama_net::client::ProxyRoute
    ///
    /// Simplified flow of how the [`EasyHttpWebClient`] works:
    /// 1. External: let response = client.serve(request)
    /// 2. Internal: let http_connection = self.connector.serve(request)
    /// 3. Internal: let response = jit_layers.layer(http_connection).serve(request)
    pub fn with_jit_layer<T>(self, jit_layers: T) -> EasyHttpWebClient<BodyIn, ConnResponse, T> {
        EasyHttpWebClient {
            connector: self.connector,
            plaintext_http_proxy_mode: self.plaintext_http_proxy_mode,
            jit_layers,
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// Enable or disable carrying plaintext HTTP through an HTTP(S) proxy with
        /// CONNECT instead of using ordinary forward-proxy semantics
        /// (absolute-form on HTTP/1).
        ///
        /// If this method is not called, a request-level
        /// [`PlaintextHttpProxyMode`]
        /// is honored and
        /// otherwise forwarding is the connector default. Calling this method
        /// explicitly selects Tunnel (`true`) or Forward (`false`) for the client.
        /// Tunneling does not encrypt the origin traffic: a plaintext `http://`
        /// request remains plaintext inside the proxy tunnel.
        pub fn tunnel_plaintext_http(mut self, enabled: bool) -> Self {
            self.plaintext_http_proxy_mode = Some(if enabled {
                PlaintextHttpProxyMode::Tunnel
            } else {
                PlaintextHttpProxyMode::Forward
            });
            self
        }
    }
}

/// The connection a request is served on, with the facts of that connection applied to it
/// closest to the wire: whatever middleware did to the request, its [`Egress`] snapshot is
/// the one of this connection, and a `Proxy-Authorization` field only stays on it when it
/// reaches an HTTP proxy which forwards the request.
#[derive(Debug, Clone)]
pub struct ConnectionEgress<S> {
    inner: S,
    extensions: Extensions,
}

impl<S: ExtensionsRef> ConnectionEgress<S> {
    /// Serve requests on `inner` with the facts of that connection.
    pub fn new(inner: S) -> Self {
        let extensions = inner.extensions().clone();
        Self { inner, extensions }
    }
}

impl<S> ExtensionsRef for ConnectionEgress<S> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<S, RequestBody> Service<Request<RequestBody>> for ConnectionEgress<S>
where
    S: Service<Request<RequestBody>>,
    RequestBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut request: Request<RequestBody>) -> Result<Self::Output, Self::Error> {
        let forwarded = self
            .extensions
            .get_ref::<EstablishedProxyRoute>()
            .is_some_and(EstablishedProxyRoute::is_http_forward);
        request.extensions().insert(Egress(self.extensions.clone()));
        if !forwarded {
            remove_proxy_auth_request_headers(request.headers_mut());
        }
        self.inner.serve(request).await
    }
}

impl<Body, ConnectionBody, Connection, IncomingBody, L> Service<Request<Body>>
    for EasyHttpWebClient<Body, EstablishedClientConnection<Connection, Request<ConnectionBody>>, L>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    Connection: Service<Request<ConnectionBody>, Output = Response<IncomingBody>, Error = BoxError>
        + ExtensionsRef,
    IncomingBody: Send + Sync + 'static,
    ResponseBody: From<IncomingBody>,
    // Body type this connection will be able to send, this is not necessarily the same one that
    // was used in the request that created this connection
    ConnectionBody:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    L: Layer<
            MapResponseBody<ConnectionEgress<Connection>, fn(IncomingBody) -> ResponseBody>,
            Service: Service<Request<ConnectionBody>, Output = Response, Error = BoxError>,
        > + Send
        + Sync
        + 'static,
{
    type Output = Response;
    type Error = OpaqueError;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        let uri = req.uri().clone();

        if let Some(mode) = self.plaintext_http_proxy_mode {
            req.extensions().insert(mode);
        }

        let EstablishedClientConnection {
            input: req,
            conn: http_connection,
        } = self.connector.serve(req).await.into_opaque_error()?;

        // Published for the JIT layers above; the connection publishes its own facts again
        // once those layers have run.
        let http_connection = ConnectionEgress::new(http_connection);
        req.extensions()
            .insert(Egress(http_connection.extensions().clone()));

        let http_connection = MapResponseBody::into_boxed_streaming_body(http_connection);
        let http_connection = self.jit_layers.layer(http_connection);

        // NOTE: stack might change request version based on connector data,
        tracing::trace!(url.full = %uri, "send http req to connector stack");

        let result = http_connection.serve(req).await;

        match result {
            Ok(resp) => {
                tracing::trace!(url.full = %uri, "response received from connector stack");
                Ok(resp)
            }
            Err(err) => Err(err
                .context("http request failure")
                .context_field("uri", uri)
                .into_opaque_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        fmt::Debug,
        net::{Ipv4Addr, Ipv6Addr},
        num::NonZeroUsize,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use crate::dns::client::{
        lb::{DnsLoadBalancerConfig, DnsLoadBalancerLayer, RoundRobinPicker},
        resolver::DnsAddressResolver,
    };
    use crate::net::{
        ConnectorTargetInputExt as _,
        address::{Domain, HostWithPort},
        mode::DnsResolveIpMode,
    };
    use rama_core::extensions::Extensions;
    use rama_core::futures::{Stream, stream};
    use rama_core::{error::BoxErrorExt as _, service::service_fn};
    use rama_http::{Body, BodyExtractExt, Version, proxy::ProxyRequestBody};
    use rama_http_backend::server::HttpServer;
    use rama_net::{
        address::{ProxyAddress, ProxyProtocol},
        client::{
            ConnectRequest, ConnectionError, ConnectionErrorDomain, ConnectionErrorKind,
            ConnectorService, ConnectorTarget, EstablishedProxyRoute, PlaintextProxyOnly,
            ProxyRoute, ProxyRouteFailureCache, ProxyRouteFailureCacheConfig,
            ProxyRouteFailureCacheScope, ProxyRoutes,
        },
        http::TargetHttpVersion,
        test_utils::client::{MockConnectorService, MockSocket},
    };
    use rama_utils::octets::kib;
    use serde::{Deserialize, Serialize};
    use tokio::time::sleep;

    #[cfg(feature = "boring")]
    use {
        crate::{
            net::address::SocketAddress,
            tcp::{TcpStream, server::TcpListener},
            tls::{
                boring::{TlsStream, server::TlsAcceptorLayer},
                client::{NegotiatedTlsParameters, ServerVerifyMode, TlsServerVerify},
                server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
            },
        },
        rama_core::{extensions::ExtensionsRef as _, layer::MapInputLayer},
        rama_http::header::CONNECTION,
    };

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Output {
        conn: usize,
        resp: usize,
        target: String,
    }

    #[tokio::test]
    async fn default_client_request_future_stays_within_stack_budget() {
        let client = DefaultHttpWebClient::<Body>::default();
        let request = Request::builder()
            .uri("https://example.com/")
            .body(Body::empty())
            .unwrap();
        let request = client.serve(request);
        let inner_size = std::mem::size_of_val(&request);
        let request = tokio::time::timeout(Duration::from_secs(1), request);
        let size = std::mem::size_of_val(&request);
        eprintln!("default client request: {inner_size} bytes; with timeout: {size} bytes");
        assert!(
            size <= kib(16),
            "default client request future is {size} bytes"
        );
    }

    #[test]
    fn default_client_can_be_constructed_and_cloned_without_a_runtime() {
        let client = DefaultHttpWebClient::<Body>::default();
        drop(client.clone());
        drop(client);
    }

    #[derive(Debug, Clone, Default, ExtensionsRef)]
    struct EmptyHttpConnection {
        extensions: Extensions,
    }

    impl Service<Request> for EmptyHttpConnection {
        type Output = Response;
        type Error = BoxError;

        async fn serve(&self, _request: Request) -> Result<Self::Output, Self::Error> {
            Ok(Response::new(Body::empty()))
        }
    }

    #[derive(Debug, Clone)]
    struct InspectConnectionRouteLayer(EstablishedProxyRoute);

    impl<S: ExtensionsRef> Layer<S> for InspectConnectionRouteLayer {
        type Service = S;

        fn layer(&self, inner: S) -> Self::Service {
            assert_eq!(
                inner.extensions().get_ref::<EstablishedProxyRoute>(),
                Some(&self.0),
            );
            inner
        }
    }

    fn dummy_server() -> impl Service<
        ConnectRequest,
        Output = EstablishedClientConnection<MockSocket, ConnectRequest>,
        Error = Infallible,
    > + Clone {
        let created_connections = Arc::new(AtomicUsize::new(0));
        MockConnectorService::new(move |input: &ConnectRequest| {
            let created_connections = created_connections.clone();
            let conn = created_connections.fetch_add(1, Ordering::Relaxed);
            let target = input.connector_target().unwrap().to_string();

            // count responses created on this specific connection
            let created_response = Arc::new(AtomicUsize::new(0));

            HttpServer::auto(WeakScope::detached()).service(service_fn(move |_req: Request| {
                let created_response = created_response.clone();
                let resp = created_response.fetch_add(1, Ordering::Relaxed);
                let target = target.clone();
                async move {
                    sleep(Duration::from_millis(5)).await;
                    let out = Output { conn, resp, target };
                    let resp = Response::new(Body::from(serde_json::to_vec(&out).unwrap()));
                    Ok::<_, Infallible>(resp)
                }
            }))
        })
    }

    /// The restriction the tunnel carries describes the connection to the
    /// proxy, which the origin's TLS inputs cannot change: it serves the next
    /// origin request whether or not that one carries the same overrides.
    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    ))]
    fn assert_tunnel_serves_the_same_proxy(
        conn: &crate::extensions::Extensions,
        route: &ProxyRoute,
    ) {
        use crate::extensions::Extensions;
        use crate::net::client::pool::ConnectionReuse;
        use crate::tls::client::{ServerVerifyMode, TlsServerName, TlsServerVerify};

        // The rules of the connection to the proxy crossed the CONNECT boundary first; the origin's own
        // were published on top of them.
        let leg = conn
            .self_first_ref::<ConnectionReuse>()
            .expect("the tunnel carries the rules of the connection to the proxy");
        assert!(
            !leg.is_complete(),
            "the connection to the proxy does not describe the origin"
        );

        let routed = || {
            let request = Extensions::new();
            request.insert(route.clone());
            request
        };
        let same = routed();
        same.insert(TlsServerVerify(ServerVerifyMode::Disable));
        same.insert(TlsServerName(crate::net::address::Host::from_static(
            "elsewhere.example",
        )));
        assert!(
            leg.matches(&same),
            "a request with the same TLS inputs reuses the tunnel"
        );
        assert!(
            leg.matches(&routed()),
            "the rules of the connection to the proxy do not read the origin's TLS inputs"
        );

        // A request that asks for other settings towards the proxy is a
        // different connection to the proxy, even with the same origin TLS inputs.
        let other_hop = routed();
        let bag = Extensions::new();
        bag.insert(TlsServerVerify(ServerVerifyMode::Disable));
        other_hop.insert(crate::net::client::ProxyConnectionExtensions(bag));
        assert!(
            !leg.matches(&other_hop),
            "a request with other hop settings never shares this tunnel"
        );
    }

    fn proxy_authority() -> HostWithPort {
        HostWithPort::try_from("proxy.example:8080").unwrap()
    }

    fn origin_authority() -> HostWithPort {
        HostWithPort::try_from("example.com:80").unwrap()
    }

    type ProxyHttpOver<T> =
        ProxyServiceConnector<HttpConnector<PlaintextProxyOnly<T>, ProxyRequestBody<Body>>>;

    fn proxies_over<T>(
        transport: T,
    ) -> ProxyConnector<
        ProxySocksMethod<PlaintextProxyOnly<T>>,
        proxy::layer::HttpConnectProxyConnector<ProxyDialer<ProxyHttpOver<T>>>,
        ProxyConnectUdpMethod<ProxyHttpOver<T>>,
        proxy::HttpForwardProxyConnector<ProxyDialer<ProxyHttpOver<T>>>,
    >
    where
        T: Clone + Service<ConnectRequest>,
        HttpConnector<PlaintextProxyOnly<T>, ProxyRequestBody<Body>>:
            ConnectorService<ConnectRequest>,
    {
        ProxyConnector::builder(WeakScope::detached())
            .with_custom_tcp_connector(transport)
            .without_dns_connector()
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .with_all_proxy_protocols()
            .build()
    }

    #[tokio::test]
    async fn custom_connector_receives_plaintext_http_proxy_mode() {
        let connector = service_fn(|request: Request| async move {
            assert_eq!(
                request.extensions().get_ref::<PlaintextHttpProxyMode>(),
                Some(&PlaintextHttpProxyMode::Tunnel)
            );

            let conn = EmptyHttpConnection::default();
            Ok::<_, Infallible>(EstablishedClientConnection {
                input: request,
                conn,
            })
        });
        let client = EasyHttpWebClient::new(connector).with_tunnel_plaintext_http(true);
        let request = Request::builder()
            .uri("http://example.com/")
            .body(Body::empty())
            .unwrap();

        let response = client.serve(request).await.unwrap();
        assert_eq!(response.status(), crate::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn jit_layer_can_read_established_connection_extensions() {
        let connector = service_fn(|request: Request| async move {
            let conn = EmptyHttpConnection::default();
            conn.extensions().insert(EstablishedProxyRoute::Direct);
            Ok::<_, Infallible>(EstablishedClientConnection {
                input: request,
                conn,
            })
        });
        let client = EasyHttpWebClient::new(connector)
            .with_jit_layer(InspectConnectionRouteLayer(EstablishedProxyRoute::Direct));
        let request = Request::builder()
            .uri("http://example.com/")
            .extension(ProxyRoute::Direct)
            .body(Body::empty())
            .unwrap();

        let response = client.serve(request).await.unwrap();
        assert_eq!(response.status(), crate::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn a_custom_connector_sends_proxy_credentials_only_over_a_forward_connection() {
        use rama_core::layer::MapInputLayer;
        use rama_http::{HeaderValue, header::PROXY_AUTHORIZATION};

        #[derive(Debug, Clone, ExtensionsRef)]
        struct RecordingConnection {
            extensions: Extensions,
            observed: Arc<parking_lot::Mutex<Option<HeaderValue>>>,
        }

        impl Service<Request> for RecordingConnection {
            type Output = Response;
            type Error = BoxError;

            async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
                *self.observed.lock() = request.headers().get(PROXY_AUTHORIZATION).cloned();
                Ok(Response::new(Body::empty()))
            }
        }

        let proxy: ProxyAddress = "http://upstream:secret@proxy.example:8080".parse().unwrap();
        let forward = EstablishedProxyRoute::Forward(proxy.clone());
        for (route, jit, expected) in [
            (
                Some(EstablishedProxyRoute::Direct),
                Some("Basic aml0"),
                None,
            ),
            (
                Some(EstablishedProxyRoute::Tunnel(proxy.clone())),
                Some("Basic aml0"),
                None,
            ),
            (
                Some(forward.clone()),
                Some("Basic aml0"),
                Some("Basic aml0"),
            ),
            (Some(forward.clone()), None, Some("Basic Y2FsbGVy")),
            (None, None, None),
        ] {
            let observed = Arc::new(parking_lot::Mutex::new(None));
            let connector = service_fn({
                let observed = observed.clone();
                move |request: Request| {
                    let route = route.clone();
                    let observed = observed.clone();
                    async move {
                        let extensions = Extensions::new();
                        if let Some(route) = route {
                            extensions.insert(route);
                        }
                        Ok::<_, Infallible>(EstablishedClientConnection {
                            input: request,
                            conn: RecordingConnection {
                                extensions,
                                observed,
                            },
                        })
                    }
                }
            });
            let request = Request::builder()
                .uri("http://origin.example/resource")
                .header(PROXY_AUTHORIZATION, "Basic Y2FsbGVy")
                .body(Body::empty())
                .unwrap();

            EasyHttpWebClient::new(connector)
                .with_jit_layer(MapInputLayer::new(move |mut request: Request| {
                    if let Some(jit) = jit {
                        request
                            .headers_mut()
                            .insert(PROXY_AUTHORIZATION, HeaderValue::from_static(jit));
                    }
                    request
                }))
                .serve(request)
                .await
                .unwrap();

            assert_eq!(*observed.lock(), expected.map(HeaderValue::from_static));
        }
    }

    #[tokio::test]
    async fn a_jit_layer_which_rewrites_the_requested_route_sends_no_credentials() {
        use rama_core::layer::MapInputLayer;

        let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let proxies = ProxyConnector::builder(WeakScope::detached())
            .with_custom_tcp_connector(())
            .without_dns_connector()
            .without_tls_support()
            .with_custom_http_connector::<Body, _>(RecordingConnector::new(None, &log))
            .without_connection_pool()
            .with_http_forward()
            .build();
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(())
            .without_dns_connector()
            .with_proxy_support(proxies)
            .without_tls_support()
            .with_custom_http_connector(RecordingConnector::new(None, &log))
            .without_proxy_route_failure_cache()
            .without_connection_pool()
            .build_client()
            .with_jit_layer(MapInputLayer::new(|request: Request| {
                request.extensions().insert(ProxyRoute::Direct);
                request
            }));
        let request = Request::builder()
            .uri("http://origin.example/resource")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ProxyRoute::Proxy(
            "http://u:p@proxy.example:8080".parse().unwrap(),
        ));

        client.serve(request).await.unwrap();

        let log = log.lock();
        assert_eq!(log.len(), 1);
        let (authority, target, auth) = &log[0];
        assert_eq!(
            authority,
            &HostWithPort::try_from("proxy.example:8080").unwrap(),
            "the connection is the one the route asked for",
        );
        assert_eq!(target, "http://origin.example/resource");
        assert_eq!(
            auth.as_deref(),
            None,
            "a route which no longer names the proxy reached names no credentials",
        );
    }

    #[tokio::test]
    async fn jit_request_metadata_cannot_change_a_custom_connectors_route_or_credentials() {
        use rama_core::layer::{MapInputLayer, MapOutputLayer};
        use rama_http::{HeaderValue, StatusCode, header::PROXY_AUTHORIZATION, proto::h1::head};

        #[derive(Debug, Clone, ExtensionsRef)]
        struct InspectProxyConnection {
            extensions: Extensions,
        }

        impl Service<Request> for InspectProxyConnection {
            type Output = Response;
            type Error = BoxError;

            async fn serve(&self, request: Request) -> Result<Response, BoxError> {
                let route = self.extensions.get_ref::<EstablishedProxyRoute>();
                let is_forward = route.is_some_and(EstablishedProxyRoute::is_http_forward);
                assert_eq!(
                    request
                        .extensions()
                        .egress()
                        .unwrap()
                        .0
                        .get_ref::<EstablishedProxyRoute>(),
                    route,
                    "the client publishes the facts of the connection, not stale metadata",
                );
                assert_eq!(
                    request.extensions().get_ref::<ProxyRoute>(),
                    Some(&ProxyRoute::Proxy(
                        "http://wrong:request-secret@requested.example:8080"
                            .parse()
                            .unwrap(),
                    )),
                    "the caller's requested route is preserved",
                );
                let mut target = Vec::new();
                head::encode_request_target(
                    request.method(),
                    request.uri(),
                    request.extensions(),
                    &mut target,
                )
                .unwrap();
                if is_forward {
                    // A custom connector owns the credentials of the proxy it reaches.
                    assert_eq!(
                        request.headers().get(PROXY_AUTHORIZATION).unwrap(),
                        "Basic downstream-secret",
                    );
                    assert_eq!(&target[..], b"http://origin.example/resource");
                } else {
                    assert!(request.headers().get(PROXY_AUTHORIZATION).is_none());
                    assert_eq!(&target[..], b"/resource");
                }
                Ok(Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header("proxy-authenticate", "Basic realm=private-upstream")
                    .body(Body::from("private upstream challenge"))
                    .unwrap())
            }
        }

        let proxy: ProxyAddress = "http://upstream:secret@proxy.example:8080".parse().unwrap();
        for route in [
            None,
            Some(EstablishedProxyRoute::Direct),
            Some(EstablishedProxyRoute::Tunnel(proxy.clone())),
            Some(EstablishedProxyRoute::Tunnel(
                "socks5://proxy.example:1080".parse().unwrap(),
            )),
            Some(EstablishedProxyRoute::Forward(proxy.clone())),
        ] {
            let is_forward = route
                .as_ref()
                .is_some_and(EstablishedProxyRoute::is_http_forward);
            let connector = service_fn(move |request: Request| {
                let route = route.clone();
                async move {
                    let extensions = Extensions::new();
                    if let Some(route) = route {
                        extensions.insert(route);
                    }
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        input: request,
                        conn: InspectProxyConnection { extensions },
                    })
                }
            });
            let stale_route = if is_forward {
                EstablishedProxyRoute::Direct
            } else {
                EstablishedProxyRoute::Forward(proxy.clone())
            };
            let observed_responses = Arc::new(AtomicUsize::new(0));
            let client = EasyHttpWebClient::new(connector).with_jit_layer((
                MapInputLayer::new(move |mut request: Request| {
                    request.extensions().insert(stale_route.clone());
                    let stale_egress = Extensions::new();
                    stale_egress.insert(stale_route.clone());
                    request.extensions().insert(Egress(stale_egress));
                    request.headers_mut().insert(
                        PROXY_AUTHORIZATION,
                        HeaderValue::from_static("Basic downstream-secret"),
                    );
                    request
                }),
                MapOutputLayer::new({
                    let observed_responses = observed_responses.clone();
                    move |response: Response| {
                        observed_responses.fetch_add(1, Ordering::Relaxed);
                        response
                    }
                }),
            ));
            let request = Request::builder()
                .uri("http://origin.example/resource")
                .body(Body::empty())
                .unwrap();
            request.extensions().insert(ProxyRoute::Proxy(
                "http://wrong:request-secret@requested.example:8080"
                    .parse()
                    .unwrap(),
            ));

            let response = client.serve(request).await.unwrap();

            assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
            assert_eq!(observed_responses.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn jit_request_metadata_cannot_change_proxy_credentials_target_or_challenge_isolation() {
        use rama_core::layer::{MapInputLayer, MapOutputLayer};
        use rama_http::{HeaderValue, StatusCode, header::PROXY_AUTHORIZATION, proto::h1::head};

        #[derive(Debug, Clone, ExtensionsRef)]
        struct InspectProxyConnection {
            extensions: Extensions,
        }

        impl<B: Send + 'static> Service<Request<B>> for InspectProxyConnection {
            type Output = Response;
            type Error = BoxError;

            async fn serve(&self, request: Request<B>) -> Result<Response, BoxError> {
                let route = self.extensions.get_ref::<EstablishedProxyRoute>();
                let is_forward = route.is_some_and(EstablishedProxyRoute::is_http_forward);
                let mut target = Vec::new();
                head::encode_request_target(
                    request.method(),
                    request.uri(),
                    request.extensions(),
                    &mut target,
                )
                .unwrap();
                if is_forward {
                    assert_eq!(
                        request.extensions().get_ref::<ProxyRoute>(),
                        Some(&ProxyRoute::Proxy(
                            "http://upstream:secret@proxy.example:8080".parse().unwrap(),
                        )),
                        "forward policy must preserve the caller's requested route",
                    );
                    assert_eq!(
                        request.headers().get(PROXY_AUTHORIZATION).unwrap(),
                        "Basic dXBzdHJlYW06c2VjcmV0",
                    );
                    assert_eq!(&target[..], b"http://origin.example/resource");
                } else {
                    assert!(request.headers().get(PROXY_AUTHORIZATION).is_none());
                    assert_eq!(&target[..], b"/resource");
                }
                Ok(Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header("proxy-authenticate", "Basic realm=private-upstream")
                    .body(Body::from("private upstream challenge"))
                    .unwrap())
            }
        }

        #[derive(Debug, Clone, Copy)]
        struct InspectingConnector;

        impl Service<ConnectRequest> for InspectingConnector {
            type Output = EstablishedClientConnection<InspectProxyConnection, ConnectRequest>;
            type Error = ConnectionError;

            async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
                Ok(EstablishedClientConnection {
                    conn: InspectProxyConnection {
                        extensions: speaks_requested_version(&input),
                    },
                    input,
                })
            }
        }

        impl<S> Layer<S> for InspectingConnector {
            type Service = Self;

            fn layer(&self, _: S) -> Self::Service {
                *self
            }
        }

        let proxy = ProxyRoute::Proxy("http://upstream:secret@proxy.example:8080".parse().unwrap());
        for isolate in [false, true] {
            for is_forward in [false, true] {
                let proxies = ProxyConnector::builder(WeakScope::detached())
                    .with_custom_tcp_connector(())
                    .without_dns_connector()
                    .without_tls_support()
                    .with_custom_http_connector::<Body, _>(InspectingConnector)
                    .without_connection_pool()
                    .with_http_forward()
                    .build()
                    .with_isolate_forward_proxy_auth_error(isolate);
                let stale_route = if is_forward {
                    EstablishedProxyRoute::Direct
                } else {
                    EstablishedProxyRoute::Forward(
                        "http://upstream:secret@proxy.example:8080".parse().unwrap(),
                    )
                };
                let observed_responses = Arc::new(AtomicUsize::new(0));
                let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
                    .with_custom_tcp_connector(())
                    .without_dns_connector()
                    .with_proxy_support(proxies)
                    .without_tls_support()
                    .with_custom_http_connector(InspectingConnector)
                    .without_connection_pool()
                    .build_client()
                    .with_jit_layer((
                        MapInputLayer::new(move |mut request: Request| {
                            request.extensions().insert(stale_route.clone());
                            let stale_egress = Extensions::new();
                            stale_egress.insert(stale_route.clone());
                            request.extensions().insert(Egress(stale_egress));
                            request.headers_mut().insert(
                                PROXY_AUTHORIZATION,
                                HeaderValue::from_static("Basic downstream-secret"),
                            );
                            request
                        }),
                        MapOutputLayer::new({
                            let observed_responses = observed_responses.clone();
                            move |response: Response| {
                                observed_responses.fetch_add(1, Ordering::Relaxed);
                                response
                            }
                        }),
                    ));
                let request = Request::builder()
                    .uri("http://origin.example/resource")
                    .body(Body::empty())
                    .unwrap();
                if is_forward {
                    request.extensions().insert(proxy.clone());
                }
                let result = client.serve(request).await;
                if isolate && is_forward {
                    assert!(result.is_err());
                    assert_eq!(observed_responses.load(Ordering::Relaxed), 0);
                } else {
                    assert_eq!(
                        result.unwrap().status(),
                        StatusCode::PROXY_AUTHENTICATION_REQUIRED
                    );
                    assert_eq!(observed_responses.load(Ordering::Relaxed), 1);
                }
            }
        }
    }

    #[derive(Debug, Clone, ExtensionsRef)]
    struct RecordingConnection {
        extensions: Extensions,
        authority: HostWithPort,
        log: Arc<parking_lot::Mutex<Vec<(HostWithPort, String, Option<String>)>>>,
    }

    impl<B: Send + 'static> Service<Request<B>> for RecordingConnection {
        type Output = Response;
        type Error = BoxError;

        async fn serve(&self, request: Request<B>) -> Result<Self::Output, Self::Error> {
            use rama_http::{header::PROXY_AUTHORIZATION, proto::h1::head};

            let mut target = Vec::new();
            head::encode_request_target(
                request.method(),
                request.uri(),
                request.extensions(),
                &mut target,
            )
            .unwrap();
            self.log.lock().push((
                self.authority.clone(),
                String::from_utf8(target).unwrap(),
                request
                    .headers()
                    .get(PROXY_AUTHORIZATION)
                    .map(|auth| auth.to_str().unwrap().to_owned()),
            ));
            Ok(Response::new(Body::empty()))
        }
    }

    #[derive(Debug, Clone)]
    struct RecordingConnector {
        unavailable: Option<HostWithPort>,
        failures: Arc<AtomicUsize>,
        log: Arc<parking_lot::Mutex<Vec<(HostWithPort, String, Option<String>)>>>,
    }

    impl RecordingConnector {
        fn new(
            unavailable: Option<HostWithPort>,
            log: &Arc<parking_lot::Mutex<Vec<(HostWithPort, String, Option<String>)>>>,
        ) -> Self {
            Self {
                unavailable,
                failures: Arc::new(AtomicUsize::new(0)),
                log: log.clone(),
            }
        }
    }

    impl Service<ConnectRequest> for RecordingConnector {
        type Output = EstablishedClientConnection<RecordingConnection, ConnectRequest>;
        type Error = ConnectionError;

        async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
            // Only the first attempt of a route fails, so a plan can reach the same proxy
            // again with another credential.
            if self.unavailable.as_ref() == Some(&input.authority)
                && self.failures.fetch_add(1, Ordering::Relaxed) == 0
            {
                return Err(ConnectionError::transport(
                    BoxError::from_static_str("proxy unavailable"),
                    ConnectionErrorKind::Unavailable,
                ));
            }
            let conn = RecordingConnection {
                extensions: speaks_requested_version(&input),
                authority: input.authority.clone(),
                log: self.log.clone(),
            };
            Ok(EstablishedClientConnection { input, conn })
        }
    }

    impl<S> Layer<S> for RecordingConnector {
        type Service = Self;

        fn layer(&self, _: S) -> Self::Service {
            self.clone()
        }
    }

    fn speaks_requested_version(input: &ConnectRequest) -> Extensions {
        let extensions = Extensions::new();
        if let Some(version) = input.extensions().get_ref::<TargetHttpVersion>() {
            extensions.insert(*version);
        }
        extensions
    }

    fn recording_client(
        proxy_http: RecordingConnector,
        origin_http: RecordingConnector,
    ) -> impl Service<Request, Output = Response, Error = OpaqueError> {
        let proxies = ProxyConnector::builder(WeakScope::detached())
            .with_custom_tcp_connector(())
            .without_dns_connector()
            .without_tls_support()
            .with_custom_http_connector::<Body, _>(proxy_http)
            .without_connection_pool()
            .with_http_forward()
            .build();
        EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(())
            .without_dns_connector()
            .with_proxy_support(proxies)
            .without_tls_support()
            .with_custom_http_connector(origin_http)
            .without_proxy_route_failure_cache()
            .without_connection_pool()
            .build_client()
    }

    #[tokio::test]
    async fn every_forward_attempt_of_a_plan_sends_the_credentials_of_its_own_proxy() {
        for second in [
            "http://b:sb@second.example:8080",
            "http://b:sb@first.example:8080",
        ] {
            let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let client = recording_client(
                RecordingConnector::new(
                    Some(HostWithPort::try_from("first.example:8080").unwrap()),
                    &log,
                ),
                RecordingConnector::new(None, &log),
            );
            let request = Request::builder()
                .uri("http://origin.example/resource")
                .body(Body::empty())
                .unwrap();
            request.extensions().insert(ProxyRoutes::new([
                ProxyRoute::Proxy("http://a:sa@first.example:8080".parse().unwrap()),
                ProxyRoute::Proxy(second.parse().unwrap()),
            ]));

            client.serve(request).await.unwrap();

            let log = log.lock();
            assert_eq!(log.len(), 1, "{second}: only the reached proxy is served");
            let (authority, target, auth) = &log[0];
            assert_eq!(
                authority,
                &HostWithPort::try_from(second.rsplit('@').next().unwrap()).unwrap(),
            );
            assert_eq!(target, "http://origin.example/resource");
            assert_eq!(
                auth.as_deref(),
                Some("Basic YjpzYg=="),
                "{second}: the credentials of the proxy actually reached",
            );
        }
    }

    #[tokio::test]
    async fn a_fallback_to_direct_carries_no_proxy_credentials() {
        use rama_http::header::PROXY_AUTHORIZATION;

        let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let client = recording_client(
            RecordingConnector::new(
                Some(HostWithPort::try_from("proxy.example:8080").unwrap()),
                &log,
            ),
            RecordingConnector::new(None, &log),
        );
        let request = Request::builder()
            .uri("http://origin.example/resource")
            .header(PROXY_AUTHORIZATION, "Basic ZG93bnN0cmVhbQ==")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ProxyRoutes::new([
            ProxyRoute::Proxy("http://u:p@proxy.example:8080".parse().unwrap()),
            ProxyRoute::Direct,
        ]));

        client.serve(request).await.unwrap();

        let log = log.lock();
        assert_eq!(log.len(), 1);
        let (authority, target, auth) = &log[0];
        assert_eq!(
            authority,
            &HostWithPort::try_from("origin.example:80").unwrap()
        );
        assert_eq!(target, "/resource");
        assert_eq!(auth.as_deref(), None);
    }

    #[derive(Debug, Clone)]
    struct TwoAddresses;

    impl DnsAddressResolver for TwoAddresses {
        type Error = Infallible;

        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            stream::iter([
                Ok(Ipv4Addr::new(10, 0, 0, 1)),
                Ok(Ipv4Addr::new(10, 0, 0, 2)),
            ])
        }

        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            stream::empty()
        }
    }

    fn round_robin() -> DnsLoadBalancerLayer<TwoAddresses, RoundRobinPicker> {
        DnsLoadBalancerLayer::new(DnsLoadBalancerConfig {
            mode: DnsResolveIpMode::SingleIpV4,
            ..DnsLoadBalancerConfig::from_parts(TwoAddresses, RoundRobinPicker::new())
        })
    }

    async fn connections_for<S>(client: &S, proxy: Option<&str>) -> Vec<Output>
    where
        S: Service<Request, Output = Response, Error: Debug>,
    {
        let mut connections = Vec::new();
        for _ in 0..4 {
            let request = Request::builder()
                .uri("http://example.com/")
                .body(Body::empty())
                .unwrap();
            if let Some(proxy) = proxy {
                request
                    .extensions()
                    .insert(ProxyRoute::Proxy(proxy.parse().unwrap()));
            }
            let response = client.serve(request).await.unwrap();
            connections.push(response.try_into_json::<Output>().await.unwrap());
        }
        connections
    }

    #[tokio::test]
    async fn a_load_balancer_above_the_pool_picks_a_pooled_connection_per_address() {
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector()
            .with_default_connection_pool()
            .with_custom_connector(round_robin())
            .build_client();

        assert_eq!(
            connections_for(&client, None).await,
            [
                Output {
                    conn: 0,
                    resp: 0,
                    target: "10.0.0.1:80".to_owned(),
                },
                Output {
                    conn: 1,
                    resp: 0,
                    target: "10.0.0.2:80".to_owned(),
                },
                Output {
                    conn: 0,
                    resp: 1,
                    target: "10.0.0.1:80".to_owned(),
                },
                Output {
                    conn: 1,
                    resp: 1,
                    target: "10.0.0.2:80".to_owned(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn a_load_balancer_above_the_proxy_pool_picks_a_pooled_connection_per_address() {
        let proxies = ProxyConnector::builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .without_tls_support()
            .with_default_http_connector::<Body>()
            .with_default_connection_pool()
            .with_custom_connector(round_robin())
            .with_http_forward()
            .build();
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .with_proxy_support(proxies)
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .build_client();

        assert_eq!(
            connections_for(&client, Some("http://proxy.example:8080")).await,
            [
                Output {
                    conn: 0,
                    resp: 0,
                    target: "10.0.0.1:8080".to_owned(),
                },
                Output {
                    conn: 1,
                    resp: 0,
                    target: "10.0.0.2:8080".to_owned(),
                },
                Output {
                    conn: 0,
                    resp: 1,
                    target: "10.0.0.1:8080".to_owned(),
                },
                Output {
                    conn: 1,
                    resp: 1,
                    target: "10.0.0.2:8080".to_owned(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn a_load_balancer_below_the_proxy_pool_does_not_split_its_connections() {
        let proxies = ProxyConnector::builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .without_tls_support()
            .with_default_http_connector::<Body>()
            .with_custom_connector(round_robin())
            .with_default_connection_pool()
            .with_http_forward()
            .build();
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .with_proxy_support(proxies)
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .build_client();

        assert_eq!(
            connections_for(&client, Some("http://proxy.example:8080")).await,
            [
                Output {
                    conn: 0,
                    resp: 0,
                    target: "10.0.0.1:8080".to_owned(),
                },
                Output {
                    conn: 0,
                    resp: 1,
                    target: "10.0.0.1:8080".to_owned(),
                },
                Output {
                    conn: 0,
                    resp: 2,
                    target: "10.0.0.1:8080".to_owned(),
                },
                Output {
                    conn: 0,
                    resp: 3,
                    target: "10.0.0.1:8080".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn blocking_client_drives_the_composed_http_stack() {
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .build_client()
            .try_into_blocking()
            .unwrap();

        let cloned = client.clone();
        drop(client);
        let response = cloned.get("http://example.com").send().unwrap();
        assert_eq!(
            response.try_into_json::<Output>().unwrap(),
            Output {
                conn: 0,
                resp: 0,
                target: "example.com:80".to_owned(),
            }
        );
    }

    #[test]
    fn default_blocking_http_client_is_cloneable_and_pooled() {
        fn assert_default_client(_: &DefaultHttpWebClient) {}

        let client = EasyHttpWebClient::try_blocking().unwrap();
        assert_default_client(client.get_ref());
        let cloned = client.clone();
        drop(client);
        let request = cloned.get("https://example.com").build().unwrap();
        assert_eq!(request.uri(), &"https://example.com".parse().unwrap());
    }

    #[cfg(feature = "ws")]
    #[test]
    fn default_blocking_http_client_builds_websocket_requests() {
        use crate::http::ws::handshake::client::BlockingHttpClientWebSocketExt as _;

        let client = EasyHttpWebClient::try_blocking().unwrap();
        let _from_url = client
            .websocket("wss://example.com/chat")
            .with_header("authorization", "Bearer secret");

        let request = Request::builder()
            .uri("wss://example.com/chat")
            .body(Body::empty())
            .unwrap();
        let _from_request = client.websocket_with_request(request);
    }

    #[tokio::test]
    async fn no_pool_tries_proxy_routes_in_order() {
        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let transport = service_fn({
            let attempts = attempts.clone();
            let direct = dummy_server();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    let dialed = input.authority.clone();
                    attempts.lock().push(dialed.clone());
                    if dialed == proxy_authority() {
                        Err(ConnectionError::transport(
                            BoxError::from_static_str("proxy unavailable"),
                            ConnectionErrorKind::Unavailable,
                        ))
                    } else {
                        direct.connect(input).await
                    }
                }
            }
        });
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(transport.clone())
            .without_dns_connector()
            .with_proxy_support(proxies_over(transport))
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .build_client();
        let proxy = ProxyRoute::Proxy("http://proxy.example:8080".parse::<ProxyAddress>().unwrap());
        let request = || {
            let request = Request::builder()
                .uri("http://example.com")
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(ProxyRoutes::new([proxy.clone(), ProxyRoute::Direct]));
            request
        };

        for _ in 0..2 {
            client
                .serve(request())
                .await
                .context("serve request through direct fallback")
                .unwrap();
        }

        assert_eq!(
            attempts.lock().as_slice(),
            [proxy_authority(), origin_authority(), origin_authority()],
        );
    }

    #[tokio::test]
    async fn no_proxy_tls_support_rejects_https_proxy() {
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .with_proxy_support(proxies_over(dummy_server()))
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .build_client();
        let request = Request::builder()
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ProxyRoutes::new([
            ProxyRoute::Proxy(
                "https://proxy.example:8443"
                    .parse::<ProxyAddress>()
                    .unwrap(),
            ),
            ProxyRoute::Direct,
        ]));

        let error =
            ConnectionError::from(client.serve(request).await.unwrap_err().into_box_error());
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
    }

    #[tokio::test]
    async fn easy_client_pools_plaintext_proxy_versions_separately() {
        let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let transport = service_fn({
            let inner = dummy_server();
            let proxy = proxy.clone();
            let dials = dials.clone();
            move |input: ConnectRequest| {
                let inner = inner.clone();
                let proxy = proxy.clone();
                let dials = dials.clone();
                async move {
                    assert_eq!(
                        input.extensions.get_ref::<ConnectorTarget>(),
                        Some(&ConnectorTarget(proxy.address.clone())),
                    );
                    assert_eq!(
                        input.extensions.get_ref::<ProxyRoute>(),
                        Some(&ProxyRoute::Direct),
                    );
                    dials.fetch_add(1, Ordering::Relaxed);
                    inner.connect(input).await
                }
            }
        });
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(transport.clone())
            .without_dns_connector()
            .with_proxy_support(proxies_over(transport))
            .without_tls_support()
            .with_default_http_connector()
            .with_default_connection_pool()
            .build_client();

        for (version, expected_conn) in [(Version::HTTP_11, 0), (Version::HTTP_2, 1)] {
            let request = Request::builder()
                .uri("http://example.com")
                .version(version)
                .body(Body::empty())
                .unwrap();
            request.extensions().insert(ProxyRoutes::from(ProxyAddress {
                protocol: ProxyProtocol::Http {
                    version: Some(version),
                    secure: false,
                    path_template: None,
                },
                ..proxy.clone()
            }));

            let response = client.serve(request).await.unwrap();
            assert_eq!(response.version(), version);
            assert_eq!(
                response.try_into_json::<Output>().await.unwrap(),
                Output {
                    conn: expected_conn,
                    resp: 0,
                    target: "proxy.example:8080".to_owned(),
                },
            );
        }
        assert_eq!(dials.load(Ordering::Relaxed), 2);
    }

    #[cfg(feature = "socks5")]
    #[tokio::test]
    async fn umbrella_proxy_connector_falls_back_across_supported_plan() {
        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let transport = service_fn({
            let attempts = attempts.clone();
            let direct = dummy_server();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    let dialed = input.authority.clone();
                    attempts.lock().push(dialed.clone());
                    if dialed == origin_authority() {
                        direct.connect(input).await
                    } else {
                        Err(ConnectionError::transport(
                            BoxError::from_static_str("proxy unavailable"),
                            ConnectionErrorKind::Unavailable,
                        ))
                    }
                }
            }
        });
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(transport.clone())
            .without_dns_connector()
            .with_proxy_support(proxies_over(transport))
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .build_client();
        let request = Request::builder()
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();
        let socks = ProxyRoute::Proxy(
            "socks5://socks.example:1080"
                .parse::<ProxyAddress>()
                .unwrap(),
        );
        let http = ProxyRoute::Proxy("http://http.example:8080".parse::<ProxyAddress>().unwrap());
        request.extensions().insert(ProxyRoutes::new([
            socks.clone(),
            http.clone(),
            ProxyRoute::Direct,
        ]));

        let response = client.serve(request).await.unwrap();
        let output = response.try_into_json::<Output>().await.unwrap();
        assert_eq!(
            output,
            Output {
                conn: 0,
                resp: 0,
                target: "example.com:80".to_owned(),
            }
        );
        assert_eq!(
            attempts.lock().as_slice(),
            [
                HostWithPort::try_from("socks.example:1080").unwrap(),
                HostWithPort::try_from("http.example:8080").unwrap(),
                origin_authority(),
            ],
        );
    }

    #[tokio::test]
    async fn default_pool_caches_failed_route_and_reuses_selected_connection() {
        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let transport = service_fn({
            let attempts = attempts.clone();
            let direct = dummy_server();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    let dialed = input.authority.clone();
                    attempts.lock().push(dialed.clone());
                    if dialed == proxy_authority() {
                        Err(ConnectionError::transport(
                            BoxError::from_static_str("proxy unavailable"),
                            ConnectionErrorKind::Unavailable,
                        ))
                    } else {
                        direct.connect(input).await
                    }
                }
            }
        });
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(transport.clone())
            .without_dns_connector()
            .with_proxy_support(proxies_over(transport))
            .without_tls_support()
            .with_default_http_connector()
            .with_default_connection_pool()
            .build_client();
        let proxy = ProxyRoute::Proxy("http://proxy.example:8080".parse::<ProxyAddress>().unwrap());
        let request = || {
            let request = Request::builder()
                .uri("http://example.com")
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(ProxyRoutes::new([proxy.clone(), ProxyRoute::Direct]));
            request
        };

        for expected_response_index in 0..2 {
            let response = client.serve(request()).await.unwrap();
            let output = response.try_into_json::<Output>().await.unwrap();
            assert_eq!(output.conn, 0);
            assert_eq!(output.resp, expected_response_index);
        }

        assert_eq!(
            attempts.lock().as_slice(),
            [proxy_authority(), origin_authority()],
        );
    }

    #[tokio::test]
    async fn easy_client_can_disable_proxy_route_failure_cache() {
        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let transport = service_fn({
            let attempts = attempts.clone();
            let direct = dummy_server();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    let dialed = input.authority.clone();
                    attempts.lock().push(dialed.clone());
                    if dialed == proxy_authority() {
                        Err(ConnectionError::transport(
                            BoxError::from_static_str("proxy unavailable"),
                            ConnectionErrorKind::Unavailable,
                        ))
                    } else {
                        direct.connect(input).await
                    }
                }
            }
        });
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(transport.clone())
            .without_dns_connector()
            .with_proxy_support(proxies_over(transport))
            .without_tls_support()
            .with_default_http_connector()
            .without_proxy_route_failure_cache()
            .without_connection_pool()
            .build_client();
        let proxy = ProxyRoute::Proxy("http://proxy.example:8080".parse().unwrap());

        for _ in 0..2 {
            let request = Request::builder()
                .uri("http://example.com")
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(ProxyRoutes::new([proxy.clone(), ProxyRoute::Direct]));
            client.serve(request).await.unwrap();
        }

        assert_eq!(
            attempts.lock().as_slice(),
            [
                proxy_authority(),
                origin_authority(),
                proxy_authority(),
                origin_authority(),
            ],
        );
    }

    #[tokio::test]
    async fn a_proxy_free_client_does_not_fall_back_from_a_refused_proxy_route() {
        let attempts = Arc::new(parking_lot::Mutex::new(0usize));
        let transport = service_fn({
            let attempts = attempts.clone();
            let direct = dummy_server();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    *attempts.lock() += 1;
                    direct.connect(input).await
                }
            }
        });
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(transport)
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .build_client();
        let request = Request::builder()
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ProxyRoutes::new([
            ProxyRoute::Proxy("http://proxy.example:8080".parse().unwrap()),
            ProxyRoute::Direct,
        ]));

        client.serve(request).await.expect_err(
            "a refused proxy route is a configuration error, not a reason to go direct",
        );
        assert_eq!(*attempts.lock(), 0);
    }

    #[tokio::test]
    async fn forwarded_requests_reuse_the_connection_to_their_proxy() {
        let proxy_dials = Arc::new(AtomicUsize::new(0));
        let transport = service_fn({
            let proxy_dials = proxy_dials.clone();
            let server = dummy_server();
            move |input: ConnectRequest| {
                if input.authority.host == "proxy.example" {
                    proxy_dials.fetch_add(1, Ordering::Relaxed);
                }
                let server = server.clone();
                async move { server.connect(input).await }
            }
        });
        let proxies = ProxyConnector::builder(WeakScope::detached())
            .with_custom_tcp_connector(transport.clone())
            .without_dns_connector()
            .without_tls_support()
            .with_default_http_connector()
            .with_default_connection_pool()
            .with_http_forward()
            .build();
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(transport)
            .without_dns_connector()
            .with_proxy_support(proxies)
            .without_tls_support()
            .with_default_http_connector()
            .with_default_connection_pool()
            .build_client();

        for path in ["/first", "/second"] {
            let request = Request::builder()
                .uri(format!("http://example.com{path}"))
                .version(Version::HTTP_11)
                .body(Body::empty())
                .unwrap();
            request.extensions().insert(ProxyRoute::Proxy(
                "http://proxy.example:8080".parse().unwrap(),
            ));
            client
                .serve(request)
                .await
                .expect("every forwarded request is served")
                .try_into_string()
                .await
                .expect("the response body reaches its end");
        }

        assert_eq!(proxy_dials.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_proxy_free_client_refuses_a_tunneled_route() {
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .build_client();
        let request = Request::builder()
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ProxyRoute::Proxy(
            "socks5://proxy.example:1080".parse().unwrap(),
        ));

        let error = client.serve(request).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("proxy route on a client without proxy support"),
            "a client without proxy support must refuse the route, not connect around it: {error}"
        );
    }

    #[tokio::test]
    async fn a_proxy_free_client_refuses_a_forwarded_route() {
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .build_client();
        let request = Request::builder()
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ProxyRoute::Proxy(
            "http://proxy.example:8080".parse().unwrap(),
        ));

        let error = client.serve(request).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("http forward proxying is not enabled"),
            "a client without proxy support must refuse the route, not serve it another way: {error}"
        );
    }

    #[tokio::test]
    async fn easy_client_accepts_custom_proxy_route_failure_cache() {
        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let transport = service_fn({
            let attempts = attempts.clone();
            let direct = dummy_server();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    if input.authority.host == "proxy.example" {
                        attempts.lock().push("proxy");
                        Err(ConnectionError::transport(
                            BoxError::from_static_str("proxy unavailable"),
                            ConnectionErrorKind::Unavailable,
                        ))
                    } else {
                        attempts.lock().push("direct");
                        direct.connect(input).await
                    }
                }
            }
        });
        let proxies = ProxyConnector::builder(WeakScope::detached())
            .with_custom_tcp_connector(transport.clone())
            .without_dns_connector()
            .without_tls_support()
            .with_default_http_connector()
            .without_connection_pool()
            .with_http_forward()
            .build();
        let mut failure_cache_config = ProxyRouteFailureCacheConfig::default();
        failure_cache_config.scope = ProxyRouteFailureCacheScope::PerProxy;
        let failure_cache = ProxyRouteFailureCache::try_new(failure_cache_config).unwrap();
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(transport)
            .without_dns_connector()
            .with_proxy_support(proxies)
            .without_tls_support()
            .with_default_http_connector()
            .with_proxy_route_failure_cache(failure_cache)
            .without_connection_pool()
            .build_client();
        let proxy = ProxyRoute::Proxy("http://proxy.example:8080".parse().unwrap());

        for destination in ["one.example", "two.example"] {
            let request = Request::builder()
                .uri(format!("http://{destination}"))
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(ProxyRoutes::new([proxy.clone(), ProxyRoute::Direct]));
            client.serve(request).await.unwrap();
        }

        assert_eq!(attempts.lock().as_slice(), ["proxy", "direct", "direct"]);
    }

    #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    #[tokio::test]
    async fn rustls_https_proxy_alpn_is_scoped_across_connect() {
        use crate::{
            extensions::ExtensionsRef as _,
            net::{
                Protocol,
                address::HostWithPort,
                client::{EstablishedClientConnection, ProxyRoute},
                stream::service::EchoService,
                tls::{ApplicationProtocol, TlsAlpn},
            },
            tls::{
                SecureTransport,
                client::{
                    NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig, TlsServerName,
                    TlsServerVerify,
                },
                rustls::{client::TlsConnector, server::TlsAcceptorLayer},
                server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
            },
        };
        use rama_core::ServiceInput;
        use rama_crypto::cert::generate_server_auth;
        use rama_http::io::upgrade::handle_upgrade;
        use rama_http_backend::client::proxy::layer::HttpConnectProxyConnectorLayer;
        use rama_net::http::TargetHttpVersion;
        use std::sync::Arc;

        let (proxy_chain, proxy_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("proxy auth");
        let proxy_trust = proxy_chain.last().expect("proxy trust anchor").clone();
        let (origin_chain, origin_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("origin auth");
        let origin_trust = origin_chain.last().expect("origin trust anchor").clone();

        let origin_server = TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_single_cert(ServerAuthData {
                    cert_chain: origin_chain,
                    private_key: origin_key,
                    ocsp: None,
                })
                .with_alpn_http_1(),
        )
        .into_layer(EchoService::new());
        let (origin_done_tx, origin_done_rx) = tokio::sync::oneshot::channel();
        let origin_done_tx = Arc::new(parking_lot::Mutex::new(Some(origin_done_tx)));

        let connect_version = Arc::new(parking_lot::Mutex::new(None));
        let observed_version = connect_version.clone();
        let proxy_sni = Arc::new(parking_lot::Mutex::new(None));
        let observed_sni = proxy_sni.clone();
        let proxy_http =
            HttpServer::auto(WeakScope::detached()).service(service_fn(move |req: Request| {
                let origin_server = origin_server.clone();
                let origin_done_tx = origin_done_tx.clone();
                let observed_version = observed_version.clone();
                let observed_sni = observed_sni.clone();
                async move {
                    assert_eq!(req.method(), rama_http::Method::CONNECT);
                    *observed_version.lock() = Some(req.version());
                    *observed_sni.lock() = req
                        .extensions()
                        .get_ref::<SecureTransport>()
                        .and_then(SecureTransport::client_hello)
                        .and_then(|hello| hello.ext_server_name().cloned());
                    let upgrade = handle_upgrade(&req);
                    tokio::spawn(async move {
                        let tunnel = upgrade.await.expect("server CONNECT upgrade");
                        // The client deliberately drops immediately after the
                        // handshake assertions, so the TLS server may finish
                        // with an EOF/close-notify error.
                        let _origin_result = origin_server.serve(tunnel).await;
                        if let Some(tx) = origin_done_tx.lock().take() {
                            tx.send(()).expect("origin completion receiver");
                        }
                    });
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                }
            }));
        let proxy_server = TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_single_cert(ServerAuthData {
                    cert_chain: proxy_chain,
                    private_key: proxy_key,
                    ocsp: None,
                })
                .with_alpn_http_2(),
        )
        .with_store_client_hello(true)
        .into_layer(proxy_http);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_io = Arc::new(parking_lot::Mutex::new(Some(client_io)));
        let transport = service_fn(move |input: ConnectRequest| {
            let conn = ServiceInput::new(client_io.lock().take().expect("one proxy connection"));
            async move { Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn }) }
        });

        let proxy_config = TlsClientConfig::new()
            .with_alpn_http_2()
            .with_server_name(crate::net::address::Host::from_static("localhost"))
            .try_with_server_trust_anchors([proxy_trust])
            .expect("proxy trust");
        let proxy_tls = TlsConnector::auto(transport).with_base_config(proxy_config);
        let proxy_connections =
            HttpConnector::<_, ProxyRequestBody<Body>>::new(proxy_tls, WeakScope::detached());
        let proxy = HttpConnectProxyConnectorLayer::new().into_layer(proxy_connections);
        let origin_config = TlsClientConfig::new()
            .with_alpn(Default::default())
            .with_server_name(crate::net::address::Host::from_static("localhost"))
            .try_with_server_trust_anchors([origin_trust])
            .expect("origin trust");
        let connector = TlsConnector::auto(proxy).with_base_config(origin_config);

        let input = ConnectRequest::new(HostWithPort::try_from("localhost:443").unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions.insert(ProxyRoute::Proxy(
            "h2://localhost:8443".parse::<ProxyAddress>().unwrap(),
        ));
        // Origin TLS inputs: they configure the origin handshake over the
        // tunnel and must not reach the handshake with the proxy.
        input.extensions.insert(TlsAlpn::http_1());
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        input
            .extensions
            .insert(TlsServerName(crate::net::address::Host::from_static(
                "elsewhere.example",
            )));
        let client = async move {
            let established = Box::pin(connector.serve(input))
                .await
                .expect("two TLS handshakes");

            assert_eq!(
                *connect_version.lock(),
                Some(Version::HTTP_2),
                "the connection to the proxy offers its own ALPN, never the origin's"
            );
            assert_eq!(
                proxy_sni
                    .lock()
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref(),
                Some("localhost"),
                "the connection to the proxy names the proxy, never the origin's server name"
            );
            let conn = established.conn.extensions();
            assert_eq!(
                conn.get_ref::<NegotiatedTlsParameters>()
                    .expect("origin TLS parameters")
                    .application_layer_protocol,
                Some(ApplicationProtocol::HTTP_11),
                "the origin handshake over the tunnel offers the request's ALPN"
            );
            assert_eq!(
                conn.get_ref::<TargetHttpVersion>().map(|version| version.0),
                Some(Version::HTTP_11),
                "proxy HTTP/2 must not leak past CONNECT into the origin"
            );
            assert_tunnel_serves_the_same_proxy(
                conn,
                established
                    .input
                    .extensions
                    .get_ref::<ProxyRoute>()
                    .unwrap(),
            );
            drop(established);
        };
        let (proxy_result, ()) =
            Box::pin(tokio::time::timeout(Duration::from_secs(5), async move {
                tokio::join!(proxy_server.serve(ServiceInput::new(server_io)), client)
            }))
            .await
            .expect("proxy/origin exchange");
        proxy_result.expect("proxy server");
        tokio::time::timeout(Duration::from_secs(5), origin_done_rx)
            .await
            .expect("origin server shutdown")
            .expect("origin completion signal");
    }

    #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    #[tokio::test]
    async fn rustls_proxy_alpn_never_reaches_a_no_alpn_origin() {
        use crate::{
            extensions::ExtensionsRef as _,
            net::{
                Protocol,
                address::HostWithPort,
                client::{EstablishedClientConnection, ProxyRoute},
                stream::service::EchoService,
            },
            tls::{
                SecureTransport,
                client::{
                    NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig, TlsServerName,
                    TlsServerVerify,
                },
                rustls::{client::TlsConnector, server::TlsAcceptorLayer},
                server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
            },
        };
        use rama_core::ServiceInput;
        use rama_crypto::cert::generate_server_auth;
        use rama_http::io::upgrade::handle_upgrade;
        use rama_http_backend::client::proxy::layer::HttpConnectProxyConnectorLayer;
        use rama_net::http::TargetHttpVersion;
        use std::sync::Arc;

        let (proxy_chain, proxy_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("proxy auth");
        let proxy_trust = proxy_chain.last().expect("proxy trust anchor").clone();
        let (origin_chain, origin_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("origin auth");
        let origin_trust = origin_chain.last().expect("origin trust anchor").clone();

        let origin_server =
            TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
                cert_chain: origin_chain,
                private_key: origin_key,
                ocsp: None,
            }))
            .into_layer(EchoService::new());
        let (origin_done_tx, origin_done_rx) = tokio::sync::oneshot::channel();
        let origin_done_tx = Arc::new(parking_lot::Mutex::new(Some(origin_done_tx)));

        let connect_version = Arc::new(parking_lot::Mutex::new(None));
        let observed_version = connect_version.clone();
        let proxy_sni = Arc::new(parking_lot::Mutex::new(None));
        let observed_sni = proxy_sni.clone();
        let proxy_http =
            HttpServer::auto(WeakScope::detached()).service(service_fn(move |req: Request| {
                let origin_server = origin_server.clone();
                let origin_done_tx = origin_done_tx.clone();
                let observed_version = observed_version.clone();
                let observed_sni = observed_sni.clone();
                async move {
                    assert_eq!(req.method(), rama_http::Method::CONNECT);
                    *observed_version.lock() = Some(req.version());
                    *observed_sni.lock() = req
                        .extensions()
                        .get_ref::<SecureTransport>()
                        .and_then(SecureTransport::client_hello)
                        .and_then(|hello| hello.ext_server_name().cloned());
                    let upgrade = handle_upgrade(&req);
                    tokio::spawn(async move {
                        let tunnel = upgrade.await.expect("server CONNECT upgrade");
                        // The client deliberately drops immediately after the
                        // handshake assertions, so the TLS server may finish
                        // with an EOF/close-notify error.
                        let _origin_result = origin_server.serve(tunnel).await;
                        if let Some(tx) = origin_done_tx.lock().take() {
                            tx.send(()).expect("origin completion receiver");
                        }
                    });
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                }
            }));
        let proxy_server = TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_single_cert(ServerAuthData {
                    cert_chain: proxy_chain,
                    private_key: proxy_key,
                    ocsp: None,
                })
                .with_alpn_http_2(),
        )
        .with_store_client_hello(true)
        .into_layer(proxy_http);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_io = Arc::new(parking_lot::Mutex::new(Some(client_io)));
        let transport = service_fn(move |input: ConnectRequest| {
            let conn = ServiceInput::new(client_io.lock().take().expect("one proxy connection"));
            async move { Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn }) }
        });

        let proxy_config = TlsClientConfig::new()
            .with_alpn_http_2()
            .with_server_name(crate::net::address::Host::from_static("localhost"))
            .try_with_server_trust_anchors([proxy_trust])
            .expect("proxy trust");
        let proxy_tls = TlsConnector::auto(transport).with_base_config(proxy_config);
        let proxy_connections =
            HttpConnector::<_, ProxyRequestBody<Body>>::new(proxy_tls, WeakScope::detached());
        let proxy = HttpConnectProxyConnectorLayer::new().into_layer(proxy_connections);
        let origin_config = TlsClientConfig::new()
            .with_alpn(Default::default())
            .with_server_name(crate::net::address::Host::from_static("localhost"))
            .try_with_server_trust_anchors([origin_trust])
            .expect("origin trust");
        let connector = TlsConnector::auto(proxy).with_base_config(origin_config);

        let input = ConnectRequest::new(HostWithPort::try_from("localhost:443").unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions.insert(ProxyRoute::Proxy(
            "h2://localhost:8443".parse::<ProxyAddress>().unwrap(),
        ));
        // Origin TLS inputs: they configure the origin handshake over the
        // tunnel and must not reach the handshake with the proxy.
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        input
            .extensions
            .insert(TlsServerName(crate::net::address::Host::from_static(
                "elsewhere.example",
            )));
        let client = async move {
            let established = Box::pin(connector.serve(input))
                .await
                .expect("two TLS handshakes");

            assert_eq!(
                *connect_version.lock(),
                Some(Version::HTTP_2),
                "the connection to the proxy offers its own ALPN, never the origin's"
            );
            assert_eq!(
                proxy_sni
                    .lock()
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref(),
                Some("localhost"),
                "the connection to the proxy names the proxy, never the origin's server name"
            );
            let conn = established.conn.extensions();
            assert_eq!(
                conn.get_ref::<NegotiatedTlsParameters>()
                    .expect("origin TLS parameters")
                    .application_layer_protocol,
                None,
                "an origin without an ALPN offer negotiates none"
            );
            assert!(
                conn.get_ref::<TargetHttpVersion>().is_none(),
                "proxy HTTP/2 must not leak past CONNECT into a no-ALPN origin"
            );
            assert_tunnel_serves_the_same_proxy(
                conn,
                established
                    .input
                    .extensions
                    .get_ref::<ProxyRoute>()
                    .unwrap(),
            );
            drop(established);
        };
        let (proxy_result, ()) =
            Box::pin(tokio::time::timeout(Duration::from_secs(5), async move {
                tokio::join!(proxy_server.serve(ServiceInput::new(server_io)), client)
            }))
            .await
            .expect("proxy/origin exchange");
        proxy_result.expect("proxy server");
        tokio::time::timeout(Duration::from_secs(5), origin_done_rx)
            .await
            .expect("origin server shutdown")
            .expect("origin completion signal");
    }

    #[cfg(feature = "boring")]
    #[tokio::test]
    async fn boring_https_proxy_alpn_is_scoped_across_connect() {
        use crate::{
            extensions::ExtensionsRef as _,
            net::{
                Protocol,
                address::HostWithPort,
                client::{EstablishedClientConnection, ProxyRoute},
                stream::service::EchoService,
                tls::{ApplicationProtocol, TlsAlpn},
            },
            tls::{
                SecureTransport,
                boring::{client::TlsConnector, server::TlsAcceptorLayer},
                client::{
                    NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig, TlsServerName,
                    TlsServerVerify,
                },
                server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
            },
        };
        use rama_core::ServiceInput;
        use rama_crypto::cert::generate_server_auth;
        use rama_http::io::upgrade::handle_upgrade;
        use rama_http_backend::client::proxy::layer::HttpConnectProxyConnectorLayer;
        use rama_net::http::TargetHttpVersion;
        use std::sync::Arc;

        let (proxy_chain, proxy_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("proxy auth");
        let proxy_trust = proxy_chain.last().expect("proxy trust anchor").clone();
        let (origin_chain, origin_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("origin auth");
        let origin_trust = origin_chain.last().expect("origin trust anchor").clone();

        let origin_server = TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_single_cert(ServerAuthData {
                    cert_chain: origin_chain,
                    private_key: origin_key,
                    ocsp: None,
                })
                .with_alpn_http_1(),
        )
        .into_layer(EchoService::new());
        let (origin_done_tx, origin_done_rx) = tokio::sync::oneshot::channel();
        let origin_done_tx = Arc::new(parking_lot::Mutex::new(Some(origin_done_tx)));

        let connect_version = Arc::new(parking_lot::Mutex::new(None));
        let observed_version = connect_version.clone();
        let proxy_sni = Arc::new(parking_lot::Mutex::new(None));
        let observed_sni = proxy_sni.clone();
        let proxy_http =
            HttpServer::auto(WeakScope::detached()).service(service_fn(move |req: Request| {
                let origin_server = origin_server.clone();
                let origin_done_tx = origin_done_tx.clone();
                let observed_version = observed_version.clone();
                let observed_sni = observed_sni.clone();
                async move {
                    assert_eq!(req.method(), rama_http::Method::CONNECT);
                    *observed_version.lock() = Some(req.version());
                    *observed_sni.lock() = req
                        .extensions()
                        .get_ref::<SecureTransport>()
                        .and_then(SecureTransport::client_hello)
                        .and_then(|hello| hello.ext_server_name().cloned());
                    let upgrade = handle_upgrade(&req);
                    tokio::spawn(async move {
                        let tunnel = upgrade.await.expect("server CONNECT upgrade");
                        // The client deliberately drops immediately after the
                        // handshake assertions, so the TLS server may finish
                        // with an EOF/close-notify error.
                        let _origin_result = origin_server.serve(tunnel).await;
                        if let Some(tx) = origin_done_tx.lock().take() {
                            tx.send(()).expect("origin completion receiver");
                        }
                    });
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                }
            }));
        let proxy_server = TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_single_cert(ServerAuthData {
                    cert_chain: proxy_chain,
                    private_key: proxy_key,
                    ocsp: None,
                })
                .with_alpn_http_2(),
        )
        .with_store_client_hello(true)
        .into_layer(proxy_http);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_io = Arc::new(parking_lot::Mutex::new(Some(client_io)));
        let transport = service_fn(move |input: ConnectRequest| {
            let conn = ServiceInput::new(client_io.lock().take().expect("one proxy connection"));
            async move { Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn }) }
        });

        let proxy_config = TlsClientConfig::new()
            .with_alpn_http_2()
            .with_server_name(crate::net::address::Host::from_static("localhost"))
            .try_with_server_trust_anchors([proxy_trust])
            .expect("proxy trust");
        let proxy_tls = TlsConnector::auto(transport).with_base_config(proxy_config);
        let proxy_connections =
            HttpConnector::<_, ProxyRequestBody<Body>>::new(proxy_tls, WeakScope::detached());
        let proxy = HttpConnectProxyConnectorLayer::new().into_layer(proxy_connections);
        let origin_config = TlsClientConfig::new()
            .with_alpn(Default::default())
            .with_server_name(crate::net::address::Host::from_static("localhost"))
            .try_with_server_trust_anchors([origin_trust])
            .expect("origin trust");
        let connector = TlsConnector::auto(proxy).with_base_config(origin_config);

        let input = ConnectRequest::new(HostWithPort::try_from("localhost:443").unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions.insert(ProxyRoute::Proxy(
            "h2://localhost:8443".parse::<ProxyAddress>().unwrap(),
        ));
        // Origin TLS inputs: they configure the origin handshake over the
        // tunnel and must not reach the handshake with the proxy.
        input.extensions.insert(TlsAlpn::http_1());
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        input
            .extensions
            .insert(TlsServerName(crate::net::address::Host::from_static(
                "elsewhere.example",
            )));
        let client = async move {
            let established = connector.serve(input).await.expect("two TLS handshakes");

            assert_eq!(
                *connect_version.lock(),
                Some(Version::HTTP_2),
                "the connection to the proxy offers its own ALPN, never the origin's"
            );
            assert_eq!(
                proxy_sni
                    .lock()
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref(),
                Some("localhost"),
                "the connection to the proxy names the proxy, never the origin's server name"
            );
            let conn = established.conn.extensions();
            assert_eq!(
                conn.get_ref::<NegotiatedTlsParameters>()
                    .expect("origin TLS parameters")
                    .application_layer_protocol,
                Some(ApplicationProtocol::HTTP_11),
                "the origin handshake over the tunnel offers the request's ALPN"
            );
            assert_eq!(
                conn.get_ref::<TargetHttpVersion>().map(|version| version.0),
                Some(Version::HTTP_11),
                "proxy HTTP/2 must not leak past CONNECT into the origin"
            );
            assert_tunnel_serves_the_same_proxy(
                conn,
                established
                    .input
                    .extensions
                    .get_ref::<ProxyRoute>()
                    .unwrap(),
            );
            drop(established);
        };
        let (proxy_result, ()) =
            Box::pin(tokio::time::timeout(Duration::from_secs(5), async move {
                tokio::join!(proxy_server.serve(ServiceInput::new(server_io)), client)
            }))
            .await
            .expect("proxy/origin exchange");
        proxy_result.expect("proxy server");
        tokio::time::timeout(Duration::from_secs(5), origin_done_rx)
            .await
            .expect("origin server shutdown")
            .expect("origin completion signal");
    }

    #[cfg(feature = "boring")]
    #[tokio::test]
    async fn boring_proxy_alpn_never_reaches_a_no_alpn_origin() {
        use crate::{
            extensions::ExtensionsRef as _,
            net::{
                Protocol,
                address::HostWithPort,
                client::{EstablishedClientConnection, ProxyRoute},
                stream::service::EchoService,
            },
            tls::{
                SecureTransport,
                boring::{client::TlsConnector, server::TlsAcceptorLayer},
                client::{
                    NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig, TlsServerName,
                    TlsServerVerify,
                },
                server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
            },
        };
        use rama_core::ServiceInput;
        use rama_crypto::cert::generate_server_auth;
        use rama_http::io::upgrade::handle_upgrade;
        use rama_http_backend::client::proxy::layer::HttpConnectProxyConnectorLayer;
        use rama_net::http::TargetHttpVersion;
        use std::sync::Arc;

        let (proxy_chain, proxy_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("proxy auth");
        let proxy_trust = proxy_chain.last().expect("proxy trust anchor").clone();
        let (origin_chain, origin_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("origin auth");
        let origin_trust = origin_chain.last().expect("origin trust anchor").clone();

        let origin_server =
            TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
                cert_chain: origin_chain,
                private_key: origin_key,
                ocsp: None,
            }))
            .into_layer(EchoService::new());
        let (origin_done_tx, origin_done_rx) = tokio::sync::oneshot::channel();
        let origin_done_tx = Arc::new(parking_lot::Mutex::new(Some(origin_done_tx)));

        let connect_version = Arc::new(parking_lot::Mutex::new(None));
        let observed_version = connect_version.clone();
        let proxy_sni = Arc::new(parking_lot::Mutex::new(None));
        let observed_sni = proxy_sni.clone();
        let proxy_http =
            HttpServer::auto(WeakScope::detached()).service(service_fn(move |req: Request| {
                let origin_server = origin_server.clone();
                let origin_done_tx = origin_done_tx.clone();
                let observed_version = observed_version.clone();
                let observed_sni = observed_sni.clone();
                async move {
                    assert_eq!(req.method(), rama_http::Method::CONNECT);
                    *observed_version.lock() = Some(req.version());
                    *observed_sni.lock() = req
                        .extensions()
                        .get_ref::<SecureTransport>()
                        .and_then(SecureTransport::client_hello)
                        .and_then(|hello| hello.ext_server_name().cloned());
                    let upgrade = handle_upgrade(&req);
                    tokio::spawn(async move {
                        let tunnel = upgrade.await.expect("server CONNECT upgrade");
                        // The client deliberately drops immediately after the
                        // handshake assertions, so the TLS server may finish
                        // with an EOF/close-notify error.
                        let _origin_result = origin_server.serve(tunnel).await;
                        if let Some(tx) = origin_done_tx.lock().take() {
                            tx.send(()).expect("origin completion receiver");
                        }
                    });
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                }
            }));
        let proxy_server = TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_single_cert(ServerAuthData {
                    cert_chain: proxy_chain,
                    private_key: proxy_key,
                    ocsp: None,
                })
                .with_alpn_http_2(),
        )
        .with_store_client_hello(true)
        .into_layer(proxy_http);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_io = Arc::new(parking_lot::Mutex::new(Some(client_io)));
        let transport = service_fn(move |input: ConnectRequest| {
            let conn = ServiceInput::new(client_io.lock().take().expect("one proxy connection"));
            async move { Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn }) }
        });

        let proxy_config = TlsClientConfig::new()
            .with_alpn_http_2()
            .with_server_name(crate::net::address::Host::from_static("localhost"))
            .try_with_server_trust_anchors([proxy_trust])
            .expect("proxy trust");
        let proxy_tls = TlsConnector::auto(transport).with_base_config(proxy_config);
        let proxy_connections =
            HttpConnector::<_, ProxyRequestBody<Body>>::new(proxy_tls, WeakScope::detached());
        let proxy = HttpConnectProxyConnectorLayer::new().into_layer(proxy_connections);
        let origin_config = TlsClientConfig::new()
            .with_alpn(Default::default())
            .with_server_name(crate::net::address::Host::from_static("localhost"))
            .try_with_server_trust_anchors([origin_trust])
            .expect("origin trust");
        let connector = TlsConnector::auto(proxy).with_base_config(origin_config);

        let input = ConnectRequest::new(HostWithPort::try_from("localhost:443").unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions.insert(ProxyRoute::Proxy(
            "h2://localhost:8443".parse::<ProxyAddress>().unwrap(),
        ));
        // Origin TLS inputs: they configure the origin handshake over the
        // tunnel and must not reach the handshake with the proxy.
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        input
            .extensions
            .insert(TlsServerName(crate::net::address::Host::from_static(
                "elsewhere.example",
            )));
        let client = async move {
            let established = connector.serve(input).await.expect("two TLS handshakes");

            assert_eq!(
                *connect_version.lock(),
                Some(Version::HTTP_2),
                "the connection to the proxy offers its own ALPN, never the origin's"
            );
            assert_eq!(
                proxy_sni
                    .lock()
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref(),
                Some("localhost"),
                "the connection to the proxy names the proxy, never the origin's server name"
            );
            let conn = established.conn.extensions();
            assert_eq!(
                conn.get_ref::<NegotiatedTlsParameters>()
                    .expect("origin TLS parameters")
                    .application_layer_protocol,
                None,
                "an origin without an ALPN offer negotiates none"
            );
            assert!(
                conn.get_ref::<TargetHttpVersion>().is_none(),
                "proxy HTTP/2 must not leak past CONNECT into a no-ALPN origin"
            );
            assert_tunnel_serves_the_same_proxy(
                conn,
                established
                    .input
                    .extensions
                    .get_ref::<ProxyRoute>()
                    .unwrap(),
            );
            drop(established);
        };
        let (proxy_result, ()) =
            Box::pin(tokio::time::timeout(Duration::from_secs(5), async move {
                tokio::join!(proxy_server.serve(ServiceInput::new(server_io)), client)
            }))
            .await
            .expect("proxy/origin exchange");
        proxy_result.expect("proxy server");
        tokio::time::timeout(Duration::from_secs(5), origin_done_rx)
            .await
            .expect("origin server shutdown")
            .expect("origin completion signal");
    }

    #[cfg(feature = "boring")]
    #[tokio::test]
    async fn default_client_resumes_tls_sessions() {
        let scope = WeakScope::detached();
        let resumed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let record = resumed.clone();
        let server = TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_server_auth(
                    ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap(),
                )
                .with_alpn_http_1(),
        )
        .with_session_resumption(true)
        .into_layer(
            MapInputLayer::new(move |stream: TlsStream<TcpStream>| {
                let params = stream.extensions().get_ref::<NegotiatedTlsParameters>();
                record.lock().push(params.and_then(|params| params.resumed));
                stream
            })
            .into_layer(HttpServer::new_http1(scope.clone()).service(service_fn(
                async |_: Request| {
                    // A fresh connection per request, so each one handshakes.
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header(CONNECTION, "close")
                            .body(Body::empty())
                            .unwrap(),
                    )
                },
            ))),
        );
        let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), scope)
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(listener.serve(server));

        let client = DefaultHttpWebClient::<Body>::default();
        for _ in 0..2 {
            let request = Request::builder()
                .uri(format!("https://localhost:{port}/"))
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(TlsServerVerify(ServerVerifyMode::Disable));
            let response = tokio::time::timeout(Duration::from_secs(5), client.serve(request))
                .await
                .unwrap()
                .unwrap();
            response.try_into_string().await.unwrap();
        }
        server.abort();
        assert_eq!(*resumed.lock(), [Some(false), Some(true)]);
    }

    #[cfg(feature = "boring")]
    #[test]
    fn proxy_failure_cache_keeps_tls_client_future_bounded() {
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_default_transport_connector()
            .with_default_dns_connector()
            .with_proxy_support(proxies_over(TcpConnector::new()))
            .with_tls_support_using_boringssl_and_default_http_version(
                TlsClientConfig::default_http(),
                Version::HTTP_11,
            )
            .with_default_http_connector()
            .without_connection_pool()
            .build_client();
        let request = Request::builder()
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();

        let future = client.serve(request);
        let future_size = std::mem::size_of_val(&future);

        assert!(
            future_size < 64 * 1024,
            "easy TLS client future is unexpectedly large: {future_size} bytes"
        );
    }

    #[tokio::test]
    async fn connection_is_in_use_until_response_body_is_consumed() {
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector()
            .with_connection_pool(HttpPooledConnectorConfig {
                max_streams_per_connection: NonZeroUsize::new(1),
                max_connections_total: NonZeroUsize::new(4),
                ..Default::default()
            })
            .build_client();

        let req = || {
            Request::builder()
                .uri("http://example.com")
                .version(Version::HTTP_2)
                .body(Body::empty())
                .unwrap()
        };

        // Get the first response but DO NOT consume its body yet: the connection
        // is logically still in use until the body is drained. Then issue a second
        // request before draining the first.
        let res1 = client.serve(req()).await.unwrap();
        let res2 = client.serve(req()).await.unwrap();

        // Drain in reverse so `res1`'s body is still outstanding when `req2` runs.
        let out2 = res2.try_into_json::<Output>().await.unwrap();
        let out1 = res1.try_into_json::<Output>().await.unwrap();

        assert_eq!(out1.conn, 0, "first request uses the first connection");
        // With `max_concurrent_streams = 1`, connection 0's response body is still
        // in flight, so the second request must NOT reuse it.
        assert_eq!(
            out2.conn, 1,
            "second request must not reuse a connection whose response body is still in flight"
        );
    }

    // These things are already tested inside the pool itself, but here we add some high level tests
    // in case we ever swap the underlying pool implementation.

    #[tokio::test]
    async fn default_pool_multiplexes_on_h2() {
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector()
            .with_default_connection_pool()
            .build_client();

        let req = || {
            Request::builder()
                .uri("http://example.com")
                .version(Version::HTTP_2)
                .body(Body::empty())
                .unwrap()
        };
        let (res1, res2, res3) = tokio::join!(
            client.serve(req()),
            client.serve(req()),
            client.serve(req()),
        );

        // Should only create single connection and send all requests over the same one
        for (i, res) in [res1, res2, res3].into_iter().enumerate() {
            let out = res.unwrap().try_into_json::<Output>().await.unwrap();
            assert_eq!(out.conn, 0);
            assert_eq!(out.resp, i);
        }
    }

    #[tokio::test]
    async fn default_pool_does_not_multiplexes_on_h1() {
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector()
            .with_default_connection_pool()
            .build_client();

        let req = || {
            Request::builder()
                .uri("http://example.com")
                .version(Version::HTTP_11)
                .body(Body::empty())
                .unwrap()
        };
        let (res1, res2, res3) = tokio::join!(
            client.serve(req()),
            client.serve(req()),
            client.serve(req()),
        );

        // Should create a new connection for each request since they are all inprogress at the same
        // time and h1 does not support multiplexing
        for (i, res) in [res1, res2, res3].into_iter().enumerate() {
            let out = res.unwrap().try_into_json::<Output>().await.unwrap();
            assert_eq!(out.conn, i);
            assert_eq!(out.resp, 0);
        }
    }

    #[tokio::test]
    async fn multiplex_on_h2_respects_limits() {
        let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_custom_tcp_connector(dummy_server())
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector()
            .with_connection_pool(HttpPooledConnectorConfig {
                max_streams_per_connection: NonZeroUsize::new(2),
                ..Default::default()
            })
            .build_client();

        let req = || {
            Request::builder()
                .uri("http://example.com")
                .version(Version::HTTP_2)
                .body(Body::empty())
                .unwrap()
        };
        let (res1, res2, res3, res4) = tokio::join!(
            client.serve(req()),
            client.serve(req()),
            client.serve(req()),
            client.serve(req()),
        );

        // Should create a connection for every two request
        for (i, res) in [res1, res2, res3, res4].into_iter().enumerate() {
            let out = res.unwrap().try_into_json::<Output>().await.unwrap();
            assert_eq!(out.conn, i / 2);
            assert_eq!(out.resp, i % 2);
        }
    }
}
