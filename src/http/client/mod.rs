//! rama http client support
//!
//! Contains re-exports from `rama-http-backend::client`
//! and adds `EasyHttpWebClient`, an opiniated http web client which
//! supports most common use cases and provides sensible defaults.
use std::{fmt, io};

use crate::{
    Layer, Service,
    error::BoxError,
    extensions::ExtensionsRef,
    http::{Request, Response, StreamingBody},
    net::client::EstablishedClientConnection,
    rt::Executor,
    service::BoxService,
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
    layer::forward_proxy::{HttpForwardProxyLayer, HttpForwardProxyService},
    proxy::PlaintextHttpProxyMode,
};

pub mod builder;
#[doc(inline)]
pub use builder::EasyHttpConnectorBuilder;

#[cfg(feature = "socks5")]
mod proxy_connector;
#[cfg(feature = "socks5")]
#[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
#[doc(inline)]
pub use proxy_connector::{MaybeProxiedConnection, ProxyConnector, ProxyConnectorLayer};

/// An opiniated http client that can be used to serve HTTP requests.
///
/// Use [`EasyHttpWebClient::connector_builder()`] to easily create a client with
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
    forward_proxy_layer: HttpForwardProxyLayer,
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
            forward_proxy_layer: self.forward_proxy_layer.clone(),
            plaintext_http_proxy_mode: self.plaintext_http_proxy_mode,
            jit_layers: self.jit_layers.clone(),
        }
    }
}

impl EasyHttpWebClient<(), (), ()> {
    /// Create a [`EasyHttpConnectorBuilder`] to easily create a [`EasyHttpWebClient`] with a custom connector
    #[must_use]
    pub fn connector_builder() -> EasyHttpConnectorBuilder {
        EasyHttpConnectorBuilder::new()
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
pub type DefaultHttpWebClient<Body = crate::http::Body> = EasyHttpWebClient<
    Body,
    EstablishedClientConnection<
        BindBodyToConn<
            crate::net::client::pool::MultiplexedConnection<HttpClientService<Body>, HttpConnId>,
        >,
        Request<Body>,
    >,
    (),
>;

/// A blocking HTTP(S) client using Rama's default pooled web connector stack.
pub type BlockingHttpWebClient = BlockingHttpClient<DefaultHttpWebClient>;

impl<Body> Default for DefaultHttpWebClient<Body>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    #[inline(always)]
    fn default() -> Self {
        Self::default_with_executor(Executor::default())
    }
}

impl<Body> DefaultHttpWebClient<Body>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    core::cfg_select! {
        feature = "boring" => {
            pub fn default_with_executor(exec: Executor) -> Self {
                let tls_config = crate::tls::client::TlsClientConfig::default_http();

                EasyHttpConnectorBuilder::new()
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_tls_proxy_support_using_boringssl()
                    .with_proxy_support()
                    .with_tls_support_using_boringssl(tls_config)
                    .with_default_http_connector(exec)
                    .with_default_connection_pool()
                    .build_client()
            }
        }
        feature = "rustls" => {
            pub fn default_with_executor(exec: Executor) -> Self {
                let tls_config = crate::tls::client::TlsClientConfig::default_http();

                EasyHttpConnectorBuilder::new()
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_tls_proxy_support_using_rustls()
                    .with_proxy_support()
                    .with_tls_support_using_rustls(tls_config)
                    .with_default_http_connector(exec)
                    .with_default_connection_pool()
                    .build_client()
            }
        }
        _ => {
            pub fn default_with_executor(exec: Executor) -> Self {
                EasyHttpConnectorBuilder::new()
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .without_tls_proxy_support()
                    .with_proxy_support()
                    .without_tls_support()
                    .with_default_http_connector(exec)
                    .with_default_connection_pool()
                    .build_client()
            }
        }
    }
}

impl<BodyIn, ConnResponse> EasyHttpWebClient<BodyIn, ConnResponse, ()>
where
    BodyIn: Send + 'static,
{
    /// Create a new [`EasyHttpWebClient`] using the provided connector.
    ///
    /// Custom proxy connectors must honor [`PlaintextHttpProxyMode`] and publish
    /// [`EstablishedProxyRoute`](crate::net::client::EstablishedProxyRoute).
    /// Connection wrappers must preserve that metadata through [`ExtensionsRef`].
    #[must_use]
    pub fn new<S>(connector: S) -> Self
    where
        S: Service<Request<BodyIn>, Output = ConnResponse, Error: Into<BoxError>>,
    {
        Self {
            connector: MapErr::into_opaque_error(connector).boxed(),
            forward_proxy_layer: HttpForwardProxyLayer::new(),
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
            forward_proxy_layer: self.forward_proxy_layer,
            plaintext_http_proxy_mode: self.plaintext_http_proxy_mode,
            jit_layers: self.jit_layers,
        }
    }

    /// [`Layer`] which will be applied just in time (JIT) before the request is sent, but after
    /// the connection has been established. Rama's built-in forward-proxy
    /// policy is the innermost JIT service so it can act on the actual
    /// connection after caller middleware has processed the request, and can
    /// isolate a proxy challenge before caller middleware sees the response.
    ///
    /// Simplified flow of how the [`EasyHttpWebClient`] works:
    /// 1. External: let response = client.serve(request)
    /// 2. Internal: let http_connection = self.connector.serve(request)
    /// 3. Internal: wrap the connection in Rama's forward-proxy policy
    /// 4. Internal: let response = jit_layers.layer(http_connection).serve(request)
    pub fn with_jit_layer<T>(self, jit_layers: T) -> EasyHttpWebClient<BodyIn, ConnResponse, T> {
        EasyHttpWebClient {
            connector: self.connector,
            forward_proxy_layer: self.forward_proxy_layer,
            plaintext_http_proxy_mode: self.plaintext_http_proxy_mode,
            jit_layers,
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// Enable or disable automatic Basic or Bearer credentials on requests
        /// sent directly to an HTTP forward proxy.
        ///
        /// This is enabled by default and acts only when the established connection
        /// is positively identified as an HTTP forward-proxy connection. It never
        /// adds credentials to direct, SOCKS, or HTTP CONNECT-tunneled requests.
        ///
        /// Disabling this only disables insertion. Caller-provided
        /// `Proxy-Authorization` headers are preserved on established HTTP
        /// forward routes and always stripped on every other route, including
        /// connections without established route metadata.
        pub fn forward_proxy_auth(mut self, enabled: bool) -> Self {
            self.forward_proxy_layer.set_proxy_auth(enabled);
            self
        }
    }

    /// Disable automatic Basic or Bearer credentials on HTTP forward-proxy
    /// requests. The credential-stripping policy described by
    /// [`Self::with_forward_proxy_auth`] still applies.
    #[must_use]
    pub fn without_forward_proxy_auth(self) -> Self {
        self.with_forward_proxy_auth(false)
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

    crate::utils::macros::generate_set_and_with! {
        /// Enable or disable isolation of `407 Proxy Authentication Required`
        /// responses received from an established HTTP forward proxy.
        ///
        /// Ordinary clients expose such responses by default. Intermediaries should
        /// enable this option so an upstream proxy's challenge, headers, and body
        /// cannot be forwarded to a different downstream proxy client.
        pub fn isolate_forward_proxy_auth_error(mut self, enabled: bool) -> Self {
            self.forward_proxy_layer.set_isolate_auth_error(enabled);
            self
        }
    }
}

impl<Body, ConnectionBody, Connection, L> Service<Request<Body>>
    for EasyHttpWebClient<Body, EstablishedClientConnection<Connection, Request<ConnectionBody>>, L>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    Connection:
        Service<Request<ConnectionBody>, Output = Response, Error = BoxError> + ExtensionsRef,
    // Body type this connection will be able to send, this is not necessarily the same one that
    // was used in the request that created this connection
    ConnectionBody:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    L: Layer<
            HttpForwardProxyService<Connection>,
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

        // Publish connection metadata for JIT middleware. The forward-proxy
        // layer refreshes it after those layers run; the backend independently
        // refreshes it for callers that use the backend without this client.
        req.extensions()
            .insert(Egress(http_connection.extensions().clone()));

        let http_connection = self.forward_proxy_layer.layer(http_connection);
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
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use rama_core::extensions::Extensions;
    use rama_core::{error::BoxErrorExt as _, service::service_fn};
    use rama_http::{Body, BodyExtractExt, Version};
    use rama_http_backend::server::HttpServer;
    use rama_net::{
        address::ProxyAddress,
        client::{
            ConnectRequest, ConnectionError, ConnectionErrorDomain, ConnectionErrorKind,
            ConnectorService, ConnectorTarget, EstablishedProxyRoute, ProxyRoute,
            ProxyRouteFailureCache, ProxyRouteFailureCacheConfig, ProxyRouteFailureCacheScope,
            ProxyRoutes,
        },
        test_utils::client::{MockConnectorService, MockSocket},
    };
    use serde::{Deserialize, Serialize};
    use tokio::time::sleep;

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Output {
        conn: usize,
        resp: usize,
    }

    #[derive(Debug, Clone, Default)]
    struct EmptyHttpConnection {
        extensions: Extensions,
    }

    impl ExtensionsRef for EmptyHttpConnection {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
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

    fn dummy_server<Input: Send + 'static>()
    -> impl Service<
        Input,
        Output = EstablishedClientConnection<MockSocket, Input>,
        Error = Infallible,
    > + Clone {
        let created_connections = Arc::new(AtomicUsize::new(0));
        MockConnectorService::new(move || {
            let created_connections = created_connections.clone();
            let conn = created_connections.fetch_add(1, Ordering::Relaxed);

            // count responses created on this specific connection
            let created_response = Arc::new(AtomicUsize::new(0));

            HttpServer::auto(Executor::default()).service(service_fn(move |_req: Request| {
                let created_response = created_response.clone();
                let resp = created_response.fetch_add(1, Ordering::Relaxed);
                async move {
                    sleep(Duration::from_millis(5)).await;
                    let out = Output { conn, resp };
                    let resp = Response::new(Body::from(serde_json::to_vec(&out).unwrap()));
                    Ok::<_, Infallible>(resp)
                }
            }))
        })
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
    async fn jit_request_metadata_cannot_change_proxy_credentials_target_or_challenge_isolation() {
        use rama_core::{
            bytes::BytesMut,
            layer::{MapInputLayer, MapOutputLayer},
        };
        use rama_http::{HeaderValue, StatusCode, header::PROXY_AUTHORIZATION};

        #[derive(Debug, Clone)]
        struct InspectProxyConnection {
            extensions: Extensions,
        }

        impl ExtensionsRef for InspectProxyConnection {
            fn extensions(&self) -> &Extensions {
                &self.extensions
            }
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
                );
                assert_eq!(
                    request.extensions().get_ref::<ProxyRoute>(),
                    Some(&ProxyRoute::Proxy(
                        "http://wrong:request-secret@requested.example:8080"
                            .parse()
                            .unwrap(),
                    )),
                    "forward policy must preserve the caller's requested route",
                );
                let mut target = BytesMut::new();
                rama_http::proto::h1::head::encode_request_target(
                    request.method(),
                    request.uri(),
                    request.extensions(),
                    &mut target,
                )
                .unwrap();
                if is_forward {
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

        let proxy: ProxyAddress = "http://upstream:secret@proxy.example:8080".parse().unwrap();
        for isolate in [false, true] {
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
                let client = EasyHttpWebClient::new(connector)
                    .with_isolate_forward_proxy_auth_error(isolate)
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
                request.extensions().insert(ProxyRoute::Proxy(
                    "http://wrong:request-secret@requested.example:8080"
                        .parse()
                        .unwrap(),
                ));
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

    #[test]
    fn blocking_client_drives_the_composed_http_stack() {
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(dummy_server())
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .without_connection_pool()
            .build_client()
            .try_into_blocking()
            .unwrap();

        let cloned = client.clone();
        drop(client);
        let response = cloned.get("http://example.com").send().unwrap();
        assert_eq!(
            response.try_into_json::<Output>().unwrap(),
            Output { conn: 0, resp: 0 }
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
            let direct = dummy_server::<ConnectRequest>();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    let route = input.extensions.get_ref::<ProxyRoute>().unwrap();
                    attempts.lock().push(route.clone());
                    if route.proxy_address().is_some() {
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
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(transport)
            .without_dns_connector()
            .without_tls_proxy_support()
            .with_custom_proxy_connector(())
            .without_tls_support()
            .with_default_http_connector(Executor::default())
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
            [proxy, ProxyRoute::Direct, ProxyRoute::Direct]
        );
    }

    #[tokio::test]
    async fn no_proxy_tls_support_rejects_https_proxy() {
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(dummy_server())
            .without_dns_connector()
            .without_tls_proxy_support()
            .with_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
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
            let inner = dummy_server::<ConnectRequest>();
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
                        input
                            .extensions
                            .get_ref::<ProxyRoute>()
                            .and_then(ProxyRoute::proxy_address),
                        Some(&proxy),
                    );
                    dials.fetch_add(1, Ordering::Relaxed);
                    inner.connect(input).await
                }
            }
        });
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(transport)
            .without_dns_connector()
            .without_tls_proxy_support()
            .with_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .with_default_connection_pool()
            .build_client();

        for (version, expected_conn) in [(Version::HTTP_11, 0), (Version::HTTP_2, 1)] {
            let request = Request::builder()
                .uri("http://example.com")
                .version(version)
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(ProxyRoutes::from(proxy.clone()));

            let response = client.serve(request).await.unwrap();
            assert_eq!(response.version(), version);
            assert_eq!(
                response.try_into_json::<Output>().await.unwrap(),
                Output {
                    conn: expected_conn,
                    resp: 0,
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
            let direct = dummy_server::<ConnectRequest>();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    let route = input.extensions.get_ref::<ProxyRoute>().unwrap().clone();
                    attempts.lock().push(route.clone());
                    if route.proxy_address().is_some() {
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
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(transport)
            .without_dns_connector()
            .without_tls_proxy_support()
            .with_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
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
        assert_eq!(output, Output { conn: 0, resp: 0 });
        assert_eq!(
            attempts.lock().as_slice(),
            [socks, http, ProxyRoute::Direct]
        );
    }

    #[tokio::test]
    async fn default_pool_caches_failed_route_and_reuses_selected_connection() {
        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let transport = service_fn({
            let attempts = attempts.clone();
            let direct = dummy_server::<ConnectRequest>();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    let route = input.extensions.get_ref::<ProxyRoute>().unwrap();
                    attempts.lock().push(route.clone());
                    if route.proxy_address().is_some() {
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
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(transport)
            .without_dns_connector()
            .without_tls_proxy_support()
            .with_custom_proxy_connector(())
            .without_tls_support()
            .with_default_http_connector(Executor::default())
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

        assert_eq!(attempts.lock().as_slice(), [proxy, ProxyRoute::Direct]);
    }

    #[tokio::test]
    async fn easy_client_can_disable_proxy_route_failure_cache() {
        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let transport = service_fn({
            let attempts = attempts.clone();
            let direct = dummy_server::<ConnectRequest>();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    let route = input.extensions.get_ref::<ProxyRoute>().unwrap();
                    attempts.lock().push(route.clone());
                    if route.proxy_address().is_some() {
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
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(transport)
            .without_dns_connector()
            .without_tls_proxy_support()
            .with_custom_proxy_connector(())
            .without_tls_support()
            .with_default_http_connector(Executor::default())
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
            [proxy.clone(), ProxyRoute::Direct, proxy, ProxyRoute::Direct]
        );
    }

    #[tokio::test]
    async fn proxy_free_easy_client_omits_proxy_route_failure_cache() {
        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let transport = service_fn({
            let attempts = attempts.clone();
            let direct = dummy_server::<ConnectRequest>();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    let route = input.extensions.get_ref::<ProxyRoute>().unwrap();
                    attempts.lock().push(route.clone());
                    if route.proxy_address().is_some() {
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
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(transport)
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
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
            [proxy.clone(), ProxyRoute::Direct, proxy, ProxyRoute::Direct]
        );
    }

    #[tokio::test]
    async fn easy_client_accepts_custom_proxy_route_failure_cache() {
        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let transport = service_fn({
            let attempts = attempts.clone();
            let direct = dummy_server::<ConnectRequest>();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                let direct = direct.clone();
                async move {
                    let route = input.extensions.get_ref::<ProxyRoute>().unwrap();
                    attempts.lock().push(route.clone());
                    if route.proxy_address().is_some() {
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
        let mut failure_cache_config = ProxyRouteFailureCacheConfig::default();
        failure_cache_config.scope = ProxyRouteFailureCacheScope::PerProxy;
        let failure_cache = ProxyRouteFailureCache::try_new(failure_cache_config).unwrap();
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(transport)
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
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

        assert_eq!(
            attempts.lock().as_slice(),
            [proxy, ProxyRoute::Direct, ProxyRoute::Direct]
        );
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
            },
            tls::{
                client::{NegotiatedTlsParameters, TlsClientConfig},
                rustls::{client::TlsConnector, server::TlsAcceptorLayer},
                server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
            },
        };
        use rama_core::ServiceInput;
        use rama_crypto::cert::generate_server_auth;
        use rama_http::io::upgrade::handle_upgrade;
        use rama_http_backend::client::proxy::layer::HttpProxyConnectorLayer;
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
        let proxy_http =
            HttpServer::auto(Executor::default()).service(service_fn(move |req: Request| {
                let origin_server = origin_server.clone();
                let origin_done_tx = origin_done_tx.clone();
                let observed_version = observed_version.clone();
                async move {
                    assert_eq!(req.method(), rama_http::Method::CONNECT);
                    *observed_version.lock() = Some(req.version());
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
        let proxy_tls = TlsConnector::tunnel(transport, None).with_base_config(proxy_config);
        let proxy = HttpProxyConnectorLayer::default().into_layer(proxy_tls);
        let origin_config = TlsClientConfig::new()
            .with_alpn(Default::default())
            .with_server_name(crate::net::address::Host::from_static("localhost"))
            .try_with_server_trust_anchors([origin_trust])
            .expect("origin trust");
        let connector = TlsConnector::auto(proxy).with_base_config(origin_config);

        let input = ConnectRequest::new(HostWithPort::try_from("localhost:443").unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions
            .insert(ProxyRoute::Proxy("https://localhost:8443".parse().unwrap()));
        let client = async move {
            let established = Box::pin(connector.serve(input))
                .await
                .expect("two TLS handshakes");

            assert_eq!(*connect_version.lock(), Some(Version::HTTP_2));
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<NegotiatedTlsParameters>()
                    .expect("origin TLS parameters")
                    .application_layer_protocol,
                None
            );
            assert!(
                established
                    .conn
                    .extensions()
                    .get_ref::<TargetHttpVersion>()
                    .is_none(),
                "proxy HTTP/2 must not leak past CONNECT into a no-ALPN origin"
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
            },
            tls::{
                boring::{client::TlsConnector, server::TlsAcceptorLayer},
                client::{NegotiatedTlsParameters, TlsClientConfig},
                server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
            },
        };
        use rama_core::ServiceInput;
        use rama_crypto::cert::generate_server_auth;
        use rama_http::io::upgrade::handle_upgrade;
        use rama_http_backend::client::proxy::layer::HttpProxyConnectorLayer;
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
        let proxy_http =
            HttpServer::auto(Executor::default()).service(service_fn(move |req: Request| {
                let origin_server = origin_server.clone();
                let origin_done_tx = origin_done_tx.clone();
                let observed_version = observed_version.clone();
                async move {
                    assert_eq!(req.method(), rama_http::Method::CONNECT);
                    *observed_version.lock() = Some(req.version());
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
        let proxy_tls = TlsConnector::tunnel(transport, None).with_base_config(proxy_config);
        let proxy = HttpProxyConnectorLayer::default().into_layer(proxy_tls);
        let origin_config = TlsClientConfig::new()
            .with_alpn(Default::default())
            .with_server_name(crate::net::address::Host::from_static("localhost"))
            .try_with_server_trust_anchors([origin_trust])
            .expect("origin trust");
        let connector = TlsConnector::auto(proxy).with_base_config(origin_config);

        let input = ConnectRequest::new(HostWithPort::try_from("localhost:443").unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions
            .insert(ProxyRoute::Proxy("https://localhost:8443".parse().unwrap()));
        let client = async move {
            let established = connector.serve(input).await.expect("two TLS handshakes");

            assert_eq!(*connect_version.lock(), Some(Version::HTTP_2));
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<NegotiatedTlsParameters>()
                    .expect("origin TLS parameters")
                    .application_layer_protocol,
                None
            );
            assert!(
                established
                    .conn
                    .extensions()
                    .get_ref::<TargetHttpVersion>()
                    .is_none(),
                "proxy HTTP/2 must not leak past CONNECT into a no-ALPN origin"
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
    #[test]
    fn proxy_failure_cache_keeps_tls_client_future_bounded() {
        let client = EasyHttpWebClient::connector_builder()
            .with_default_transport_connector()
            .with_default_dns_connector()
            .without_tls_proxy_support()
            .with_proxy_support()
            .with_tls_support_using_boringssl_and_default_http_version(
                crate::tls::client::TlsClientConfig::default_http(),
                Version::HTTP_11,
            )
            .with_default_http_connector(Executor::default())
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
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(dummy_server())
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .try_with_connection_pool(HttpPooledConnectorConfig {
                max_concurrent_streams: 1,
                max_total: 4,
                ..Default::default()
            })
            .unwrap()
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
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(dummy_server())
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
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
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(dummy_server())
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
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
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(dummy_server())
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .try_with_connection_pool(HttpPooledConnectorConfig {
                max_concurrent_streams: 2,
                ..Default::default()
            })
            .unwrap()
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
