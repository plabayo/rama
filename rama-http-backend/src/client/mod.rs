//! Rama HTTP client module,
//! which provides the [`EasyHttpWebClient`] type to serve HTTP requests.

use std::fmt;

use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    service::BoxService,
    telemetry::tracing,
};
use rama_http_types::{Request, Response, dep::http_body};
use rama_net::client::EstablishedClientConnection;

mod svc;
#[doc(inline)]
pub use svc::HttpClientService;

mod conn;
#[doc(inline)]
pub use conn::{HttpConnector, HttpConnectorLayer};

pub mod http_inspector;
pub mod proxy;

/// An opiniated http client that can be used to serve HTTP requests.
///
/// Use [`EasyHttpWebClient::builder()`] to easily create a client with
/// a common Http connector setup (tcp + proxy + tls + http) or bring your
/// own http connector.
///
/// You can fork this http client in case you have use cases not possible with this service example.
/// E.g. perhaps you wish to have middleware in into outbound requests, after they
/// passed through your "connector" setup. All this and more is possible by defining your own
/// http client. Rama is here to empower you, the building blocks are there, go crazy
/// with your own service fork and use the full power of Rust at your fingertips ;)
pub struct EasyHttpWebClient<State, BodyIn, ConnResponse> {
    connector: BoxService<State, Request<BodyIn>, ConnResponse, BoxError>,
}

impl<State, BodyIn, ConnResponse> fmt::Debug for EasyHttpWebClient<State, BodyIn, ConnResponse> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHttpWebClient").finish()
    }
}

impl<State, BodyIn, ConnResponse> Clone for EasyHttpWebClient<State, BodyIn, ConnResponse> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
        }
    }
}

impl EasyHttpWebClient<(), (), ()> {
    /// Create a [`EasyHttpWebClientBuilder`] to easily create a [`EasyHttpWebClient`]
    #[must_use]
    pub fn builder() -> EasyHttpWebClientBuilder {
        EasyHttpWebClientBuilder::new()
    }
}

impl<State, Body> Default
    for EasyHttpWebClient<
        State,
        Body,
        EstablishedClientConnection<HttpClientService<Body>, State, Request<Body>>,
    >
where
    State: Clone + Send + Sync + 'static,
    Body: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    #[cfg(feature = "boring")]
    fn default() -> Self {
        let tls_config =
            rama_tls_boring::client::TlsConnectorDataBuilder::new_http_auto().into_shared_builder();

        EasyHttpWebClientBuilder::new()
            .with_default_transport_connector()
            .with_tls_proxy_support_using_boringssl()
            .with_proxy_support()
            .with_tls_support_using_boringssl(Some(tls_config))
            .build()
    }

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    fn default() -> Self {
        let tls_config = rama_tls_rustls::client::TlsConnectorData::new_http_auto()
            .expect("connector data with http auto");

        EasyHttpWebClientBuilder::new()
            .with_default_transport_connector()
            .with_tls_proxy_support_using_rustls()
            .with_proxy_support()
            .with_tls_support_using_rustls(Some(tls_config))
            .build()
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    fn default() -> Self {
        EasyHttpWebClientBuilder::new()
            .with_default_transport_connector()
            .without_tls_proxy_support()
            .with_proxy_support()
            .without_tls_support()
            .build()
    }
}

impl<State, BodyIn, ConnResponse> EasyHttpWebClient<State, BodyIn, ConnResponse> {
    /// Create a new [`EasyHttpWebClient`] using the provided connector
    #[must_use]
    pub fn new(connector: BoxService<State, Request<BodyIn>, ConnResponse, BoxError>) -> Self {
        Self { connector }
    }

    /// Set the [`Connector`] that this [`EasyHttpWebClient`] will use
    #[must_use]
    pub fn with_connector<BodyInNew, ConnResponseNew>(
        self,
        connector: BoxService<State, Request<BodyInNew>, ConnResponseNew, BoxError>,
    ) -> EasyHttpWebClient<State, BodyInNew, ConnResponseNew> {
        EasyHttpWebClient { connector }
    }
}

impl<State, Body, ModifiedBody, ConnResponse> Service<State, Request<Body>>
    for EasyHttpWebClient<
        State,
        Body,
        EstablishedClientConnection<ConnResponse, State, Request<ModifiedBody>>,
    >
where
    State: Send + Sync + 'static,
    Body: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    ModifiedBody:
        http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    ConnResponse: Service<State, Request<ModifiedBody>, Response = Response, Error = BoxError>,
{
    type Response = Response;

    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let uri = req.uri().clone();

        let EstablishedClientConnection { ctx, req, conn } = self.connector.serve(ctx, req).await?;
        // NOTE: stack might change request version based on connector data,
        tracing::trace!(url.full = %uri, "send http req to connector stack");

        let result = conn.serve(ctx, req).await;

        let resp = result
            .map_err(OpaqueError::from_boxed)
            .with_context(|| format!("http request failure for uri: {uri}"))?;

        tracing::trace!(url.full = %uri, "response received from connector stack");

        Ok(resp)
    }
}

#[doc(inline)]
pub use easy_connector::EasyHttpWebClientBuilder;

mod easy_connector {
    use super::{
        HttpConnector, http_inspector::HttpVersionAdapter, proxy::layer::HttpProxyConnector,
    };
    use rama_core::{
        Layer, Service,
        error::{BoxError, OpaqueError},
    };
    use rama_dns::DnsResolver;
    use rama_http::{Request, dep::http_body};
    use rama_net::client::{
        EstablishedClientConnection,
        pool::{
            LruDropPool, PooledConnector,
            http::{BasicHttpConId, BasicHttpConnIdentifier, HttpPooledConnectorConfig},
        },
    };
    use rama_tcp::client::service::TcpConnector;
    use std::{marker::PhantomData, time::Duration};

    #[cfg(feature = "boring")]
    use ::{rama_tls_boring::client as boring_client, std::sync::Arc};

    #[cfg(feature = "rustls")]
    use rama_tls_rustls::client as rustls_client;

    #[cfg(any(feature = "rustls", feature = "boring"))]
    use super::http_inspector::HttpsAlpnModifier;

    /// Builder that is designed to easily create a [`super::EasyHttpWebClient`] from most basic use cases
    #[derive(Default)]
    pub struct EasyHttpWebClientBuilder<C = (), S = ()> {
        connector: C,
        _phantom: PhantomData<S>,
    }

    pub struct TransportStage;
    pub struct ProxyTunnelStage;
    pub struct ProxyStage;
    pub struct HttpStage;
    pub struct PoolStage;

    impl EasyHttpWebClientBuilder {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        #[must_use]
        pub fn with_default_transport_connector(
            self,
        ) -> EasyHttpWebClientBuilder<TcpConnector, TransportStage> {
            let connector = TcpConnector::default();
            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        /// Add a custom transport connector that will be used by this client for the transport layer
        pub fn with_custom_transport_connector<C>(
            self,
            connector: C,
        ) -> EasyHttpWebClientBuilder<C, TransportStage> {
            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }
    }

    impl EasyHttpWebClientBuilder<TcpConnector, TransportStage> {
        /// Add a custom [`DnsResolver`] that will be used by this client
        pub fn with_dns_resolver<T: DnsResolver + Clone>(
            self,
            resolver: T,
        ) -> EasyHttpWebClientBuilder<TcpConnector<T>, TransportStage> {
            let connector = self.connector.with_dns(resolver);
            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }
    }

    impl<T> EasyHttpWebClientBuilder<T, TransportStage> {
        #[cfg(any(feature = "rustls", feature = "boring"))]
        /// Add a custom proxy tls connector that will be used to setup a tls connection to the proxy
        pub fn with_custom_tls_proxy_connector<L>(
            self,
            connector_layer: L,
        ) -> EasyHttpWebClientBuilder<L::Service, ProxyTunnelStage>
        where
            L: Layer<T>,
        {
            let connector = connector_layer.into_layer(self.connector);
            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        #[cfg(feature = "boring")]
        /// Support a tls tunnel to the proxy itself using boringssl
        ///
        /// Note that a tls proxy is not needed to make a https connection
        /// to the final target. It only has an influence on the initial connection
        /// to the proxy itself
        pub fn with_tls_proxy_support_using_boringssl(
            self,
        ) -> EasyHttpWebClientBuilder<
            boring_client::TlsConnector<T, boring_client::ConnectorKindTunnel>,
            ProxyTunnelStage,
        > {
            let connector = boring_client::TlsConnector::tunnel(self.connector, None);
            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        #[cfg(feature = "boring")]
        /// Support a tls tunnel to the proxy itself using boringssl and the provided config
        ///
        /// Note that a tls proxy is not needed to make a https connection
        /// to the final target. It only has an influence on the initial connection
        /// to the proxy itself
        pub fn with_tls_proxy_support_using_boringssl_config(
            self,
            config: Arc<boring_client::TlsConnectorDataBuilder>,
        ) -> EasyHttpWebClientBuilder<
            boring_client::TlsConnector<T, boring_client::ConnectorKindTunnel>,
            ProxyTunnelStage,
        > {
            let connector = boring_client::TlsConnector::tunnel(self.connector, None)
                .with_connector_data(config);
            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        #[cfg(feature = "rustls")]
        /// Support a tls tunnel to the proxy itself using rustls
        ///
        /// Note that a tls proxy is not needed to make a https connection
        /// to the final target. It only has an influence on the initial connection
        /// to the proxy itself
        pub fn with_tls_proxy_support_using_rustls(
            self,
        ) -> EasyHttpWebClientBuilder<
            rustls_client::TlsConnector<T, rustls_client::ConnectorKindTunnel>,
            ProxyTunnelStage,
        > {
            let connector = rustls_client::TlsConnector::tunnel(self.connector, None);

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        #[cfg(feature = "rustls")]
        /// Support a tls tunnel to the proxy itself using rustls and the provided config
        ///
        /// Note that a tls proxy is not needed to make a https connection
        /// to the final target. It only has an influence on the initial connection
        /// to the proxy itself
        pub fn with_tls_proxy_support_using_rustls_config(
            self,
            config: rustls_client::TlsConnectorData,
        ) -> EasyHttpWebClientBuilder<
            rustls_client::TlsConnector<T, rustls_client::ConnectorKindTunnel>,
            ProxyTunnelStage,
        > {
            let connector = rustls_client::TlsConnector::tunnel(self.connector, None)
                .with_connector_data(config);

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        /// Don't support a tls tunnel to the proxy itself
        ///
        /// Note that a tls proxy is not needed to make a https connection
        /// to the final target. It only has an influence on the initial connection
        /// to the proxy itself
        pub fn without_tls_proxy_support(self) -> EasyHttpWebClientBuilder<T, ProxyTunnelStage> {
            EasyHttpWebClientBuilder {
                connector: self.connector,
                _phantom: PhantomData,
            }
        }
    }

    impl<T> EasyHttpWebClientBuilder<T, ProxyTunnelStage> {
        /// Add a custom proxy connector that will be used by this client
        pub fn with_custom_proxy_connector<L>(
            self,
            connector_layer: L,
        ) -> EasyHttpWebClientBuilder<L::Service, ProxyStage>
        where
            L: Layer<T>,
        {
            let connector = connector_layer.into_layer(self.connector);
            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        /// Add support for usage of a http proxy to this client
        ///
        /// Note that a tls proxy is not needed to make a https connection
        /// to the final target. It only has an influence on the initial connection
        /// to the proxy itself
        ///
        /// TODO: Currently we only support http(s) proxies here, but socks proxy support will
        /// be added in: https://github.com/plabayo/rama/issues/498
        pub fn with_proxy_support(
            self,
        ) -> EasyHttpWebClientBuilder<HttpProxyConnector<T>, ProxyStage> {
            let connector = HttpProxyConnector::optional(self.connector);
            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        /// Make a client without proxy support
        pub fn without_proxy_support(self) -> EasyHttpWebClientBuilder<T, ProxyStage> {
            EasyHttpWebClientBuilder {
                connector: self.connector,
                _phantom: PhantomData,
            }
        }
    }

    impl<T> EasyHttpWebClientBuilder<T, ProxyStage> {
        #[cfg(any(feature = "rustls", feature = "boring"))]
        /// Add a custom tls connector that will be used by the client
        ///
        /// This will also add the [`HttpsAlpnModifier`] request inspector as that one is
        /// crucial to make tls alpn work and set the correct [`TargetHttpVersion`]
        ///
        /// And a [`HttpVersionAdapter`] that will adapt the request version to the configured
        /// [`TargetHttpVersion`]
        ///
        /// If you don't want any of these inspector you can use [`Self::with_advanced_jit_req_inspector`]
        /// to configure your own request inspectors or [`Self::without_jit_req_inspector`] to remove
        /// all the default request inspectors
        ///
        /// [`TargetHttpVersion`]: rama_http::conn::TargetHttpVersion;
        pub fn with_custom_tls_connector<L>(
            self,
            connector_layer: L,
        ) -> EasyHttpWebClientBuilder<
            HttpConnector<L::Service, (HttpsAlpnModifier, HttpVersionAdapter)>,
            HttpStage,
        >
        where
            L: Layer<T>,
        {
            let connector = connector_layer.into_layer(self.connector);

            let connector = HttpConnector::new(connector).with_jit_req_inspector((
                HttpsAlpnModifier::default(),
                HttpVersionAdapter::default(),
            ));

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        #[cfg(feature = "boring")]
        /// Support https connections by using boringssl for tls
        ///
        /// This will also add the [`HttpsAlpnModifier`] request inspector as that one is
        /// crucial to make tls alpn work and set the correct [`TargetHttpVersion`]
        ///
        /// And a [`HttpVersionAdapter`] that will adapt the request version to the configured
        /// [`TargetHttpVersion`]
        ///
        /// If you don't want any of these inspector you can use [`Self::with_advanced_jit_req_inspector`]
        /// to configure your own request inspectors or [`Self::without_jit_req_inspector`] to remove
        /// all the default request inspectors
        ///
        /// [`TargetHttpVersion`]: rama_http::conn::TargetHttpVersion;
        pub fn with_tls_support_using_boringssl(
            self,
            config: Option<Arc<boring_client::TlsConnectorDataBuilder>>,
        ) -> EasyHttpWebClientBuilder<
            HttpConnector<boring_client::TlsConnector<T>, (HttpsAlpnModifier, HttpVersionAdapter)>,
            HttpStage,
        > {
            let connector =
                boring_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);

            let connector = HttpConnector::new(connector).with_jit_req_inspector((
                HttpsAlpnModifier::default(),
                HttpVersionAdapter::default(),
            ));

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        #[cfg(feature = "rustls")]
        /// Support https connections by using ruslts for tls
        ///
        /// This will also add the [`HttpsAlpnModifier`] request inspector as that one is
        /// crucial to make tls alpn work and set the correct [`TargetHttpVersion`]
        ///
        /// And a [`HttpVersionAdapter`] that will adapt the request version to the configured
        /// [`TargetHttpVersion`]
        ///
        /// If you don't want any of these inspector you can use [`Self::with_advanced_jit_req_inspector`]
        /// to configure your own request inspectors or [`Self::without_jit_req_inspector`] to remove
        /// all the default request inspectors
        ///
        /// [`TargetHttpVersion`]: rama_http::conn::TargetHttpVersion;
        pub fn with_tls_support_using_rustls(
            self,
            config: Option<rustls_client::TlsConnectorData>,
        ) -> EasyHttpWebClientBuilder<
            HttpConnector<rustls_client::TlsConnector<T>, (HttpsAlpnModifier, HttpVersionAdapter)>,
            HttpStage,
        > {
            let connector =
                rustls_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);

            let connector = HttpConnector::new(connector).with_jit_req_inspector((
                HttpsAlpnModifier::default(),
                HttpVersionAdapter::default(),
            ));

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        /// Dont support https on this connector
        ///
        /// This will also add the [`HttpVersionAdapter`] that will adapt the request version to
        /// the configured [`TargetHttpVersion`]
        ///
        /// If you don't want any of these inspector you can use [`Self::with_advanced_jit_req_inspector`]
        /// to configure your own request inspectors or [`Self::without_jit_req_inspector`] to remove
        /// all the default request inspectors
        ///
        /// [`TargetHttpVersion`]: rama_http::conn::TargetHttpVersion;
        pub fn without_tls_support(
            self,
        ) -> EasyHttpWebClientBuilder<HttpConnector<T, HttpVersionAdapter>, HttpStage> {
            let connector = HttpConnector::new(self.connector)
                .with_jit_req_inspector(HttpVersionAdapter::default());

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }
    }

    impl<T, I1, I2> EasyHttpWebClientBuilder<HttpConnector<T, I1, I2>, HttpStage> {
        /// Add a http request inspector that will run just after the inner http connector
        /// has connected but before the http handshake happens
        ///
        /// This function doesn't add any default request inspectors
        pub fn with_advanced_jit_req_inspector<I>(
            self,
            http_req_inspector: I,
        ) -> EasyHttpWebClientBuilder<HttpConnector<T, I, I2>, HttpStage> {
            EasyHttpWebClientBuilder {
                connector: self.connector.with_jit_req_inspector(http_req_inspector),
                _phantom: PhantomData,
            }
        }

        /// Removes the currently configured request inspector(s)
        ///
        /// By default most methods add some request inspectors, this
        /// can be used to remove them
        pub fn without_jit_req_inspector(
            self,
        ) -> EasyHttpWebClientBuilder<HttpConnector<T, (), I2>, HttpStage> {
            EasyHttpWebClientBuilder {
                connector: self.connector.with_jit_req_inspector(()),
                _phantom: PhantomData,
            }
        }

        #[cfg(any(feature = "rustls", feature = "boring"))]
        /// Add a http request inspector that will run just after the inner http connector
        /// has connected but before the http handshake happens
        ///
        /// This will also add the [`HttpsAlpnModifier`] request inspector as that one is
        /// crucial to make tls alpn work and set the correct [`TargetHttpVersion`]
        ///
        /// And a [`HttpVersionAdapter`] that will adapt the request version to the configured
        /// [`TargetHttpVersion`]
        ///
        /// If you don't want any of these inspector you can use [`Self::with_advanced_jit_req_inspector`]
        /// to configure your own request inspectors without any defaults
        ///
        /// [`TargetHttpVersion`]: rama_http::conn::TargetHttpVersion;
        pub fn with_jit_req_inspector<I>(
            self,
            http_req_inspector: I,
        ) -> EasyHttpWebClientBuilder<
            HttpConnector<T, (HttpsAlpnModifier, HttpVersionAdapter, I), I2>,
            HttpStage,
        > {
            EasyHttpWebClientBuilder {
                connector: self.connector.with_jit_req_inspector((
                    HttpsAlpnModifier::default(),
                    HttpVersionAdapter::default(),
                    http_req_inspector,
                )),
                _phantom: PhantomData,
            }
        }

        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        /// Add a http request inspector that will run just after the inner http connector
        /// has finished but before the http handshake
        ///
        /// This will also add the [`HttpVersionAdapter`] that will adapt the request version to
        /// the configured [`TargetHttpVersion`]
        ///
        /// If you don't want any of these inspector you can use [`Self::with_advanced_jit_req_inspector`]
        /// to configure your own request inspectors without any defaults
        ///
        /// [`TargetHttpVersion`]: rama_http::conn::TargetHttpVersion;
        pub fn with_jit_req_inspector<I>(
            self,
            http_req_inspector: I,
        ) -> EasyHttpWebClientBuilder<HttpConnector<T, (HttpVersionAdapter, I), I2>, HttpStage>
        {
            EasyHttpWebClientBuilder {
                connector: self
                    .connector
                    .with_jit_req_inspector((HttpVersionAdapter::default(), http_req_inspector)),
                _phantom: PhantomData,
            }
        }

        /// Add a http request inspector that will run just before doing the actual http request
        pub fn with_svc_req_inspector<I>(
            self,
            http_req_inspector: I,
        ) -> EasyHttpWebClientBuilder<HttpConnector<T, I1, I>, HttpStage> {
            EasyHttpWebClientBuilder {
                connector: self.connector.with_svc_req_inspector(http_req_inspector),
                _phantom: PhantomData,
            }
        }
    }

    type DefaultConnectionPoolBuilder<T, C> = EasyHttpWebClientBuilder<
        PooledConnector<T, LruDropPool<C, BasicHttpConId>, BasicHttpConnIdentifier>,
        PoolStage,
    >;

    impl<T> EasyHttpWebClientBuilder<T, HttpStage> {
        /// Use the default connection pool for this [`super::EasyHttpWebClient`]
        ///
        /// This will create a [`FiFoReuseLruDropPool`] using the provided limits
        /// and will use [`BasicHttpConnIdentifier`] to group connection on protocol
        /// and authority, which should cover most common use cases
        ///
        /// Use `wait_for_pool_timeout` to limit how long we wait for the pool to give us a connection
        ///
        /// If you need a different pool or custom way to group connection you can
        /// use [`EasyHttpWebClientBuilder::with_custom_connection_pool()`] to provide
        /// you own.
        pub fn with_connection_pool<C>(
            self,
            config: HttpPooledConnectorConfig,
        ) -> Result<DefaultConnectionPoolBuilder<T, C>, OpaqueError> {
            let connector = config.build_connector(self.connector)?;

            Ok(EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            })
        }

        /// Configure this client to use the provided [`Pool`] and [`ReqToConnId`]
        ///
        /// Use `wait_for_pool_timeout` to limit how long we wait for the pool to give us a connection
        ///
        /// [`Pool`]: rama_net::client::pool::Pool
        /// [`ReqToConnId`]: rama_net::client::pool::ReqToConnID
        pub fn with_custom_connection_pool<P, R>(
            self,
            pool: P,
            req_to_conn_id: R,
            wait_for_pool_timeout: Option<Duration>,
        ) -> EasyHttpWebClientBuilder<PooledConnector<T, P, R>, PoolStage> {
            let connector = PooledConnector::new(self.connector, pool, req_to_conn_id)
                .maybe_with_wait_for_pool_timeout(wait_for_pool_timeout);

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }
    }

    impl<T, S> EasyHttpWebClientBuilder<T, S> {
        /// Build a [`super::EasyHttpWebClient`] using the provided config
        pub fn build<State, Body, ModifiedBody, ConnResponse>(
            self,
        ) -> super::EasyHttpWebClient<State, Body, T::Response>
        where
            State: Send + Sync + 'static,
            Body: http_body::Body<Data: Send + 'static, Error: Into<BoxError>>
                + Unpin
                + Send
                + 'static,
            ModifiedBody: http_body::Body<Data: Send + 'static, Error: Into<BoxError>>
                + Unpin
                + Send
                + 'static,
            T: Service<
                    State,
                    Request<Body>,
                    Response = EstablishedClientConnection<
                        ConnResponse,
                        State,
                        Request<ModifiedBody>,
                    >,
                    Error = BoxError,
                >,
        {
            super::EasyHttpWebClient::new(self.connector.boxed())
        }
    }
}
