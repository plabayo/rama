//! Rama HTTP client module,
//! which provides the [`EasyHttpWebClient`] type to serve HTTP requests.

use std::{fmt, sync::Arc};

use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext, OpaqueError},
};
use rama_http_types::{Request, Response, dep::http_body};
use rama_net::client::EstablishedClientConnection;

mod svc;
#[doc(inline)]
pub use svc::HttpClientService;

mod conn;
#[doc(inline)]
pub use conn::{HttpConnector, HttpConnectorLayer};
use tracing::trace;

pub mod http_inspector;
pub mod proxy;

/// An opiniated http client that can be used to serve HTTP requests.
///
/// You can fork this http client in case you have use cases not possible with this service example.
/// E.g. perhaps you wish to have middleware in into outbound requests, after they
/// passed through your "connector" setup. All this and more is possible by defining your own
/// http client. Rama is here to empower you, the building blocks are there, go crazy
/// with your own service fork and use the full power of Rust at your fingertips ;)
pub struct EasyHttpWebClient<C> {
    connector: C,
}

impl<C: fmt::Debug> fmt::Debug for EasyHttpWebClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHttpWebClient")
            .field("connector", &self.connector)
            .finish()
    }
}

impl<C: Clone> Clone for EasyHttpWebClient<C> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
        }
    }
}

#[cfg(not(any(feature = "rustls", feature = "boring")))]
impl Default for EasyHttpWebClient<Arc<easy_connector::DefaultNoTlsConnector>> {
    fn default() -> Self {
        Self {
            connector: Arc::new(EasyConnectorBuilder::default().build()),
        }
    }
}

#[cfg(feature = "boring")]
impl Default for EasyHttpWebClient<Arc<easy_connector::DefaultBoringConnector>> {
    fn default() -> Self {
        Self {
            connector: Arc::new(EasyConnectorBuilder::default().build()),
        }
    }
}

#[cfg(all(feature = "rustls", not(feature = "boring")))]
impl Default for EasyHttpWebClient<Arc<easy_connector::DefaultRustlsConnector>> {
    fn default() -> Self {
        Self {
            connector: Arc::new(EasyConnectorBuilder::default().build()),
        }
    }
}

impl<C> EasyHttpWebClient<C> {
    /// Create a new [`EasyHttpWebClient`].
    pub fn new(connector: C) -> Self {
        Self { connector }
    }

    /// Set the [`Connector`] that this [`EasyHttpWebClient`] will use.
    ///
    /// To easily create a connector for most use cases you can use [`EasyConnectorBuilder`].
    /// If you want this client to also implement [`Clone`] the easiest option is to place
    /// the result of [`EasyConnectorBuilder::build`] inside and [`Arc`].
    pub fn with_connector<T>(self, connector: T) -> EasyHttpWebClient<T> {
        EasyHttpWebClient { connector }
    }
}

impl<State, Body, ModifiedBody, C, Conn> Service<State, Request<Body>> for EasyHttpWebClient<C>
where
    State: Send + Sync + 'static,
    Body: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    ModifiedBody:
        http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    C: Service<
            State,
            Request<Body>,
            Response = EstablishedClientConnection<Conn, State, Request<ModifiedBody>>,
            Error: Into<BoxError>,
        >,
    Conn: Service<State, Request<ModifiedBody>, Response = Response, Error: Into<BoxError>>,
{
    type Response = Response;

    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let uri = req.uri().clone();

        let EstablishedClientConnection { ctx, req, conn } =
            self.connector.serve(ctx, req).await.map_err(Into::into)?;

        // NOTE: stack might change request version based on connector data,
        trace!(uri = %uri, "send http req to connector stack");

        let result = conn.serve(ctx, req).await;

        let resp = result
            .map_err(|err| OpaqueError::from_boxed(err.into()))
            .with_context(|| format!("http request failure for uri: {uri}"))?;

        trace!(uri = %uri, "response received from connector stack");

        Ok(resp)
    }
}

#[doc(inline)]
pub use easy_connector::EasyConnectorBuilder;

mod easy_connector {
    use super::{HttpConnector, proxy::layer::HttpProxyConnector};
    use rama_http::Version;
    use rama_net::client::pool::{PooledConnector, http::BasicHttpConnIdentifier};
    use rama_tcp::client::service::TcpConnector;
    use std::{marker::PhantomData, sync::Arc};

    #[cfg(feature = "boring")]
    use rama_tls_boring::client as boring_client;

    #[cfg(feature = "rustls")]
    use rama_tls_rustls::client as rustls_client;

    /// Builder that is designed to easily create a connector for most basic use cases.
    ///
    /// Use [`EasyConnectorBuilder::default`] to get an easy to use connector that is highly opiniated, but
    /// that should work for most common scenarios. If this builder is too limited for the use case you have
    /// no problem, in those cases you can create the connector stack yourself, and use that instead
    pub struct EasyConnectorBuilder<C, S> {
        connector: C,
        _phantom: PhantomData<S>,
    }

    pub struct TransportStage;
    pub struct ProxyStage;
    pub struct HttpStage;
    pub struct PoolStage;

    impl EasyConnectorBuilder<(), ()> {
        pub fn new() -> EasyConnectorBuilder<TcpConnector, TransportStage> {
            EasyConnectorBuilder {
                connector: TcpConnector::new(),
                _phantom: PhantomData,
            }
        }
    }

    impl<T, S> EasyConnectorBuilder<T, S> {
        pub fn build(self) -> T {
            self.connector
        }
    }

    impl<T> EasyConnectorBuilder<T, TransportStage> {
        #[cfg(feature = "boring")]
        pub fn with_tls_proxy_using_boringssl(
            self,
            config: Option<Arc<boring_client::TlsConnectorDataBuilder>>,
            http_connect_version: Option<Version>,
        ) -> EasyConnectorBuilder<
            HttpProxyConnector<boring_client::TlsConnector<T, boring_client::ConnectorKindTunnel>>,
            ProxyStage,
        > {
            let connector = boring_client::TlsConnector::tunnel(self.connector, None)
                .maybe_with_connector_data(config);
            let mut connector = HttpProxyConnector::optional(connector);
            match http_connect_version {
                Some(version) => connector.set_version(version),
                None => connector.set_auto_version(),
            };

            EasyConnectorBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        #[cfg(feature = "rustls")]
        pub fn with_tls_proxy_using_rustls(
            self,
            config: Option<rustls_client::TlsConnectorData>,
            http_connect_version: Option<Version>,
        ) -> EasyConnectorBuilder<
            HttpProxyConnector<rustls_client::TlsConnector<T, rustls_client::ConnectorKindTunnel>>,
            ProxyStage,
        > {
            let connector = rustls_client::TlsConnector::tunnel(self.connector, None)
                .maybe_with_connector_data(config);

            let mut connector = HttpProxyConnector::optional(connector);
            match http_connect_version {
                Some(version) => connector.set_version(version),
                None => connector.set_auto_version(),
            };

            EasyConnectorBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        pub fn with_proxy(self) -> EasyConnectorBuilder<HttpProxyConnector<T>, ProxyStage> {
            let connector = HttpProxyConnector::optional(self.connector);
            EasyConnectorBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        pub fn without_proxy(self) -> EasyConnectorBuilder<T, ProxyStage> {
            EasyConnectorBuilder {
                connector: self.connector,
                _phantom: PhantomData,
            }
        }
    }

    impl<T> EasyConnectorBuilder<T, ProxyStage> {
        #[cfg(feature = "boring")]
        pub fn with_tls_using_boringssl(
            self,
            config: Option<Arc<boring_client::TlsConnectorDataBuilder>>,
        ) -> EasyConnectorBuilder<HttpConnector<boring_client::TlsConnector<T>>, HttpStage>
        {
            let connector =
                boring_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);

            let connector = HttpConnector::new(connector);

            EasyConnectorBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        #[cfg(feature = "rustls")]
        pub fn with_tls_using_rustls(
            self,
            config: Option<rustls_client::TlsConnectorData>,
        ) -> EasyConnectorBuilder<HttpConnector<rustls_client::TlsConnector<T>>, HttpStage>
        {
            let connector =
                rustls_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);

            let connector = HttpConnector::new(connector);

            EasyConnectorBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        pub fn without_tls(self) -> EasyConnectorBuilder<HttpConnector<T>, HttpStage> {
            let connector = HttpConnector::new(self.connector);

            EasyConnectorBuilder {
                connector: connector,
                _phantom: PhantomData,
            }
        }
    }

    impl<T, I1, I2> EasyConnectorBuilder<HttpConnector<T, I1, I2>, HttpStage> {
        pub fn with_jit_req_inspector<I>(
            self,
            http_req_inspector: I,
        ) -> EasyConnectorBuilder<HttpConnector<T, I, I2>, HttpStage> {
            EasyConnectorBuilder {
                connector: self.connector.with_jit_req_inspector(http_req_inspector),
                _phantom: PhantomData,
            }
        }

        pub fn with_svc_req_inspector<I>(
            self,
            http_req_inspector: I,
        ) -> EasyConnectorBuilder<HttpConnector<T, I1, I>, HttpStage> {
            EasyConnectorBuilder {
                connector: self.connector.with_svc_req_inspector(http_req_inspector),
                _phantom: PhantomData,
            }
        }
    }

    impl<T> EasyConnectorBuilder<T, HttpStage> {
        pub fn with_conn_pool_using_basic_id<P>(
            self,
            pool: P,
        ) -> EasyConnectorBuilder<PooledConnector<T, P, BasicHttpConnIdentifier>, PoolStage>
        {
            let connector =
                PooledConnector::new(self.connector, pool, BasicHttpConnIdentifier::default());

            EasyConnectorBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        pub fn with_conn_pool_using_custom_id<P, R>(
            self,
            pool: P,
            req_to_conn_id: R,
        ) -> EasyConnectorBuilder<PooledConnector<T, P, R>, PoolStage> {
            let connector = PooledConnector::new(self.connector, pool, req_to_conn_id);

            EasyConnectorBuilder {
                connector,
                _phantom: PhantomData,
            }
        }
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    pub(super) type DefaultNoTlsConnector = HttpConnector<HttpProxyConnector<TcpConnector>>;

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    impl Default for EasyConnectorBuilder<DefaultNoTlsConnector, HttpStage> {
        fn default() -> Self {
            EasyConnectorBuilder::new().with_proxy().without_tls()
        }
    }

    #[cfg(feature = "boring")]
    pub(super) type DefaultBoringConnector = HttpConnector<
        boring_client::TlsConnector<
            HttpProxyConnector<
                boring_client::TlsConnector<TcpConnector, boring_client::ConnectorKindTunnel>,
            >,
        >,
    >;

    #[cfg(feature = "boring")]
    impl Default for EasyConnectorBuilder<DefaultBoringConnector, HttpStage> {
        fn default() -> Self {
            let tls_config =
                boring_client::TlsConnectorDataBuilder::new_http_auto().into_shared_builder();

            EasyConnectorBuilder::new()
                .with_tls_proxy_using_boringssl(None, None)
                .with_tls_using_boringssl(Some(tls_config))
        }
    }

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    pub(super) type DefaultRustlsConnector = HttpConnector<
        rustls_client::TlsConnector<
            HttpProxyConnector<
                rustls_client::TlsConnector<TcpConnector, rustls_client::ConnectorKindTunnel>,
            >,
        >,
    >;

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    impl Default for EasyConnectorBuilder<DefaultRustlsConnector, HttpStage> {
        fn default() -> Self {
            let tls_config = rustls_client::TlsConnectorData::new_http_auto()
                .expect("connector data with http auto");

            EasyConnectorBuilder::new()
                .with_tls_proxy_using_rustls(None, None)
                .with_tls_using_rustls(Some(tls_config))
        }
    }
}
