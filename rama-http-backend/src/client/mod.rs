//! Rama HTTP client module,
//! which provides the [`EasyHttpWebClient`] type to serve HTTP requests.

use std::fmt;

use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    service::BoxService,
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
    pub fn builder() -> easy_connector::NewBuilder {
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
            .with_tls_proxy_using_boringssl(None, None)
            .with_tls_using_boringssl(Some(tls_config))
            .build()
    }

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    fn default() -> Self {
        let tls_config = rama_tls_rustls::client::TlsConnectorData::new_http_auto()
            .expect("connector data with http auto");

        EasyHttpWebClientBuilder::new()
            .with_tls_proxy_using_rustls(None, None)
            .with_tls_using_rustls(Some(tls_config))
            .build()
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    fn default() -> Self {
        EasyHttpWebClientBuilder::new()
            .with_proxy()
            .without_tls()
            .build()
    }
}

impl<State, BodyIn, ConnResponse> EasyHttpWebClient<State, BodyIn, ConnResponse> {
    /// Create a new [`EasyHttpWebClient`].
    pub fn new(connector: BoxService<State, Request<BodyIn>, ConnResponse, BoxError>) -> Self {
        Self { connector }
    }

    /// Set the [`Connector`] that this [`EasyHttpWebClient`] will use.
    ///
    /// TODO
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
        trace!(uri = %uri, "send http req to connector stack");

        let result = conn.serve(ctx, req).await;

        let resp = result
            .map_err(OpaqueError::from_boxed)
            .with_context(|| format!("http request failure for uri: {uri}"))?;

        trace!(uri = %uri, "response received from connector stack");

        Ok(resp)
    }
}

#[doc(inline)]
pub use easy_connector::EasyHttpWebClientBuilder;

mod easy_connector {
    use super::{
        HttpConnector, http_inspector::HttpsAlpnModifier, proxy::layer::HttpProxyConnector,
    };
    use rama_core::{
        Service,
        error::{BoxError, OpaqueError},
    };
    use rama_http::{Request, dep::http_body};
    use rama_net::client::{
        EstablishedClientConnection,
        pool::{
            FiFoReuseLruDropPool, PooledConnector,
            http::{BasicHttpConId, BasicHttpConnIdentifier},
        },
    };
    use rama_tcp::client::service::TcpConnector;
    use std::marker::PhantomData;

    #[cfg(feature = "boring")]
    use ::{rama_http::Version, rama_tls_boring::client as boring_client, std::sync::Arc};

    #[cfg(feature = "rustls")]
    use rama_tls_rustls::client as rustls_client;

    /// Builder that is designed to easily create a connector for most basic use cases.
    ///
    /// Use [`EasyHttpWebClientBuilder::default`] to get an easy to use connector that is highly opiniated, but
    /// that should work for most common scenarios. If this builder is too limited for the use case you have
    /// no problem, in those cases you can create the connector stack yourself, and use that instead
    pub struct EasyHttpWebClientBuilder<C, S> {
        connector: C,
        _phantom: PhantomData<S>,
    }

    pub struct TransportStage;
    pub struct ProxyStage;
    pub struct HttpStage;
    pub struct PoolStage;

    pub(super) type NewBuilder = EasyHttpWebClientBuilder<TcpConnector, TransportStage>;

    impl EasyHttpWebClientBuilder<(), ()> {
        pub fn new() -> NewBuilder {
            EasyHttpWebClientBuilder {
                connector: TcpConnector::new(),
                _phantom: PhantomData,
            }
        }
    }

    impl<T, S> EasyHttpWebClientBuilder<T, S> {
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

    impl<T> EasyHttpWebClientBuilder<T, TransportStage> {
        #[cfg(feature = "boring")]
        pub fn with_tls_proxy_using_boringssl(
            self,
            config: Option<Arc<boring_client::TlsConnectorDataBuilder>>,
            http_connect_version: Option<Version>,
        ) -> EasyHttpWebClientBuilder<
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

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        #[cfg(feature = "rustls")]
        pub fn with_tls_proxy_using_rustls(
            self,
            config: Option<rustls_client::TlsConnectorData>,
            http_connect_version: Option<Version>,
        ) -> EasyHttpWebClientBuilder<
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

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        pub fn with_proxy(self) -> EasyHttpWebClientBuilder<HttpProxyConnector<T>, ProxyStage> {
            let connector = HttpProxyConnector::optional(self.connector);
            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        pub fn without_proxy(self) -> EasyHttpWebClientBuilder<T, ProxyStage> {
            EasyHttpWebClientBuilder {
                connector: self.connector,
                _phantom: PhantomData,
            }
        }
    }

    impl<T> EasyHttpWebClientBuilder<T, ProxyStage> {
        #[cfg(feature = "boring")]
        pub fn with_tls_using_boringssl(
            self,
            config: Option<Arc<boring_client::TlsConnectorDataBuilder>>,
        ) -> EasyHttpWebClientBuilder<HttpConnector<boring_client::TlsConnector<T>>, HttpStage>
        {
            let connector =
                boring_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);

            let connector = HttpConnector::new(connector);

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        #[cfg(feature = "rustls")]
        pub fn with_tls_using_rustls(
            self,
            config: Option<rustls_client::TlsConnectorData>,
        ) -> EasyHttpWebClientBuilder<HttpConnector<rustls_client::TlsConnector<T>>, HttpStage>
        {
            let connector =
                rustls_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);

            let connector = HttpConnector::new(connector);

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }

        pub fn without_tls(self) -> EasyHttpWebClientBuilder<HttpConnector<T>, HttpStage> {
            let connector = HttpConnector::new(self.connector);

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }
    }

    impl<T, I1, I2> EasyHttpWebClientBuilder<HttpConnector<T, I1, I2>, HttpStage> {
        pub fn with_jit_req_inspector<I>(
            self,
            http_req_inspector: I,
        ) -> EasyHttpWebClientBuilder<HttpConnector<T, (HttpsAlpnModifier, I), I2>, HttpStage>
        {
            EasyHttpWebClientBuilder {
                connector: self
                    .connector
                    .with_jit_req_inspector((HttpsAlpnModifier::default(), http_req_inspector)),
                _phantom: PhantomData,
            }
        }

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

    impl<T> EasyHttpWebClientBuilder<T, HttpStage> {
        pub fn with_connection_pool<C>(
            self,
            max_active: usize,
            max_total: usize,
        ) -> Result<
            EasyHttpWebClientBuilder<
                PooledConnector<
                    T,
                    FiFoReuseLruDropPool<C, BasicHttpConId>,
                    BasicHttpConnIdentifier,
                >,
                PoolStage,
            >,
            OpaqueError,
        > {
            let pool = FiFoReuseLruDropPool::new(max_active, max_total)?;
            let connector =
                PooledConnector::new(self.connector, pool, BasicHttpConnIdentifier::default());

            Ok(EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            })
        }

        pub fn with_custom_connection_pool<P, R>(
            self,
            pool: P,
            req_to_conn_id: R,
        ) -> EasyHttpWebClientBuilder<PooledConnector<T, P, R>, PoolStage> {
            let connector = PooledConnector::new(self.connector, pool, req_to_conn_id);

            EasyHttpWebClientBuilder {
                connector,
                _phantom: PhantomData,
            }
        }
    }
}
