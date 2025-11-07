use super::HttpConnector;
use crate::{
    Layer, Service,
    dns::DnsResolver,
    error::{BoxError, OpaqueError},
    extensions::ExtensionsMut,
    http::{Request, StreamingBody, client::proxy::layer::HttpProxyConnector},
    net::client::{
        EstablishedClientConnection,
        pool::{
            LruDropPool, PooledConnector,
            http::{BasicHttpConId, BasicHttpConnIdentifier, HttpPooledConnectorConfig},
        },
    },
    tcp::client::service::TcpConnector,
};
use std::{marker::PhantomData, time::Duration};

#[cfg(feature = "boring")]
use crate::tls::boring::client as boring_client;

#[cfg(feature = "rustls")]
use crate::tls::rustls::client as rustls_client;

#[cfg(any(feature = "rustls", feature = "boring"))]
use crate::http::layer::version_adapter::RequestVersionAdapter;

#[cfg(feature = "socks5")]
use crate::{http::client::proxy_connector::ProxyConnector, proxy::socks5::Socks5ProxyConnector};

/// Builder that is designed to easily create a [`super::EasyHttpWebClient`] from most basic use cases
#[derive(Default)]
pub struct EasyHttpWebClientBuilder<C = (), S = ()> {
    connector: C,
    _phantom: PhantomData<S>,
}

#[non_exhaustive]
#[derive(Debug)]
pub struct TransportStage;
#[non_exhaustive]
#[derive(Debug)]
pub struct ProxyTunnelStage;
#[non_exhaustive]
#[derive(Debug)]
pub struct ProxyStage;
#[non_exhaustive]
#[derive(Debug)]
pub struct TlsStage;
#[non_exhaustive]
#[derive(Debug)]
pub struct HttpStage;
#[non_exhaustive]
#[derive(Debug)]
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

impl<T, Stage> EasyHttpWebClientBuilder<T, Stage> {
    /// Add a custom connector to this Stage.
    ///
    /// Adding a custom connector to a stage will not change the state
    /// so this can be used to modify behaviour at a specific stage.
    pub fn with_custom_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpWebClientBuilder<L::Service, TlsStage>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);

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
    #[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
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
    #[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
    /// Support a tls tunnel to the proxy itself using boringssl and the provided config
    ///
    /// Note that a tls proxy is not needed to make a https connection
    /// to the final target. It only has an influence on the initial connection
    /// to the proxy itself
    pub fn with_tls_proxy_support_using_boringssl_config(
        self,
        config: std::sync::Arc<boring_client::TlsConnectorDataBuilder>,
    ) -> EasyHttpWebClientBuilder<
        boring_client::TlsConnector<T, boring_client::ConnectorKindTunnel>,
        ProxyTunnelStage,
    > {
        let connector =
            boring_client::TlsConnector::tunnel(self.connector, None).with_connector_data(config);
        EasyHttpWebClientBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    #[cfg(feature = "rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
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
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
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
        let connector =
            rustls_client::TlsConnector::tunnel(self.connector, None).with_connector_data(config);

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

    #[cfg(feature = "socks5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
    /// Add support for usage of a http(s) and socks5(h) [`ProxyAddress`] to this client
    ///
    /// Note that a tls proxy is not needed to make a https connection
    /// to the final target. It only has an influence on the initial connection
    /// to the proxy itself
    ///
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn with_proxy_support(
        self,
    ) -> EasyHttpWebClientBuilder<ProxyConnector<std::sync::Arc<T>>, ProxyStage> {
        use rama_http_backend::client::proxy::layer::HttpProxyConnectorLayer;
        use rama_socks5::Socks5ProxyConnectorLayer;

        let connector = ProxyConnector::optional(
            self.connector,
            Socks5ProxyConnectorLayer::required(),
            HttpProxyConnectorLayer::required(),
        );

        EasyHttpWebClientBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    #[cfg(not(feature = "socks5"))]
    /// Add support for usage of a http(s) [`ProxyAddress`] to this client
    ///
    /// Note that a tls proxy is not needed to make a https connection
    /// to the final target. It only has an influence on the initial connection
    /// to the proxy itself
    ///
    /// Note to also enable socks proxy support enable feature `socks5`
    ///
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn with_proxy_support(self) -> EasyHttpWebClientBuilder<HttpProxyConnector<T>, ProxyStage> {
        self.with_http_proxy_support()
    }

    /// Add support for usage of a http(s) [`ProxyAddress`] to this client
    ///
    /// Note that a tls proxy is not needed to make a https connection
    /// to the final target. It only has an influence on the initial connection
    /// to the proxy itself
    ///
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn with_http_proxy_support(
        self,
    ) -> EasyHttpWebClientBuilder<HttpProxyConnector<T>, ProxyStage> {
        let connector = HttpProxyConnector::optional(self.connector);

        EasyHttpWebClientBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    #[cfg(feature = "socks5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
    /// Add support for usage of a socks5(h) [`ProxyAddress`] to this client
    ///
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn with_socks5_proxy_support(
        self,
    ) -> EasyHttpWebClientBuilder<Socks5ProxyConnector<T>, ProxyStage> {
        let connector = Socks5ProxyConnector::optional(self.connector);

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
    /// Note: when using a tls_connector you probably want to also
    /// add a [`RequestVersionAdapter`] which applies the negotiated
    /// http version from tls alpn. This can be achieved by using
    /// [`Self::with_custom_connector`] just after adding the tls connector.
    pub fn with_custom_tls_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpWebClientBuilder<L::Service, TlsStage>
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
    #[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
    /// Support https connections by using boringssl for tls
    ///
    /// Note: this also adds a [`RequestVersionAdapter`] to automatically change the
    /// request version to the one configured with tls alpn. If this is not
    /// wanted, use [`Self::with_custom_tls_connector`] instead.
    pub fn with_tls_support_using_boringssl(
        self,
        config: Option<std::sync::Arc<boring_client::TlsConnectorDataBuilder>>,
    ) -> EasyHttpWebClientBuilder<RequestVersionAdapter<boring_client::TlsConnector<T>>, TlsStage>
    {
        let connector =
            boring_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);
        let connector = RequestVersionAdapter::new(connector);

        EasyHttpWebClientBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    #[cfg(feature = "rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
    /// Support https connections by using ruslts for tls
    ///
    /// Note: this also adds a [`RequestVersionAdapter`] to automatically change the
    /// request version to the one configured with tls alpn. If this is not
    /// wanted, use [`Self::with_custom_tls_connector`] instead.
    pub fn with_tls_support_using_rustls(
        self,
        config: Option<rustls_client::TlsConnectorData>,
    ) -> EasyHttpWebClientBuilder<RequestVersionAdapter<rustls_client::TlsConnector<T>>, TlsStage>
    {
        let connector =
            rustls_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);
        let connector = RequestVersionAdapter::new(connector);

        EasyHttpWebClientBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    /// Dont support https on this connector
    pub fn without_tls_support(self) -> EasyHttpWebClientBuilder<T, TlsStage> {
        EasyHttpWebClientBuilder {
            connector: self.connector,
            _phantom: PhantomData,
        }
    }
}

impl<T> EasyHttpWebClientBuilder<T, TlsStage> {
    /// Add http support to this connector
    pub fn with_default_http_connector(
        self,
    ) -> EasyHttpWebClientBuilder<HttpConnector<T>, HttpStage> {
        let connector = HttpConnector::new(self.connector);

        EasyHttpWebClientBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    /// Add a custom http connector that will be run just after tls
    pub fn with_custom_http_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpWebClientBuilder<L::Service, HttpStage>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);

        EasyHttpWebClientBuilder {
            connector,
            _phantom: PhantomData,
        }
    }
}

impl<T, I> EasyHttpWebClientBuilder<HttpConnector<T, I>, HttpStage> {
    /// Add a http request inspector that will run just before doing the actual http request
    pub fn with_svc_req_inspector<U>(
        self,
        http_req_inspector: U,
    ) -> EasyHttpWebClientBuilder<HttpConnector<T, U>, HttpStage> {
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
    /// This will create a [`LruDropPool`] using the provided limits
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
    pub fn build<Body, ModifiedBody, ConnResponse>(
        self,
    ) -> super::EasyHttpWebClient<Body, T::Response>
    where
        Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
        ModifiedBody:
            StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
        T: Service<
                Request<Body>,
                Response = EstablishedClientConnection<ConnResponse, Request<ModifiedBody>>,
                Error = BoxError,
            >,
        ConnResponse: ExtensionsMut,
    {
        super::EasyHttpWebClient::new(self.connector.boxed())
    }
}
