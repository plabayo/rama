use rama_core::rt::Executor;

use super::HttpConnector;
use crate::{
    Layer, Service,
    dns::DnsResolver,
    error::BoxError,
    extensions::ExtensionsMut,
    http::{
        Request, StreamingBody, client::proxy::layer::HttpProxyConnector,
        layer::version_adapter::RequestVersionAdapter,
    },
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

#[cfg(feature = "socks5")]
use crate::{http::client::proxy_connector::ProxyConnector, proxy::socks5::Socks5ProxyConnector};

/// Builder that is designed to easily create a connoector for [`super::EasyHttpWebClient`] from most basic use cases
#[derive(Default)]
pub struct EasyHttpConnectorBuilder<C = (), S = ()> {
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

impl EasyHttpConnectorBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_default_transport_connector(
        self,
    ) -> EasyHttpConnectorBuilder<TcpConnector, TransportStage> {
        let connector = TcpConnector::default();
        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    /// Add a custom transport connector that will be used by this client for the transport layer
    pub fn with_custom_transport_connector<C>(
        self,
        connector: C,
    ) -> EasyHttpConnectorBuilder<C, TransportStage> {
        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }
}

impl<T, Stage> EasyHttpConnectorBuilder<T, Stage> {
    /// Add a custom connector to this Stage.
    ///
    /// Adding a custom connector to a stage will not change the state
    /// so this can be used to modify behaviour at a specific stage.
    pub fn with_custom_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, Stage>
    where
        L: Layer<T>,
    {
        self.map_connector(|c| connector_layer.into_layer(c))
    }

    /// Map the current connector using the given fn.
    ///
    /// Mapping a connector to a stage will not change the state
    /// so this can be used to modify behaviour at a specific stage.
    pub fn map_connector<T2>(
        self,
        map_fn: impl FnOnce(T) -> T2,
    ) -> EasyHttpConnectorBuilder<T2, Stage> {
        let connector = map_fn(self.connector);
        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }
}

impl EasyHttpConnectorBuilder<TcpConnector, TransportStage> {
    /// Add a custom [`DnsResolver`] that will be used by this client
    pub fn with_dns_resolver<T: DnsResolver + Clone>(
        self,
        resolver: T,
    ) -> EasyHttpConnectorBuilder<TcpConnector<T>, TransportStage> {
        let connector = self.connector.with_dns(resolver);
        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }
}

impl<T> EasyHttpConnectorBuilder<T, TransportStage> {
    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Add a custom proxy tls connector that will be used to setup a tls connection to the proxy
    pub fn with_custom_tls_proxy_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, ProxyTunnelStage>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);
        EasyHttpConnectorBuilder {
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
    ) -> EasyHttpConnectorBuilder<
        boring_client::TlsConnector<T, boring_client::ConnectorKindTunnel>,
        ProxyTunnelStage,
    > {
        let connector = boring_client::TlsConnector::tunnel(self.connector, None);
        EasyHttpConnectorBuilder {
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
    ) -> EasyHttpConnectorBuilder<
        boring_client::TlsConnector<T, boring_client::ConnectorKindTunnel>,
        ProxyTunnelStage,
    > {
        let connector =
            boring_client::TlsConnector::tunnel(self.connector, None).with_connector_data(config);
        EasyHttpConnectorBuilder {
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
    ) -> EasyHttpConnectorBuilder<
        rustls_client::TlsConnector<T, rustls_client::ConnectorKindTunnel>,
        ProxyTunnelStage,
    > {
        let connector = rustls_client::TlsConnector::tunnel(self.connector, None);

        EasyHttpConnectorBuilder {
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
    ) -> EasyHttpConnectorBuilder<
        rustls_client::TlsConnector<T, rustls_client::ConnectorKindTunnel>,
        ProxyTunnelStage,
    > {
        let connector =
            rustls_client::TlsConnector::tunnel(self.connector, None).with_connector_data(config);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    /// Don't support a tls tunnel to the proxy itself
    ///
    /// Note that a tls proxy is not needed to make a https connection
    /// to the final target. It only has an influence on the initial connection
    /// to the proxy itself
    pub fn without_tls_proxy_support(self) -> EasyHttpConnectorBuilder<T, ProxyTunnelStage> {
        EasyHttpConnectorBuilder {
            connector: self.connector,
            _phantom: PhantomData,
        }
    }
}

impl<T> EasyHttpConnectorBuilder<T, ProxyTunnelStage> {
    /// Add a custom proxy connector that will be used by this client
    pub fn with_custom_proxy_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, ProxyStage>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);
        EasyHttpConnectorBuilder {
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
    pub fn with_proxy_support(self) -> EasyHttpConnectorBuilder<HttpProxyConnector<T>, ProxyStage> {
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
    ) -> EasyHttpConnectorBuilder<HttpProxyConnector<T>, ProxyStage> {
        let connector = HttpProxyConnector::optional(self.connector);

        EasyHttpConnectorBuilder {
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
    ) -> EasyHttpConnectorBuilder<Socks5ProxyConnector<T>, ProxyStage> {
        let connector = Socks5ProxyConnector::optional(self.connector);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    /// Make a client without proxy support
    pub fn without_proxy_support(self) -> EasyHttpConnectorBuilder<T, ProxyStage> {
        EasyHttpConnectorBuilder {
            connector: self.connector,
            _phantom: PhantomData,
        }
    }
}

impl<T: Clone> EasyHttpConnectorBuilder<T, ProxyTunnelStage> {
    #[cfg(feature = "socks5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
    /// Add support for usage of a http(s) and socks5(h) [`ProxyAddress`] to this client
    ///
    /// Note that a tls proxy is not needed to make a https connection
    /// to the final target. It only has an influence on the initial connection
    /// to the proxy itself
    ///
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn with_proxy_support(self) -> EasyHttpConnectorBuilder<ProxyConnector<T>, ProxyStage> {
        use rama_http_backend::client::proxy::layer::HttpProxyConnectorLayer;
        use rama_socks5::Socks5ProxyConnectorLayer;

        let connector = ProxyConnector::optional(
            self.connector,
            Socks5ProxyConnectorLayer::required(),
            HttpProxyConnectorLayer::required(),
        );

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }
}

impl<T> EasyHttpConnectorBuilder<T, ProxyStage> {
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
    ) -> EasyHttpConnectorBuilder<L::Service, TlsStage>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);

        EasyHttpConnectorBuilder {
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
    ) -> EasyHttpConnectorBuilder<RequestVersionAdapter<boring_client::TlsConnector<T>>, TlsStage>
    {
        let connector =
            boring_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);
        let connector = RequestVersionAdapter::new(connector);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    #[cfg(feature = "boring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
    /// Same as [`Self::with_tls_support_using_boringssl`] but also
    /// setting the default `TargetHttpVersion` in case no ALPN is negotiated.
    ///
    /// This is a fairly important detail for proxy purposes given otherwise
    /// you might come in situations where the ingress traffic is negotiated to `h2`,
    /// but the egress traffic has no negotiation which would without a default
    /// http version remain on h2... In such a case you can get failed
    /// requests if the egress server does not handle multiple http versions.
    pub fn with_tls_support_using_boringssl_and_default_http_version(
        self,
        config: Option<std::sync::Arc<boring_client::TlsConnectorDataBuilder>>,
        default_http_version: rama_http::Version,
    ) -> EasyHttpConnectorBuilder<RequestVersionAdapter<boring_client::TlsConnector<T>>, TlsStage>
    {
        let connector =
            boring_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);
        let connector =
            RequestVersionAdapter::new(connector).with_default_version(default_http_version);

        EasyHttpConnectorBuilder {
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
    ) -> EasyHttpConnectorBuilder<RequestVersionAdapter<rustls_client::TlsConnector<T>>, TlsStage>
    {
        let connector =
            rustls_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);
        let connector = RequestVersionAdapter::new(connector);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    #[cfg(feature = "rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
    /// Same as [`Self::with_tls_support_using_rustls`] but also
    /// setting the default `TargetHttpVersion` in case no ALPN is negotiated.
    ///
    /// This is a fairly important detail for proxy purposes given otherwise
    /// you might come in situations where the ingress traffic is negotiated to `h2`,
    /// but the egress traffic has no negotiation which would without a default
    /// http version remain on h2... In such a case you can get failed
    /// requests if the egress server does not handle multiple http versions.
    pub fn with_tls_support_using_rustls_and_default_http_version(
        self,
        config: Option<rustls_client::TlsConnectorData>,
        default_http_version: rama_http::Version,
    ) -> EasyHttpConnectorBuilder<RequestVersionAdapter<rustls_client::TlsConnector<T>>, TlsStage>
    {
        let connector =
            rustls_client::TlsConnector::auto(self.connector).maybe_with_connector_data(config);
        let connector =
            RequestVersionAdapter::new(connector).with_default_version(default_http_version);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    /// Dont support https on this connector
    pub fn without_tls_support(self) -> EasyHttpConnectorBuilder<T, TlsStage> {
        EasyHttpConnectorBuilder {
            connector: self.connector,
            _phantom: PhantomData,
        }
    }
}

impl<T> EasyHttpConnectorBuilder<T, TlsStage> {
    /// Add http support to this connector
    pub fn with_default_http_connector<Body>(
        self,
        exec: Executor,
    ) -> EasyHttpConnectorBuilder<HttpConnector<T, Body>, HttpStage> {
        let connector = HttpConnector::new(self.connector, exec);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    /// Add a custom http connector that will be run just after tls
    pub fn with_custom_http_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, HttpStage>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }
}

type DefaultConnectionPoolBuilder<T, C> = EasyHttpConnectorBuilder<
    RequestVersionAdapter<
        PooledConnector<T, LruDropPool<C, BasicHttpConId>, BasicHttpConnIdentifier>,
    >,
    PoolStage,
>;

impl<T> EasyHttpConnectorBuilder<T, HttpStage> {
    /// Use the default connection pool for this [`super::EasyHttpWebClient`]
    ///
    /// This will create a [`LruDropPool`] using the provided limits
    /// and will use [`BasicHttpConnIdentifier`] to group connection on protocol
    /// and authority, which should cover most common use cases
    ///
    /// Use `wait_for_pool_timeout` to limit how long we wait for the pool to give us a connection
    ///
    /// If you need a different pool or custom way to group connection you can
    /// use [`EasyHttpConnectorBuilder::with_custom_connection_pool()`] to provide
    /// you own.
    ///
    /// This also applies a [`RequestVersionAdapter`] layer to make sure that request versions
    /// are adapted when pooled connections are used, which you almost always need, but in case
    /// that is unwanted, you can use [`Self::with_custom_connection_pool`] instead.
    pub fn try_with_connection_pool<C: ExtensionsMut>(
        self,
        config: HttpPooledConnectorConfig,
    ) -> Result<DefaultConnectionPoolBuilder<T, C>, BoxError> {
        let connector = config.build_connector(self.connector)?;
        let connector = RequestVersionAdapter::new(connector);

        Ok(EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        })
    }

    #[inline(always)]
    /// Same as [`Self::try_with_connection_pool`] but using the default [`HttpPooledConnectorConfig`].
    pub fn try_with_default_connection_pool<C: ExtensionsMut>(
        self,
    ) -> Result<DefaultConnectionPoolBuilder<T, C>, BoxError> {
        self.try_with_connection_pool(Default::default())
    }

    /// Configure this client to use the provided [`Pool`] and [`ReqToConnId`]
    ///
    /// Use `wait_for_pool_timeout` to limit how long we wait for the pool to give us a connection
    ///
    /// Warning: this does not apply a [`RequestVersionAdapter`] layer to make sure that request versions
    /// are adapted when pooled connections are used, which you almost always. This should be manually added
    /// by using [`Self::with_custom_connector`] after configuring this pool and providing a [`RequestVersionAdapter`] there.
    ///
    /// [`Pool`]: rama_net::client::pool::Pool
    /// [`ReqToConnId`]: rama_net::client::pool::ReqToConnID
    pub fn with_custom_connection_pool<P, R>(
        self,
        pool: P,
        req_to_conn_id: R,
        wait_for_pool_timeout: Option<Duration>,
    ) -> EasyHttpConnectorBuilder<PooledConnector<T, P, R>, PoolStage> {
        let connector = PooledConnector::new(self.connector, pool, req_to_conn_id)
            .maybe_with_wait_for_pool_timeout(wait_for_pool_timeout);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }
}

impl<T, S> EasyHttpConnectorBuilder<T, S> {
    /// Build a [`super::EasyHttpWebClient`] using the currently configured connector
    pub fn build_client<Body, ModifiedBody, ConnResponse>(
        self,
    ) -> super::EasyHttpWebClient<Body, T::Output, ()>
    where
        Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
        ModifiedBody:
            StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
        T: Service<
                Request<Body>,
                Output = EstablishedClientConnection<ConnResponse, Request<ModifiedBody>>,
                Error = BoxError,
            >,
        ConnResponse: ExtensionsMut,
    {
        super::EasyHttpWebClient::new(self.connector.boxed())
    }

    /// Build a connector from the currently configured setup
    pub fn build_connector(self) -> T {
        self.connector
    }
}
