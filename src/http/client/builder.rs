#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_core::layer::AddInputExtension;
use rama_core::rt::Executor;

use super::{
    HttpConnectRequestAdapter, HttpConnector, HttpPooledConnector, HttpPooledConnectorConfig,
};
#[cfg(any(feature = "rustls", feature = "boring"))]
use crate::http::conn::TargetHttpVersion;
use crate::{
    Layer, Service,
    dns::client::{DnsConnectorLayer, resolver::DnsAddressResolver},
    error::BoxError,
    extensions::ExtensionsRef,
    http::{
        Request, StreamingBody, client::proxy::layer::HttpProxyConnector,
        layer::version_adapter::RequestVersionAdapter,
    },
    net::client::{
        ConnectRequest, ConnectorService, EstablishedClientConnection, ProxyRoutesConnector,
        pool::PooledConnector,
    },
    tcp::client::service::TcpConnector,
};
use std::{marker::PhantomData, time::Duration};

#[cfg(feature = "boring")]
use crate::tls::boring::client as boring_client;

#[cfg(any(feature = "rustls", feature = "boring"))]
use crate::tls::client::TlsClientConfig;
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
pub struct DnsStage;
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

impl<T> EasyHttpConnectorBuilder<T, TransportStage> {
    /// Add the default DNS connector layer using the global DNS resolver.
    pub fn with_default_dns_connector(
        self,
    ) -> EasyHttpConnectorBuilder<crate::dns::client::DnsConnector<T>, DnsStage> {
        self.with_dns_connector(DnsConnectorLayer::new())
    }

    /// Add a DNS connector layer using a custom [`DnsAddressResolver`].
    pub fn with_dns_address_resolver<R: DnsAddressResolver + Clone>(
        self,
        resolver: R,
    ) -> EasyHttpConnectorBuilder<crate::dns::client::DnsConnector<T, R>, DnsStage> {
        self.with_dns_connector(DnsConnectorLayer::with_resolver(resolver))
    }

    /// Don't add a DNS connector
    ///
    /// Warning: this means the transport connector will only work if the configured target
    /// is using an IP address and not a DNS address
    pub fn without_dns_connector(
        self,
    ) -> EasyHttpConnectorBuilder<crate::dns::client::DnsConnector<T>, DnsStage> {
        self.with_dns_connector(DnsConnectorLayer::new())
    }

    /// Add a custom DNS connector layer.
    pub fn with_dns_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, DnsStage>
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

impl<T> EasyHttpConnectorBuilder<T, DnsStage> {
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
        config: TlsClientConfig,
    ) -> EasyHttpConnectorBuilder<
        boring_client::TlsConnector<T, boring_client::ConnectorKindTunnel>,
        ProxyTunnelStage,
    > {
        let connector =
            boring_client::TlsConnector::tunnel(self.connector, None).with_base_config(config);
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
        config: TlsClientConfig,
    ) -> EasyHttpConnectorBuilder<
        rustls_client::TlsConnector<T, rustls_client::ConnectorKindTunnel>,
        ProxyTunnelStage,
    > {
        let connector =
            rustls_client::TlsConnector::tunnel(self.connector, None).with_base_config(config);

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
    /// The final HTTP transition applies a [`RequestVersionAdapter`] outside
    /// the complete connection attempt so it can apply the negotiated version
    /// to the original HTTP request.
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
    /// The final HTTP transition automatically applies the HTTP version
    /// negotiated through TLS to the original request.
    pub fn with_tls_support_using_boringssl(
        self,
        config: TlsClientConfig,
    ) -> EasyHttpConnectorBuilder<boring_client::TlsConnector<T>, TlsStage> {
        let connector = boring_client::TlsConnector::auto(self.connector).with_base_config(config);

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
        config: TlsClientConfig,
        default_http_version: rama_http::Version,
    ) -> EasyHttpConnectorBuilder<
        AddInputExtension<boring_client::TlsConnector<T>, TargetHttpVersion>,
        TlsStage,
    > {
        let connector = boring_client::TlsConnector::auto(self.connector).with_base_config(config);
        let connector =
            AddInputExtension::new_if_absent(connector, TargetHttpVersion(default_http_version));

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    #[cfg(feature = "rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
    /// Support https connections by using ruslts for tls
    ///
    /// The final HTTP transition automatically applies the HTTP version
    /// negotiated through TLS to the original request.
    pub fn with_tls_support_using_rustls(
        self,
        config: TlsClientConfig,
    ) -> EasyHttpConnectorBuilder<rustls_client::TlsConnector<T>, TlsStage> {
        let connector = rustls_client::TlsConnector::auto(self.connector).with_base_config(config);

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
        config: TlsClientConfig,
        default_http_version: rama_http::Version,
    ) -> EasyHttpConnectorBuilder<
        AddInputExtension<rustls_client::TlsConnector<T>, TargetHttpVersion>,
        TlsStage,
    > {
        let connector = rustls_client::TlsConnector::auto(self.connector).with_base_config(config);
        let connector =
            AddInputExtension::new_if_absent(connector, TargetHttpVersion(default_http_version));

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    /// Don't support https on this connector
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

type DefaultHttpConnector<T> =
    RequestVersionAdapter<HttpConnectRequestAdapter<ProxyRoutesConnector<T>>>;

type DefaultConnectionBuilder<T> = EasyHttpConnectorBuilder<DefaultHttpConnector<T>, PoolStage>;

type DefaultConnectionPoolBuilder<T> =
    EasyHttpConnectorBuilder<DefaultHttpConnector<HttpPooledConnector<T>>, PoolStage>;

fn finalize_http_connector<T>(connector: T) -> DefaultHttpConnector<T> {
    let connector = ProxyRoutesConnector::new(connector);
    let connector = HttpConnectRequestAdapter::new(connector);
    RequestVersionAdapter::new(connector)
}

impl<T> EasyHttpConnectorBuilder<T, HttpStage> {
    /// Finish the default HTTP connector stack without adding a connection pool.
    ///
    /// This still installs HTTP request adaptation and ordered proxy-route
    /// fallback. The only omitted component is the pool itself.
    pub fn without_connection_pool(self) -> DefaultConnectionBuilder<T>
    where
        T: ConnectorService<ConnectRequest>,
    {
        EasyHttpConnectorBuilder {
            connector: finalize_http_connector(self.connector),
            _phantom: PhantomData,
        }
    }

    /// Use the default connection pool for this [`super::EasyHttpWebClient`]
    ///
    /// This will create a [`MultiplexPool`](crate::net::client::pool::MultiplexPool)
    /// using the provided limits and will use
    /// [`BasicHttpConnIdentifier`](super::BasicHttpConnIdentifier) to group connections
    /// on protocol, authority and the selected singular proxy route, which should
    /// cover most common use cases.
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
    pub fn try_with_connection_pool(
        self,
        config: HttpPooledConnectorConfig,
    ) -> Result<DefaultConnectionPoolBuilder<T>, BoxError>
    where
        T: ConnectorService<ConnectRequest>,
    {
        let connector = config.build_connector(self.connector)?;
        let connector = finalize_http_connector(connector);

        Ok(EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        })
    }

    #[inline(always)]
    /// Use the default connection pool for this [`super::EasyHttpWebClient`].
    ///
    /// The default pool is a multiplexing pool (see
    /// [`Self::try_with_connection_pool`]) with a default
    /// [`HttpPooledConnectorConfig`]: http/2 connections serve multiple
    /// concurrent requests, while http/1 connections are used one request at a
    /// time.
    pub fn try_with_default_connection_pool(
        self,
    ) -> Result<DefaultConnectionPoolBuilder<T>, BoxError>
    where
        T: ConnectorService<ConnectRequest>,
    {
        self.try_with_connection_pool(Default::default())
    }

    /// Configure this client to use the provided [`Pool`] and [`ReqToConnId`]
    ///
    /// Use `wait_for_pool_timeout` to limit how long we wait for the pool to give us a connection
    ///
    /// Warning: this does not apply a [`RequestVersionAdapter`] layer to make sure that request versions
    /// are adapted when pooled connections are used, which you almost always. This should be manually added
    /// by using [`Self::with_custom_connector`] after configuring this pool and providing a [`RequestVersionAdapter`] there.
    /// Unlike [`Self::try_with_connection_pool`], this fully generic method also does not install the HTTP
    /// connect-request adapter or proxy-route connector. Callers that want route-aware fallback around a custom
    /// pool can compose those layers explicitly around their [`PooledConnector`].
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

impl<T> EasyHttpConnectorBuilder<T, PoolStage> {
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
                Error: Into<BoxError>,
            >,
        ConnResponse: ExtensionsRef,
    {
        super::EasyHttpWebClient::new(self.connector)
    }
}

impl<T, S> EasyHttpConnectorBuilder<T, S> {
    /// Build a connector from the currently configured setup
    pub fn build_connector(self) -> T {
        self.connector
    }
}
