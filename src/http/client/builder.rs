#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_core::layer::AddInputExtension;
use rama_core::rt::Executor;

use super::{
    HttpConnectRequestAdapter, HttpConnector, HttpPooledConnector, HttpPooledConnectorConfig,
};
#[cfg(any(feature = "rustls", feature = "boring"))]
use crate::http::conn::FallbackHttpVersion;
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
        ConnectRequest, ConnectionError, ConnectorService, EstablishedClientConnection,
        ProxyRouteFailureCache, ProxyRouteFailureCacheConnector, ProxyRoutesConnector,
        pool::PooledConnector,
    },
    service::BoxService,
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

/// Builder that is designed to easily create a connector for [`super::EasyHttpWebClient`] from most basic use cases
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
pub struct ProxyTunnelStage<const TLS_PROXY: bool = true>;
#[non_exhaustive]
#[derive(Debug)]
pub struct ProxyStage<const PROXY: bool = true>;
#[non_exhaustive]
#[derive(Debug)]
pub struct TlsStage<const PROXY: bool = true>;
#[non_exhaustive]
#[derive(Debug)]
pub struct HttpStage<const PROXY: bool = true>;
#[non_exhaustive]
#[derive(Debug)]
pub struct ProxyRouteFailureCacheStage;
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
    /// Add a custom proxy TLS connector used to establish TLS to an HTTPS proxy.
    ///
    /// The layer must attach `rama_tls::client::NegotiatedTlsParameters` to
    /// the established connection. Rama uses this as positive proof that TLS
    /// was negotiated and to select the proxy-side HTTP version; missing
    /// evidence fails closed before proxy HTTP is sent.
    pub fn with_custom_tls_proxy_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, ProxyTunnelStage<true>>
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
        ProxyTunnelStage<true>,
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
        ProxyTunnelStage<true>,
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
        ProxyTunnelStage<true>,
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
        ProxyTunnelStage<true>,
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
    pub fn without_tls_proxy_support(self) -> EasyHttpConnectorBuilder<T, ProxyTunnelStage<false>> {
        EasyHttpConnectorBuilder {
            connector: self.connector,
            _phantom: PhantomData,
        }
    }
}

impl<T, const TLS_PROXY: bool> EasyHttpConnectorBuilder<T, ProxyTunnelStage<TLS_PROXY>> {
    /// Add a custom proxy connector that will be used by this client
    pub fn with_custom_proxy_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, ProxyStage<true>>
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
    pub fn with_proxy_support(
        self,
    ) -> EasyHttpConnectorBuilder<HttpProxyConnector<T>, ProxyStage<true>> {
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
    ) -> EasyHttpConnectorBuilder<HttpProxyConnector<T>, ProxyStage<true>> {
        let connector =
            HttpProxyConnector::optional(self.connector).with_tls_proxy_support(TLS_PROXY);

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
    ) -> EasyHttpConnectorBuilder<Socks5ProxyConnector<T>, ProxyStage<true>> {
        let connector = Socks5ProxyConnector::optional(self.connector);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    /// Make a client without proxy support
    pub fn without_proxy_support(self) -> EasyHttpConnectorBuilder<T, ProxyStage<false>> {
        EasyHttpConnectorBuilder {
            connector: self.connector,
            _phantom: PhantomData,
        }
    }
}

impl<T: Clone, const TLS_PROXY: bool> EasyHttpConnectorBuilder<T, ProxyTunnelStage<TLS_PROXY>> {
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
    ) -> EasyHttpConnectorBuilder<ProxyConnector<T>, ProxyStage<true>> {
        use rama_http_backend::client::proxy::layer::HttpProxyConnectorLayer;
        use rama_socks5::Socks5ProxyConnectorLayer;

        let connector = ProxyConnector::optional(
            self.connector,
            Socks5ProxyConnectorLayer::required(),
            HttpProxyConnectorLayer::required().with_tls_proxy_support(TLS_PROXY),
        );

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }
}

impl<T, const PROXY: bool> EasyHttpConnectorBuilder<T, ProxyStage<PROXY>> {
    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Add a custom tls connector that will be used by the client
    ///
    /// The final HTTP transition applies a [`RequestVersionAdapter`] outside
    /// the complete connection attempt so it can apply the negotiated version
    /// to the original HTTP request.
    pub fn with_custom_tls_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, TlsStage<PROXY>>
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
    ) -> EasyHttpConnectorBuilder<boring_client::TlsConnector<T>, TlsStage<PROXY>> {
        let connector = boring_client::TlsConnector::auto(self.connector).with_base_config(config);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    #[cfg(feature = "boring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
    /// Same as [`Self::with_tls_support_using_boringssl`] but also
    /// setting a fallback HTTP version in case no ALPN is negotiated.
    /// The fallback does not constrain the ALPN protocols offered by TLS.
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
        AddInputExtension<boring_client::TlsConnector<T>, FallbackHttpVersion>,
        TlsStage<PROXY>,
    > {
        let connector = boring_client::TlsConnector::auto(self.connector).with_base_config(config);
        let connector =
            AddInputExtension::new(connector, FallbackHttpVersion(default_http_version))
                .with_overwrite(false);

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
    ) -> EasyHttpConnectorBuilder<rustls_client::TlsConnector<T>, TlsStage<PROXY>> {
        let connector = rustls_client::TlsConnector::auto(self.connector).with_base_config(config);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    #[cfg(feature = "rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
    /// Same as [`Self::with_tls_support_using_rustls`] but also
    /// setting a fallback HTTP version in case no ALPN is negotiated.
    /// The fallback does not constrain the ALPN protocols offered by TLS.
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
        AddInputExtension<rustls_client::TlsConnector<T>, FallbackHttpVersion>,
        TlsStage<PROXY>,
    > {
        let connector = rustls_client::TlsConnector::auto(self.connector).with_base_config(config);
        let connector =
            AddInputExtension::new(connector, FallbackHttpVersion(default_http_version))
                .with_overwrite(false);

        EasyHttpConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    /// Don't support https on this connector
    pub fn without_tls_support(self) -> EasyHttpConnectorBuilder<T, TlsStage<PROXY>> {
        EasyHttpConnectorBuilder {
            connector: self.connector,
            _phantom: PhantomData,
        }
    }
}

impl<T, const PROXY: bool> EasyHttpConnectorBuilder<T, TlsStage<PROXY>> {
    /// Add http support to this connector
    pub fn with_default_http_connector<Body>(
        self,
        exec: Executor,
    ) -> EasyHttpConnectorBuilder<HttpConnector<T, Body>, HttpStage<PROXY>> {
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
    ) -> EasyHttpConnectorBuilder<L::Service, HttpStage<PROXY>>
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

type ConfiguredConnectionBuilder<T> = EasyHttpConnectorBuilder<DefaultHttpConnector<T>, PoolStage>;

type ConfiguredConnectionPoolBuilder<T> =
    EasyHttpConnectorBuilder<DefaultHttpConnector<HttpPooledConnector<T>>, PoolStage>;

type ErasedConnector<C> =
    BoxService<ConnectRequest, EstablishedClientConnection<C, ConnectRequest>, ConnectionError>;

type DefaultConnectionBuilder<C> =
    ConfiguredConnectionBuilder<ProxyRouteFailureCacheConnector<ErasedConnector<C>>>;

type DefaultConnectionPoolBuilder<C> =
    ConfiguredConnectionPoolBuilder<ProxyRouteFailureCacheConnector<ErasedConnector<C>>>;

// Keep the configured connector and its future behind one dynamic boundary
// before adding route caching and fallback. This prevents deeply nested TLS
// connector futures from overflowing ordinary thread stacks while dispatching
// only once per new connection (and behind the pool when pooling is enabled).
struct ConnectorServiceAdapter<T>(T);

impl<T> Service<ConnectRequest> for ConnectorServiceAdapter<T>
where
    T: ConnectorService<ConnectRequest>,
{
    type Output = EstablishedClientConnection<T::Connection, ConnectRequest>;
    type Error = ConnectionError;

    fn serve(
        &self,
        input: ConnectRequest,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        self.0.connect(input)
    }
}

fn erase_connector<T>(connector: T) -> ErasedConnector<T::Connection>
where
    T: ConnectorService<ConnectRequest>,
{
    ConnectorServiceAdapter(connector).boxed()
}

fn finalize_http_connector<T>(connector: T) -> DefaultHttpConnector<T> {
    let connector = ProxyRoutesConnector::new(connector);
    let connector = HttpConnectRequestAdapter::new(connector);
    RequestVersionAdapter::new(connector)
}

fn finish_without_connection_pool<T, Stage>(
    builder: EasyHttpConnectorBuilder<T, Stage>,
) -> ConfiguredConnectionBuilder<T>
where
    T: ConnectorService<ConnectRequest>,
{
    EasyHttpConnectorBuilder {
        connector: finalize_http_connector(builder.connector),
        _phantom: PhantomData,
    }
}

fn finish_with_connection_pool<T, Stage>(
    builder: EasyHttpConnectorBuilder<T, Stage>,
    config: HttpPooledConnectorConfig,
) -> Result<ConfiguredConnectionPoolBuilder<T>, BoxError>
where
    T: ConnectorService<ConnectRequest>,
{
    let connector = config.try_build_connector(builder.connector)?;
    Ok(EasyHttpConnectorBuilder {
        connector: finalize_http_connector(connector),
        _phantom: PhantomData,
    })
}

fn finish_with_default_connection_pool<T, Stage>(
    builder: EasyHttpConnectorBuilder<T, Stage>,
) -> ConfiguredConnectionPoolBuilder<T>
where
    T: ConnectorService<ConnectRequest>,
{
    let connector = HttpPooledConnectorConfig::build_default_connector(builder.connector);
    EasyHttpConnectorBuilder {
        connector: finalize_http_connector(connector),
        _phantom: PhantomData,
    }
}

fn finish_with_custom_connection_pool<T, Stage, P, R>(
    builder: EasyHttpConnectorBuilder<T, Stage>,
    pool: P,
    req_to_conn_id: R,
    wait_for_pool_timeout: Option<Duration>,
) -> EasyHttpConnectorBuilder<PooledConnector<T, P, R>, PoolStage> {
    let connector = PooledConnector::new(builder.connector, pool, req_to_conn_id)
        .maybe_with_wait_for_pool_timeout(wait_for_pool_timeout);
    EasyHttpConnectorBuilder {
        connector,
        _phantom: PhantomData,
    }
}

impl<T, const PROXY: bool> EasyHttpConnectorBuilder<T, HttpStage<PROXY>> {
    /// Explicitly use the given shared proxy route failure cache.
    ///
    /// This selects the failure-cache policy for the final connection stage.
    /// The configured connector is type-erased at this boundary to keep the
    /// combined connector future stack-safe.
    #[must_use]
    pub fn with_proxy_route_failure_cache(
        self,
        cache: ProxyRouteFailureCache,
    ) -> EasyHttpConnectorBuilder<
        ProxyRouteFailureCacheConnector<ErasedConnector<T::Connection>>,
        ProxyRouteFailureCacheStage,
    >
    where
        T: ConnectorService<ConnectRequest>,
    {
        EasyHttpConnectorBuilder {
            connector: ProxyRouteFailureCacheConnector::new(erase_connector(self.connector), cache),
            _phantom: PhantomData,
        }
    }

    /// Disable negative caching of temporarily failing proxy routes.
    #[must_use]
    pub fn without_proxy_route_failure_cache(
        self,
    ) -> EasyHttpConnectorBuilder<T, ProxyRouteFailureCacheStage> {
        EasyHttpConnectorBuilder {
            connector: self.connector,
            _phantom: PhantomData,
        }
    }
}

impl<T> EasyHttpConnectorBuilder<T, HttpStage<true>> {
    /// Finish the default HTTP connector stack without adding a connection pool.
    ///
    /// This still installs HTTP request adaptation and ordered proxy-route
    /// fallback. It also installs the default proxy-route failure cache. The
    /// only omitted component is the pool itself.
    pub fn without_connection_pool(self) -> DefaultConnectionBuilder<T::Connection>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_without_connection_pool(
            self.with_proxy_route_failure_cache(ProxyRouteFailureCache::default()),
        )
    }

    /// Use the default connection pool for this [`super::EasyHttpWebClient`]
    ///
    /// This will create a [`MultiplexPool`](crate::net::client::pool::MultiplexPool)
    /// using the provided limits and will use
    /// [`HttpConnIdentifier`](super::HttpConnIdentifier) to group connections on
    /// protocol, authority, selected route, physical transport, any HTTP
    /// version requirement, and the selected plaintext HTTP proxy mode. This
    /// keeps forward-proxy connections separate from CONNECT tunnels to the
    /// same proxy. The default proxy-route failure cache is installed behind
    /// the pool, so reusable connections bypass negative-cache checks.
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
    ) -> Result<DefaultConnectionPoolBuilder<T::Connection>, BoxError>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_with_connection_pool(
            self.with_proxy_route_failure_cache(ProxyRouteFailureCache::default()),
            config,
        )
    }

    /// Use Rama's default connection pool and default proxy-route failure
    /// cache.
    ///
    /// This operation is infallible because Rama's built-in pool limits are
    /// known to be valid and non-zero.
    pub fn with_default_connection_pool(self) -> DefaultConnectionPoolBuilder<T::Connection>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_with_default_connection_pool(
            self.with_proxy_route_failure_cache(ProxyRouteFailureCache::default()),
        )
    }

    /// Configure this client to use the provided [`Pool`] and [`ReqToConnId`]
    ///
    /// Use `wait_for_pool_timeout` to limit how long we wait for the pool to give us a connection
    ///
    /// Warning: this does not apply a [`RequestVersionAdapter`] layer to make sure that request versions
    /// are adapted when pooled connections are used, which you almost always. This should be manually added
    /// by using [`Self::with_custom_connector`] after configuring this pool and providing a [`RequestVersionAdapter`] there.
    /// Unlike [`Self::try_with_connection_pool`], this fully generic method also does not install the HTTP
    /// connect-request adapter or proxy-route connector. It installs the default proxy-route failure cache behind
    /// the custom pool. Callers that want route-aware fallback around a custom pool can compose those layers
    /// explicitly around their [`PooledConnector`].
    ///
    /// When the connector supports plaintext HTTP through an HTTP proxy, the
    /// custom [`ReqToConnId`] must keep ordinary forward-proxy connections
    /// separate from CONNECT tunnels to the same proxy. Rama's
    /// [`HttpConnIdentifier`](super::HttpConnIdentifier) includes this
    /// distinction automatically.
    ///
    /// [`Pool`]: rama_net::client::pool::Pool
    /// [`ReqToConnId`]: rama_net::client::pool::ReqToConnID
    pub fn with_custom_connection_pool<P, R>(
        self,
        pool: P,
        req_to_conn_id: R,
        wait_for_pool_timeout: Option<Duration>,
    ) -> EasyHttpConnectorBuilder<
        PooledConnector<ProxyRouteFailureCacheConnector<ErasedConnector<T::Connection>>, P, R>,
        PoolStage,
    >
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_with_custom_connection_pool(
            self.with_proxy_route_failure_cache(ProxyRouteFailureCache::default()),
            pool,
            req_to_conn_id,
            wait_for_pool_timeout,
        )
    }
}

impl<T> EasyHttpConnectorBuilder<T, HttpStage<false>> {
    /// Finish the proxy-free HTTP connector stack without a connection pool.
    ///
    /// No proxy-route failure cache is installed. Call
    /// [`Self::with_proxy_route_failure_cache`] before this method to
    /// explicitly add one for a custom transport.
    pub fn without_connection_pool(self) -> ConfiguredConnectionBuilder<T>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_without_connection_pool(self)
    }

    /// Use the default connection pool without a proxy-route failure cache.
    pub fn try_with_connection_pool(
        self,
        config: HttpPooledConnectorConfig,
    ) -> Result<ConfiguredConnectionPoolBuilder<T>, BoxError>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_with_connection_pool(self, config)
    }

    /// Use Rama's known-valid default connection pool configuration without a
    /// proxy-route failure cache.
    pub fn with_default_connection_pool(self) -> ConfiguredConnectionPoolBuilder<T>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_with_default_connection_pool(self)
    }

    /// Use a custom connection pool without a proxy-route failure cache.
    pub fn with_custom_connection_pool<P, R>(
        self,
        pool: P,
        req_to_conn_id: R,
        wait_for_pool_timeout: Option<Duration>,
    ) -> EasyHttpConnectorBuilder<PooledConnector<T, P, R>, PoolStage> {
        finish_with_custom_connection_pool(self, pool, req_to_conn_id, wait_for_pool_timeout)
    }
}

impl<T> EasyHttpConnectorBuilder<T, ProxyRouteFailureCacheStage> {
    /// Finish the default HTTP connector stack without a connection pool.
    pub fn without_connection_pool(self) -> ConfiguredConnectionBuilder<T>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_without_connection_pool(self)
    }

    /// Use the default connection pool with the selected failure-cache policy.
    pub fn try_with_connection_pool(
        self,
        config: HttpPooledConnectorConfig,
    ) -> Result<ConfiguredConnectionPoolBuilder<T>, BoxError>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_with_connection_pool(self, config)
    }

    /// Use Rama's known-valid default connection pool configuration with the
    /// selected failure-cache policy.
    pub fn with_default_connection_pool(self) -> ConfiguredConnectionPoolBuilder<T>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_with_default_connection_pool(self)
    }

    /// Use a custom connection pool with the selected failure-cache policy.
    ///
    /// For a proxy-capable connector, the custom
    /// [`ReqToConnID`](rama_net::client::pool::ReqToConnID) must partition
    /// plaintext HTTP forward-proxy connections from CONNECT tunnels to the
    /// same proxy. [`HttpConnIdentifier`](super::HttpConnIdentifier) does so by
    /// default.
    pub fn with_custom_connection_pool<P, R>(
        self,
        pool: P,
        req_to_conn_id: R,
        wait_for_pool_timeout: Option<Duration>,
    ) -> EasyHttpConnectorBuilder<PooledConnector<T, P, R>, PoolStage> {
        finish_with_custom_connection_pool(self, pool, req_to_conn_id, wait_for_pool_timeout)
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
