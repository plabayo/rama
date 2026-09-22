#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_core::layer::AddInputExtension;
use rama_core::rt::Executor;

use super::{
    HttpConnIdentifier, HttpConnectRequestAdapter, HttpConnector, HttpPooledConnector,
    HttpPooledConnectorConfig,
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
use rama_http::layer::{alt_svc::AltSvcCache, http_service::HttpServiceConnector};
use rama_net::tls::ApplicationProtocol;
use rama_tls::TlsBackend;
use std::time::Duration;

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
    stage: S,
}

#[non_exhaustive]
#[derive(Debug, Default)]
pub struct TransportStage;
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct DnsStage;
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct ProxyTunnelStage<const TLS_PROXY: bool = true>;
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct ProxyStage<const PROXY: bool = true>;
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct TlsStage<const PROXY: bool = true> {
    tls: Option<TlsBackend>,
}
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct HttpStage<const PROXY: bool = true> {
    tls: Option<TlsBackend>,
    h3: Option<H3State>,
}
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct ProxyRouteFailureCacheStage {
    tls: Option<TlsBackend>,
    h3: Option<H3State>,
}
#[derive(Debug)]
struct H3State {
    tls: Option<TlsBackend>,
}

#[non_exhaustive]
#[derive(Debug, Default)]
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
            stage: Default::default(),
        }
    }

    /// Add a custom transport connector that will be used by this client for the transport layer
    pub fn with_custom_transport_connector<C>(
        self,
        connector: C,
    ) -> EasyHttpConnectorBuilder<C, TransportStage> {
        EasyHttpConnectorBuilder {
            connector,
            stage: Default::default(),
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
            stage: self.stage,
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
            stage: Default::default(),
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
            stage: Default::default(),
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
            stage: Default::default(),
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
            stage: Default::default(),
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
            stage: Default::default(),
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
            stage: Default::default(),
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
            stage: Default::default(),
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
            stage: Default::default(),
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
            stage: Default::default(),
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
            stage: Default::default(),
        }
    }

    /// Make a client without proxy support
    pub fn without_proxy_support(self) -> EasyHttpConnectorBuilder<T, ProxyStage<false>> {
        EasyHttpConnectorBuilder {
            connector: self.connector,
            stage: Default::default(),
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
            stage: Default::default(),
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
            stage: Default::default(),
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
        let tls = Some(TlsBackend::Boring);
        let connector = boring_client::TlsConnector::auto(self.connector).with_base_config(config);

        EasyHttpConnectorBuilder {
            connector,
            stage: TlsStage { tls },
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
        let tls = Some(TlsBackend::Boring);
        let connector = boring_client::TlsConnector::auto(self.connector).with_base_config(config);
        let connector =
            AddInputExtension::new(connector, FallbackHttpVersion(default_http_version))
                .with_overwrite(false);

        EasyHttpConnectorBuilder {
            connector,
            stage: TlsStage { tls },
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
        let tls = Some(TlsBackend::Rustls);
        let connector = rustls_client::TlsConnector::auto(self.connector).with_base_config(config);

        EasyHttpConnectorBuilder {
            connector,
            stage: TlsStage { tls },
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
        let tls = Some(TlsBackend::Rustls);
        let connector = rustls_client::TlsConnector::auto(self.connector).with_base_config(config);
        let connector =
            AddInputExtension::new(connector, FallbackHttpVersion(default_http_version))
                .with_overwrite(false);

        EasyHttpConnectorBuilder {
            connector,
            stage: TlsStage { tls },
        }
    }

    /// Don't support https on this connector
    pub fn without_tls_support(self) -> EasyHttpConnectorBuilder<T, TlsStage<PROXY>> {
        EasyHttpConnectorBuilder {
            connector: self.connector,
            stage: Default::default(),
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
            stage: HttpStage {
                tls: self.stage.tls,
                h3: None,
            },
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
            stage: HttpStage {
                tls: self.stage.tls,
                h3: None,
            },
        }
    }
}

impl<T, Body, const PROXY: bool>
    EasyHttpConnectorBuilder<HttpConnector<T, Body>, HttpStage<PROXY>>
{
    /// Add a separately configured QUIC transport below the common HTTP handshake.
    /// The connector supplies its own transport, DNS and TLS policy. Its policy
    /// must remain fixed for the lifetime of the pool. Custom request policies
    /// can provide a `TlsPoolId` extension before pool lookup or a custom `ReqToConnID`.
    /// Use [`Self::with_http3_support`] for the built-in connector.
    pub fn with_http3_connector<C>(
        mut self,
        connector: C,
    ) -> EasyHttpConnectorBuilder<
        HttpConnector<super::HttpTransportConnector<T, C>, Body>,
        HttpStage<PROXY>,
    > {
        self.stage.h3 = Some(H3State { tls: None });
        EasyHttpConnectorBuilder {
            connector: self.connector.with_http3_connector(connector),
            stage: self.stage,
        }
    }

    /// Enable a configured QUIC connector with DNS and provider-aware TLS pool identity.
    pub fn with_http3_support(
        self,
        connector: super::Http3Connector,
    ) -> EasyHttpConnectorBuilder<
        HttpConnector<
            super::HttpTransportConnector<
                T,
                crate::dns::client::DnsConnector<super::Http3Connector>,
            >,
            Body,
        >,
        HttpStage<PROXY>,
    > {
        let tls = Some(connector.tls_backend());
        let mut builder =
            self.with_http3_connector(crate::dns::client::DnsConnector::new(connector));
        builder.stage.h3 = Some(H3State { tls });
        builder
    }
}

type DefaultHttpConnector<T> =
    RequestVersionAdapter<HttpConnectRequestAdapter<HttpServiceConnector<ProxyRoutesConnector<T>>>>;

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

fn finalize_http_connector<T>(connector: T, h3_enabled: bool) -> DefaultHttpConnector<T> {
    let connector = ProxyRoutesConnector::new(connector);
    let connector = HttpServiceConnector::new(connector)
        .with_protocols(
            [
                ApplicationProtocol::HTTP_10,
                ApplicationProtocol::HTTP_11,
                ApplicationProtocol::HTTP_2,
            ]
            .into_iter()
            .chain(h3_enabled.then_some(ApplicationProtocol::HTTP_3)),
        )
        .with_cache(AltSvcCache::default());
    adapt_http_service_connector(connector)
}

fn adapt_http_service_connector<T>(
    connector: HttpServiceConnector<ProxyRoutesConnector<T>>,
) -> DefaultHttpConnector<T> {
    RequestVersionAdapter::new(HttpConnectRequestAdapter::new(connector))
}

impl<T> EasyHttpConnectorBuilder<DefaultHttpConnector<T>, PoolStage> {
    /// Disable advertised alternatives and response learning for every HTTP version.
    #[must_use]
    pub fn without_alt_svc(self) -> Self {
        let selector = self
            .connector
            .into_inner()
            .into_inner()
            .maybe_with_cache(None);
        Self {
            connector: adapt_http_service_connector(selector),
            stage: self.stage,
        }
    }

    /// Share an alternative-service cache across HTTP clients.
    #[must_use]
    pub fn with_alt_svc_cache(self, cache: AltSvcCache) -> Self {
        let selector = self.connector.into_inner().into_inner().with_cache(cache);
        Self {
            connector: adapt_http_service_connector(selector),
            stage: self.stage,
        }
    }
}

fn finish_without_connection_pool<T, Stage: PoolConfig>(
    builder: EasyHttpConnectorBuilder<T, Stage>,
) -> ConfiguredConnectionBuilder<T>
where
    T: ConnectorService<ConnectRequest>,
{
    let (_, h3_enabled) = builder.stage.into_pool_setup();
    EasyHttpConnectorBuilder {
        connector: finalize_http_connector(builder.connector, h3_enabled),
        stage: Default::default(),
    }
}

trait PoolConfig {
    fn into_pool_setup(self) -> (HttpConnIdentifier, bool);
}

impl<const PROXY: bool> PoolConfig for HttpStage<PROXY> {
    fn into_pool_setup(self) -> (HttpConnIdentifier, bool) {
        (
            HttpConnIdentifier::new()
                .maybe_with_tls_backend(self.tls)
                .maybe_with_http3_tls_backend(self.h3.as_ref().and_then(|h3| h3.tls)),
            self.h3.is_some(),
        )
    }
}

impl PoolConfig for ProxyRouteFailureCacheStage {
    fn into_pool_setup(self) -> (HttpConnIdentifier, bool) {
        (
            HttpConnIdentifier::new()
                .maybe_with_tls_backend(self.tls)
                .maybe_with_http3_tls_backend(self.h3.as_ref().and_then(|h3| h3.tls)),
            self.h3.is_some(),
        )
    }
}

fn finish_with_connection_pool<T, Stage: PoolConfig>(
    builder: EasyHttpConnectorBuilder<T, Stage>,
    config: HttpPooledConnectorConfig,
) -> Result<ConfiguredConnectionPoolBuilder<T>, BoxError>
where
    T: ConnectorService<ConnectRequest>,
{
    let (identifier, h3_enabled) = builder.stage.into_pool_setup();
    let connector = config.try_build_connector_with_identifier(builder.connector, identifier)?;
    Ok(EasyHttpConnectorBuilder {
        connector: finalize_http_connector(connector, h3_enabled),
        stage: Default::default(),
    })
}

fn finish_with_default_connection_pool<T, Stage: PoolConfig>(
    builder: EasyHttpConnectorBuilder<T, Stage>,
) -> ConfiguredConnectionPoolBuilder<T>
where
    T: ConnectorService<ConnectRequest>,
{
    let (identifier, h3_enabled) = builder.stage.into_pool_setup();
    let connector = HttpPooledConnectorConfig::build_default_connector_with_identifier(
        builder.connector,
        identifier,
    );
    EasyHttpConnectorBuilder {
        connector: finalize_http_connector(connector, h3_enabled),
        stage: Default::default(),
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
        stage: Default::default(),
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
            stage: ProxyRouteFailureCacheStage {
                tls: self.stage.tls,
                h3: self.stage.h3,
            },
        }
    }

    /// Disable negative caching of temporarily failing proxy routes.
    #[must_use]
    pub fn without_proxy_route_failure_cache(
        self,
    ) -> EasyHttpConnectorBuilder<T, ProxyRouteFailureCacheStage> {
        EasyHttpConnectorBuilder {
            connector: self.connector,
            stage: ProxyRouteFailureCacheStage {
                tls: self.stage.tls,
                h3: self.stage.h3,
            },
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
    ///
    /// The supplied `ReqToConnID` replaces the built-in TLS pool identity. It owns
    /// request-override compatibility and must separate incompatible connector
    /// policies when the pool is shared. Return a non-reusable `ConnID` when a
    /// request needs a fresh connection that must not return to the pool.
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
    ///
    /// The supplied `ReqToConnID` replaces the built-in TLS pool identity. It owns
    /// request-override compatibility and must separate incompatible connector
    /// policies when the pool is shared. Return a non-reusable `ConnID` when a
    /// request needs a fresh connection that must not return to the pool.
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
    ///
    /// The supplied `ReqToConnID` replaces the built-in TLS pool identity. It owns
    /// request-override compatibility and must separate incompatible connector
    /// policies when the pool is shared. Return a non-reusable `ConnID` when a
    /// request needs a fresh connection that must not return to the pool.
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
