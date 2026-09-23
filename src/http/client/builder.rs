use rama_core::rt::Executor;

use super::{
    HttpConnId, HttpConnIdentifier, HttpConnectRequestAdapter, HttpConnector, HttpPooledConnector,
    HttpPooledConnectorConfig,
};
use crate::http::conn::FallbackHttpVersion;
use crate::{
    Layer, Service,
    dns::client::{
        DnsConnector, DnsConnectorLayer, GlobalDnsResolver, resolver::DnsAddressResolver,
    },
    error::BoxError,
    extensions::ExtensionsRef,
    http::{
        Request, StreamingBody, Version, client::proxy::layer::HttpProxyConnector,
        layer::version_adapter::RequestVersionAdapter,
    },
    net::client::{
        ConnectRequest, ConnectionError, ConnectorService, EstablishedClientConnection,
        ProxyRouteFailureCache, ProxyRouteFailureCacheConnector, ProxyRoutesConnector,
        pool::{PooledConnector, ReqToConnID},
    },
    service::BoxService,
    tcp::client::service::TcpConnector,
};
use rama_http::layer::{alt_svc::AltSvcCache, http_service::HttpServiceConnector};
use rama_net::{HttpVersionInputExt, TargetHttpVersionInputExt, tls::ApplicationProtocol};
use rama_tls::client::{TlsClientConfigProvider, TlsPoolId};
use rama_utils::macros::generate_set_and_with;
use std::{sync::Arc, time::Duration};

#[cfg(feature = "boring")]
use crate::tls::boring::client as boring_client;

#[cfg(feature = "rustls")]
use crate::tls::rustls::client as rustls_client;
#[cfg(any(feature = "rustls", feature = "boring"))]
use {rama_core::layer::AddInputExtension, rama_tls::client::TlsClientConfig};

#[cfg(feature = "socks5")]
use crate::{http::client::proxy_connector::ProxyConnector, proxy::socks5::Socks5ProxyConnector};

/// Builder that is designed to easily create a connector for [`super::EasyHttpWebClient`] from most basic use cases
#[derive(Default)]
pub struct EasyHttpConnectorBuilder<C = (), S = (), D = ()> {
    connector: C,
    stage: S,
    // Retain the layer so both transports apply exactly the same DNS policy.
    dns: D,
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
    tls: Option<Arc<dyn TlsClientConfigProvider>>,
}

#[non_exhaustive]
#[derive(Debug, Default)]
pub struct HttpStage<const PROXY: bool = true> {
    tls: Option<Arc<dyn TlsClientConfigProvider>>,
    h3: Option<H3State>,
}

#[non_exhaustive]
#[derive(Debug, Default)]
pub struct ProxyRouteFailureCacheStage {
    tls: Option<Arc<dyn TlsClientConfigProvider>>,
    h3: Option<H3State>,
}

#[derive(Debug)]
struct H3State {
    tls: Option<Arc<dyn TlsClientConfigProvider>>,
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
            dns: self.dns,
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
            dns: self.dns,
            connector,
            stage: Default::default(),
        }
    }
}

impl<T, Stage, D> EasyHttpConnectorBuilder<T, Stage, D> {
    /// Add a custom connector to this Stage.
    ///
    /// Adding a custom connector to a stage will not change the state
    /// so this can be used to modify behaviour at a specific stage.
    pub fn with_custom_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, Stage, D>
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
    ) -> EasyHttpConnectorBuilder<T2, Stage, D> {
        let connector = map_fn(self.connector);
        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector,
            stage: self.stage,
        }
    }
}

impl<T> EasyHttpConnectorBuilder<T, TransportStage> {
    /// Add the global DNS policy to both the stream and built-in QUIC transports.
    pub fn with_default_dns_connector(
        self,
    ) -> EasyHttpConnectorBuilder<DnsConnector<T>, DnsStage, DnsConnectorLayer> {
        self.with_dns_address_resolver(GlobalDnsResolver::new())
    }

    /// Add a custom address resolver to both the stream and built-in QUIC transports.
    pub fn with_dns_address_resolver<R: DnsAddressResolver + Clone>(
        self,
        resolver: R,
    ) -> EasyHttpConnectorBuilder<DnsConnector<T, R>, DnsStage, DnsConnectorLayer<R>> {
        self.with_dns_connector(DnsConnectorLayer::with_resolver(resolver))
    }

    /// Omit DNS resolution. Transports require IP targets or their own resolution.
    pub fn without_dns_connector(self) -> EasyHttpConnectorBuilder<T, DnsStage> {
        self.with_dns_connector(())
    }

    /// Retain a custom DNS layer for both transport stacks.
    ///
    /// The layer is applied to the stream transport here and to the built-in
    /// QUIC connector when `with_http3_support` is called. A layer specific to
    /// the stream transport can instead be paired with `with_http3_connector`,
    /// whose supplied connector owns its DNS policy independently.
    pub fn with_dns_connector<L: Layer<T>>(
        self,
        layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, DnsStage, L> {
        let connector = layer.layer(self.connector);
        EasyHttpConnectorBuilder {
            connector,
            stage: DnsStage,
            dns: layer,
        }
    }
}

impl<T, D> EasyHttpConnectorBuilder<T, DnsStage, D> {
    /// Add a custom proxy TLS connector used to establish TLS to an HTTPS proxy.
    ///
    /// The layer must attach `rama_tls::client::NegotiatedTlsParameters` to
    /// the established connection. Rama uses this as positive proof that TLS
    /// was negotiated and to select the proxy-side HTTP version; missing
    /// evidence fails closed before proxy HTTP is sent.
    pub fn with_custom_tls_proxy_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, ProxyTunnelStage<true>, D>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);
        EasyHttpConnectorBuilder {
            dns: self.dns,
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
        D,
    > {
        let connector = boring_client::TlsConnector::tunnel(self.connector, None);
        EasyHttpConnectorBuilder {
            dns: self.dns,
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
        D,
    > {
        let connector =
            boring_client::TlsConnector::tunnel(self.connector, None).with_base_config(config);
        EasyHttpConnectorBuilder {
            dns: self.dns,
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
        D,
    > {
        let connector = rustls_client::TlsConnector::tunnel(self.connector, None);

        EasyHttpConnectorBuilder {
            dns: self.dns,
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
        D,
    > {
        let connector =
            rustls_client::TlsConnector::tunnel(self.connector, None).with_base_config(config);

        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector,
            stage: Default::default(),
        }
    }

    /// Don't support a tls tunnel to the proxy itself
    ///
    /// Note that a tls proxy is not needed to make a https connection
    /// to the final target. It only has an influence on the initial connection
    /// to the proxy itself
    pub fn without_tls_proxy_support(
        self,
    ) -> EasyHttpConnectorBuilder<T, ProxyTunnelStage<false>, D> {
        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector: self.connector,
            stage: Default::default(),
        }
    }
}

impl<T, D, const TLS_PROXY: bool> EasyHttpConnectorBuilder<T, ProxyTunnelStage<TLS_PROXY>, D> {
    /// Add a custom proxy connector that will be used by this client
    pub fn with_custom_proxy_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, ProxyStage<true>, D>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);
        EasyHttpConnectorBuilder {
            dns: self.dns,
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
    ) -> EasyHttpConnectorBuilder<HttpProxyConnector<T>, ProxyStage<true>, D> {
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
    ) -> EasyHttpConnectorBuilder<HttpProxyConnector<T>, ProxyStage<true>, D> {
        let connector =
            HttpProxyConnector::optional(self.connector).with_tls_proxy_support(TLS_PROXY);

        EasyHttpConnectorBuilder {
            dns: self.dns,
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
    ) -> EasyHttpConnectorBuilder<Socks5ProxyConnector<T>, ProxyStage<true>, D> {
        let connector = Socks5ProxyConnector::optional(self.connector);

        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector,
            stage: Default::default(),
        }
    }

    /// Make a client without proxy support
    pub fn without_proxy_support(self) -> EasyHttpConnectorBuilder<T, ProxyStage<false>, D> {
        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector: self.connector,
            stage: Default::default(),
        }
    }
}

impl<T: Clone, D, const TLS_PROXY: bool>
    EasyHttpConnectorBuilder<T, ProxyTunnelStage<TLS_PROXY>, D>
{
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
    ) -> EasyHttpConnectorBuilder<ProxyConnector<T>, ProxyStage<true>, D> {
        use rama_http_backend::client::proxy::layer::HttpProxyConnectorLayer;
        use rama_socks5::Socks5ProxyConnectorLayer;

        let connector = ProxyConnector::optional(
            self.connector,
            Socks5ProxyConnectorLayer::required(),
            HttpProxyConnectorLayer::required().with_tls_proxy_support(TLS_PROXY),
        );

        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector,
            stage: Default::default(),
        }
    }
}

impl<T, D, const PROXY: bool> EasyHttpConnectorBuilder<T, ProxyStage<PROXY>, D> {
    /// Add a custom tls connector that will be used by the client.
    ///
    /// The default pool assumes this connector has a fixed TLS policy. If it
    /// consumes request overrides, configure `with_tls_config_provider` before
    /// adding HTTP, or supply an appropriate `TlsPoolId` before pool lookup.
    /// Opaque policies must use `TlsPoolId::non_reusable()` or a custom pool.
    ///
    /// The final HTTP transition applies a [`RequestVersionAdapter`] outside
    /// the complete connection attempt so it can apply the negotiated version
    /// to the original HTTP request.
    pub fn with_custom_tls_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, TlsStage<PROXY>, D>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);

        EasyHttpConnectorBuilder {
            dns: self.dns,
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
    ) -> EasyHttpConnectorBuilder<boring_client::TlsConnector<T>, TlsStage<PROXY>, D> {
        let tls = Some(Arc::new(boring_client::BoringTlsClientConfigProvider)
            as Arc<dyn TlsClientConfigProvider>);
        let connector = boring_client::TlsConnector::auto(self.connector).with_base_config(config);

        EasyHttpConnectorBuilder {
            dns: self.dns,
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
        D,
    > {
        let tls = Some(Arc::new(boring_client::BoringTlsClientConfigProvider)
            as Arc<dyn TlsClientConfigProvider>);
        let connector = boring_client::TlsConnector::auto(self.connector).with_base_config(config);
        let connector =
            AddInputExtension::new(connector, FallbackHttpVersion(default_http_version))
                .with_overwrite(false);

        EasyHttpConnectorBuilder {
            dns: self.dns,
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
    ) -> EasyHttpConnectorBuilder<rustls_client::TlsConnector<T>, TlsStage<PROXY>, D> {
        let tls = Some(Arc::new(rustls_client::RustlsTlsClientConfigProvider)
            as Arc<dyn TlsClientConfigProvider>);
        let connector = rustls_client::TlsConnector::auto(self.connector).with_base_config(config);

        EasyHttpConnectorBuilder {
            dns: self.dns,
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
        D,
    > {
        let tls = Some(Arc::new(rustls_client::RustlsTlsClientConfigProvider)
            as Arc<dyn TlsClientConfigProvider>);
        let connector = rustls_client::TlsConnector::auto(self.connector).with_base_config(config);
        let connector =
            AddInputExtension::new(connector, FallbackHttpVersion(default_http_version))
                .with_overwrite(false);

        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector,
            stage: TlsStage { tls },
        }
    }

    /// Don't support https on this connector
    pub fn without_tls_support(self) -> EasyHttpConnectorBuilder<T, TlsStage<PROXY>, D> {
        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector: self.connector,
            stage: Default::default(),
        }
    }
}

impl<T, D, const PROXY: bool> EasyHttpConnectorBuilder<T, TlsStage<PROXY>, D> {
    generate_set_and_with! {
        /// Identify TLS request overrides for a custom stream connector's pool.
        ///
        /// The provider's `pool_id` must describe the same overrides as the connector.
        /// Its defaults and behavior must remain fixed for the lifetime of the pool.
        /// Without a provider, custom connectors may supply a request `TlsPoolId`.
        pub fn tls_config_provider(mut self, provider: Arc<dyn TlsClientConfigProvider>) -> Self {
            self.stage.tls = Some(provider);
            self
        }
    }

    /// Add http support to this connector
    pub fn with_default_http_connector<Body>(
        self,
        exec: Executor,
    ) -> EasyHttpConnectorBuilder<HttpConnector<T, Body>, HttpStage<PROXY>, D> {
        let connector = HttpConnector::new(self.connector, exec);

        EasyHttpConnectorBuilder {
            dns: self.dns,
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
    ) -> EasyHttpConnectorBuilder<L::Service, HttpStage<PROXY>, D>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);

        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector,
            stage: HttpStage {
                tls: self.stage.tls,
                h3: None,
            },
        }
    }
}

impl<T, Body, D, const PROXY: bool>
    EasyHttpConnectorBuilder<HttpConnector<T, Body>, HttpStage<PROXY>, D>
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
        D,
    > {
        self.stage.h3 = Some(H3State { tls: None });
        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector: self.connector.with_http3_connector(connector),
            stage: self.stage,
        }
    }

    /// Enable the built-in QUIC connector with the same DNS layer as the stream transport.
    ///
    /// The retained layer must support the QUIC connector as its inner service.
    /// This does not copy a custom stream transport or its routing policy.
    /// Use [`Self::with_http3_connector`] for an equivalent custom QUIC path.
    pub fn with_http3_support(
        self,
        connector: super::Http3Connector,
    ) -> EasyHttpConnectorBuilder<
        HttpConnector<super::HttpTransportConnector<T, D::Service>, Body>,
        HttpStage<PROXY>,
        D,
    >
    where
        D: Layer<super::Http3Connector>,
    {
        let tls = Some(connector.tls_provider().clone() as Arc<dyn TlsClientConfigProvider>);
        let connector = self.dns.layer(connector);
        let mut builder = self.with_http3_connector(connector);
        builder.stage.h3 = Some(H3State { tls });
        builder
    }
}

type DefaultHttpConnector<T> =
    RequestVersionAdapter<HttpConnectRequestAdapter<HttpServiceConnector<ProxyRoutesConnector<T>>>>;

type ConfiguredConnectionBuilder<T> = EasyHttpConnectorBuilder<DefaultHttpConnector<T>, PoolStage>;

type ConfiguredConnectionPoolBuilder<T> = EasyHttpConnectorBuilder<
    DefaultHttpConnector<HttpPooledConnector<T, EasyHttpConnIdentifier>>,
    PoolStage,
>;

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
        self.maybe_with_alt_svc_cache(None)
    }

    generate_set_and_with! {
        /// Share an alternative-service cache across HTTP clients; `None` disables discovery.
        pub fn alt_svc_cache(mut self, cache: Option<AltSvcCache>) -> Self {
            self.connector.get_mut().get_mut().maybe_set_cache(cache);
            self
        }
    }
}

fn finish_without_connection_pool<T, Stage: PoolConfig, D>(
    builder: EasyHttpConnectorBuilder<T, Stage, D>,
) -> ConfiguredConnectionBuilder<T>
where
    T: ConnectorService<ConnectRequest>,
{
    let (_, h3_enabled) = builder.stage.into_pool_setup();
    EasyHttpConnectorBuilder {
        dns: (),
        connector: finalize_http_connector(builder.connector, h3_enabled),
        stage: Default::default(),
    }
}

/// Pool identity for the fixed transports assembled by [`EasyHttpConnectorBuilder`].
///
/// The connector's TLS provider classifies request overrides before defaults are
/// applied. The resulting HTTP connection identity contains only protocol policy,
/// never the provider. Custom transports can supply a `TlsPoolId` extension or
/// configure their own `ReqToConnID` with a custom pool.
#[derive(Clone, Debug, Default)]
pub struct EasyHttpConnIdentifier {
    stream_tls: Option<Arc<dyn TlsClientConfigProvider>>,
    h3_tls: Option<Arc<dyn TlsClientConfigProvider>>,
}

impl EasyHttpConnIdentifier {
    fn tls_pool_id(&self, input: &ConnectRequest) -> Option<TlsPoolId> {
        let fallback = input
            .extensions()
            .get_ref::<FallbackHttpVersion>()
            .map(|v| v.0);
        let version = input
            .target_http_version_with_fallback(fallback)
            .or_else(|| input.http_version());
        let provider = if version == Some(Version::HTTP_3) {
            self.h3_tls.as_ref()
        } else {
            self.stream_tls.as_ref()
        };

        // A caller-supplied identity must not hide overrides from the provider
        // actually configured to perform this transport's handshake.
        match provider {
            Some(provider) => provider.pool_id(input.extensions()),
            None => input.extensions().get_ref::<TlsPoolId>().copied(),
        }
    }
}

impl ReqToConnID<ConnectRequest> for EasyHttpConnIdentifier {
    type ID = HttpConnId;

    fn id(&self, input: &ConnectRequest) -> Result<Self::ID, BoxError> {
        HttpConnIdentifier::new().id_with_tls(input, self.tls_pool_id(input))
    }
}

trait PoolConfig {
    fn into_pool_setup(self) -> (EasyHttpConnIdentifier, bool);
}

impl<const PROXY: bool> PoolConfig for HttpStage<PROXY> {
    fn into_pool_setup(self) -> (EasyHttpConnIdentifier, bool) {
        let h3_enabled = self.h3.is_some();
        (
            EasyHttpConnIdentifier {
                stream_tls: self.tls,
                h3_tls: self.h3.and_then(|h3| h3.tls),
            },
            h3_enabled,
        )
    }
}

impl PoolConfig for ProxyRouteFailureCacheStage {
    fn into_pool_setup(self) -> (EasyHttpConnIdentifier, bool) {
        let h3_enabled = self.h3.is_some();
        (
            EasyHttpConnIdentifier {
                stream_tls: self.tls,
                h3_tls: self.h3.and_then(|h3| h3.tls),
            },
            h3_enabled,
        )
    }
}

fn finish_with_connection_pool<T, Stage: PoolConfig, D>(
    builder: EasyHttpConnectorBuilder<T, Stage, D>,
    config: HttpPooledConnectorConfig,
) -> Result<ConfiguredConnectionPoolBuilder<T>, BoxError>
where
    T: ConnectorService<ConnectRequest>,
{
    let (identifier, h3_enabled) = builder.stage.into_pool_setup();
    let connector = config.try_build_connector_with_identifier(builder.connector, identifier)?;
    Ok(EasyHttpConnectorBuilder {
        dns: (),
        connector: finalize_http_connector(connector, h3_enabled),
        stage: Default::default(),
    })
}

fn finish_with_default_connection_pool<T, Stage: PoolConfig, D>(
    builder: EasyHttpConnectorBuilder<T, Stage, D>,
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
        dns: (),
        connector: finalize_http_connector(connector, h3_enabled),
        stage: Default::default(),
    }
}

fn finish_with_custom_connection_pool<T, Stage, D, P, R>(
    builder: EasyHttpConnectorBuilder<T, Stage, D>,
    pool: P,
    req_to_conn_id: R,
    wait_for_pool_timeout: Option<Duration>,
) -> EasyHttpConnectorBuilder<PooledConnector<T, P, R>, PoolStage> {
    let connector = PooledConnector::new(builder.connector, pool, req_to_conn_id)
        .maybe_with_wait_for_pool_timeout(wait_for_pool_timeout);
    EasyHttpConnectorBuilder {
        dns: (),
        connector,
        stage: Default::default(),
    }
}

impl<T, D, const PROXY: bool> EasyHttpConnectorBuilder<T, HttpStage<PROXY>, D> {
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
        D,
    >
    where
        T: ConnectorService<ConnectRequest>,
    {
        EasyHttpConnectorBuilder {
            dns: self.dns,
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
    ) -> EasyHttpConnectorBuilder<T, ProxyRouteFailureCacheStage, D> {
        EasyHttpConnectorBuilder {
            dns: self.dns,
            connector: self.connector,
            stage: ProxyRouteFailureCacheStage {
                tls: self.stage.tls,
                h3: self.stage.h3,
            },
        }
    }
}

impl<T, D> EasyHttpConnectorBuilder<T, HttpStage<true>, D> {
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
    /// [`HttpConnIdentifier`] to group connections on
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
    /// [`HttpConnIdentifier`] includes this
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

impl<T, D> EasyHttpConnectorBuilder<T, HttpStage<false>, D> {
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

impl<T, D> EasyHttpConnectorBuilder<T, ProxyRouteFailureCacheStage, D> {
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
    /// [`ReqToConnID`] must partition
    /// plaintext HTTP forward-proxy connections from CONNECT tunnels to the
    /// same proxy. [`HttpConnIdentifier`] does so by
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

impl<T, S, D> EasyHttpConnectorBuilder<T, S, D> {
    /// Build a connector from the currently configured setup
    pub fn build_connector(self) -> T {
        self.connector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Body;
    use rama_net::{
        Protocol,
        address::HostWithPort,
        client::{
            ConnectRequest,
            pool::{ConnID as _, ReqToConnID},
        },
    };
    use rama_tls::client::{ServerVerifyMode, TlsClientConfigProvider, TlsPoolId, TlsServerVerify};
    use rama_utils::octets::kib;
    #[cfg(feature = "rustls")]
    use {
        rama_net::http::{HttpRequestVersion, TargetHttpVersion},
        rama_tls::client::TlsServerCertPin,
    };

    use rama_core::{extensions::Extensions, layer::layer_fn};
    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
    ))]
    use {
        crate::http::client::Http3Connector,
        crate::quic::Endpoint,
        rama_core::futures::{Stream, stream},
        rama_http::layer::http_service::HttpServiceAttempt,
        rama_net::{
            address::{Domain, SocketAddress},
            client::ConnectionErrorKind,
            http::TargetHttpVersion as RequestedVersion,
        },
        std::{
            convert::Infallible,
            net::{Ipv4Addr, Ipv6Addr, SocketAddr},
            sync::atomic::{AtomicUsize, Ordering},
        },
    };

    #[derive(Debug)]
    struct CustomTlsPolicy;

    impl TlsClientConfigProvider for CustomTlsPolicy {
        fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
            TlsPoolId::builder()
                .maybe_with_verify(extensions.get_ref::<TlsServerVerify>())
                .build()
        }

        fn authenticates_server(&self, _: &Extensions) -> bool {
            false
        }
    }

    fn assert_future_budget(connector: &impl Service<Request>, name: &str) {
        let request = Request::builder()
            .uri("https://example.com/")
            .body(Body::empty())
            .unwrap();
        let future = connector.serve(request);
        let size = std::mem::size_of_val(&future);
        assert!(
            size <= kib(64),
            "{name} connector future is {size} bytes; connector error adapters must not duplicate nested future storage"
        );
    }

    #[tokio::test]
    async fn default_connector_futures_stay_within_stack_budget() {
        let builder = || {
            EasyHttpConnectorBuilder::new()
                .with_default_transport_connector()
                .without_dns_connector()
                .without_tls_proxy_support()
                .without_proxy_support()
        };
        let plain = builder()
            .without_tls_support()
            .with_default_http_connector::<Body>(Executor::default())
            .with_default_connection_pool()
            .build_connector();
        assert_future_budget(&plain, "plain pooled");
        #[cfg(feature = "rustls")]
        {
            let pooled = builder()
                .with_tls_support_using_rustls(TlsClientConfig::new())
                .with_default_http_connector::<Body>(Executor::default())
                .with_default_connection_pool()
                .build_connector();
            assert_future_budget(&pooled, "rustls pooled");
            let unpooled = builder()
                .with_tls_support_using_rustls(TlsClientConfig::new())
                .with_default_http_connector::<Body>(Executor::default())
                .without_connection_pool()
                .build_connector();
            assert_future_budget(&unpooled, "rustls unpooled");
        }
    }

    #[test]
    fn custom_tls_proxy_layer_requires_no_builtin_provider() {
        EasyHttpConnectorBuilder::new()
            .with_custom_transport_connector(())
            .without_dns_connector()
            .with_custom_tls_proxy_connector(layer_fn(|inner| inner))
            .build_connector();
    }

    #[test]
    fn custom_stream_provider_classifies_overrides_before_pool_lookup() {
        let builder = EasyHttpConnectorBuilder {
            dns: (),
            connector: (),
            stage: ProxyStage::<false>::default(),
        }
        .with_custom_tls_connector(layer_fn(|inner| inner))
        .with_tls_config_provider(Arc::new(CustomTlsPolicy))
        .with_default_http_connector::<()>(Executor::default());
        let (identifier, h3_enabled) = builder.stage.into_pool_setup();
        assert!(!h3_enabled);
        let input = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS);
        let baseline = identifier.id(&input).unwrap();
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        assert_ne!(identifier.id(&input).unwrap(), baseline);
        input.extensions.insert(TlsPoolId::non_reusable());
        assert!(identifier.id(&input).unwrap().is_reusable());
    }

    #[test]
    fn custom_fixed_policy_pool_respects_explicit_override_identity() {
        let identifier = EasyHttpConnIdentifier::default();
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        let fixed = identifier.id(&input).unwrap();
        assert!(fixed.is_reusable());
        let policy = TlsPoolId::builder()
            .with_verify(&TlsServerVerify(ServerVerifyMode::Disable))
            .build()
            .unwrap();
        input.extensions.insert(policy);
        let overridden = identifier.id(&input).unwrap();
        assert!(overridden.is_reusable());
        assert_ne!(fixed, overridden);
        assert_eq!(overridden, identifier.id(&input).unwrap());
        input.extensions.insert(TlsPoolId::non_reusable());
        assert!(!identifier.id(&input).unwrap().is_reusable());
    }

    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
    ))]
    #[derive(Clone)]
    struct RecordingResolver {
        calls: Arc<AtomicUsize>,
        loopback: bool,
    }

    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
    ))]
    impl DnsAddressResolver for RecordingResolver {
        type Error = Infallible;

        fn lookup_ipv4(
            &self,
            domain: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            assert_eq!(domain.as_str(), "private.invalid");
            self.calls.fetch_add(1, Ordering::Relaxed);
            stream::iter(self.loopback.then_some(Ok(Ipv4Addr::LOCALHOST)))
        }

        fn lookup_ipv6(
            &self,
            domain: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            assert_eq!(domain.as_str(), "private.invalid");
            self.calls.fetch_add(1, Ordering::Relaxed);
            stream::iter(self.loopback.then_some(Ok(Ipv6Addr::LOCALHOST)))
        }
    }

    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
    ))]
    struct RecordingDnsLayer {
        resolver: RecordingResolver,
        applied: Arc<AtomicUsize>,
    }

    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
    ))]
    impl<S> Layer<S> for RecordingDnsLayer {
        type Service = DnsConnector<S, RecordingResolver>;

        fn layer(&self, inner: S) -> Self::Service {
            self.applied.fetch_add(1, Ordering::Relaxed);
            DnsConnector::with_resolver(inner, self.resolver.clone())
        }
    }

    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
    ))]
    #[tokio::test]
    async fn built_in_quic_uses_the_configured_dns_resolver() {
        let calls = Arc::new(AtomicUsize::new(0));
        let applied = Arc::new(AtomicUsize::new(0));
        let executor = Executor::default();
        let h3 = Http3Connector::builder(executor.clone())
            .build()
            .await
            .unwrap();
        let connector = EasyHttpConnectorBuilder::new()
            .with_default_transport_connector()
            .with_dns_connector(RecordingDnsLayer {
                resolver: RecordingResolver {
                    calls: calls.clone(),
                    loopback: false,
                },
                applied: applied.clone(),
            })
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector::<Body>(executor)
            .with_http3_support(h3)
            .build_connector();
        let input = ConnectRequest::new("private.invalid:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions.insert(RequestedVersion(Version::HTTP_3));
        let error = connector.serve(input).await.err().unwrap();
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert!(calls.load(Ordering::Relaxed) > 0);
        assert_eq!(
            applied.load(Ordering::Relaxed),
            2,
            "the same DNS layer must wrap both transports"
        );
    }

    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
    ))]
    #[tokio::test]
    async fn ipv4_quic_endpoint_skips_ipv6_candidates_without_terminal_failure() {
        let executor = Executor::default();
        let endpoint = Endpoint::bind_client(executor.clone(), SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let blackhole = tokio::net::UdpSocket::bind(SocketAddr::from(SocketAddress::local_ipv4(0)))
            .await
            .unwrap();
        let connector = Http3Connector::builder(executor)
            .with_endpoint(endpoint.clone())
            .build()
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let connector = DnsConnector::with_resolver(
            connector,
            RecordingResolver {
                calls: calls.clone(),
                loopback: true,
            },
        );
        let input = ConnectRequest::new(
            format!("private.invalid:{}", blackhole.local_addr().unwrap().port())
                .parse()
                .unwrap(),
        )
        .with_application_protocol(Protocol::HTTPS);
        let attempt = Arc::new(HttpServiceAttempt::default());
        input.extensions.insert_arc(attempt.clone());
        tokio::time::timeout(Duration::from_millis(500), connector.serve(input))
            .await
            .unwrap_err();
        assert!(calls.load(Ordering::Relaxed) >= 2);
        assert!(
            !attempt.failed(),
            "a mismatched candidate family must not turn the IPv4 timeout into an authentication failure"
        );
        endpoint.close(0u32, b"test complete");
    }

    #[cfg(feature = "rustls")]
    fn custom_tls_pool_id(verify: ServerVerifyMode) -> TlsPoolId {
        TlsPoolId::builder()
            .with_verify(&TlsServerVerify(verify))
            .build()
            .unwrap()
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_identity_follows_the_connectors_version_resolution() {
        let identifier = EasyHttpConnIdentifier {
            stream_tls: Some(Arc::new(rustls_client::RustlsTlsClientConfigProvider)
                as Arc<dyn TlsClientConfigProvider>),
            h3_tls: None,
        };
        let input = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        input.extensions.insert(HttpRequestVersion(Version::HTTP_3));
        let h3 = identifier.id(&input).unwrap();
        assert_eq!(identifier.tls_pool_id(&input), None);

        input
            .extensions
            .insert(FallbackHttpVersion(Version::HTTP_2));
        let fallback = identifier.id(&input).unwrap();
        assert!(identifier.tls_pool_id(&input).is_some());
        assert_ne!(h3, fallback);
        input.extensions.insert(TargetHttpVersion(Version::HTTP_3));
        assert_eq!(identifier.tls_pool_id(&input), None);
        input.extensions.insert(TargetHttpVersion(Version::HTTP_2));
        assert_eq!(identifier.id(&input).unwrap(), fallback);
    }

    #[cfg(all(feature = "rustls", feature = "boring"))]
    #[test]
    fn native_tls_identity_uses_selected_transport_provider() {
        let identifier = EasyHttpConnIdentifier {
            stream_tls: Some(Arc::new(rustls_client::RustlsTlsClientConfigProvider)
                as Arc<dyn TlsClientConfigProvider>),
            h3_tls: Some(Arc::new(boring_client::BoringTlsClientConfigProvider)
                as Arc<dyn TlsClientConfigProvider>),
        };
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(rama_tls_boring::client::BoringGrease(true));
        input.extensions.insert(TargetHttpVersion(Version::HTTP_2));
        assert_eq!(identifier.tls_pool_id(&input), None);
        input.extensions.insert(TargetHttpVersion(Version::HTTP_3));
        assert!(identifier.tls_pool_id(&input).is_some());
        let boring = identifier.id(&input).unwrap();
        input
            .extensions
            .insert(rama_tls_rustls::client::ModifyRustlsClientConfig::new(Ok));
        assert_eq!(identifier.id(&input).unwrap(), boring);
        input.extensions.insert(TargetHttpVersion(Version::HTTP_2));
        assert!(!identifier.id(&input).unwrap().is_reusable());

        let reversed = EasyHttpConnIdentifier {
            stream_tls: Some(Arc::new(boring_client::BoringTlsClientConfigProvider)
                as Arc<dyn TlsClientConfigProvider>),
            h3_tls: Some(Arc::new(rustls_client::RustlsTlsClientConfigProvider)
                as Arc<dyn TlsClientConfigProvider>),
        };
        assert!(reversed.id(&input).unwrap().is_reusable());
        input.extensions.insert(TargetHttpVersion(Version::HTTP_3));
        assert!(!reversed.id(&input).unwrap().is_reusable());
    }

    #[cfg(all(feature = "rustls", feature = "boring"))]
    #[test]
    fn common_tls_identity_agrees_across_providers_and_preserves_presence() {
        use rama_tls::client::{
            ServerVerifyMode, TlsClientConfig, TlsServerCertPins, TlsServerName, TlsServerVerify,
            TlsStoreServerCertChain,
        };
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        let rustls = EasyHttpConnIdentifier {
            stream_tls: Some(Arc::new(rustls_client::RustlsTlsClientConfigProvider)
                as Arc<dyn TlsClientConfigProvider>),
            h3_tls: None,
        };
        let boring = EasyHttpConnIdentifier {
            stream_tls: Some(Arc::new(boring_client::BoringTlsClientConfigProvider)
                as Arc<dyn TlsClientConfigProvider>),
            h3_tls: None,
        };
        let baseline = rustls.id(&input).unwrap();
        assert_eq!(baseline, boring.id(&input).unwrap());
        for intent in [
            rama_tls::KeyLogIntent::Disabled,
            rama_tls::KeyLogIntent::Environment,
            rama_tls::KeyLogIntent::File("pool-test-keylog.txt".into()),
        ] {
            input.extensions.insert(rama_tls::TlsKeyLog(intent));
            assert_ne!(baseline, rustls.id(&input).unwrap());
            assert_eq!(rustls.id(&input).unwrap(), boring.id(&input).unwrap());
        }
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        for alpn in [
            rama_net::tls::TlsAlpn(Default::default()),
            rama_net::tls::TlsAlpn::http_1(),
        ] {
            input.extensions.insert(alpn);
            assert_ne!(baseline, rustls.id(&input).unwrap());
            assert_eq!(rustls.id(&input).unwrap(), boring.id(&input).unwrap());
        }
        input.extensions.insert(rama_tls::TlsSupportedVersions(vec![
            rama_tls::ProtocolVersion::TLSv1_3,
        ]));
        assert_eq!(rustls.id(&input).unwrap(), boring.id(&input).unwrap());
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Auto));
        assert_ne!(baseline, rustls.id(&input).unwrap());
        assert_eq!(rustls.id(&input).unwrap(), boring.id(&input).unwrap());
        input
            .extensions
            .insert(TlsServerName("example.com".parse().unwrap()));
        input.extensions.insert(TlsStoreServerCertChain(true));
        assert_eq!(rustls.id(&input).unwrap(), boring.id(&input).unwrap());
        input
            .extensions
            .insert(TlsServerCertPins::new(TlsServerCertPin::SpkiSha256(
                [1; 32],
            )));
        assert_eq!(rustls.id(&input).unwrap(), boring.id(&input).unwrap());
        TlsClientConfig::new()
            .try_with_server_trust_anchors([vec![4, 5, 6].into()])
            .unwrap()
            .write_to(&input.extensions);
        assert_eq!(rustls.id(&input).unwrap(), boring.id(&input).unwrap());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn explicit_custom_identity_cannot_mask_builtin_tls_policy() {
        use rama_tls::client::TlsServerCertPins;
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        let identifier = EasyHttpConnIdentifier {
            stream_tls: Some(Arc::new(rustls_client::RustlsTlsClientConfigProvider)
                as Arc<dyn TlsClientConfigProvider>),
            h3_tls: None,
        };
        input
            .extensions
            .insert(custom_tls_pool_id(ServerVerifyMode::Auto));
        let baseline = identifier.id(&input).unwrap();
        assert_eq!(identifier.tls_pool_id(&input), None);
        input
            .extensions
            .insert(TlsServerCertPins::new(TlsServerCertPin::SpkiSha256(
                [2; 32],
            )));
        let pins = identifier.id(&input).unwrap();
        assert_ne!(baseline, pins);
        input
            .extensions
            .insert(custom_tls_pool_id(ServerVerifyMode::Disable));
        assert_eq!(pins, identifier.id(&input).unwrap());
        input
            .extensions
            .insert(rama_tls_rustls::client::ModifyRustlsClientConfig::new(Ok));
        assert!(!identifier.id(&input).unwrap().is_reusable());
    }
}
