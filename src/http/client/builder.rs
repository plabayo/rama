use rama_core::{error::extra::OpaqueError, graceful::WeakScope, layer::MapInput};

use super::{
    HttpConnectRequestAdapter, HttpConnector, HttpPooledConnector, HttpPooledConnectorConfig,
};
use crate::{
    Layer, Service,
    dns::client::{
        DnsConnector, DnsConnectorLayer, GlobalDnsResolver,
        resolver::{DnsAddressResolver, DnsResolver},
    },
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    http::{
        Body as ResponseBody, Request, Response, StreamingBody,
        client::proxy::HttpTunnelRoute,
        client::proxy_connector::{
            DefaultProxyConnectMethod, DefaultProxyConnectUdpMethod, DefaultProxyForwardMethod,
            DefaultProxySocksMethod, MaybeForwardedConnection, MaybeForwardedConnector,
            NoProxyConnection, ProxyConnector, ProxyConnectorParts, ProxyMethodNotEnabled,
            ProxyStreamConnector,
        },
        layer::version_adapter::RequestVersionAdapter,
    },
    net::client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService,
        DirectOnlyConnector, EstablishedClientConnection, MapEstablishedConnection, MaybeProxied,
        MaybeProxiedConnector, ProxyRouteFailureCache, ProxyRouteFailureCacheConnector,
        ProxyRoutesConnector, pool::PooledConnector,
    },
    service::BoxService,
    tcp::client::service::TcpConnector,
};
use rama_http::layer::{
    alt_svc::{AltSvc, AltSvcCache, AltSvcLayer},
    http_service::HttpServiceConnector,
    retry::{
        ManagedPolicy, Retry, RetryBody, RetryError,
        early_data::{is_early_data_rejected, permit_attempt, with_recovery},
        managed::{PrepareBody, RetryRule},
    },
};
use rama_net::http::{TargetHttpVersion, Version};
use rama_utils::macros::generate_set_and_with;
#[cfg(any(
    feature = "boring",
    all(
        feature = "quic",
        feature = "rustls",
        any(feature = "aws-lc", feature = "ring")
    )
))]
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "boring")]
use crate::tls::boring::client as boring_client;

#[cfg(all(feature = "boring", feature = "quic"))]
use crate::quic::tls::BoringTlsProvider;
#[cfg(all(
    feature = "quic",
    any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    )
))]
use crate::quic::tls::QuicClientConfigProvider;
#[cfg(all(
    feature = "rustls",
    feature = "quic",
    any(feature = "boring", feature = "aws-lc", feature = "ring")
))]
use crate::quic::tls::default_tls_provider;
#[cfg(feature = "rustls")]
use crate::tls::rustls::client as rustls_client;
#[cfg(any(feature = "rustls", feature = "boring"))]
use {
    crate::http::conn::FallbackHttpVersion, rama_core::layer::AddInputExtension,
    rama_tls::client::TlsClientConfig,
};

#[cfg(feature = "quic")]
use crate::{
    dns::client::resolver::BoxDnsResolver,
    http::layer::https_service::{HttpsService, HttpsServiceLayer},
};

#[cfg(feature = "quic")]
use crate::{
    http::core::h3::connection::Config as Http3Config,
    quic::{
        TransportConfig,
        client::{ClientEndpoint, SharedQuicEndpoint},
    },
};
#[cfg(all(feature = "masque", feature = "quic"))]
use crate::{net::client::ProxiedRoute, quic::client::QuicEndpointConnector};

/// Builder that is designed to easily create a connector for [`super::EasyHttpWebClient`] from most basic use cases
pub struct EasyHttpConnectorBuilder<C = (), S = (), D = (), F = ProxyMethodNotEnabled> {
    connector: C,
    stage: S,
    dns: D,
    discovery: HttpsDiscovery,
    forward: F,
    scope: WeakScope,
    target_version: Option<Version>,
}

#[derive(Debug, Clone)]
struct HttpsDiscovery {
    #[cfg(feature = "quic")]
    layer: HttpsServiceLayer<BoxDnsResolver>,
}

impl Default for HttpsDiscovery {
    fn default() -> Self {
        Self {
            #[cfg(feature = "quic")]
            layer: HttpsServiceLayer::new()
                .with_resolver(BoxDnsResolver::new(GlobalDnsResolver::new())),
        }
    }
}

#[cfg(any(feature = "boring", feature = "rustls"))]
impl HttpsDiscovery {
    fn with_tls(self, config: &TlsClientConfig, capable: bool) -> Self {
        #[cfg(feature = "quic")]
        {
            Self {
                layer: self
                    .layer
                    .with_tls(config.clone())
                    .with_ech_capable(capable),
            }
        }
        #[cfg(not(feature = "quic"))]
        {
            let _ = (config, capable);
            self
        }
    }
}

/// The QUIC leg of a builder stage: the endpoints HTTP/3 runs on, and the HTTP/3
/// configuration of the built-in connector over them. `()` is no QUIC leg, and so no
/// HTTP/3.
#[derive(Debug, Clone)]
pub struct QuicLeg<E> {
    pub(super) endpoints: E,
    #[cfg(feature = "quic")]
    config: Option<Http3Config>,
    #[cfg(feature = "quic")]
    pub(super) transport: Option<TransportConfig>,
}

impl<E> QuicLeg<E> {
    pub(super) fn new(endpoints: E) -> Self {
        Self {
            endpoints,
            #[cfg(feature = "quic")]
            config: None,
            #[cfg(feature = "quic")]
            transport: None,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Default)]
pub struct TransportStage<Q = ()> {
    pub(super) quic: Q,
}

#[cfg(feature = "quic")]
impl<T, E, F> EasyHttpConnectorBuilder<T, TransportStage<QuicLeg<E>>, (), F> {
    /// Configure the QUIC transport of the connections the QUIC leg dials, such as a
    /// larger initial MTU; HTTP/3 limits are applied on top. A request's `QuicProfile`
    /// replaces it.
    #[must_use]
    pub fn with_quic_transport_config(mut self, transport: TransportConfig) -> Self {
        self.stage.quic.transport = Some(transport);
        self
    }
}

#[non_exhaustive]
#[derive(Debug, Default)]
pub struct DnsStage<Q = ()> {
    pub(super) quic: Q,
}

#[non_exhaustive]
#[derive(Debug, Default)]
pub struct ProxyStage<const PROXY: bool = true, Q = ()> {
    quic: Q,
}

#[non_exhaustive]
#[derive(Debug, Default)]
pub struct TlsStage<const PROXY: bool = true, Tls = (), Q = ()> {
    #[cfg_attr(
        not(all(
            feature = "quic",
            any(
                feature = "boring",
                all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
            )
        )),
        expect(
            dead_code,
            reason = "only the built-in HTTP/3 transport reads it, which needs a QUIC TLS backend"
        )
    )]
    pub(super) tls: Tls,
    #[cfg(all(
        feature = "quic",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
        )
    ))]
    pub(super) quic_tls: Option<Arc<dyn QuicClientConfigProvider>>,
    pub(super) quic: Q,
}

#[cfg(any(feature = "boring", feature = "rustls"))]
impl<const PROXY: bool, Q> TlsStage<PROXY, TlsClientConfig, Q> {
    #[cfg(feature = "boring")]
    pub(super) fn using_boring(tls: TlsClientConfig, quic: Q) -> Self {
        Self {
            tls,
            #[cfg(all(
                feature = "quic",
                any(
                    feature = "boring",
                    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
                )
            ))]
            quic_tls: Some(Arc::new(BoringTlsProvider)),
            quic,
        }
    }

    #[cfg(feature = "rustls")]
    pub(super) fn using_rustls(tls: TlsClientConfig, quic: Q) -> Self {
        Self {
            tls,
            #[cfg(all(
                feature = "quic",
                any(
                    feature = "boring",
                    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
                )
            ))]
            quic_tls: default_tls_provider().ok(),
            quic,
        }
    }
}

impl<const PROXY: bool, Q> TlsStage<PROXY, (), Q> {
    pub(super) fn without_tls(quic: Q) -> Self {
        Self {
            tls: (),
            #[cfg(all(
                feature = "quic",
                any(
                    feature = "boring",
                    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
                )
            ))]
            quic_tls: None,
            quic,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Default)]
pub struct HttpStage<const PROXY: bool = true>;

#[non_exhaustive]
#[derive(Debug, Default)]
pub struct ProxyRouteFailureCacheStage;

#[non_exhaustive]
#[derive(Debug, Default)]
pub struct PoolStage;

impl Default for EasyHttpConnectorBuilder {
    fn default() -> Self {
        Self::new(WeakScope::default())
    }
}

impl EasyHttpConnectorBuilder {
    /// Start a connector whose connections and tunnels run in `scope`.
    #[must_use]
    pub fn new(scope: impl Into<WeakScope>) -> Self {
        Self {
            connector: (),
            stage: (),
            dns: (),
            discovery: HttpsDiscovery::default(),
            forward: ProxyMethodNotEnabled::HTTP_FORWARD,
            scope: scope.into(),
            target_version: None,
        }
    }

    /// Dial origins over TCP, and over QUIC for HTTP/3 where this build has a QUIC
    /// TLS backend.
    #[cfg(feature = "quic")]
    #[must_use]
    pub fn with_default_transport_connector(
        self,
    ) -> EasyHttpConnectorBuilder<TcpConnector, TransportStage<QuicLeg<SharedQuicEndpoint>>> {
        let quic = QuicLeg::new(SharedQuicEndpoint::managed(self.scope.clone()));
        self.with_transport(TcpConnector::default(), quic)
    }

    /// Dial origins over TCP.
    #[cfg(not(feature = "quic"))]
    #[must_use]
    pub fn with_default_transport_connector(
        self,
    ) -> EasyHttpConnectorBuilder<TcpConnector, TransportStage> {
        self.with_default_tcp_connector()
    }

    /// Dial origins over QUIC only: every request is sent over HTTP/3, whichever version
    /// it was built with. Only a request which explicitly targets another version, with a
    /// [`TargetHttpVersion`] of its own, fails: this client has no byte stream to carry it.
    #[cfg(feature = "quic")]
    #[must_use]
    pub fn with_default_quic_connector(
        self,
    ) -> EasyHttpConnectorBuilder<NoTcpConnector, TransportStage<QuicLeg<SharedQuicEndpoint>>> {
        let quic = QuicLeg::new(SharedQuicEndpoint::managed(self.scope.clone()));
        self.with_quic_transport(quic)
    }

    /// Dial origins over TCP only: no HTTP/3.
    #[must_use]
    pub fn with_default_tcp_connector(
        self,
    ) -> EasyHttpConnectorBuilder<TcpConnector, TransportStage> {
        self.with_transport(TcpConnector::default(), ())
    }

    /// Dial origins over `connector` only: this first call is the only transport leg, so
    /// there is no HTTP/3 unless a QUIC leg is added with
    /// [`EasyHttpConnectorBuilder::with_custom_quic_connector`].
    pub fn with_custom_tcp_connector<C>(
        self,
        connector: C,
    ) -> EasyHttpConnectorBuilder<C, TransportStage> {
        self.with_transport(connector, ())
    }

    /// Dial origins over the QUIC endpoints `endpoints` hands out only, like
    /// [`EasyHttpConnectorBuilder::with_default_quic_connector`]: this first call is the
    /// only transport leg, so every request is sent over HTTP/3. A TCP leg can be added
    /// with [`EasyHttpConnectorBuilder::with_custom_tcp_connector`], which then serves the
    /// requests that explicitly target another version.
    #[cfg(feature = "quic")]
    pub fn with_custom_quic_connector<E>(
        self,
        endpoints: E,
    ) -> EasyHttpConnectorBuilder<NoTcpConnector, TransportStage<QuicLeg<E>>>
    where
        E: ConnectorService<ConnectRequest, Connection = ClientEndpoint>,
    {
        self.with_quic_transport(QuicLeg::new(endpoints))
    }

    /// Dial over `quic` only: every request without a [`TargetHttpVersion`] of its own is
    /// sent over HTTP/3, as there is no TCP leg.
    #[cfg(feature = "quic")]
    fn with_quic_transport<Q>(
        mut self,
        quic: Q,
    ) -> EasyHttpConnectorBuilder<NoTcpConnector, TransportStage<Q>> {
        self.target_version = Some(Version::HTTP_3);
        self.with_transport(NoTcpConnector, quic)
    }

    fn with_transport<C, Q>(
        self,
        connector: C,
        quic: Q,
    ) -> EasyHttpConnectorBuilder<C, TransportStage<Q>> {
        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery: self.discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector,
            stage: TransportStage { quic },
        }
    }
}

#[cfg(feature = "quic")]
impl<T, Q, F> EasyHttpConnectorBuilder<T, TransportStage<Q>, (), F> {
    /// Run HTTP/3 over the QUIC endpoints `endpoints` hands out, instead of the built-in
    /// ones or none: on a builder which already has a transport this swaps the QUIC leg
    /// and keeps the TCP leg.
    pub fn with_custom_quic_connector<E>(
        self,
        endpoints: E,
    ) -> EasyHttpConnectorBuilder<T, TransportStage<QuicLeg<E>>, (), F>
    where
        E: ConnectorService<ConnectRequest, Connection = ClientEndpoint>,
    {
        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery: self.discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector: self.connector,
            stage: TransportStage {
                quic: QuicLeg::new(endpoints),
            },
        }
    }

    /// Run HTTP/3 over the built-in QUIC endpoints, keeping the TCP leg chosen before,
    /// such as a custom one.
    #[must_use]
    pub fn with_default_quic_connector(
        self,
    ) -> EasyHttpConnectorBuilder<T, TransportStage<QuicLeg<SharedQuicEndpoint>>, (), F> {
        let endpoints = SharedQuicEndpoint::managed(self.scope.clone());
        self.with_custom_quic_connector(endpoints)
    }
}

impl<T, Q, F> EasyHttpConnectorBuilder<T, TransportStage<Q>, (), F> {
    /// Dial origins over `connector` instead of the TCP leg chosen before, keeping the
    /// QUIC leg: `with_default_transport_connector().with_custom_tcp_connector(c)` dials
    /// HTTP/1.1 and HTTP/2 over `c` and HTTP/3 over rama's default QUIC endpoints.
    pub fn with_custom_tcp_connector<C>(
        self,
        connector: C,
    ) -> EasyHttpConnectorBuilder<C, TransportStage<Q>, (), F> {
        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery: self.discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector,
            stage: self.stage,
        }
    }
}

impl<T, Stage, D, F> EasyHttpConnectorBuilder<T, Stage, D, F> {
    /// Add a custom connector to this Stage.
    ///
    /// Adding a custom connector to a stage will not change the state
    /// so this can be used to modify behaviour at a specific stage.
    pub fn with_custom_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, Stage, D, F>
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
    ) -> EasyHttpConnectorBuilder<T2, Stage, D, F> {
        let connector = map_fn(self.connector);
        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery: self.discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector,
            stage: self.stage,
        }
    }
}

impl<T, Q, F> EasyHttpConnectorBuilder<T, TransportStage<Q>, (), F> {
    /// Add the global DNS policy to both the stream and built-in QUIC transports.
    pub fn with_default_dns_connector(
        self,
    ) -> EasyHttpConnectorBuilder<DnsConnector<T>, DnsStage<Q>, DnsConnectorLayer, F> {
        self.with_dns_resolver(GlobalDnsResolver::new())
    }

    /// Share one resolver between transport address resolution and HTTPS discovery.
    pub fn with_dns_resolver<R: DnsResolver + Clone>(
        self,
        resolver: R,
    ) -> EasyHttpConnectorBuilder<DnsConnector<T, R>, DnsStage<Q>, DnsConnectorLayer<R>, F> {
        let builder = self.with_dns_address_resolver(resolver.clone());
        #[cfg(feature = "quic")]
        let builder = {
            let mut builder = builder;
            builder.discovery.layer = builder
                .discovery
                .layer
                .with_resolver(BoxDnsResolver::new(resolver))
                .with_enabled(true);
            builder
        };
        builder
    }

    /// Add a custom address resolver to both the stream and built-in QUIC transports.
    /// Automatic HTTPS discovery is disabled because this resolver need not support
    /// HTTPS records. Use `with_dns_resolver` to share an aggregate resolver, or
    /// explicitly opt in with `with_https_resolver` after configuring the pool.
    pub fn with_dns_address_resolver<R: DnsAddressResolver + Clone>(
        self,
        resolver: R,
    ) -> EasyHttpConnectorBuilder<DnsConnector<T, R>, DnsStage<Q>, DnsConnectorLayer<R>, F> {
        self.with_dns_connector(DnsConnectorLayer::with_resolver(resolver))
    }

    /// Omit DNS resolution and automatic HTTPS discovery.
    /// Transports require IP targets or their own resolution.
    pub fn without_dns_connector(self) -> EasyHttpConnectorBuilder<T, DnsStage<Q>, (), F> {
        self.with_dns_connector(())
    }

    /// Retain a custom DNS layer for both transport stacks.
    ///
    /// The layer is applied to the TCP leg here and to the HTTP/3 connector over the QUIC leg
    /// the HTTP step builds. Automatic HTTPS discovery is disabled: an opaque layer cannot
    /// authorize global DNS queries.
    pub fn with_dns_connector<L: Layer<T>>(
        self,
        layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, DnsStage<Q>, L, F> {
        let connector = layer.layer(self.connector);
        let discovery = self.discovery;
        #[cfg(feature = "quic")]
        let discovery = HttpsDiscovery {
            layer: discovery.layer.with_enabled(false),
        };
        EasyHttpConnectorBuilder {
            connector,
            stage: DnsStage {
                quic: self.stage.quic,
            },
            dns: layer,
            discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
        }
    }
}

/// The TCP leg of a client that dials QUIC only: it refuses every connection.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct NoTcpConnector;

impl<Input: Send + 'static> Service<Input> for NoTcpConnector {
    type Output = EstablishedClientConnection<NoProxyConnection, Input>;
    type Error = ConnectionError;

    async fn serve(&self, _: Input) -> Result<Self::Output, Self::Error> {
        Err(ConnectionError::local(
            BoxError::from_static_str("this client dials over QUIC only"),
            ConnectionErrorKind::Unavailable,
        ))
    }
}

/// A QUIC leg the proxy stage can put CONNECT-UDP ([RFC 9298]) next to, the way it puts
/// SOCKS5 and CONNECT next to the TCP leg: `()`, no QUIC leg, stays without one.
///
/// [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
pub trait ProxiedQuicLeg<U> {
    type Proxied;

    fn with_connect_udp(self, connect_udp: U, scope: &WeakScope) -> Self::Proxied;
}

impl<U> ProxiedQuicLeg<U> for () {
    type Proxied = ();

    fn with_connect_udp(self, _: U, _: &WeakScope) -> Self::Proxied {}
}

#[cfg(all(feature = "masque", feature = "quic"))]
impl<E, U> ProxiedQuicLeg<U> for QuicLeg<E> {
    type Proxied = QuicLeg<
        MapEstablishedConnection<
            MaybeProxiedConnector<E, QuicEndpointConnector<U>, ProxiedRoute>,
            FlattenMaybeProxied,
        >,
    >;

    fn with_connect_udp(self, connect_udp: U, scope: &WeakScope) -> Self::Proxied {
        QuicLeg {
            endpoints: MapEstablishedConnection::new(
                MaybeProxiedConnector::new(
                    self.endpoints,
                    QuicEndpointConnector::new(connect_udp, scope.clone()),
                    ProxiedRoute,
                ),
                FlattenMaybeProxied,
            ),
            config: self.config,
            transport: self.transport,
        }
    }
}

#[cfg(all(feature = "quic", not(feature = "masque")))]
impl<E, U> ProxiedQuicLeg<U> for QuicLeg<E> {
    type Proxied = Self;

    fn with_connect_udp(self, _: U, _: &WeakScope) -> Self::Proxied {
        self
    }
}

/// Turn a [`MaybeProxied`] connection whose two sides are of one type into that type.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct FlattenMaybeProxied;

impl<A> Layer<MaybeProxied<A, A>> for FlattenMaybeProxied {
    type Service = A;

    fn layer(&self, conn: MaybeProxied<A, A>) -> Self::Service {
        match conn {
            MaybeProxied::Direct { conn } | MaybeProxied::Proxied { conn } => conn,
        }
    }
}

impl<T, Q, D, F> EasyHttpConnectorBuilder<T, DnsStage<Q>, D, F> {
    /// Reach the origin of a request with a proxied [`ProxyRoute`] through `proxies`, and
    /// every other origin over the connector built so far.
    ///
    /// Every proxy method lands next to the leg it belongs to: SOCKS5 and CONNECT next to
    /// the TCP leg, as they answer with a byte stream to the origin; CONNECT-UDP next to
    /// the QUIC leg, as it answers with the datagrams HTTP/3 runs on; forwarding above the
    /// HTTP connections, where the proxy plays origin for the request.
    ///
    /// The connections to proxies are client connections of their own, with their own
    /// transport, DNS, TLS and connection pool: nothing of this client's transport, DNS, TLS
    /// or HTTP configuration applies to them. To dial proxies over a transport of your own,
    /// build the connector with
    /// [`ProxyConnector::builder(scope).with_custom_tcp_connector(..)`](ProxyConnector::builder).
    ///
    /// [`ProxyRoute`]: rama_net::client::ProxyRoute
    pub fn with_proxy_support<S, C, U, F2>(
        self,
        proxies: ProxyConnector<S, C, U, F2>,
    ) -> EasyHttpConnectorBuilder<
        MaybeProxiedConnector<T, ProxyStreamConnector<S, C>, HttpTunnelRoute>,
        ProxyStage<true, Q::Proxied>,
        D,
        F2,
    >
    where
        Q: ProxiedQuicLeg<U>,
    {
        let ProxyConnectorParts {
            socks,
            connect,
            connect_udp,
            forward,
            ..
        } = proxies.into_parts();
        let quic = self.stage.quic.with_connect_udp(connect_udp, &self.scope);
        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery: self.discovery,
            target_version: self.target_version,
            forward,
            scope: self.scope,
            connector: MaybeProxiedConnector::new(
                self.connector,
                ProxyStreamConnector::new(socks, connect),
                HttpTunnelRoute,
            ),
            stage: ProxyStage { quic },
        }
    }

    /// [`Self::with_proxy_support`] with rama's default connections towards proxies, which
    /// run in the scope of this builder; see [`ProxyConnector::default_with_scope`].
    ///
    /// `Body` is the body type sent to a proxy, the one this client serves origins with.
    /// These connections are clients of their own, as in [`Self::with_proxy_support`]: they
    /// have their own transport, DNS, TLS and pool, and none of this client's. Isolating the
    /// `407` of an upstream proxy, as an intermediary needs, is a setting of the
    /// [`ProxyConnector`]: pass one to [`Self::with_proxy_support`] instead.
    pub fn with_default_proxy_support<Body>(
        self,
    ) -> EasyHttpConnectorBuilder<
        MaybeProxiedConnector<
            T,
            ProxyStreamConnector<
                DefaultProxySocksMethod,
                DefaultProxyConnectMethod<TcpConnector, Body>,
            >,
            HttpTunnelRoute,
        >,
        ProxyStage<true, Q::Proxied>,
        D,
        DefaultProxyForwardMethod<TcpConnector, Body>,
    >
    where
        Q: ProxiedQuicLeg<DefaultProxyConnectUdpMethod<TcpConnector, Body>>,
        Body: Default
            + StreamingBody<Data: Send + 'static, Error: Into<BoxError>>
            + Unpin
            + Send
            + 'static,
    {
        let proxies = ProxyConnector::default_with_scope(self.scope.clone());
        self.with_proxy_support(proxies)
    }

    /// Make a client without proxy support: a request with a proxied [`ProxyRoute`] is
    /// refused rather than connected around its proxy.
    ///
    /// [`ProxyRoute`]: rama_net::client::ProxyRoute
    pub fn without_proxy_support(
        self,
    ) -> EasyHttpConnectorBuilder<DirectOnlyConnector<T>, ProxyStage<false, Q>, D, F> {
        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery: self.discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector: DirectOnlyConnector::new(self.connector),
            stage: ProxyStage {
                quic: self.stage.quic,
            },
        }
    }
}
impl<T, Q, D, F, const PROXY: bool> EasyHttpConnectorBuilder<T, ProxyStage<PROXY, Q>, D, F> {
    /// Add a custom tls connector that will be used by the client.
    ///
    /// The QUIC leg gets no TLS from a custom connector, so this client has no built-in
    /// HTTP/3.
    ///
    /// TLS connectors publish connection reuse policies on their established
    /// transports. Custom secure connectors without this metadata are not pooled;
    /// implement the generic connection reuse policy to support safe pooling.
    ///
    /// The final HTTP transition applies a [`RequestVersionAdapter`] outside
    /// the complete connection attempt so it can apply the negotiated version
    /// to the original HTTP request.
    pub fn with_custom_tls_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, TlsStage<PROXY, (), Q>, D, F>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);

        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery: self.discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector,
            stage: TlsStage::without_tls(self.stage.quic),
        }
    }

    #[cfg(feature = "boring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
    /// Support https connections by using boringssl for tls
    ///
    /// The final HTTP transition automatically applies the HTTP version
    /// negotiated through TLS to the original request.
    ///
    /// `config` secures both legs, but its ALPN only applies to TCP: the QUIC leg always
    /// offers `h3`.
    pub fn with_tls_support_using_boringssl(
        self,
        config: TlsClientConfig,
    ) -> EasyHttpConnectorBuilder<
        boring_client::TlsConnector<T>,
        TlsStage<PROXY, TlsClientConfig, Q>,
        D,
        F,
    > {
        let discovery = self.discovery.with_tls(&config, true);
        let connector =
            boring_client::TlsConnector::auto(self.connector).with_base_config(config.clone());

        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector,
            stage: TlsStage::using_boring(config, self.stage.quic),
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
        TlsStage<PROXY, TlsClientConfig, Q>,
        D,
        F,
    > {
        let discovery = self.discovery.with_tls(&config, true);
        let connector =
            boring_client::TlsConnector::auto(self.connector).with_base_config(config.clone());
        let connector =
            AddInputExtension::new(connector, FallbackHttpVersion(default_http_version))
                .with_overwrite(false);

        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector,
            stage: TlsStage::using_boring(config, self.stage.quic),
        }
    }

    #[cfg(feature = "rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
    /// Support https connections by using ruslts for tls
    ///
    /// The final HTTP transition automatically applies the HTTP version
    /// negotiated through TLS to the original request.
    ///
    /// `config` secures both legs, but its ALPN only applies to TCP: the QUIC leg always
    /// offers `h3`.
    pub fn with_tls_support_using_rustls(
        self,
        config: TlsClientConfig,
    ) -> EasyHttpConnectorBuilder<
        rustls_client::TlsConnector<T>,
        TlsStage<PROXY, TlsClientConfig, Q>,
        D,
        F,
    > {
        let discovery = self.discovery.with_tls(&config, false);
        let connector =
            rustls_client::TlsConnector::auto(self.connector).with_base_config(config.clone());

        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector,
            stage: TlsStage::using_rustls(config, self.stage.quic),
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
        TlsStage<PROXY, TlsClientConfig, Q>,
        D,
        F,
    > {
        let discovery = self.discovery.with_tls(&config, false);
        let connector =
            rustls_client::TlsConnector::auto(self.connector).with_base_config(config.clone());
        let connector =
            AddInputExtension::new(connector, FallbackHttpVersion(default_http_version))
                .with_overwrite(false);

        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector,
            stage: TlsStage::using_rustls(config, self.stage.quic),
        }
    }

    core::cfg_select! {
        feature = "boring" => {
            /// Support https connections with the TLS implementation this build of rama
            /// prefers; see [`Self::with_tls_support_using_boringssl`].
            pub fn with_default_tls_support(
                self,
                config: TlsClientConfig,
            ) -> EasyHttpConnectorBuilder<
                boring_client::TlsConnector<T>,
                TlsStage<PROXY, TlsClientConfig, Q>,
                D,
                F,
            > {
                self.with_tls_support_using_boringssl(config)
            }
        }
        feature = "rustls" => {
            /// Support https connections with the TLS implementation this build of rama
            /// prefers; see [`Self::with_tls_support_using_rustls`].
            pub fn with_default_tls_support(
                self,
                config: TlsClientConfig,
            ) -> EasyHttpConnectorBuilder<
                rustls_client::TlsConnector<T>,
                TlsStage<PROXY, TlsClientConfig, Q>,
                D,
                F,
            > {
                self.with_tls_support_using_rustls(config)
            }
        }
        _ => {}
    }

    /// Don't support https on this connector, nor HTTP/3, which is always secure.
    pub fn without_tls_support(self) -> EasyHttpConnectorBuilder<T, TlsStage<PROXY, (), Q>, D, F> {
        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery: self.discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector: self.connector,
            stage: TlsStage::without_tls(self.stage.quic),
        }
    }
}

#[cfg(feature = "boring")]
impl<T, D, F, Tls, Q, const PROXY: bool>
    EasyHttpConnectorBuilder<boring_client::TlsConnector<T>, TlsStage<PROXY, Tls, Q>, D, F>
{
    #[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
    /// Resume TLS sessions with servers connected to before, keeping them in `store`;
    /// see [`boring_client::TlsConnector::with_session_store`].
    ///
    /// Servers can link the connections that resume each other's sessions, so a
    /// client acting for several users should keep a store per user.
    #[must_use]
    pub fn with_tls_session_store(
        mut self,
        store: Arc<dyn boring_client::TlsClientSessionStore>,
    ) -> Self {
        self.connector.set_session_store(store);
        self
    }
}

impl<T, D, F, Tls, Q, const PROXY: bool>
    EasyHttpConnectorBuilder<T, TlsStage<PROXY, Tls, Q>, D, F>
{
    fn http_connector<Body>(
        self,
    ) -> EasyHttpConnectorBuilder<HttpConnector<T, Body>, HttpStage<PROXY>, D, F> {
        let connector = HttpConnector::new(self.connector, self.scope.clone());

        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery: self.discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector,
            stage: HttpStage,
        }
    }

    /// Add a custom http connector that will be run just after tls, instead of the one
    /// [`Self::with_default_http_connector`] builds; the QUIC leg is left out.
    pub fn with_custom_http_connector<L>(
        self,
        connector_layer: L,
    ) -> EasyHttpConnectorBuilder<L::Service, HttpStage<PROXY>, D, F>
    where
        L: Layer<T>,
    {
        let connector = connector_layer.into_layer(self.connector);

        EasyHttpConnectorBuilder {
            dns: self.dns,
            discovery: self.discovery,
            target_version: self.target_version,
            forward: self.forward,
            scope: self.scope,
            connector,
            stage: HttpStage,
        }
    }
}

impl<T, D, F, Q, const PROXY: bool> EasyHttpConnectorBuilder<T, TlsStage<PROXY, (), Q>, D, F> {
    /// Speak HTTP/1.1 and HTTP/2 over the TCP leg. Without TLS there is no HTTP/3: that
    /// runs over QUIC, which is always secure.
    pub fn with_default_http_connector<Body>(
        self,
    ) -> EasyHttpConnectorBuilder<HttpConnector<T, Body>, HttpStage<PROXY>, D, F> {
        self.http_connector()
    }
}

#[cfg(any(feature = "boring", feature = "rustls"))]
impl<T, D, F, const PROXY: bool>
    EasyHttpConnectorBuilder<T, TlsStage<PROXY, TlsClientConfig, ()>, D, F>
{
    /// Speak HTTP/1.1 and HTTP/2 over the TCP leg; there is no QUIC leg for HTTP/3.
    pub fn with_default_http_connector<Body>(
        self,
    ) -> EasyHttpConnectorBuilder<HttpConnector<T, Body>, HttpStage<PROXY>, D, F> {
        self.http_connector()
    }
}

#[cfg(all(
    feature = "rustls",
    not(feature = "boring"),
    feature = "quic",
    not(any(feature = "aws-lc", feature = "ring"))
))]
impl<T, D, F, E, const PROXY: bool>
    EasyHttpConnectorBuilder<T, TlsStage<PROXY, TlsClientConfig, QuicLeg<E>>, D, F>
{
    /// Speak HTTP/1.1 and HTTP/2 over the TCP leg; HTTP/3 over the QUIC leg needs a QUIC
    /// TLS backend (boringssl, or rustls with `aws-lc` or `ring`).
    pub fn with_default_http_connector<Body>(
        self,
    ) -> EasyHttpConnectorBuilder<HttpConnector<T, Body>, HttpStage<PROXY>, D, F> {
        self.http_connector()
    }
}

#[cfg(all(
    feature = "quic",
    any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    )
))]
#[cfg_attr(docsrs, doc(cfg(feature = "quic")))]
impl<T, D, F, E, const PROXY: bool>
    EasyHttpConnectorBuilder<T, TlsStage<PROXY, TlsClientConfig, QuicLeg<E>>, D, F>
{
    /// Configure the HTTP/3 connector [`Self::with_default_http_connector`] builds over
    /// the QUIC leg, such as `Config { early_requests: true, ..Default::default() }`.
    ///
    /// A client which brings its own HTTP/3 connector configures it itself and adds it
    /// with [`Self::with_custom_http_connector`].
    #[must_use]
    pub fn with_http3_config(mut self, config: Http3Config) -> Self {
        self.stage.quic.config = Some(config);
        self
    }

    /// Build the QUIC TLS configurations through `provider` instead of the backend the
    /// TLS stage selected, so the QUIC leg can use another backend than the TCP leg.
    #[must_use]
    pub fn with_quic_tls_provider(mut self, provider: Arc<dyn QuicClientConfigProvider>) -> Self {
        self.stage.quic_tls = Some(provider);
        self
    }

    /// Speak HTTP/1.1 and HTTP/2 over the TCP leg and HTTP/3 over the QUIC leg, on the TLS
    /// of the stage before this one and the same DNS policy for both. HTTP/3 is reached
    /// through alternative-service discovery or an explicit HTTP/3 request.
    pub fn with_default_http_connector<Body>(
        self,
    ) -> EasyHttpConnectorBuilder<
        HttpConnector<super::HttpTransportConnector<T, D::Service>, Body>,
        HttpStage<PROXY>,
        D,
        F,
    >
    where
        E: ConnectorService<ConnectRequest, Connection = ClientEndpoint> + Clone,
        D: Layer<super::Http3Connector<E>>,
        D::Service: Service<
                ConnectRequest,
                Output = EstablishedClientConnection<super::Http3Transport, ConnectRequest>,
                Error = ConnectionError,
            > + Clone
            + Send
            + Sync
            + 'static,
    {
        let Self {
            connector,
            stage,
            dns,
            mut discovery,
            target_version,
            forward,
            scope,
        } = self;
        #[expect(
            clippy::expect_used,
            reason = "every TLS stage of a build with a QUIC TLS backend picks a provider"
        )]
        let provider = stage
            .quic_tls
            .expect("TLS stage without a QUIC TLS provider");
        let http3 = super::default_http3_builder(scope.clone(), stage.tls, provider)
            .with_endpoints(stage.quic.endpoints)
            .maybe_with_transport(stage.quic.transport);
        let http3 = match stage.quic.config {
            Some(config) => http3.with_config(config),
            None => http3,
        };
        #[expect(
            clippy::expect_used,
            reason = "the built-in HTTP/3 configuration is always valid"
        )]
        let http3 = http3.build_lazy().expect("built-in HTTP/3 configuration");
        let capable = discovery.layer.is_ech_capable() || http3.tls_provider().supports_ech();
        discovery.layer.set_ech_capable(capable);
        let quic = dns.layer(http3);
        EasyHttpConnectorBuilder {
            connector: HttpConnector::new(connector, scope.clone()).with_http3_connector(quic),
            stage: HttpStage,
            dns,
            discovery,
            target_version,
            forward,
            scope,
        }
    }
}

#[cfg(feature = "quic")]
type SelectedConnector<T> =
    HttpsService<HttpServiceConnector<ProxyRoutesConnector<T>>, BoxDnsResolver>;
#[cfg(not(feature = "quic"))]
type SelectedConnector<T> = HttpServiceConnector<ProxyRoutesConnector<T>>;

type DefaultHttpConnector<T> = TargetVersionConnector<
    RequestVersionAdapter<
        HttpConnectRequestAdapter<
            MapEstablishedConnection<SelectedConnector<T>, AltSvcConnectionLayer>,
        >,
    >,
>;

/// The HTTP version a client dials with unless the request names one of its own, as a
/// client which dials over QUIC only targets HTTP/3.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct TargetVersionConnector<S> {
    inner: S,
    version: Option<Version>,
}

impl<S> TargetVersionConnector<S> {
    fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S, Input> Service<Input> for TargetVersionConnector<S>
where
    S: Service<Input>,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if let Some(version) = self.version
            && !input.extensions().contains::<TargetHttpVersion>()
        {
            input.extensions().insert(TargetHttpVersion(version));
        }
        self.inner.serve(input).await
    }
}

/// HTTP response observation configured by the easy-client builder.
///
/// Protocol selection and response observation share the configured cache but
/// remain independently composable services.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct AltSvcConnectionLayer {
    cache: Option<AltSvcCache>,
}

impl<S> Layer<S> for AltSvcConnectionLayer {
    type Service = AltSvc<S>;

    fn layer(&self, inner: S) -> Self::Service {
        match &self.cache {
            Some(cache) => AltSvcLayer::new(cache.clone()).layer(inner),
            None => AltSvc::passthrough(inner),
        }
    }
}

type ConfiguredConnectionBuilder<T> = EasyHttpConnectorBuilder<DefaultHttpConnector<T>, PoolStage>;

type ConfiguredConnectionPoolBuilder<T> =
    EasyHttpConnectorBuilder<DefaultHttpConnector<HttpPooledConnector<T>>, PoolStage>;

type ErasedConnector<C> =
    BoxService<ConnectRequest, EstablishedClientConnection<C, ConnectRequest>, ConnectionError>;

type DefaultConnectionBuilder<C, F> = ConfiguredConnectionBuilder<
    ProxyRouteFailureCacheConnector<ErasedConnector<MaybeForwardedConnection<C, F>>>,
>;

type DefaultConnectionPoolBuilder<C, F> = ConfiguredConnectionPoolBuilder<
    ProxyRouteFailureCacheConnector<ErasedConnector<MaybeForwardedConnection<C, F>>>,
>;

// Keep the configured connector and its future behind one dynamic boundary
// before adding route caching and fallback. This prevents deeply nested TLS
// connector futures from overflowing ordinary thread stacks while dispatching
// only once per new connection (and behind the pool when pooling is enabled).
#[derive(ExtensionsRef)]
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

fn finalize_http_connector<T>(
    connector: T,
    discovery: HttpsDiscovery,
    target_version: Option<Version>,
) -> DefaultHttpConnector<T> {
    let connector = ProxyRoutesConnector::new(connector);
    let cache = AltSvcCache::default();
    let connector = HttpServiceConnector::new(connector).with_cache(cache.clone());
    #[cfg(feature = "quic")]
    let connector = discovery.layer.with_cache(cache.clone()).layer(connector);
    #[cfg(not(feature = "quic"))]
    let _ = discovery;
    adapt_http_service_connector(connector, Some(cache), target_version)
}

fn adapt_http_service_connector<T>(
    connector: SelectedConnector<T>,
    cache: Option<AltSvcCache>,
    target_version: Option<Version>,
) -> DefaultHttpConnector<T> {
    let connector = MapEstablishedConnection::new(connector, AltSvcConnectionLayer { cache });
    TargetVersionConnector {
        inner: RequestVersionAdapter::new(HttpConnectRequestAdapter::new(connector)),
        version: target_version,
    }
}

impl<T> EasyHttpConnectorBuilder<DefaultHttpConnector<T>, PoolStage> {
    fn selected_connector_mut(&mut self) -> &mut SelectedConnector<T> {
        self.connector.get_mut().get_mut().get_mut().get_mut()
    }

    fn service_selector_mut(&mut self) -> &mut HttpServiceConnector<ProxyRoutesConnector<T>> {
        let connector = self.selected_connector_mut();
        #[cfg(feature = "quic")]
        let connector = connector.get_mut();
        connector
    }

    /// Configure HTTP service selection, including attempt timeouts and budgets.
    #[must_use]
    pub fn configure_http_service(
        mut self,
        configure: impl FnOnce(&mut HttpServiceConnector<ProxyRoutesConnector<T>>),
    ) -> Self {
        configure(self.service_selector_mut());
        self
    }

    #[cfg(feature = "quic")]
    /// Disable HTTPS discovery while retaining independently configured Alt-Svc.
    #[must_use]
    pub fn without_https_discovery(mut self) -> Self {
        self.selected_connector_mut()
            .config_mut()
            .set_enabled(false);
        self
    }

    #[cfg(feature = "quic")]
    /// Enable HTTPS discovery with this resolver for HTTPS and A/AAAA records.
    /// Its lazy address source takes precedence over the transport resolver for
    /// matching HTTPS endpoints. Use `with_dns_resolver` to share one DNS policy.
    #[must_use]
    pub fn with_https_resolver<R: DnsResolver>(mut self, resolver: R) -> Self {
        let config = self.selected_connector_mut().config_mut();
        *config = config
            .clone()
            .with_resolver(BoxDnsResolver::new(resolver))
            .with_enabled(true);
        self
    }

    #[cfg(feature = "quic")]
    /// Configure the reusable discovery layer, including proxy permission and limits.
    #[must_use]
    pub fn configure_https_discovery(
        mut self,
        configure: impl FnOnce(&mut HttpsServiceLayer<BoxDnsResolver>),
    ) -> Self {
        configure(self.selected_connector_mut().config_mut());
        self
    }

    /// Disable advertised alternatives and response learning for every HTTP version.
    #[must_use]
    pub fn without_alt_svc(self) -> Self {
        self.maybe_with_alt_svc_cache(None)
    }

    generate_set_and_with! {
        /// Share an Alt-Svc cache across HTTP clients; `None` disables Alt-Svc only.
        /// HTTPS-record discovery is configured separately.
        pub fn alt_svc_cache(mut self, cache: Option<AltSvcCache>) -> Self {
            self.service_selector_mut().maybe_set_cache(cache.clone());
            #[cfg(feature = "quic")]
            self.selected_connector_mut().config_mut().maybe_set_cache(cache.clone());
            self.connector.get_mut().get_mut().get_mut().layer_mut().cache = cache;
            self
        }
    }
}

fn finish_without_connection_pool<T, Stage, D, F>(
    builder: EasyHttpConnectorBuilder<T, Stage, D, F>,
) -> ConfiguredConnectionBuilder<T>
where
    T: ConnectorService<ConnectRequest>,
{
    EasyHttpConnectorBuilder {
        dns: (),
        discovery: HttpsDiscovery::default(),
        forward: ProxyMethodNotEnabled::HTTP_FORWARD,
        scope: builder.scope,
        connector: finalize_http_connector(
            builder.connector,
            builder.discovery,
            builder.target_version,
        ),
        stage: Default::default(),
        target_version: builder.target_version,
    }
}

fn finish_with_connection_pool<T, Stage, D, F>(
    builder: EasyHttpConnectorBuilder<T, Stage, D, F>,
    config: HttpPooledConnectorConfig,
) -> ConfiguredConnectionPoolBuilder<T>
where
    T: ConnectorService<ConnectRequest>,
{
    let connector = config.build_connector(builder.connector);
    EasyHttpConnectorBuilder {
        dns: (),
        discovery: HttpsDiscovery::default(),
        forward: ProxyMethodNotEnabled::HTTP_FORWARD,
        scope: builder.scope,
        connector: finalize_http_connector(connector, builder.discovery, builder.target_version),
        stage: Default::default(),
        target_version: builder.target_version,
    }
}

fn finish_with_custom_connection_pool<T, Stage, D, F, P, R>(
    builder: EasyHttpConnectorBuilder<T, Stage, D, F>,
    pool: P,
    req_to_conn_id: R,
    wait_for_pool_timeout: Option<Duration>,
) -> EasyHttpConnectorBuilder<TargetVersionConnector<PooledConnector<T, P, R>>, PoolStage> {
    let connector = PooledConnector::new(builder.connector, pool, req_to_conn_id)
        .maybe_with_wait_for_pool_timeout(wait_for_pool_timeout);
    EasyHttpConnectorBuilder {
        dns: (),
        discovery: HttpsDiscovery::default(),
        forward: ProxyMethodNotEnabled::HTTP_FORWARD,
        scope: builder.scope,
        connector: TargetVersionConnector {
            inner: connector,
            version: builder.target_version,
        },
        stage: Default::default(),
        target_version: builder.target_version,
    }
}

#[cfg(feature = "quic")]
impl<T, Q, Body, D, F, const PROXY: bool>
    EasyHttpConnectorBuilder<
        HttpConnector<super::HttpTransportConnector<T, Q>, Body>,
        HttpStage<PROXY>,
        D,
        F,
    >
{
    /// Wrap the HTTP/3 transport connector [`Self::with_default_http_connector`] built,
    /// as [`Self::map_connector`] wraps the stream transport at an earlier stage.
    pub fn map_http3_connector<Q2>(
        self,
        map: impl FnOnce(Q) -> Q2,
    ) -> EasyHttpConnectorBuilder<
        HttpConnector<super::HttpTransportConnector<T, Q2>, Body>,
        HttpStage<PROXY>,
        D,
        F,
    > {
        self.map_connector(|connector| connector.map_http3_connector(map))
    }
}

impl<T, D, F, const PROXY: bool> EasyHttpConnectorBuilder<T, HttpStage<PROXY>, D, F> {
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
        ProxyRouteFailureCacheConnector<
            ErasedConnector<MaybeForwardedConnection<T::Connection, F::Connection>>,
        >,
        ProxyRouteFailureCacheStage,
        D,
    >
    where
        T: ConnectorService<ConnectRequest>,
        F: ConnectorService<ConnectRequest>,
    {
        let Self {
            connector,
            dns,
            discovery,
            target_version,
            forward,
            ..
        } = self;
        let connector = MaybeForwardedConnector::new(connector, forward);
        EasyHttpConnectorBuilder {
            dns,
            discovery,
            target_version,
            forward: ProxyMethodNotEnabled::HTTP_FORWARD,
            scope: self.scope,
            connector: ProxyRouteFailureCacheConnector::new(erase_connector(connector), cache),
            stage: ProxyRouteFailureCacheStage,
        }
    }

    /// Disable negative caching of temporarily failing proxy routes.
    #[must_use]
    pub fn without_proxy_route_failure_cache(
        self,
    ) -> EasyHttpConnectorBuilder<
        ErasedConnector<MaybeForwardedConnection<T::Connection, F::Connection>>,
        ProxyRouteFailureCacheStage,
        D,
    >
    where
        T: ConnectorService<ConnectRequest>,
        F: ConnectorService<ConnectRequest>,
    {
        let Self {
            connector,
            dns,
            discovery,
            target_version,
            forward,
            ..
        } = self;
        EasyHttpConnectorBuilder {
            connector: erase_connector(MaybeForwardedConnector::new(connector, forward)),
            dns,
            discovery,
            target_version,
            forward: ProxyMethodNotEnabled::HTTP_FORWARD,
            scope: self.scope,
            stage: ProxyRouteFailureCacheStage,
        }
    }
}

impl<T, D, F> EasyHttpConnectorBuilder<T, HttpStage<true>, D, F> {
    /// Finish the default HTTP connector stack without adding a connection pool.
    ///
    /// This still installs HTTP request adaptation and ordered proxy-route
    /// fallback. It also installs the default proxy-route failure cache. The
    /// only omitted component is the pool itself.
    pub fn without_connection_pool(self) -> DefaultConnectionBuilder<T::Connection, F::Connection>
    where
        T: ConnectorService<ConnectRequest>,
        F: ConnectorService<ConnectRequest>,
    {
        finish_without_connection_pool(
            self.with_proxy_route_failure_cache(ProxyRouteFailureCache::default()),
        )
    }

    /// Use the default connection pool for this [`super::EasyHttpWebClient`]
    ///
    /// This will create a [`MultiplexPool`](crate::net::client::pool::MultiplexPool)
    /// using the provided limits and will use
    /// [`super::HttpConnIdentifier`] to group connections on
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
    pub fn with_connection_pool(
        self,
        config: HttpPooledConnectorConfig,
    ) -> DefaultConnectionPoolBuilder<T::Connection, F::Connection>
    where
        T: ConnectorService<ConnectRequest>,
        F: ConnectorService<ConnectRequest>,
    {
        finish_with_connection_pool(
            self.with_proxy_route_failure_cache(ProxyRouteFailureCache::default()),
            config,
        )
    }

    /// Use Rama's default connection pool and default proxy-route failure
    /// cache.
    pub fn with_default_connection_pool(
        self,
    ) -> DefaultConnectionPoolBuilder<T::Connection, F::Connection>
    where
        T: ConnectorService<ConnectRequest>,
        F: ConnectorService<ConnectRequest>,
    {
        self.with_connection_pool(HttpPooledConnectorConfig::default())
    }

    /// Configure this client to use the provided [`Pool`] and [`ReqToConnId`]
    ///
    /// Use `wait_for_pool_timeout` to limit how long we wait for the pool to give us a connection
    ///
    /// Warning: this does not apply a [`RequestVersionAdapter`] layer to make sure that request versions
    /// are adapted when pooled connections are used, which you almost always. This should be manually added
    /// by using [`Self::with_custom_connector`] after configuring this pool and providing a [`RequestVersionAdapter`] there.
    /// Unlike [`Self::with_connection_pool`], this fully generic method also does not install the HTTP
    /// connect-request adapter or proxy-route connector. It installs the default proxy-route failure cache behind
    /// the custom pool. Callers that want route-aware fallback around a custom pool can compose those layers
    /// explicitly around their [`PooledConnector`].
    ///
    /// When the connector supports plaintext HTTP through an HTTP proxy, the
    /// custom [`ReqToConnId`] must keep ordinary forward-proxy connections
    /// separate from CONNECT tunnels to the same proxy. Rama's
    /// [`super::HttpConnIdentifier`] includes this
    /// distinction automatically.
    ///
    /// [`Pool`]: rama_net::client::pool::Pool
    /// [`ReqToConnId`]: rama_net::client::pool::ReqToConnID
    ///
    /// The supplied `ReqToConnID` partitions routes and application protocols.
    /// The pool must also honor connection-owned reuse policies published by
    /// transport connectors. Return a non-reusable `ConnID` to require a fresh
    /// connection that must not return to the pool.
    pub fn with_custom_connection_pool<P, R>(
        self,
        pool: P,
        req_to_conn_id: R,
        wait_for_pool_timeout: Option<Duration>,
    ) -> EasyHttpConnectorBuilder<
        TargetVersionConnector<
            PooledConnector<
                ProxyRouteFailureCacheConnector<
                    ErasedConnector<MaybeForwardedConnection<T::Connection, F::Connection>>,
                >,
                P,
                R,
            >,
        >,
        PoolStage,
    >
    where
        T: ConnectorService<ConnectRequest>,
        F: ConnectorService<ConnectRequest>,
    {
        finish_with_custom_connection_pool(
            self.with_proxy_route_failure_cache(ProxyRouteFailureCache::default()),
            pool,
            req_to_conn_id,
            wait_for_pool_timeout,
        )
    }
}

impl<T, D, F> EasyHttpConnectorBuilder<T, HttpStage<false>, D, F> {
    /// Finish the proxy-free HTTP connector stack without a connection pool.
    ///
    /// No proxy-route failure cache is installed. Call
    /// [`Self::with_proxy_route_failure_cache`] before this method to
    /// explicitly add one for a custom transport.
    pub fn without_connection_pool(
        self,
    ) -> ConfiguredConnectionBuilder<
        ErasedConnector<MaybeForwardedConnection<T::Connection, F::Connection>>,
    >
    where
        T: ConnectorService<ConnectRequest>,
        F: ConnectorService<ConnectRequest>,
    {
        finish_without_connection_pool(self.without_proxy_route_failure_cache())
    }

    /// Use a connection pool of `config` without a proxy-route failure cache.
    pub fn with_connection_pool(
        self,
        config: HttpPooledConnectorConfig,
    ) -> ConfiguredConnectionPoolBuilder<
        ErasedConnector<MaybeForwardedConnection<T::Connection, F::Connection>>,
    >
    where
        T: ConnectorService<ConnectRequest>,
        F: ConnectorService<ConnectRequest>,
    {
        finish_with_connection_pool(self.without_proxy_route_failure_cache(), config)
    }

    /// Use Rama's default connection pool without a
    /// proxy-route failure cache.
    pub fn with_default_connection_pool(
        self,
    ) -> ConfiguredConnectionPoolBuilder<
        ErasedConnector<MaybeForwardedConnection<T::Connection, F::Connection>>,
    >
    where
        T: ConnectorService<ConnectRequest>,
        F: ConnectorService<ConnectRequest>,
    {
        self.with_connection_pool(HttpPooledConnectorConfig::default())
    }

    /// Use a custom connection pool without a proxy-route failure cache.
    ///
    /// The supplied `ReqToConnID` partitions routes and application protocols.
    /// The pool must also honor connection-owned reuse policies published by
    /// transport connectors. Return a non-reusable `ConnID` to require a fresh
    /// connection that must not return to the pool.
    pub fn with_custom_connection_pool<P, R>(
        self,
        pool: P,
        req_to_conn_id: R,
        wait_for_pool_timeout: Option<Duration>,
    ) -> EasyHttpConnectorBuilder<
        TargetVersionConnector<
            PooledConnector<
                ErasedConnector<MaybeForwardedConnection<T::Connection, F::Connection>>,
                P,
                R,
            >,
        >,
        PoolStage,
    >
    where
        T: ConnectorService<ConnectRequest>,
        F: ConnectorService<ConnectRequest>,
    {
        finish_with_custom_connection_pool(
            self.without_proxy_route_failure_cache(),
            pool,
            req_to_conn_id,
            wait_for_pool_timeout,
        )
    }
}

impl<T, D, F> EasyHttpConnectorBuilder<T, ProxyRouteFailureCacheStage, D, F> {
    /// Finish the default HTTP connector stack without a connection pool.
    pub fn without_connection_pool(self) -> ConfiguredConnectionBuilder<T>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_without_connection_pool(self)
    }

    /// Use a connection pool of `config` with the selected failure-cache policy.
    pub fn with_connection_pool(
        self,
        config: HttpPooledConnectorConfig,
    ) -> ConfiguredConnectionPoolBuilder<T>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_with_connection_pool(self, config)
    }

    /// Use Rama's default connection pool with the
    /// selected failure-cache policy.
    pub fn with_default_connection_pool(self) -> ConfiguredConnectionPoolBuilder<T>
    where
        T: ConnectorService<ConnectRequest>,
    {
        finish_with_connection_pool(self, HttpPooledConnectorConfig::default())
    }

    /// Use a custom connection pool with the selected failure-cache policy.
    ///
    /// For a proxy-capable connector, the custom
    /// [`ReqToConnID`](rama_net::client::pool::ReqToConnID) must partition
    /// plaintext HTTP forward-proxy connections from CONNECT tunnels to the
    /// same proxy. [`super::HttpConnIdentifier`] does so by
    /// default.
    ///
    /// The supplied `ReqToConnID` partitions routes and application protocols.
    /// The pool must also honor connection-owned reuse policies published by
    /// transport connectors. Return a non-reusable `ConnID` to require a fresh
    /// connection that must not return to the pool.
    pub fn with_custom_connection_pool<P, R>(
        self,
        pool: P,
        req_to_conn_id: R,
        wait_for_pool_timeout: Option<Duration>,
    ) -> EasyHttpConnectorBuilder<TargetVersionConnector<PooledConnector<T, P, R>>, PoolStage> {
        finish_with_custom_connection_pool(self, pool, req_to_conn_id, wait_for_pool_timeout)
    }
}

impl<T> EasyHttpConnectorBuilder<T, PoolStage> {
    /// Build a client with one owner for HTTP early-data recovery.
    ///
    /// This composes the existing Retry and MapInput services around the client,
    /// above pool selection. Configure HTTP/3 `Config::early_requests` to make
    /// early transport available; ordinary clients remain handshake-first.
    /// That explicit HTTP/3 setting can add an early-data offer to a resumed
    /// ClientHello even for requests that wait. Leave it off for exact TLS
    /// fingerprint emulation; compiled captured profiles disable early data.
    ///
    /// This helper is optional. Custom recovery middleware can wrap
    /// [`Self::build_client`] and use [`rama_net::tls::EarlyDataPermit`],
    /// [`rama_net::tls::ForbidEarlyData`] and the transport facts in
    /// [`rama_http::proto::ext::early_data`] directly, without Retry or RetryBody.
    /// The custom owner must isolate each attempt's extensions, retain its
    /// replayable request, and bound recovery itself.
    ///
    /// `prepare_body` decides which bodies to collect and the collection bounds.
    /// Use [`rama_http::layer::retry::early_data::prepare_bodyless`] to stream
    /// payloads once, or provide a bounded preparation policy for ordinary payload
    /// retries. Only safe, truly empty requests may send early, regardless of that
    /// policy. A 425 with actual original-client early-send evidence, or a
    /// per-request TLS early rejection, receives one confirmed retry. Forwarded
    /// 425 responses pass through. Other results use `application_rule`, with
    /// its normal limits; no additional outer retry loop should own recovery.
    pub fn build_client_with_early_data<Body, ModifiedBody, ConnResponse, IncomingBody, R, P>(
        self,
        application_rule: R,
        prepare_body: P,
    ) -> impl Service<Request<Body>, Output = Response, Error = RetryError>
    where
        Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
        ModifiedBody:
            StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
        T: Service<
                Request<RetryBody>,
                Output = EstablishedClientConnection<ConnResponse, Request<ModifiedBody>>,
                Error: Into<BoxError>,
            >,
        ConnResponse: Service<Request<ModifiedBody>, Output = Response<IncomingBody>, Error = BoxError>
            + ExtensionsRef,
        IncomingBody: Send + Sync + 'static,
        ResponseBody: From<IncomingBody>,
        R: RetryRule<Request<RetryBody>, Response, OpaqueError>,
        P: PrepareBody,
    {
        let client = self.build_client::<RetryBody, ModifiedBody, ConnResponse>();
        let rule = with_recovery(application_rule, |error: &OpaqueError| {
            is_early_data_rejected(error)
        });
        Retry::new(
            ManagedPolicy::new(rule).with_prepare_body(prepare_body),
            MapInput::new(client, permit_attempt),
        )
    }

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

impl<T, S, D, F> EasyHttpConnectorBuilder<T, S, D, F> {
    /// Build a connector from the currently configured setup
    pub fn build_connector(self) -> T {
        self.connector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Body, client::ProxyConnectorBuilder};
    use rama_utils::octets::kib;

    use rama_core::layer::layer_fn;
    #[cfg(feature = "quic")]
    use rama_dns::{
        client::resolver::*,
        wire::{Name, ServiceBinding, Txt},
    };
    #[cfg(all(
        feature = "quic",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
        )
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
            net::{Ipv4Addr, Ipv6Addr, SocketAddr},
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
        },
    };
    #[cfg(feature = "tls")]
    use {
        crate::http::client::HttpConnIdentifier,
        crate::http::{
            HeaderMap, Version,
            conn::{HttpOrigin, SelectedHttpService},
            header::ALT_SVC,
        },
        rama_core::{ServiceInput, service::service_fn},
        rama_net::{
            Protocol,
            address::HostWithPort,
            client::{
                ConnectRequest,
                pool::{ConnID as _, ReqToConnID},
            },
        },
        rama_net::{http::TargetHttpVersion, tls::ApplicationProtocol},
        rama_tls::client::{ServerVerifyMode, TlsPoolId, TlsServerVerify},
        rama_tls::{
            ProtocolVersion,
            client::{NegotiatedTlsParameters, TlsServerAuthentication},
        },
        std::convert::Infallible,
    };

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
            EasyHttpConnectorBuilder::new(WeakScope::detached())
                .with_default_transport_connector()
                .without_dns_connector()
                .without_proxy_support()
        };
        let plain = builder()
            .without_tls_support()
            .with_default_http_connector::<Body>()
            .with_default_connection_pool()
            .build_connector();
        assert_future_budget(&plain, "plain pooled");
        #[cfg(feature = "rustls")]
        {
            let pooled = builder()
                .with_tls_support_using_rustls(TlsClientConfig::new())
                .with_default_http_connector::<Body>()
                .with_default_connection_pool()
                .build_connector();
            assert_future_budget(&pooled, "rustls pooled");
            let unpooled = builder()
                .with_tls_support_using_rustls(TlsClientConfig::new())
                .with_default_http_connector::<Body>()
                .without_connection_pool()
                .build_connector();
            assert_future_budget(&unpooled, "rustls unpooled");
        }
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn custom_http_connector_discovers_h3_without_capability_configuration() {
        let cache = AltSvcCache::default();
        let origin =
            HttpOrigin::new(Protocol::HTTPS, HostWithPort::example_domain_https()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(ALT_SVC, "h3=\":8443\"".parse().unwrap());
        cache.record(&origin, &headers, Duration::ZERO);

        let builder = EasyHttpConnectorBuilder::new(WeakScope::detached())
            .with_custom_tcp_connector(())
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_custom_http_connector(layer_fn(|_| {
                service_fn(|input: ConnectRequest| async move {
                    let version = input
                        .extensions()
                        .get_ref::<TargetHttpVersion>()
                        .map_or(Version::HTTP_2, |version| version.0);
                    let conn = ServiceInput::new(());
                    conn.extensions.insert(TargetHttpVersion(version));
                    conn.extensions
                        .insert(TlsServerAuthentication(Some(input.authority.host.clone())));
                    conn.extensions.insert(NegotiatedTlsParameters {
                        protocol_version: ProtocolVersion::TLSv1_3,
                        application_layer_protocol: Some(if version == Version::HTTP_3 {
                            ApplicationProtocol::HTTP_3
                        } else {
                            ApplicationProtocol::HTTP_2
                        }),
                        peer_certificate_chain: None,
                        server_name: None,
                        resumed: None,
                        algorithms: Default::default(),
                        server_hello: None,
                    });
                    Ok::<_, Infallible>(EstablishedClientConnection { input, conn })
                })
            }))
            .without_connection_pool()
            .with_alt_svc_cache(cache.clone());
        let connector = builder.build_connector();
        for _ in 0..2 {
            let established = connector
                .serve(
                    Request::builder()
                        .uri("https://example.com/")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                established
                    .input
                    .extensions()
                    .contains::<SelectedHttpService>()
            );
            assert_eq!(established.input.version(), Version::HTTP_3);
            assert_eq!(
                established
                    .input
                    .extensions()
                    .get_ref::<SelectedHttpService>()
                    .unwrap()
                    .candidate
                    .target
                    .port,
                8443
            );
        }
    }

    #[tokio::test]
    async fn https_proxy_without_available_tls_support_is_rejected_before_dial() {
        use rama_net::{
            Protocol,
            address::HostWithPort,
            client::{ConnectionErrorDomain, ConnectorService as _, ProxyRoute},
        };
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let dials = Arc::new(AtomicUsize::new(0));
        let transport = service_fn({
            let dials = dials.clone();
            move |_: ConnectRequest| {
                dials.fetch_add(1, Ordering::Relaxed);
                async {
                    Err::<
                        EstablishedClientConnection<
                            ServiceInput<tokio::io::DuplexStream>,
                            ConnectRequest,
                        >,
                        _,
                    >(ConnectionError::local(
                        BoxError::from_static_str("the proxy must not be dialed"),
                        ConnectionErrorKind::Unavailable,
                    ))
                }
            }
        });
        let ProxyConnectorParts { connect, .. } = ProxyConnectorBuilder::new(WeakScope::detached())
            .with_custom_tcp_connector(transport)
            .without_dns_connector()
            .without_tls_support()
            .with_default_http_connector::<Body>()
            .without_connection_pool()
            .with_http_connect()
            .build()
            .into_parts();

        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(ProxyRoute::Proxy(
            "https://proxy.example:8443".parse().unwrap(),
        ));

        let error = connect.connect(input).await.unwrap_err();

        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
        assert_eq!(dials.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn custom_tls_proxy_layer_requires_no_builtin_provider() {
        ProxyConnectorBuilder::new(WeakScope::detached())
            .with_custom_tcp_connector(())
            .without_dns_connector()
            .with_custom_tls_connector(layer_fn(|inner| inner))
            .with_default_http_connector::<Body>();
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn a_refused_http3_alternative_is_served_over_the_stream_and_not_retried() {
        let cache = AltSvcCache::default();
        let origin =
            HttpOrigin::new(Protocol::HTTPS, HostWithPort::example_domain_https()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(ALT_SVC, "h3=\":8443\"".parse().unwrap());
        cache.record(&origin, &headers, Duration::ZERO);

        let attempts = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let connector = EasyHttpConnectorBuilder::new(WeakScope::detached())
            .with_custom_tcp_connector(())
            .without_dns_connector()
            .without_proxy_support()
            .without_tls_support()
            .with_custom_http_connector(layer_fn({
                let attempts = attempts.clone();
                move |_| {
                    let attempts = attempts.clone();
                    service_fn(move |input: ConnectRequest| {
                        let version = input
                            .extensions()
                            .get_ref::<TargetHttpVersion>()
                            .map_or(Version::HTTP_11, |version| version.0);
                        attempts.lock().push(version);
                        async move {
                            if version == Version::HTTP_3 {
                                // What a proxy refusing CONNECT-UDP answers with.
                                return Err(ConnectionError::transport(
                                    BoxError::from_static_str("connect-udp is not available"),
                                    ConnectionErrorKind::Unavailable,
                                ));
                            }
                            let conn = ServiceInput::new(());
                            conn.extensions.insert(TargetHttpVersion(version));
                            Ok(EstablishedClientConnection { input, conn })
                        }
                    })
                }
            }))
            .without_connection_pool()
            .with_alt_svc_cache(cache)
            .build_connector();

        for _ in 0..2 {
            let request = Request::builder()
                .uri("https://example.com/")
                .body(Body::empty())
                .unwrap();
            let established = connector.serve(request).await.unwrap();
            assert_eq!(established.input.version(), Version::HTTP_11);
        }

        let attempts = attempts.lock();
        assert_eq!(
            attempts
                .iter()
                .filter(|version| **version == Version::HTTP_3)
                .count(),
            1,
            "a refused alternative is not tried again: {attempts:?}"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn custom_fixed_policy_pool_respects_explicit_override_identity() {
        let identifier = HttpConnIdentifier::default();
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

    #[cfg(all(
        feature = "quic",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
        )
    ))]
    #[derive(Clone)]
    struct RecordingResolver {
        calls: Arc<AtomicUsize>,
        loopback: bool,
    }

    #[cfg(all(
        feature = "quic",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
        )
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

    #[cfg(all(
        feature = "quic",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
        )
    ))]
    struct RecordingDnsLayer {
        resolver: RecordingResolver,
        applied: Arc<AtomicUsize>,
    }

    #[cfg(all(
        feature = "quic",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
        )
    ))]
    impl<S> Layer<S> for RecordingDnsLayer {
        type Service = DnsConnector<S, RecordingResolver>;

        fn layer(&self, inner: S) -> Self::Service {
            self.applied.fetch_add(1, Ordering::Relaxed);
            DnsConnector::with_resolver(inner, self.resolver.clone())
        }
    }

    #[cfg(all(
        feature = "quic",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
        )
    ))]
    #[tokio::test]
    async fn a_quic_only_client_dials_a_plain_request_over_quic() {
        async fn assert_quic_is_dialed(
            connector: impl Service<Request, Error: Send>,
            dials: &AtomicUsize,
        ) {
            // An address target keeps this test clear of DNS; a QUIC domain needs a resolver.
            let request = Request::builder()
                .uri("https://127.0.0.1:8443/")
                .body(Body::empty())
                .unwrap();
            let Err(_) = connector.serve(request).await else {
                panic!("a client with only a QUIC leg has no origin to reach here")
            };
            assert_eq!(
                dials.load(Ordering::Relaxed),
                1,
                "a request without a version of its own is dialed over the QUIC leg"
            );
        }

        let quic_only = |dials: Arc<AtomicUsize>| {
            let endpoints = service_fn(move |_: ConnectRequest| {
                dials.fetch_add(1, Ordering::Relaxed);
                async {
                    Err::<
                        EstablishedClientConnection<
                            crate::quic::client::ClientEndpoint,
                            ConnectRequest,
                        >,
                        _,
                    >(ConnectionError::local(
                        BoxError::from_static_str("no endpoint in this test"),
                        ConnectionErrorKind::Unavailable,
                    ))
                }
            });
            let builder = EasyHttpConnectorBuilder::new(WeakScope::detached())
                .with_custom_quic_connector(endpoints)
                .without_dns_connector()
                .without_proxy_support();
            #[cfg(feature = "boring")]
            let builder = builder.with_tls_support_using_boringssl(TlsClientConfig::new());
            #[cfg(not(feature = "boring"))]
            let builder = builder.with_tls_support_using_rustls(TlsClientConfig::new());
            builder.with_default_http_connector::<Body>()
        };

        let dials = Arc::new(AtomicUsize::new(0));
        let connector = quic_only(dials.clone())
            .without_connection_pool()
            .build_connector();
        assert_quic_is_dialed(connector, &dials).await;

        // A custom pool serves connect requests of its own, without the request adapters.
        let dials = Arc::new(AtomicUsize::new(0));
        let config = HttpPooledConnectorConfig::default();
        let connector = quic_only(dials.clone())
            .with_custom_connection_pool(
                config.build_pool(),
                HttpConnIdentifier::default(),
                config.wait_for_pool_timeout,
            )
            .build_connector();
        let input = ConnectRequest::new("127.0.0.1:8443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        let Err(_) = connector.serve(input).await else {
            panic!("a client with only a QUIC leg has no origin to reach here")
        };
        assert_eq!(
            dials.load(Ordering::Relaxed),
            1,
            "a client with a custom pool dials over the QUIC leg too"
        );
    }

    #[cfg(all(
        feature = "quic",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
        )
    ))]
    #[tokio::test]
    async fn built_in_quic_uses_the_configured_dns_resolver() {
        let calls = Arc::new(AtomicUsize::new(0));
        let applied = Arc::new(AtomicUsize::new(0));
        let builder = EasyHttpConnectorBuilder::new(WeakScope::detached())
            .with_default_transport_connector()
            .with_dns_connector(RecordingDnsLayer {
                resolver: RecordingResolver {
                    calls: calls.clone(),
                    loopback: false,
                },
                applied: applied.clone(),
            })
            .without_proxy_support();
        #[cfg(feature = "boring")]
        let builder = builder.with_tls_support_using_boringssl(TlsClientConfig::new());
        #[cfg(not(feature = "boring"))]
        let builder = builder.with_tls_support_using_rustls(TlsClientConfig::new());
        let connector = builder
            .with_default_http_connector::<Body>()
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

    #[cfg(all(
        feature = "quic",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
        )
    ))]
    #[tokio::test]
    async fn ipv4_quic_endpoint_skips_ipv6_candidates_without_terminal_failure() {
        let scope = WeakScope::detached();
        let endpoint = Endpoint::bind_client(scope.clone(), SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let blackhole = tokio::net::UdpSocket::bind(SocketAddr::from(SocketAddress::local_ipv4(0)))
            .await
            .unwrap();
        let connector = Http3Connector::builder(scope)
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
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn default_https_discovery_accepts_a_custom_resolver_and_can_be_disabled() {
        #[derive(Clone, Default)]
        struct Resolver(Arc<AtomicUsize>, Arc<AtomicUsize>);
        impl DnsAddressResolver for Resolver {
            type Error = BoxError;
            fn lookup_ipv4(
                &self,
                _: Domain,
            ) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send + '_ {
                self.1.fetch_add(1, Ordering::SeqCst);
                stream::empty()
            }
            fn lookup_ipv6(
                &self,
                _: Domain,
            ) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send + '_ {
                stream::empty()
            }
        }
        impl DnsCnameResolver for Resolver {
            type Error = BoxError;
            fn lookup_cname(
                &self,
                _: Domain,
            ) -> impl Stream<Item = Result<Name, BoxError>> + Send + '_ {
                stream::empty()
            }
        }
        impl DnsTxtResolver for Resolver {
            type Error = BoxError;
            fn lookup_txt(
                &self,
                _: Domain,
            ) -> impl Stream<Item = Result<Txt, BoxError>> + Send + '_ {
                stream::empty()
            }
        }
        impl DnsServiceBindingResolver for Resolver {
            type Error = BoxError;
            fn lookup_svcb(
                &self,
                _: Domain,
            ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_
            {
                stream::empty()
            }
            fn lookup_https(
                &self,
                _: Domain,
            ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_
            {
                self.0.fetch_add(1, Ordering::SeqCst);
                stream::once(async {
                    Ok(ServiceBindingRecord {
                        owner: Name::from_presentation("origin.example").unwrap(),
                        binding: ServiceBinding::parse_rdata(&[0, 1, 0, 0, 1, 0, 3, 2, b'h', b'2'])
                            .unwrap(),
                    })
                })
            }
        }
        impl DnsResolver for Resolver {}
        for (shared, override_https, disabled) in [
            (true, false, false),
            (true, false, true),
            (false, false, false),
            (false, true, false),
        ] {
            let enabled = (shared || override_https) && !disabled;
            let resolver = Resolver::default();
            let selected = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let builder =
                EasyHttpConnectorBuilder::new(WeakScope::detached()).with_custom_tcp_connector(());
            let builder = if shared {
                builder.with_dns_resolver(resolver.clone())
            } else {
                builder.with_dns_address_resolver(resolver.clone())
            };
            let builder = builder
                .without_proxy_support()
                .without_tls_support()
                .with_custom_http_connector(layer_fn({
                    let selected = selected.clone();
                    move |_inner| {
                        let selected = selected.clone();
                        service_fn(move |input: ConnectRequest| {
                            if input
                                .extensions()
                                .get_ref::<SelectedHttpService>()
                                .is_some_and(|service| {
                                    service.candidate.source
                                        == rama_http::conn::HttpServiceSource::Https
                                })
                            {
                                selected.store(true, Ordering::SeqCst);
                            }
                            async {
                                Err::<
                                    EstablishedClientConnection<ServiceInput<()>, ConnectRequest>,
                                    _,
                                >(ConnectionError::local(
                                    BoxError::from_static_str("test stopped before transport"),
                                    ConnectionErrorKind::Unavailable,
                                ))
                            }
                        })
                    }
                }))
                .without_connection_pool();
            let builder = if override_https {
                builder.with_https_resolver(resolver.clone())
            } else {
                builder
            };
            let builder = if disabled {
                builder.without_https_discovery()
            } else {
                builder
            };
            let error = builder
                .build_connector()
                .serve(
                    Request::builder()
                        .uri("https://origin.example/")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap_err();
            assert!(!error.to_string().is_empty());
            assert_eq!(resolver.0.load(Ordering::SeqCst), usize::from(enabled));
            assert_eq!(selected.load(Ordering::SeqCst), enabled);
            // This connector stops before transport: discovery must not start A/AAAA.
            assert_eq!(resolver.1.load(Ordering::SeqCst), 0);
        }
    }

    #[cfg(all(feature = "boring", feature = "quic"))]
    #[tokio::test]
    async fn every_combination_of_legs_builds_a_connector() {
        let scope = WeakScope::detached();
        let tls = || TlsClientConfig::default_http();

        drop(
            EasyHttpConnectorBuilder::new(scope.clone())
                .with_default_transport_connector()
                .with_default_dns_connector()
                .without_proxy_support()
                .with_tls_support_using_boringssl(tls())
                .with_default_http_connector::<Body>()
                .with_default_connection_pool()
                .build_connector(),
        );

        drop(
            EasyHttpConnectorBuilder::new(scope.clone())
                .with_default_tcp_connector()
                .with_default_dns_connector()
                .without_proxy_support()
                .with_tls_support_using_boringssl(tls())
                .with_default_http_connector::<Body>()
                .with_default_connection_pool()
                .build_connector(),
        );

        drop(
            EasyHttpConnectorBuilder::new(scope.clone())
                .with_default_transport_connector()
                .with_default_dns_connector()
                .with_proxy_support(ProxyConnector::default_with_scope::<Body>(scope.clone()))
                .with_tls_support_using_boringssl(tls())
                .with_default_http_connector::<Body>()
                .with_default_connection_pool()
                .build_connector(),
        );

        drop(
            EasyHttpConnectorBuilder::new(scope.clone())
                .with_default_tcp_connector()
                .with_custom_quic_connector(SharedQuicEndpoint::managed(scope.clone()))
                .with_default_dns_connector()
                .without_proxy_support()
                .with_tls_support_using_boringssl(tls())
                .with_default_http_connector::<Body>()
                .without_connection_pool()
                .build_connector(),
        );

        drop(
            EasyHttpConnectorBuilder::new(scope.clone())
                .with_custom_tcp_connector(TcpConnector::new())
                .with_default_quic_connector()
                .with_default_dns_connector()
                .without_proxy_support()
                .with_tls_support_using_boringssl(tls())
                .with_default_http_connector::<Body>()
                .without_connection_pool()
                .build_connector(),
        );

        drop(
            EasyHttpConnectorBuilder::new(scope.clone())
                .with_default_quic_connector()
                .with_default_dns_connector()
                .without_proxy_support()
                .with_tls_support_using_boringssl(tls())
                .with_default_http_connector::<Body>()
                .with_default_connection_pool()
                .build_connector(),
        );

        drop(
            EasyHttpConnectorBuilder::new(scope)
                .with_default_transport_connector()
                .without_dns_connector()
                .without_proxy_support()
                .without_tls_support()
                .with_default_http_connector::<Body>()
                .without_connection_pool()
                .build_connector(),
        );
    }
}
