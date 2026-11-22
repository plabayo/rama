use super::{ProxyConnector, ProxyMethodNotEnabled};
use crate::{
    Layer,
    dns::client::{
        DnsConnector, DnsConnectorLayer, GlobalDnsResolver, resolver::DnsAddressResolver,
    },
    extensions::{ExtensionsTransfer, SharedExtensionsTransfer},
    graceful::WeakScope,
    http::{
        Body as ResponseBody, HeaderValue,
        client::{
            HttpConnector, HttpPooledConnector, HttpPooledConnectorConfig,
            builder::{AltSvcConnectionLayer, DnsStage, HttpsDiscovery, TlsStage, TransportStage},
            proxy::{HttpForwardProxyConnector, layer::HttpConnectProxyConnector},
        },
        header::IntoHeaderName,
        layer::{
            alt_svc::{AltSvc, AltSvcBody, AltSvcCache},
            http_service::HttpServiceConnector,
            map_response_body::MapResponseBody,
        },
        proxy::ProxyRequestBody,
    },
    net::{
        client::{
            ConnectRequest, ConnectorService, MapEstablishedConnection, PlaintextProxyOnly,
            PlaintextProxyOnlyLayer, ProxyDialer,
        },
        stream::DefaultExtensionsTransfer,
    },
    tcp::client::service::TcpConnector,
};
use rama_utils::macros::generate_set_and_with;
use std::marker::PhantomData;

#[cfg(feature = "quic")]
use crate::{
    dns::client::resolver::{BoxDnsResolver, DnsResolver},
    http::layer::https_service::{HttpsService, HttpsServiceLayer},
};

#[cfg(feature = "socks5")]
use crate::proxy::socks5::{Socks5ConnectProxyConnector, Socks5ConnectProxyConnectorLayer};

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_tls::client::TlsClientConfig;

#[cfg(feature = "boring")]
use crate::tls::boring::client as boring_client;
#[cfg(feature = "rustls")]
use crate::tls::rustls::client as rustls_client;

#[cfg(all(
    feature = "masque",
    feature = "quic",
    any(feature = "boring", feature = "rustls")
))]
use crate::http::client::masque_quic_transport;
#[cfg(all(feature = "quic", any(feature = "boring", feature = "rustls")))]
use crate::{
    http::client::builder::{NoTcpConnector, QuicLeg, quic_tls_provider_or_unavailable},
    quic::{
        TransportConfig,
        client::{ClientEndpoint, SharedQuicEndpoint},
    },
};

#[cfg(all(feature = "quic", any(feature = "boring", feature = "rustls")))]
use {
    crate::{
        Service,
        http::client::{
            Http3Connector, Http3Transport, HttpTransportConnector, default_http3_builder,
        },
        net::client::{ConnectionError, EstablishedClientConnection},
        quic::tls::QuicClientConfigProvider,
    },
    std::sync::Arc,
};

#[cfg(all(feature = "masque", feature = "quic"))]
use crate::{
    net::client::{MaybeProxiedConnector, ProxiedRoute},
    proxy::masque::connect_udp::HttpConnectUdpProxyConnector,
    udp::proxy::UdpConnector,
};

/// Builds the connections towards proxies of a client, which are client connections of
/// their own and share nothing with the connections to origins.
///
/// Its stages are those of [`EasyHttpConnectorBuilder`] up to the HTTP connections, which
/// is all a proxy needs: a proxy is never reached through another proxy. The proxy methods
/// spoken on those connections follow, see [`ProxyMethodBuilder`].
///
/// [`EasyHttpConnectorBuilder`]: super::super::EasyHttpConnectorBuilder
#[derive(Debug)]
pub struct ProxyConnectorBuilder<T = (), C = (), S = (), D = ()> {
    stream: T,
    http: C,
    stage: S,
    dns: D,
    scope: WeakScope,
}

/// The stage of a [`ProxyConnectorBuilder`] which speaks HTTP to a proxy, in the body
/// type `B` its connections send.
#[derive(Debug)]
pub struct ProxyHttpStage<B = ResponseBody> {
    discovery: HttpsDiscovery,
    _phantom: PhantomData<fn() -> B>,
}

impl<B> ProxyHttpStage<B> {
    const fn new(discovery: HttpsDiscovery) -> Self {
        Self {
            discovery,
            _phantom: PhantomData,
        }
    }
}

impl ProxyConnectorBuilder {
    /// Create a new [`ProxyConnectorBuilder`] whose connections and tunnels run in
    /// `scope`; see [`ProxyConnector::builder`].
    #[must_use]
    pub fn new(scope: impl Into<WeakScope>) -> Self {
        Self {
            stream: (),
            http: (),
            stage: (),
            dns: (),
            scope: scope.into(),
        }
    }
}

impl<T, S, D> ProxyConnectorBuilder<T, (), S, D> {
    /// Map the connector towards proxies built so far, keeping the stage.
    ///
    /// After the TLS stage this is how every connection to a proxy is secured, also one
    /// whose address does not ask for TLS: `.map_connector(|tls| tls.into_secure())`.
    pub fn map_connector<T2>(
        self,
        map_fn: impl FnOnce(T) -> T2,
    ) -> ProxyConnectorBuilder<T2, (), S, D> {
        ProxyConnectorBuilder {
            stream: map_fn(self.stream),
            http: (),
            stage: self.stage,
            dns: self.dns,
            scope: self.scope,
        }
    }
}

impl<T, C, S, D> ProxyConnectorBuilder<T, C, S, D> {
    fn into_stage<C2, S2>(
        self,
        stage: S2,
        http: impl FnOnce(C) -> C2,
    ) -> ProxyConnectorBuilder<T, C2, S2, D> {
        ProxyConnectorBuilder {
            stream: self.stream,
            http: http(self.http),
            stage,
            dns: self.dns,
            scope: self.scope,
        }
    }
}

impl<D> ProxyConnectorBuilder<(), (), (), D> {
    /// Dial proxies over TCP, and over QUIC for an `h3://` proxy where this build has a
    /// QUIC TLS backend.
    #[cfg(all(feature = "quic", any(feature = "boring", feature = "rustls")))]
    #[must_use]
    pub fn with_default_transport_connector(
        self,
    ) -> ProxyConnectorBuilder<TcpConnector, (), TransportStage<QuicLeg<SharedQuicEndpoint>>, D>
    {
        let quic = QuicLeg::new(SharedQuicEndpoint::managed(self.scope.clone()));
        self.with_transport(TcpConnector::new(), quic)
    }

    /// Dial proxies over TCP.
    #[cfg(not(all(feature = "quic", any(feature = "boring", feature = "rustls"))))]
    #[must_use]
    pub fn with_default_transport_connector(
        self,
    ) -> ProxyConnectorBuilder<TcpConnector, (), TransportStage, D> {
        self.with_default_tcp_connector()
    }

    /// Dial proxies over QUIC only, which makes every proxy but an `h3://` one unreachable.
    #[cfg(all(feature = "quic", any(feature = "boring", feature = "rustls")))]
    #[must_use]
    pub fn with_default_quic_connector(
        self,
    ) -> ProxyConnectorBuilder<NoTcpConnector, (), TransportStage<QuicLeg<SharedQuicEndpoint>>, D>
    {
        let quic = QuicLeg::new(SharedQuicEndpoint::managed(self.scope.clone()));
        self.with_transport(NoTcpConnector, quic)
    }

    /// Dial proxies over TCP only, which makes an `h3://` proxy unreachable.
    #[must_use]
    pub fn with_default_tcp_connector(
        self,
    ) -> ProxyConnectorBuilder<TcpConnector, (), TransportStage, D> {
        self.with_transport(TcpConnector::new(), ())
    }

    /// Dial proxies over `connector` only: this first call is the only transport leg, so
    /// no `h3://` proxy is reachable unless a QUIC leg is added with
    /// [`ProxyConnectorBuilder::with_custom_quic_connector`].
    pub fn with_custom_tcp_connector<T>(
        self,
        connector: T,
    ) -> ProxyConnectorBuilder<T, (), TransportStage, D> {
        self.with_transport(connector, ())
    }

    /// Dial proxies over the QUIC endpoints `endpoints` hands out only: this first call is
    /// the only transport leg, which makes every proxy but an `h3://` one unreachable
    /// unless a TCP leg is added with
    /// [`ProxyConnectorBuilder::with_custom_tcp_connector`].
    #[cfg(all(feature = "quic", any(feature = "boring", feature = "rustls")))]
    pub fn with_custom_quic_connector<E>(
        self,
        endpoints: E,
    ) -> ProxyConnectorBuilder<NoTcpConnector, (), TransportStage<QuicLeg<E>>, D>
    where
        E: ConnectorService<ConnectRequest, Connection = ClientEndpoint>,
    {
        self.with_transport(NoTcpConnector, QuicLeg::new(endpoints))
    }

    fn with_transport<T, Q>(
        self,
        connector: T,
        quic: Q,
    ) -> ProxyConnectorBuilder<T, (), TransportStage<Q>, D> {
        ProxyConnectorBuilder {
            stream: connector,
            http: (),
            stage: TransportStage { quic },
            dns: self.dns,
            scope: self.scope,
        }
    }
}

#[cfg(all(feature = "quic", any(feature = "boring", feature = "rustls")))]
impl<T, E, D> ProxyConnectorBuilder<T, (), TransportStage<QuicLeg<E>>, D> {
    /// Configure the QUIC transport of the connections to `h3://` proxies, replacing the
    /// default one, which leaves a MASQUE proxy room for tunneled QUIC packets.
    #[must_use]
    pub fn with_quic_transport_config(mut self, transport: TransportConfig) -> Self {
        self.stage.quic.transport = Some(transport);
        self
    }
}

#[cfg(all(feature = "quic", any(feature = "boring", feature = "rustls")))]
impl<T, Q, D> ProxyConnectorBuilder<T, (), TransportStage<Q>, D> {
    /// Reach an `h3://` proxy over the QUIC endpoints `endpoints` hands out, instead of the
    /// built-in ones or none: on a builder which already has a transport this swaps the
    /// QUIC leg and keeps the TCP leg.
    pub fn with_custom_quic_connector<E>(
        self,
        endpoints: E,
    ) -> ProxyConnectorBuilder<T, (), TransportStage<QuicLeg<E>>, D>
    where
        E: ConnectorService<ConnectRequest, Connection = ClientEndpoint>,
    {
        ProxyConnectorBuilder {
            stream: self.stream,
            http: (),
            stage: TransportStage {
                quic: QuicLeg::new(endpoints),
            },
            dns: self.dns,
            scope: self.scope,
        }
    }

    /// Reach an `h3://` proxy over the built-in QUIC endpoints, keeping the TCP leg chosen
    /// before, such as a custom one.
    #[must_use]
    pub fn with_default_quic_connector(
        self,
    ) -> ProxyConnectorBuilder<T, (), TransportStage<QuicLeg<SharedQuicEndpoint>>, D> {
        let endpoints = SharedQuicEndpoint::managed(self.scope.clone());
        self.with_custom_quic_connector(endpoints)
    }
}

impl<T, Q, D> ProxyConnectorBuilder<T, (), TransportStage<Q>, D> {
    /// Dial proxies over `connector` instead of the TCP leg chosen before, keeping the
    /// QUIC leg: `with_default_transport_connector().with_custom_tcp_connector(c)` dials
    /// every proxy over `c` and keeps rama's default QUIC endpoints for an `h3://` one.
    pub fn with_custom_tcp_connector<T2>(
        self,
        connector: T2,
    ) -> ProxyConnectorBuilder<T2, (), TransportStage<Q>, D> {
        ProxyConnectorBuilder {
            stream: connector,
            http: (),
            stage: self.stage,
            dns: self.dns,
            scope: self.scope,
        }
    }

    /// Resolve the addresses of proxies with the default resolver.
    pub fn with_default_dns_connector(
        self,
    ) -> ProxyConnectorBuilder<DnsConnector<T>, (), DnsStage<Q>, DnsConnectorLayer> {
        self.with_dns_address_resolver(GlobalDnsResolver::new())
    }

    /// Resolve the addresses of proxies with `resolver`, on both legs.
    pub fn with_dns_address_resolver<R: DnsAddressResolver + Clone>(
        self,
        resolver: R,
    ) -> ProxyConnectorBuilder<DnsConnector<T, R>, (), DnsStage<Q>, DnsConnectorLayer<R>> {
        let layer = DnsConnectorLayer::with_resolver(resolver);
        ProxyConnectorBuilder {
            stream: layer.layer(self.stream),
            http: (),
            stage: DnsStage {
                quic: self.stage.quic,
            },
            dns: layer,
            scope: self.scope,
        }
    }

    /// Leave resolving the addresses of proxies to the transport connectors.
    pub fn without_dns_connector(self) -> ProxyConnectorBuilder<T, (), DnsStage<Q>, ()> {
        ProxyConnectorBuilder {
            stream: self.stream,
            http: (),
            stage: DnsStage {
                quic: self.stage.quic,
            },
            dns: (),
            scope: self.scope,
        }
    }
}

impl<T, Q, D> ProxyConnectorBuilder<T, (), DnsStage<Q>, D> {
    #[cfg(feature = "boring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
    /// Secure the connection to a proxy whose address asks for TLS, using boringssl.
    ///
    /// `config` secures both legs, but its ALPN only applies to TCP: the QUIC leg always
    /// offers `h3`.
    pub fn with_tls_support_using_boringssl(
        self,
        config: TlsClientConfig,
    ) -> ProxyConnectorBuilder<
        boring_client::TlsConnector<T>,
        (),
        TlsStage<false, TlsClientConfig, Q>,
        D,
    > {
        ProxyConnectorBuilder {
            stream: boring_client::TlsConnector::auto(self.stream).with_base_config(config.clone()),
            http: (),
            stage: TlsStage::using_boring(config, self.stage.quic),
            dns: self.dns,
            scope: self.scope,
        }
    }

    #[cfg(feature = "rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
    /// Secure the connection to a proxy whose address asks for TLS, using rustls.
    ///
    /// `config` secures both legs, but its ALPN only applies to TCP: the QUIC leg always
    /// offers `h3`.
    pub fn with_tls_support_using_rustls(
        self,
        config: TlsClientConfig,
    ) -> ProxyConnectorBuilder<
        rustls_client::TlsConnector<T>,
        (),
        TlsStage<false, TlsClientConfig, Q>,
        D,
    > {
        ProxyConnectorBuilder {
            stream: rustls_client::TlsConnector::auto(self.stream).with_base_config(config.clone()),
            http: (),
            stage: TlsStage::using_rustls(config, self.stage.quic),
            dns: self.dns,
            scope: self.scope,
        }
    }

    /// Secure the connection to a proxy with the given TLS connector; the QUIC leg gets no
    /// TLS from it, so no `h3://` proxy is reachable.
    ///
    /// It must attach `rama_tls::client::NegotiatedTlsParameters` to the connections it
    /// secures: rama uses this as positive proof that TLS was negotiated, and sends nothing
    /// to an `https://` proxy without it.
    pub fn with_custom_tls_connector<L: Layer<T>>(
        self,
        connector_layer: L,
    ) -> ProxyConnectorBuilder<L::Service, (), TlsStage<false, (), Q>, D> {
        ProxyConnectorBuilder {
            stream: connector_layer.into_layer(self.stream),
            http: (),
            stage: TlsStage::without_tls(self.stage.quic),
            dns: self.dns,
            scope: self.scope,
        }
    }

    core::cfg_select! {
        feature = "boring" => {
            /// Secure the connection to a proxy whose address asks for TLS, with the TLS
            /// implementation this build of rama prefers.
            pub fn with_default_tls_support(
                self,
                config: TlsClientConfig,
            ) -> ProxyConnectorBuilder<
                boring_client::TlsConnector<T>,
                (),
                TlsStage<false, TlsClientConfig, Q>,
                D,
            > {
                self.with_tls_support_using_boringssl(config)
            }
        }
        feature = "rustls" => {
            /// Secure the connection to a proxy whose address asks for TLS, with the TLS
            /// implementation this build of rama prefers.
            pub fn with_default_tls_support(
                self,
                config: TlsClientConfig,
            ) -> ProxyConnectorBuilder<
                rustls_client::TlsConnector<T>,
                (),
                TlsStage<false, TlsClientConfig, Q>,
                D,
            > {
                self.with_tls_support_using_rustls(config)
            }
        }
        _ => {}
    }

    /// Reach proxies in plaintext only: an `https://` or `h3://` proxy is refused before
    /// it is dialed.
    pub fn without_tls_support(
        self,
    ) -> ProxyConnectorBuilder<PlaintextProxyOnly<T>, (), TlsStage<false, (), Q>, D> {
        ProxyConnectorBuilder {
            stream: PlaintextProxyOnlyLayer::new().into_layer(self.stream),
            http: (),
            stage: TlsStage::without_tls(self.stage.quic),
            dns: self.dns,
            scope: self.scope,
        }
    }
}

impl<T: Clone, Tls, Q, D> ProxyConnectorBuilder<T, (), TlsStage<false, Tls, Q>, D> {
    fn http_connector<B>(
        self,
    ) -> ProxyConnectorBuilder<T, HttpConnector<T, ProxyRequestBody<B>>, ProxyHttpStage<B>, D> {
        let stream = self.stream.clone();
        let scope = self.scope.clone();
        self.into_stage(ProxyHttpStage::new(HttpsDiscovery::disabled()), move |()| {
            HttpConnector::new(stream, scope)
        })
    }

    /// Speak HTTP to a proxy over a connector of your own, built on the connections dialed
    /// so far, instead of the one [`Self::with_default_http_connector`] builds; the QUIC leg
    /// is left out.
    ///
    /// `B` is the body type sent to a proxy, which is the one the client serves origins with.
    /// Its connections report the HTTP version they speak in a `TargetHttpVersion`, as
    /// `HttpConnector` does: a proxy address that names a version is checked against it.
    pub fn with_custom_http_connector<B, L: Layer<T>>(
        self,
        connector_layer: L,
    ) -> ProxyConnectorBuilder<T, L::Service, ProxyHttpStage<B>, D> {
        let stream = self.stream.clone();
        self.into_stage(ProxyHttpStage::new(HttpsDiscovery::disabled()), move |()| {
            connector_layer.into_layer(stream)
        })
    }
}

impl<T: Clone, Q, D> ProxyConnectorBuilder<T, (), TlsStage<false, (), Q>, D> {
    /// Speak HTTP to a proxy over the TCP leg, in the version its [`ProxyAddress`] asks for.
    /// Without TLS there is no HTTP/3 proxy: that runs over QUIC, which is always secure.
    ///
    /// `B` is the body type sent to a proxy, which is the one the client serves origins with.
    ///
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn with_default_http_connector<B>(
        self,
    ) -> ProxyConnectorBuilder<T, HttpConnector<T, ProxyRequestBody<B>>, ProxyHttpStage<B>, D> {
        self.http_connector()
    }
}

#[cfg(any(feature = "boring", feature = "rustls"))]
impl<T: Clone, D> ProxyConnectorBuilder<T, (), TlsStage<false, TlsClientConfig, ()>, D> {
    /// Speak HTTP to a proxy over the TCP leg, in the version its [`ProxyAddress`] asks for;
    /// there is no QUIC leg for an `h3://` proxy.
    ///
    /// `B` is the body type sent to a proxy, which is the one the client serves origins with.
    ///
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn with_default_http_connector<B>(
        self,
    ) -> ProxyConnectorBuilder<T, HttpConnector<T, ProxyRequestBody<B>>, ProxyHttpStage<B>, D> {
        self.http_connector()
    }
}

#[cfg(all(feature = "quic", any(feature = "boring", feature = "rustls")))]
#[cfg_attr(docsrs, doc(cfg(feature = "quic")))]
impl<T: Clone, D, E> ProxyConnectorBuilder<T, (), TlsStage<false, TlsClientConfig, QuicLeg<E>>, D> {
    /// Build the QUIC TLS configurations through `provider` instead of the backend the
    /// TLS stage selected, so the QUIC leg can use another backend than the TCP leg.
    #[must_use]
    pub fn with_quic_tls_provider(mut self, provider: Arc<dyn QuicClientConfigProvider>) -> Self {
        self.stage.quic_tls = Some(provider);
        self
    }

    /// Speak HTTP to a proxy in the version its [`ProxyAddress`] asks for: over the TCP leg,
    /// or over the QUIC leg for an `h3://` proxy, on the TLS of the stage before this one
    /// and the same DNS policy for both.
    ///
    /// `B` is the body type sent to a proxy, which is the one the client serves origins with.
    ///
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn with_default_http_connector<B>(
        self,
    ) -> ProxyConnectorBuilder<
        T,
        HttpConnector<HttpTransportConnector<T, D::Service>, ProxyRequestBody<B>>,
        ProxyHttpStage<B>,
        D,
    >
    where
        E: ConnectorService<ConnectRequest, Connection = ClientEndpoint> + Clone,
        D: Layer<Http3Connector<E>>,
        D::Service: Service<
                ConnectRequest,
                Output = EstablishedClientConnection<Http3Transport, ConnectRequest>,
                Error = ConnectionError,
            > + Send
            + Sync
            + 'static,
    {
        // A MASQUE proxy carries tunneled QUIC packets on its own HTTP/3 connection, which
        // needs room for them.
        #[cfg(feature = "masque")]
        let transport = Some(
            self.stage
                .quic
                .transport
                .clone()
                .unwrap_or_else(masque_quic_transport),
        );
        #[cfg(not(feature = "masque"))]
        let transport = self.stage.quic.transport.clone();
        let provider = quic_tls_provider_or_unavailable(self.stage.quic_tls.clone());
        #[expect(
            clippy::expect_used,
            reason = "the built-in HTTP/3 configuration is always valid"
        )]
        let quic = default_http3_builder(self.scope.clone(), self.stage.tls.clone(), provider)
            .with_endpoints(self.stage.quic.endpoints.clone())
            .maybe_with_transport(transport)
            .build_lazy()
            .expect("built-in HTTP/3 configuration");
        let quic = self.dns.layer(quic);
        let discovery = HttpsDiscovery::default().with_tls(&self.stage.tls, false);
        let stream = self.stream.clone();
        let scope = self.scope.clone();
        self.into_stage(ProxyHttpStage::new(discovery), move |()| {
            HttpConnector::new(stream, scope).with_http3_connector(quic)
        })
    }
}

impl<T, C, B, D> ProxyConnectorBuilder<T, C, ProxyHttpStage<B>, D>
where
    C: ConnectorService<ConnectRequest>,
{
    /// Pool the HTTP connections to a proxy with rama's defaults, so the tunnels and
    /// forwarded requests through one proxy share its HTTP/2 and HTTP/3 connections.
    ///
    /// Outside the pool sit HTTPS-record discovery and Alt-Svc, as on an origin, so an
    /// `https://` proxy without a version is reached over HTTP/3 when it advertises it.
    pub fn with_default_connection_pool(
        self,
    ) -> ProxyMethodBuilder<T, ProxyServiceConnector<HttpPooledConnector<C>>, B> {
        self.with_connection_pool(HttpPooledConnectorConfig::default())
    }

    /// [`Self::with_default_connection_pool`], with the given pool configuration.
    pub fn with_connection_pool(
        self,
        config: HttpPooledConnectorConfig,
    ) -> ProxyMethodBuilder<T, ProxyServiceConnector<HttpPooledConnector<C>>, B> {
        let http = config.build_connector(self.http);
        let http = proxy_service_connector(http, self.stage.discovery);
        ProxyMethodBuilder::new(self.stream, http, self.scope)
    }

    /// Give every tunnel and forwarded request a connection to the proxy of its own, with
    /// the discovery and Alt-Svc of [`Self::with_default_connection_pool`].
    pub fn without_connection_pool(self) -> ProxyMethodBuilder<T, ProxyServiceConnector<C>, B> {
        let http = proxy_service_connector(self.http, self.stage.discovery);
        ProxyMethodBuilder::new(self.stream, http, self.scope)
    }
}

#[cfg(feature = "quic")]
type ProxyServiceSelector<C> = HttpsService<HttpServiceConnector<C>, BoxDnsResolver>;
#[cfg(not(feature = "quic"))]
type ProxyServiceSelector<C> = HttpServiceConnector<C>;

/// The HTTP connector towards proxies the pool stage of a [`ProxyConnectorBuilder`] builds:
/// `C` with HTTPS-record discovery and Alt-Svc around it.
pub type ProxyServiceConnector<C> =
    MapEstablishedConnection<ProxyServiceSelector<C>, ProxyAltSvcConnectionLayer>;

fn proxy_service_connector<C>(connector: C, discovery: HttpsDiscovery) -> ProxyServiceConnector<C> {
    let cache = AltSvcCache::default();
    let connector = HttpServiceConnector::new(connector).with_cache(cache.clone());
    #[cfg(feature = "quic")]
    let connector = discovery.layer.with_cache(cache.clone()).layer(connector);
    #[cfg(not(feature = "quic"))]
    let _ = discovery;
    MapEstablishedConnection::new(
        connector,
        ProxyAltSvcConnectionLayer {
            alt_svc: AltSvcConnectionLayer { cache: Some(cache) },
        },
    )
}

/// [`AltSvcConnectionLayer`] for a connection to a proxy, whose responses the proxy
/// methods read as plain [`ResponseBody`]s.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct ProxyAltSvcConnectionLayer {
    alt_svc: AltSvcConnectionLayer,
}

impl<S> Layer<S> for ProxyAltSvcConnectionLayer {
    type Service = MapResponseBody<AltSvc<S>, fn(AltSvcBody<ResponseBody>) -> ResponseBody>;

    fn layer(&self, inner: S) -> Self::Service {
        MapResponseBody::into_boxed_streaming_body(self.alt_svc.layer(inner))
    }
}

/// The proxy methods of a [`ProxyConnector`], over the connections towards proxies an
/// [`ProxyConnectorBuilder`] built: `T` dials a stream to a proxy, `C` speaks HTTP to
/// one in the body type `B`.
///
/// A method which is not enabled refuses the routes asking for it.
#[derive(Debug)]
pub struct ProxyMethodBuilder<
    T,
    C,
    B = ResponseBody,
    Socks = ProxyMethodNotEnabled<T>,
    Connect = ProxyMethodNotEnabled<C>,
    ConnectUdp = ProxyConnectUdpNotEnabled<C, B>,
    Forward = ProxyMethodNotEnabled<C>,
> {
    stream: T,
    http: C,
    scope: WeakScope,
    socks: Socks,
    connect: Connect,
    connect_udp: ConnectUdp,
    forward: Forward,
    extensions_transfer: SharedExtensionsTransfer,
    _phantom: PhantomData<fn() -> B>,
}

impl<T, C, B> ProxyMethodBuilder<T, ProxyServiceConnector<C>, B> {
    fn service_selector_mut(&mut self) -> &mut HttpServiceConnector<C> {
        let connector = self.http.get_mut();
        #[cfg(feature = "quic")]
        let connector = connector.get_mut();
        connector
    }

    /// Configure HTTP service selection towards proxies, including attempt timeouts and
    /// budgets.
    #[must_use]
    pub fn configure_http_service(
        mut self,
        configure: impl FnOnce(&mut HttpServiceConnector<C>),
    ) -> Self {
        configure(self.service_selector_mut());
        self
    }

    #[cfg(feature = "quic")]
    /// Disable HTTPS discovery of proxies while retaining independently configured Alt-Svc.
    #[must_use]
    pub fn without_https_discovery(mut self) -> Self {
        self.http.get_mut().config_mut().set_enabled(false);
        self
    }

    #[cfg(feature = "quic")]
    /// Enable HTTPS discovery of proxies with this resolver for HTTPS and A/AAAA records.
    #[must_use]
    pub fn with_https_resolver<R: DnsResolver>(mut self, resolver: R) -> Self {
        let config = self.http.get_mut().config_mut();
        *config = config
            .clone()
            .with_resolver(BoxDnsResolver::new(resolver))
            .with_enabled(true);
        self
    }

    #[cfg(feature = "quic")]
    /// Configure the HTTPS discovery layer towards proxies.
    #[must_use]
    pub fn configure_https_discovery(
        mut self,
        configure: impl FnOnce(&mut HttpsServiceLayer<BoxDnsResolver>),
    ) -> Self {
        configure(self.http.get_mut().config_mut());
        self
    }

    /// Disable advertised alternatives and response learning towards proxies.
    #[must_use]
    pub fn without_alt_svc(self) -> Self {
        self.maybe_with_alt_svc_cache(None)
    }

    generate_set_and_with! {
        /// The Alt-Svc cache of the connections towards proxies; `None` disables Alt-Svc
        /// only. HTTPS-record discovery is configured separately.
        pub fn alt_svc_cache(mut self, cache: Option<AltSvcCache>) -> Self {
            self.service_selector_mut().maybe_set_cache(cache.clone());
            #[cfg(feature = "quic")]
            self.http.get_mut().config_mut().maybe_set_cache(cache.clone());
            self.http.layer_mut().alt_svc.cache = cache;
            self
        }
    }
}

impl<T, C, B> ProxyMethodBuilder<T, C, B> {
    fn new(stream: T, http: C, scope: WeakScope) -> Self {
        Self {
            connect_udp: connect_udp_not_enabled(&scope),
            stream,
            http,
            scope,
            socks: ProxyMethodNotEnabled::SOCKS5,
            connect: ProxyMethodNotEnabled::HTTP_CONNECT,
            forward: ProxyMethodNotEnabled::HTTP_FORWARD,
            extensions_transfer: DefaultExtensionsTransfer::new().into_shared(),
            _phantom: PhantomData,
        }
    }

    generate_set_and_with! {
        /// Set what a tunnel opened by any of the methods added next keeps from the proxy
        /// connection it is nested on.
        ///
        /// Defaults to [`DefaultExtensionsTransfer`]. Chain transfers with
        /// [`ExtensionsTransfer::and`] to also carry your own connection-scoped
        /// extension types across every tunnel.
        pub fn extensions_transfer(mut self, transfer: impl ExtensionsTransfer) -> Self {
            self.extensions_transfer = transfer.into_shared();
            self
        }
    }

    /// Support every proxy protocol this build of rama has, with its defaults: SOCKS5
    /// (`socks5` feature), HTTP CONNECT and forwarding, and CONNECT-UDP (`masque` and
    /// `quic` features). Pick a subset with `with_socks5`, `with_http_connect`,
    /// `with_http_forward` and `with_http_connect_udp`.
    pub fn with_all_proxy_protocols(
        self,
    ) -> ProxyMethodBuilder<
        T,
        C,
        B,
        ProxySocksMethod<T>,
        HttpConnectProxyConnector<ProxyDialer<C>, ProxyRequestBody<B>>,
        ProxyConnectUdpMethod<C, B>,
        HttpForwardProxyConnector<ProxyDialer<C>>,
    >
    where
        T: Clone,
        C: Clone,
    {
        #[cfg(feature = "socks5")]
        let builder = self.with_socks5();
        #[cfg(not(feature = "socks5"))]
        let builder = self;
        let builder = builder.with_http_connect();
        #[cfg(all(feature = "masque", feature = "quic"))]
        let builder = builder.with_http_connect_udp();
        builder.with_http_forward()
    }
}

impl<T, C, B, Socks, Connect, ConnectUdp, Forward>
    ProxyMethodBuilder<T, C, B, Socks, Connect, ConnectUdp, Forward>
{
    #[cfg(feature = "socks5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
    /// Reach the origin of a `socks5://` or `socks5h://` route over a stream its proxy
    /// opens for it.
    pub fn with_socks5(
        self,
    ) -> ProxyMethodBuilder<
        T,
        C,
        B,
        Socks5ConnectProxyConnector<ProxyDialer<T>>,
        Connect,
        ConnectUdp,
        Forward,
    >
    where
        T: Clone,
    {
        let socks = Socks5ConnectProxyConnectorLayer::default()
            .with_extensions_transfer(self.extensions_transfer.clone())
            .into_layer(self.stream.clone());
        self.with_socks(socks)
    }

    /// Open a tunnel to the origin over an HTTP proxy with CONNECT.
    pub fn with_http_connect(
        self,
    ) -> ProxyMethodBuilder<
        T,
        C,
        B,
        Socks,
        HttpConnectProxyConnector<ProxyDialer<C>, ProxyRequestBody<B>>,
        ConnectUdp,
        Forward,
    >
    where
        C: Clone,
    {
        let connect = HttpConnectProxyConnector::new(self.http.clone())
            .with_extensions_transfer(self.extensions_transfer.clone());
        self.with_connect(connect)
    }

    #[cfg(all(feature = "masque", feature = "quic"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "masque", feature = "quic"))))]
    /// Open a datagram tunnel to the origin over an HTTP proxy with CONNECT-UDP
    /// ([RFC 9298]), for the QUIC endpoint of an HTTP/3 origin reached through one. Every
    /// other datagram request takes a UDP socket of its own.
    ///
    /// [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
    pub fn with_http_connect_udp(
        self,
    ) -> ProxyMethodBuilder<T, C, B, Socks, Connect, ProxyConnectUdpMethod<C, B>, Forward>
    where
        C: Clone,
    {
        let connect_udp = HttpConnectUdpProxyConnector::new(self.http.clone(), self.scope.clone())
            .with_extensions_transfer(self.extensions_transfer.clone());
        self.with_connect_udp(MaybeProxiedConnector::new(
            UdpConnector::new(),
            connect_udp,
            ProxiedRoute::new(),
        ))
    }

    /// Have an HTTP proxy forward a plaintext request to its origin, over the HTTP
    /// connection to that proxy.
    pub fn with_http_forward(
        self,
    ) -> ProxyMethodBuilder<
        T,
        C,
        B,
        Socks,
        Connect,
        ConnectUdp,
        HttpForwardProxyConnector<ProxyDialer<C>>,
    >
    where
        C: Clone,
    {
        let forward = HttpForwardProxyConnector::new(self.http.clone());
        self.with_forward(forward)
    }

    /// The [`ProxyConnector`] of the methods enabled so far.
    pub fn build(self) -> ProxyConnector<Socks, Connect, ConnectUdp, Forward> {
        ProxyConnector::from_methods(self.socks, self.connect, self.connect_udp, self.forward)
    }

    #[cfg(feature = "socks5")]
    fn with_socks<S2>(
        self,
        socks: S2,
    ) -> ProxyMethodBuilder<T, C, B, S2, Connect, ConnectUdp, Forward> {
        ProxyMethodBuilder {
            stream: self.stream,
            http: self.http,
            scope: self.scope,
            socks,
            connect: self.connect,
            connect_udp: self.connect_udp,
            forward: self.forward,
            extensions_transfer: self.extensions_transfer,
            _phantom: PhantomData,
        }
    }

    fn with_connect<C2>(
        self,
        connect: C2,
    ) -> ProxyMethodBuilder<T, C, B, Socks, C2, ConnectUdp, Forward> {
        ProxyMethodBuilder {
            stream: self.stream,
            http: self.http,
            scope: self.scope,
            socks: self.socks,
            connect,
            connect_udp: self.connect_udp,
            forward: self.forward,
            extensions_transfer: self.extensions_transfer,
            _phantom: PhantomData,
        }
    }

    #[cfg(all(feature = "masque", feature = "quic"))]
    fn with_connect_udp<U2>(
        self,
        connect_udp: U2,
    ) -> ProxyMethodBuilder<T, C, B, Socks, Connect, U2, Forward> {
        ProxyMethodBuilder {
            stream: self.stream,
            http: self.http,
            scope: self.scope,
            socks: self.socks,
            connect: self.connect,
            connect_udp,
            forward: self.forward,
            extensions_transfer: self.extensions_transfer,
            _phantom: PhantomData,
        }
    }

    fn with_forward<F2>(
        self,
        forward: F2,
    ) -> ProxyMethodBuilder<T, C, B, Socks, Connect, ConnectUdp, F2> {
        ProxyMethodBuilder {
            stream: self.stream,
            http: self.http,
            scope: self.scope,
            socks: self.socks,
            connect: self.connect,
            connect_udp: self.connect_udp,
            forward,
            extensions_transfer: self.extensions_transfer,
            _phantom: PhantomData,
        }
    }
}

impl<T, C, B, Socks, ConnectUdp, Forward>
    ProxyMethodBuilder<
        T,
        C,
        B,
        Socks,
        HttpConnectProxyConnector<ProxyDialer<C>, ProxyRequestBody<B>>,
        ConnectUdp,
        Forward,
    >
{
    /// See [`HttpConnectProxyConnector::with_custom_header`].
    #[must_use]
    pub fn with_connect_custom_header(
        mut self,
        name: impl IntoHeaderName,
        value: HeaderValue,
    ) -> Self {
        self.connect.set_custom_header(name, value);
        self
    }
}

core::cfg_select! {
    feature = "socks5" => {
        /// The SOCKS5 method of a [`ProxyConnector`] over the streams `T` dials.
        pub type ProxySocksMethod<T> = Socks5ConnectProxyConnector<ProxyDialer<T>>;
    }
    _ => {
        /// SOCKS5 is not compiled into this build of rama.
        pub type ProxySocksMethod<T> = ProxyMethodNotEnabled<T>;
    }
}

core::cfg_select! {
    all(feature = "masque", feature = "quic") => {
        /// The CONNECT-UDP method of a [`ProxyConnector`] over the HTTP connections `C`
        /// makes to a proxy in the body type `B`.
        ///
        /// Built on a method which is not enabled it refuses a MASQUE route, while every
        /// other datagram request still takes a UDP socket of its own, as an HTTP/3 origin
        /// reached without a proxy needs.
        pub type ProxyConnectUdpMethod<C, B = ResponseBody> = MaybeProxiedConnector<
            UdpConnector,
            HttpConnectUdpProxyConnector<ProxyDialer<C>, ProxyRequestBody<B>>,
            ProxiedRoute,
        >;

        /// The CONNECT-UDP slot of a [`ProxyConnector`] whose method is not enabled.
        pub type ProxyConnectUdpNotEnabled<C, B = ResponseBody> =
            ProxyConnectUdpMethod<ProxyMethodNotEnabled<C>, B>;

        pub(super) fn connect_udp_not_enabled<C, B>(scope: &WeakScope) -> ProxyConnectUdpNotEnabled<C, B> {
            MaybeProxiedConnector::new(
                UdpConnector::new(),
                HttpConnectUdpProxyConnector::new(
                    ProxyMethodNotEnabled::HTTP_CONNECT_UDP,
                    scope.clone(),
                ),
                ProxiedRoute::new(),
            )
        }
    }
    _ => {
        /// MASQUE over QUIC is not compiled into this build of rama.
        pub type ProxyConnectUdpMethod<C, B = ResponseBody> = ProxyMethodNotEnabled<(C, B)>;

        /// The CONNECT-UDP slot of a [`ProxyConnector`] whose method is not enabled, which in
        /// this build is the only one it has.
        pub type ProxyConnectUdpNotEnabled<C, B = ResponseBody> = ProxyConnectUdpMethod<C, B>;

        pub(super) fn connect_udp_not_enabled<C, B>(_scope: &WeakScope) -> ProxyConnectUdpNotEnabled<C, B> {
            ProxyMethodNotEnabled::HTTP_CONNECT_UDP
        }
    }
}

core::cfg_select! {
    feature = "boring" => {
        type DefaultProxyStream<T> = boring_client::TlsConnector<DnsConnector<T>>;
    }
    feature = "rustls" => {
        type DefaultProxyStream<T> = rustls_client::TlsConnector<DnsConnector<T>>;
    }
    _ => {
        type DefaultProxyStream<T> = PlaintextProxyOnly<DnsConnector<T>>;
    }
}

core::cfg_select! {
    all(feature = "quic", any(feature = "boring", feature = "rustls")) => {
        type DefaultProxyTransport<T> = HttpTransportConnector<
            DefaultProxyStream<T>,
            DnsConnector<Http3Connector<SharedQuicEndpoint>>,
        >;
    }
    _ => {
        type DefaultProxyTransport<T> = DefaultProxyStream<T>;
    }
}

pub(crate) type DefaultProxyHttpConnector<T, B> = ProxyServiceConnector<
    HttpPooledConnector<HttpConnector<DefaultProxyTransport<T>, ProxyRequestBody<B>>>,
>;

pub(crate) type DefaultProxySocksMethod<T = TcpConnector> = ProxySocksMethod<DefaultProxyStream<T>>;

pub(crate) type DefaultProxyConnectMethod<T = TcpConnector, B = ResponseBody> =
    HttpConnectProxyConnector<ProxyDialer<DefaultProxyHttpConnector<T, B>>, ProxyRequestBody<B>>;

pub(crate) type DefaultProxyConnectUdpMethod<T = TcpConnector, B = ResponseBody> =
    ProxyConnectUdpMethod<DefaultProxyHttpConnector<T, B>, B>;

pub(crate) type DefaultProxyForwardMethod<T = TcpConnector, B = ResponseBody> =
    HttpForwardProxyConnector<ProxyDialer<DefaultProxyHttpConnector<T, B>>>;

/// Rama's default connector towards proxies, as [`ProxyConnector::default_with_scope`]
/// builds it: every proxy method this build of rama has, over the streams `T` dials to a
/// proxy and the pooled HTTP connections it makes to one in the body type `B`.
pub type DefaultProxyConnector<T = TcpConnector, B = ResponseBody> = ProxyConnector<
    DefaultProxySocksMethod<T>,
    DefaultProxyConnectMethod<T, B>,
    DefaultProxyConnectUdpMethod<T, B>,
    DefaultProxyForwardMethod<T, B>,
>;
