//! MASQUE ingress: CONNECT-UDP ([RFC 9298]) next to ordinary CONNECT, over HTTP/1.1, HTTP/2
//! and HTTP/3, and the UDP egress of its tunnels.
//!
//! [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298

use clap::ValueEnum;
use rama::net::client::MaybeProxied;
use rama::{
    Service,
    dns::client::GlobalDnsResolver,
    error::BoxError,
    extensions::ExtensionsRef,
    graceful::WeakScope,
    http::{Body, client::ProxyConnector},
    io::BridgeIo,
    net::{
        Protocol,
        address::{Host, ProxyPathTemplate},
        client::{ConnectRequest, ConnectorService},
        stream::SocketAddresses,
    },
    proxy::masque::connect_udp::{ConnectUdpService, ConnectUdpSocket, DestinationScopePolicy},
    quic::{Connection, proxy::InputWithQuicClientHello},
    tls::client::TlsClientConfig,
    udp::UdpPacketSocket,
};

use super::{
    InspectionState, MitmPolicy,
    capture::{CaptureStore, ConnectionId},
    upstream::UpstreamProxyConfig,
};

/// A tunnel method MASQUE ingress serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub(super) enum MasqueTunnel {
    /// TCP targets, through ordinary CONNECT.
    Connect,
    /// UDP targets, through CONNECT-UDP (RFC 9298).
    ConnectUdp,
}

/// Parse `--masque-template`, so an invalid template is refused at startup.
pub(super) fn parse_template(value: &str) -> Result<ProxyPathTemplate, BoxError> {
    Ok(ProxyPathTemplate::try_new(value)?)
}

/// The CONNECT-UDP service of MASQUE ingress. Targets are resolved and checked against the
/// destination policy here; their sockets are direct, or tunnels through a MASQUE
/// `--upstream-proxy`. Any other upstream proxy refuses them, so it is never bypassed.
pub(super) fn connect_udp_service(
    scope: WeakScope,
    template: Option<&ProxyPathTemplate>,
    allow_private: bool,
    upstream: &UpstreamProxyConfig,
) -> Result<
    ConnectUdpService<
        DestinationScopePolicy,
        GlobalDnsResolver,
        impl ConnectorService<
            ConnectRequest,
            Connection = MaybeProxied<UdpPacketSocket, ConnectUdpSocket>,
        > + Clone
        + use<>,
    >,
    BoxError,
> {
    let policy = if allow_private {
        DestinationScopePolicy::allow_private()
    } else {
        DestinationScopePolicy::default()
    };
    // The client sending CONNECT-UDP requests to a MASQUE upstream proxy.
    let proxy_tls = upstream
        .proxy_tls_config()
        .unwrap_or_else(TlsClientConfig::default_http);
    // Only CONNECT-UDP is used. Building `HttpConnectUdpProxyConnector` directly over an
    // `EasyHttpWebClient` connector (with a `UdpConnector` for direct routes) works too;
    // the builder just sets up TLS and the pool towards the proxy for us.
    let upstream_proxies = ProxyConnector::builder(scope.clone())
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_support_using_boringssl(proxy_tls)
        .with_default_http_connector::<Body>()
        .with_default_connection_pool()
        .with_http_connect_udp()
        .build();
    let tunnels = upstream_proxies.into_parts().connect_udp;
    Ok(ConnectUdpService::try_new(scope, template)?
        .with_policy(policy)
        .with_connector(upstream.connector_service(tunnels)))
}

/// Decides per tunneled QUIC connection, from its ClientHello, whether it is terminated and
/// inspected or forwarded untouched: the same scope rules as TLS over CONNECT.
#[derive(Debug, Clone)]
pub(super) struct QuicHelloMitmPolicyService<I, P> {
    pub(super) inspection: InspectionState,
    pub(super) inspect: I,
    pub(super) passthrough: P,
    pub(super) policy: MitmPolicy,
}

impl<I, P, IO> Service<InputWithQuicClientHello<IO>> for QuicHelloMitmPolicyService<I, P>
where
    IO: ExtensionsRef + Send + 'static,
    I: Service<InputWithQuicClientHello<IO>, Output = (), Error: Into<BoxError>>,
    P: Service<IO, Output = (), Error: Into<BoxError>>,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, input: InputWithQuicClientHello<IO>) -> Result<(), BoxError> {
        let sni = input
            .peeked
            .client_hello
            .ext_server_name()
            .cloned()
            .map(Host::Name);
        let should_inspect = self
            .policy
            .should_inspect_target_and_host(input.input.extensions(), sni.as_ref());
        if should_inspect && let Some(session) = self.inspection.session() {
            return session
                .run(async { self.inspect.serve(input).await.map_err(Into::into) })
                .await;
        }
        self.passthrough
            .serve(input.input)
            .await
            .map_err(Into::into)
    }
}

/// Records each terminated QUIC connection as an inspector connection, as a TCP connection is
/// recorded, so its HTTP/3 exchanges share the QUIC and TLS facts published on it.
#[derive(Debug, Clone)]
pub(super) struct ObserveQuicConnectionService<S> {
    pub(super) capture: CaptureStore,
    pub(super) inner: S,
}

impl<S> Service<BridgeIo<Connection, Connection>> for ObserveQuicConnectionService<S>
where
    S: Service<BridgeIo<Connection, Connection>>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: BridgeIo<Connection, Connection>) -> Result<S::Output, S::Error> {
        let BridgeIo(ingress, _) = &input;
        let id = self.capture.begin_connection_if_enabled(
            Some(SocketAddresses {
                local_address: None,
                peer_address: ingress.remote_address().into(),
            }),
            Protocol::HTTPS,
            None,
        );
        let _guard = id.map(|id| {
            ingress.extensions().insert(ConnectionId(id));
            self.capture.confirm_connection_if_enabled(id);
            self.capture.connection_guard(id)
        });
        self.inner.serve(input).await
    }
}
