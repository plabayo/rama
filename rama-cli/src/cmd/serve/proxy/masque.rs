//! MASQUE ingress: CONNECT-UDP ([RFC 9298]) next to ordinary CONNECT, over HTTP/1.1, HTTP/2
//! and HTTP/3, and the UDP egress of its tunnels.
//!
//! [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298

use clap::ValueEnum;
use rama::{
    Service,
    dns::client::GlobalDnsResolver,
    error::BoxError,
    extensions::ExtensionsRef,
    http::client::DefaultHttpWebClient,
    net::address::Host,
    net::{
        address::ProxyPathTemplate,
        client::{ConnectRequest, ConnectorService},
    },
    proxy::masque::connect_udp::{
        ConnectUdpConnector, ConnectUdpService, DestinationScopePolicy, MaybeTunneledSocket,
    },
    quic::proxy::InputWithQuicClientHello,
    rt::Executor,
    tls::client::TlsClientConfig,
    udp::{UdpPacketSocket, proxy::UdpConnector},
};

use super::{InspectionState, MitmPolicy, upstream::UpstreamProxyConfig};

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
    exec: Executor,
    template: Option<&ProxyPathTemplate>,
    allow_private: bool,
    upstream: &UpstreamProxyConfig,
) -> Result<
    ConnectUdpService<
        DestinationScopePolicy,
        GlobalDnsResolver,
        impl ConnectorService<ConnectRequest, Connection = MaybeTunneledSocket<UdpPacketSocket>>
        + Clone
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
        .map_or_else(TlsClientConfig::default_http, |tls| {
            tls.with_alpn_http_auto()
        });
    let upstream_client = DefaultHttpWebClient::try_default_masque_proxy_client_using_boringssl(
        exec.clone(),
        proxy_tls,
    )?;
    let tunnels = ConnectUdpConnector::new(UdpConnector::new(), upstream_client, exec.clone());
    Ok(ConnectUdpService::try_new(exec, template)?
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
