use std::{convert::Infallible, fmt, num::NonZeroUsize, sync::Arc, time::Duration};

use rama_core::{
    Service, error::BoxError, extensions::ExtensionsRef as _, futures::StreamExt as _,
    io::BridgeIo, rt::Executor, telemetry::tracing,
};
use rama_dns::client::{
    GlobalDnsResolver,
    resolver::{DnsAddressResolver, HappyEyeballAddressResolverExt as _},
};
use rama_http::{
    Body, HeaderValue, Request, Response, StatusCode, Version,
    datagram::{HttpDatagramSession, handshake::capsule_response},
    header,
    headers::{HeaderMapExt as _, ProxyErrorType, ProxyStatus, ProxyStatusEntry},
    io::upgrade::handle_upgrade,
    proto::ext::{HttpDatagrams, Protocol},
};
use rama_net::{
    address::{
        HostWithOptPort, HostWithPort, ProxyPathTemplate, SocketAddress,
        ip::{IntoCanonicalIpAddr as _, TranslationPrefix},
    },
    client::{ConnectRequest, ConnectionErrorKind, ConnectorService, ConnectorTarget},
    rate::{InputToRateKey, RateKey},
    stream::SocketInfo,
    uri::UriTemplateError,
};
use rama_udp::{
    DatagramError, DatagramSocket,
    proxy::{
        DatagramForwardError, DatagramForwardService, EcnPolicy, PacketErrorPolicy, UdpConnector,
    },
};
use rama_utils::{macros::generate_set_and_with, octets::kib};

use super::{
    ConnectUdpDestination, ConnectUdpLimits, ConnectUdpPolicy, ConnectUdpRequestError,
    ConnectUdpRequestMatcher, ConnectUdpSocket, ConnectUdpSocketConfig, ConnectUdpTarget,
    DestinationScopePolicy, TunnelBudget,
    limits::{AdmitTunnel, Refused},
    policy::embedded_destinations,
    session_config,
    socket::{TunnelAccounting, TunnelReport},
    telemetry::{self, TunnelEnd, TunnelObserver, TunnelTelemetry},
};

/// Receive buffer per relay direction: the largest UDP payload fits.
const RELAY_BUFFER: NonZeroUsize = NonZeroUsize::new(kib(64)).unwrap();

/// A CONNECT-UDP proxy ([RFC 9298]) for every HTTP version.
///
/// Matches requests against the proxy's URI template, resolves the target before
/// answering (RFC 9298 §3.1), sends only to a resolved address the [`ConnectUdpPolicy`]
/// allows, and hands the tunnel and a connected UDP socket to the relay `F`: by default
/// [`ConnectUdpRelay`], which forwards payloads until either side ends or the tunnel idles
/// out; an inspecting relay can terminate the tunneled QUIC instead. Refusals carry a `Proxy-Status`
/// ([RFC 9209]) entry. Authentication is any layer in front of this service.
///
/// Every tunnel opened, refused and ended is a DEBUG event at the tracing target
/// `rama_masque::connect_udp::audit` (`event` = `tunnel_opened`, `tunnel_refused`,
/// `tunnel_closed`), with the target, the resolved address and the client's address, and the
/// principal's kind but never who it is; enable that target to keep an audit trail. Metrics are recorded once set
/// ([`ConnectUdpService::with_metrics`], feature `opentelemetry`).
///
/// The listener must allow the tunnel: HTTP/1.1 upgrades, Extended CONNECT on HTTP/2
/// (`enable_connect_protocol`) and HTTP/3 (`extended_connect`), with HTTP/3 datagrams
/// enabled for native payloads.
///
/// [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
/// [RFC 9209]: https://datatracker.ietf.org/doc/html/rfc9209
pub struct ConnectUdpService<
    P = DestinationScopePolicy,
    R = GlobalDnsResolver,
    C = UdpConnector,
    F = ConnectUdpRelay,
> {
    matcher: ConnectUdpRequestMatcher,
    policy: Arc<P>,
    resolver: Arc<R>,
    connector: Arc<C>,
    relay: Arc<F>,
    exec: Executor,
    proxy_name: Option<Arc<str>>,
    dns_timeout: Duration,
    socket: ConnectUdpSocketConfig,
    translation_prefixes: Arc<Vec<TranslationPrefix>>,
    limits: Arc<dyn AdmitTunnel>,
    tunnel_budget: Option<TunnelBudget>,
    telemetry: TunnelTelemetry,
}

impl<P, R, C, F> Clone for ConnectUdpService<P, R, C, F> {
    fn clone(&self) -> Self {
        Self {
            matcher: self.matcher.clone(),
            policy: self.policy.clone(),
            resolver: self.resolver.clone(),
            connector: self.connector.clone(),
            relay: self.relay.clone(),
            exec: self.exec.clone(),
            proxy_name: self.proxy_name.clone(),
            dns_timeout: self.dns_timeout,
            socket: self.socket,
            translation_prefixes: self.translation_prefixes.clone(),
            limits: self.limits.clone(),
            tunnel_budget: self.tunnel_budget,
            telemetry: self.telemetry.clone(),
        }
    }
}

impl<P, R, C, F> fmt::Debug for ConnectUdpService<P, R, C, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectUdpService")
            .field("template", self.matcher.template())
            .field("proxy_name", &self.proxy_name)
            .field("dns_timeout", &self.dns_timeout)
            .field("socket", &self.socket)
            .field("translation_prefixes", &self.translation_prefixes)
            .field("tunnel_budget", &self.tunnel_budget)
            .finish_non_exhaustive()
    }
}

impl ConnectUdpService {
    /// A proxy for `template`, or for the RFC 9298 default template when `None`, with the
    /// safe [`DestinationScopePolicy`], the global DNS resolver and plain UDP sockets.
    pub fn try_new(
        exec: Executor,
        template: Option<&ProxyPathTemplate>,
    ) -> Result<Self, UriTemplateError> {
        Ok(Self {
            matcher: ConnectUdpRequestMatcher::try_new(template)?,
            policy: Arc::new(DestinationScopePolicy::new()),
            resolver: Arc::new(GlobalDnsResolver::new()),
            connector: Arc::new(UdpConnector::new()),
            relay: Arc::new(ConnectUdpRelay),
            exec,
            proxy_name: None,
            dns_timeout: Duration::from_secs(5),
            socket: ConnectUdpSocketConfig::default(),
            translation_prefixes: Arc::default(),
            limits: Arc::new(ConnectUdpLimits::new()),
            tunnel_budget: Some(TunnelBudget::new()),
            telemetry: TunnelTelemetry::default(),
        })
    }
}

impl<P, R, C, F> ConnectUdpService<P, R, C, F> {
    /// Decide which resolved addresses tunnels may send to.
    pub fn with_policy<P2>(self, policy: P2) -> ConnectUdpService<P2, R, C, F> {
        ConnectUdpService {
            matcher: self.matcher,
            policy: Arc::new(policy),
            resolver: self.resolver,
            connector: self.connector,
            relay: self.relay,
            exec: self.exec,
            proxy_name: self.proxy_name,
            dns_timeout: self.dns_timeout,
            socket: self.socket,
            translation_prefixes: self.translation_prefixes,
            limits: self.limits,
            tunnel_budget: self.tunnel_budget,
            telemetry: self.telemetry,
        }
    }

    /// Resolve target names with `resolver`.
    pub fn with_resolver<R2>(self, resolver: R2) -> ConnectUdpService<P, R2, C, F> {
        ConnectUdpService {
            matcher: self.matcher,
            policy: self.policy,
            resolver: Arc::new(resolver),
            connector: self.connector,
            relay: self.relay,
            exec: self.exec,
            proxy_name: self.proxy_name,
            dns_timeout: self.dns_timeout,
            socket: self.socket,
            translation_prefixes: self.translation_prefixes,
            limits: self.limits,
            tunnel_budget: self.tunnel_budget,
            telemetry: self.telemetry,
        }
    }

    /// Create the target-side UDP sockets with `connector`.
    ///
    /// It must return a socket connected to the requested address: the tunnel is refused
    /// unless the socket's peer is exactly the address the policy approved.
    pub fn with_connector<C2>(self, connector: C2) -> ConnectUdpService<P, R, C2, F> {
        ConnectUdpService {
            matcher: self.matcher,
            policy: self.policy,
            resolver: self.resolver,
            connector: Arc::new(connector),
            relay: self.relay,
            exec: self.exec,
            proxy_name: self.proxy_name,
            dns_timeout: self.dns_timeout,
            socket: self.socket,
            translation_prefixes: self.translation_prefixes,
            limits: self.limits,
            tunnel_budget: self.tunnel_budget,
            telemetry: self.telemetry,
        }
    }

    /// Relay each accepted tunnel with `relay`, given the tunnel and its connected target
    /// socket. The tunnel carries the target as its [`ConnectorTarget`].
    pub fn with_relay<F2>(self, relay: F2) -> ConnectUdpService<P, R, C, F2> {
        ConnectUdpService {
            matcher: self.matcher,
            policy: self.policy,
            resolver: self.resolver,
            connector: self.connector,
            relay: Arc::new(relay),
            exec: self.exec,
            proxy_name: self.proxy_name,
            dns_timeout: self.dns_timeout,
            socket: self.socket,
            translation_prefixes: self.translation_prefixes,
            limits: self.limits,
            tunnel_budget: self.tunnel_budget,
            telemetry: self.telemetry,
        }
    }

    generate_set_and_with! {
        /// How this proxy names itself in `Proxy-Status`: a service name, hostname or
        /// alias. Defaults to the host the request addressed.
        pub fn proxy_name(mut self, name: Option<Arc<str>>) -> Self {
            self.proxy_name = name;
            self
        }
    }

    generate_set_and_with! {
        /// How long resolving a target may take before the request fails with `dns_timeout`.
        pub fn dns_timeout(mut self, timeout: Duration) -> Self {
            self.dns_timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Limits of each tunnel, including its idle timeout.
        pub fn socket_config(mut self, config: ConnectUdpSocketConfig) -> Self {
            self.socket = config;
            self
        }
    }

    /// How many tunnels run at once, in total and per principal, and how principals are keyed;
    /// clones of this service, and of `limits`, share them. No limits by default.
    #[must_use]
    pub fn with_limits<X, K>(mut self, limits: ConnectUdpLimits<X, K>) -> Self
    where
        X: InputToRateKey<Request, Key = K>,
        K: RateKey,
    {
        self.limits = Arc::new(limits);
        self
    }

    generate_set_and_with! {
        /// What each tunnel may move ([`TunnelBudget`]), or `None` for no limit at all. By
        /// default [`TunnelBudget::new`]: no rates or quota, and a small allowance toward a
        /// target that has not answered.
        pub fn tunnel_budget(mut self, budget: Option<TunnelBudget>) -> Self {
            self.tunnel_budget = budget;
            self
        }
    }

    generate_set_and_with! {
        /// Add an IPv4/IPv6 translation prefix of the proxy's network ([RFC 6052]), such as
        /// one inside the local-use `64:ff9b:1::/48`. Policies then judge an address inside
        /// it by the IPv4 address it carries ([`ConnectUdpDestination::embedded`]), and an
        /// address inside it carrying none is refused.
        ///
        /// [RFC 6052]: https://datatracker.ietf.org/doc/html/rfc6052
        pub fn translation_prefix(mut self, prefix: TranslationPrefix) -> Self {
            Arc::make_mut(&mut self.translation_prefixes).push(prefix);
            self
        }
    }

    #[cfg(feature = "opentelemetry")]
    generate_set_and_with! {
        /// Record the proxy's tunnels in `metrics`.
        pub fn metrics(mut self, metrics: Option<telemetry::ConnectUdpMetrics>) -> Self {
            self.telemetry.metrics = metrics;
            self
        }
    }

    /// The matcher recognising this proxy's CONNECT-UDP requests, for routing.
    #[must_use]
    pub fn matcher(&self) -> &ConnectUdpRequestMatcher {
        &self.matcher
    }
}

/// Why a tunnel could not be opened, as a `Proxy-Status` error type.
#[derive(Debug)]
struct Refusal {
    error: ProxyErrorType,
    status: StatusCode,
    /// The resolved address it concerned, for the audit event only.
    address: Option<SocketAddress>,
}

impl Refusal {
    fn new(error: ProxyErrorType) -> Self {
        let status = error
            .recommended_status()
            .unwrap_or(StatusCode::BAD_GATEWAY);
        Self {
            error,
            status,
            address: None,
        }
    }

    fn at(mut self, address: SocketAddress) -> Self {
        self.address = Some(address);
        self
    }
}

/// Records a relayed tunnel when its task ends, as it is then: a task dropped before the relay
/// ended is cancelled, whatever handles of the tunnel live on.
struct RelayWatch {
    observer: Option<TunnelObserver>,
    report: TunnelReport,
    end: Option<TunnelEnd>,
}

impl Drop for RelayWatch {
    fn drop(&mut self) {
        if let Some(observer) = self.observer.take() {
            let end = self.end.unwrap_or(TunnelEnd::Cancelled);
            observer.finish(end, &self.report.stats());
        }
    }
}

impl<P, R, C, F, S> Service<Request> for ConnectUdpService<P, R, C, F>
where
    P: ConnectUdpPolicy,
    R: DnsAddressResolver,
    C: ConnectorService<ConnectRequest, Connection = S>,
    S: DatagramSocket,
    F: Service<BridgeIo<ConnectUdpSocket, S>, Output = (), Error: Into<BoxError>>,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, request: Request) -> Result<Response, Infallible> {
        let version = request.version();
        let socket_info = SocketInfo::ingress(request.extensions());
        let proxy_address = socket_info.and_then(SocketInfo::local_addr);
        let client_address = socket_info.map(SocketInfo::peer_addr);
        let target = match self.matcher.match_request(&request) {
            Ok(target) => target,
            Err(error) => {
                tracing::debug!(%error, "refused connect-udp request");
                let status = error.status().unwrap_or(StatusCode::BAD_REQUEST);
                let proxy_error = match error {
                    // Not a CONNECT-UDP request for this proxy: nothing to audit.
                    ConnectUdpRequestError::TemplateMismatch
                    | ConnectUdpRequestError::NotConnectUdp => None,
                    _ => Some(ProxyErrorType::HttpRequestError),
                };
                if let Some(error) = &proxy_error {
                    self.telemetry.refused(&telemetry::Refused {
                        reason: telemetry::refusal_reason(error),
                        target: None,
                        address: None,
                        client: client_address,
                        principal: None,
                        extensions: request.extensions(),
                    });
                }
                return Ok(self.refuse(&request, status, proxy_error));
            }
        };

        // Admitted before anything is resolved or connected; every exit gives the place back.
        let lease = match self.limits.admit(&request) {
            Ok(lease) => lease,
            Err(refused) => {
                let (status, error) = match refused {
                    Refused::LimitReached => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        ProxyErrorType::ConnectionLimitReached,
                    ),
                    Refused::NoPrincipal => {
                        (StatusCode::FORBIDDEN, ProxyErrorType::HttpRequestDenied)
                    }
                    // The keyer's error may quote what it read from the request: never logged.
                    Refused::Keyer => {
                        tracing::debug!(%target, "connect-udp principal keyer failed");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            ProxyErrorType::ProxyInternalError,
                        )
                    }
                };
                tracing::debug!(%target, error = error.as_str(), "connect-udp tunnel not admitted");
                self.telemetry.refused(&telemetry::Refused {
                    reason: telemetry::refusal_reason(&error),
                    target: Some(&target),
                    address: None,
                    client: client_address,
                    principal: None,
                    extensions: request.extensions(),
                });
                return Ok(self.refuse(&request, status, Some(error)));
            }
        };

        let principal_kind = lease.principal_kind();
        let (egress, address) = match self.open(&request, &target, proxy_address).await {
            Ok(opened) => opened,
            Err(refusal) => {
                tracing::debug!(%target, error = refusal.error.as_str(), "connect-udp tunnel refused");
                self.telemetry.refused(&telemetry::Refused {
                    reason: telemetry::refusal_reason(&refusal.error),
                    target: Some(&target),
                    address: refusal.address,
                    client: client_address,
                    principal: principal_kind,
                    extensions: request.extensions(),
                });
                return Ok(self.refuse(&request, refusal.status, Some(refusal.error)));
            }
        };
        let Ok(response) = capsule_response::<Body>(version, &Protocol::CONNECT_UDP) else {
            self.telemetry.refused(&telemetry::Refused {
                reason: "http_version_not_supported",
                target: Some(&target),
                address: Some(address),
                client: client_address,
                principal: principal_kind,
                extensions: request.extensions(),
            });
            return Ok(self.refuse(&request, StatusCode::HTTP_VERSION_NOT_SUPPORTED, None));
        };
        // Accepting the token declares its datagram semantics for this request (RFC 9297 §2).
        response.extensions().insert(HttpDatagrams);

        let upgrade = handle_upgrade(&request);
        let exec = self.exec.clone();
        let socket_config = self.socket;
        let tunnel_local = proxy_address.unwrap_or(SocketAddress::default_ipv4(0));
        let tunnel_peer = client_address.unwrap_or(SocketAddress::default_ipv4(0));
        let relay = self.relay.clone();
        let tunnel_budget = self.tunnel_budget;
        let principal = lease.principal_spend();
        // Owned by the task: however it ends, even dropped unpolled, the tunnel is recorded once.
        let observer = self.telemetry.opened(
            &target,
            address,
            client_address,
            principal_kind,
            request.extensions(),
        );
        // A tunnel ends with the proxy's graceful shutdown instead of holding it up.
        self.exec.spawn_cancellable_task(async move {
            let _lease = lease;
            let upgraded = match upgrade.await {
                Ok(upgraded) => upgraded,
                Err(error) => {
                    tracing::debug!(%error, %target, "connect-udp upgrade failed");
                    observer.finish(TunnelEnd::UpgradeFailed, &Default::default());
                    return;
                }
            };
            let tunnel = ConnectUdpSocket::with_accounting(
                &exec,
                HttpDatagramSession::with_config(upgraded, session_config()),
                tunnel_local,
                tunnel_peer,
                socket_config,
                TunnelAccounting {
                    budget: tunnel_budget,
                    principal,
                },
            );
            let mut watch = RelayWatch {
                observer: Some(observer),
                report: tunnel.report(),
                end: None,
            };
            tunnel
                .extensions()
                .insert(ConnectorTarget(HostWithPort::new(
                    target.host.clone(),
                    target.port.get(),
                )));
            watch.end = Some(match relay.serve(BridgeIo(tunnel, egress)).await {
                Ok(()) => watch.report.end(),
                Err(error) => {
                    tracing::debug!(error = %error.into(), %target, "connect-udp relay failed");
                    TunnelEnd::RelayFailed
                }
            });
        });
        Ok(response)
    }
}

impl<P, R, C, F> ConnectUdpService<P, R, C, F> {
    /// Resolve the target, pick the first address the policy allows and connect to it.
    async fn open<S>(
        &self,
        request: &Request,
        target: &ConnectUdpTarget,
        proxy_address: Option<SocketAddress>,
    ) -> Result<(S, SocketAddress), Refusal>
    where
        P: ConnectUdpPolicy,
        R: DnsAddressResolver,
        C: ConnectorService<ConnectRequest, Connection = S>,
        S: DatagramSocket,
    {
        let resolve = async {
            let mut addresses = std::pin::pin!(
                self.resolver
                    .happy_eyeballs_resolver(target.host.clone())
                    .with_extensions(request.extensions())
                    .lookup_ip()
            );
            let mut prohibited = false;
            while let Some(address) = addresses.next().await {
                let Ok(ip) = address else { continue };
                let address = SocketAddress::new(ip, target.port.get()).into_canonical_ip_addr();
                let allowed = embedded_destinations(address.ip_addr, &self.translation_prefixes)
                    .is_some_and(|(embedded, translated)| {
                        self.policy.allows(&ConnectUdpDestination {
                            target,
                            address,
                            proxy_address,
                            extensions: request.extensions(),
                            embedded: &embedded,
                            translated,
                        })
                    });
                if allowed {
                    return Ok(address);
                }
                prohibited = true;
            }
            Err(Refusal::new(if prohibited {
                ProxyErrorType::DestinationIpProhibited
            } else {
                ProxyErrorType::DnsError
            }))
        };
        let address = tokio::time::timeout(self.dns_timeout, resolve)
            .await
            .map_err(|_elapsed| Refusal::new(ProxyErrorType::DnsTimeout))??;

        let mut connect = ConnectRequest::new(address.into());
        connect.extensions = request.extensions().clone();
        let established = self.connector.connect(connect).await.map_err(|error| {
            tracing::debug!(%error, %address, "connect-udp target socket failed");
            Refusal::new(match error.kind() {
                ConnectionErrorKind::Unavailable | ConnectionErrorKind::Rejected => {
                    ProxyErrorType::DestinationIpUnroutable
                }
                _ => ProxyErrorType::ProxyInternalError,
            })
            .at(address)
        })?;
        // Only the address the policy approved may receive the tunnel's payloads.
        match established.conn.peer_addr() {
            Ok(peer) if peer.into_canonical_ip_addr() == address => {}
            Ok(peer) => {
                tracing::debug!(%peer, %address, "connect-udp target socket peer is not the approved address");
                return Err(Refusal::new(ProxyErrorType::ProxyInternalError).at(address));
            }
            Err(error) => {
                tracing::debug!(%error, %address, "connect-udp target socket has no peer");
                return Err(Refusal::new(ProxyErrorType::ProxyInternalError).at(address));
            }
        }
        Ok((established.conn, address))
    }

    fn refuse(
        &self,
        request: &Request,
        status: StatusCode,
        error: Option<ProxyErrorType>,
    ) -> Response {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = status;
        if let Some(error) = error
            && let Some(name) = self.proxy_name.clone().or_else(|| addressed_host(request))
        {
            response
                .headers_mut()
                .typed_insert(ProxyStatus::new(ProxyStatusEntry::error(&*name, error)));
        }
        if request.version() == Version::HTTP_11 {
            // Bytes a client sent after its upgrade request are never read as a request.
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        response
    }
}

/// The host a request addressed: its URI authority (HTTP/2, HTTP/3) or `Host` header.
fn addressed_host(request: &Request) -> Option<Arc<str>> {
    if let Some(host) = request.uri().host() {
        return Some(host.to_string().into());
    }
    let host = request.headers().get(header::HOST)?.to_str().ok()?;
    let host = HostWithOptPort::try_from(host).ok()?.host;
    Some(host.to_string().into())
}

/// The default relay of a [`ConnectUdpService`]: forwards UDP payloads between two connected
/// sockets, such as a tunnel and its target socket, until either side ends. A payload too large for the other side is
/// dropped alone; a clean or idle tunnel end is no failure.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ConnectUdpRelay;

impl ConnectUdpRelay {
    /// The forwarding relay.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<A: DatagramSocket, B: DatagramSocket> Service<BridgeIo<A, B>> for ConnectUdpRelay {
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, sockets: BridgeIo<A, B>) -> Result<(), BoxError> {
        match DatagramForwardService::new(RELAY_BUFFER, EcnPolicy::Discard)
            .with_packet_errors(PacketErrorPolicy::DropPacketLocal)
            .serve(sockets)
            .await
        {
            Ok(()) | Err(DatagramForwardError::Datagram(DatagramError::Closed)) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests;
