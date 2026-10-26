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
        ip::IntoCanonicalIpAddr as _,
    },
    client::{ConnectRequest, ConnectionErrorKind, ConnectorService, ConnectorTarget},
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
    ConnectUdpDestination, ConnectUdpPolicy, ConnectUdpRequestError, ConnectUdpRequestMatcher,
    ConnectUdpSocket, ConnectUdpSocketConfig, ConnectUdpTarget, DestinationScopePolicy,
    session_config,
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
        }
    }

    /// Create the target-side UDP sockets with `connector`.
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
}

impl Refusal {
    fn new(error: ProxyErrorType) -> Self {
        let status = error
            .recommended_status()
            .unwrap_or(StatusCode::BAD_GATEWAY);
        Self { error, status }
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
        let target = match self.matcher.match_request(&request) {
            Ok(target) => target,
            Err(error) => {
                tracing::debug!(%error, "refused connect-udp request");
                let status = error.status().unwrap_or(StatusCode::BAD_REQUEST);
                let proxy_error = match error {
                    ConnectUdpRequestError::TemplateMismatch
                    | ConnectUdpRequestError::NotConnectUdp => None,
                    _ => Some(ProxyErrorType::HttpRequestError),
                };
                return Ok(self.refuse(&request, status, proxy_error));
            }
        };
        let socket_info = SocketInfo::ingress(request.extensions());
        let proxy_address = socket_info.and_then(SocketInfo::local_addr);
        let client_address = socket_info.map(SocketInfo::peer_addr);

        let egress = match self.open(&request, &target, proxy_address).await {
            Ok(egress) => egress,
            Err(refusal) => {
                tracing::debug!(%target, error = refusal.error.as_str(), "connect-udp tunnel refused");
                return Ok(self.refuse(&request, refusal.status, Some(refusal.error)));
            }
        };
        let Ok(response) = capsule_response::<Body>(version, &Protocol::CONNECT_UDP) else {
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
        // A tunnel ends with the proxy's graceful shutdown instead of holding it up.
        self.exec.spawn_cancellable_task(async move {
            let upgraded = match upgrade.await {
                Ok(upgraded) => upgraded,
                Err(error) => {
                    tracing::debug!(%error, %target, "connect-udp upgrade failed");
                    return;
                }
            };
            let tunnel = ConnectUdpSocket::new(
                &exec,
                HttpDatagramSession::with_config(upgraded, session_config()),
                tunnel_local,
                tunnel_peer,
                socket_config,
            );
            tunnel
                .extensions()
                .insert(ConnectorTarget(HostWithPort::new(
                    target.host.clone(),
                    target.port.get(),
                )));
            if let Err(error) = relay.serve(BridgeIo(tunnel, egress)).await {
                tracing::debug!(error = %error.into(), %target, "connect-udp relay failed");
            }
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
    ) -> Result<S, Refusal>
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
                if self.policy.allows(&ConnectUdpDestination {
                    target,
                    address,
                    proxy_address,
                }) {
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
        })?;
        if let Err(error) = established.conn.peer_addr() {
            tracing::debug!(%error, %address, "connect-udp target socket has no peer");
            return Err(Refusal::new(ProxyErrorType::ProxyInternalError));
        }
        Ok(established.conn)
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
mod tests {
    use std::num::NonZeroU16;

    use rama_http::Method;
    use rama_net::address::{Host, ProxyAddress};

    use super::*;
    use crate::connect_udp::connect_udp_request;

    fn service() -> ConnectUdpService {
        ConnectUdpService::try_new(Executor::default(), None).unwrap()
    }

    fn request(version: Version) -> Request {
        let proxy = ProxyAddress::try_from("masque://proxy.example:443").unwrap();
        let target = ConnectUdpTarget::new(Host::LOCALHOST_IPV4, NonZeroU16::MIN);
        connect_udp_request(&proxy, &target, version).unwrap()
    }

    fn proxy_error(response: &Response) -> Option<(Box<str>, ProxyErrorType)> {
        let status: ProxyStatus = response.headers().typed_get()?;
        let entry = &status.entries()[0];
        Some((entry.proxy.clone(), entry.error.clone()?))
    }

    #[tokio::test]
    async fn malformed_requests_get_400_with_proxy_status() {
        let mut request = request(Version::HTTP_11);
        *request.method_mut() = Method::POST;
        let response = service().serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            proxy_error(&response),
            Some(("proxy.example".into(), ProxyErrorType::HttpRequestError))
        );
        assert_eq!(response.headers()[header::CONNECTION], "close");
    }

    #[tokio::test]
    async fn the_proxy_name_overrides_the_addressed_host() {
        let mut request = request(Version::HTTP_2);
        *request.uri_mut() = "https://proxy.example/.well-known/masque/udp/127.0.0.1/0/"
            .parse()
            .unwrap();
        let response = service()
            .with_proxy_name(Arc::from("edge-7"))
            .serve(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            proxy_error(&response),
            Some(("edge-7".into(), ProxyErrorType::HttpRequestError))
        );
        assert!(!response.headers().contains_key(header::CONNECTION));
    }

    #[tokio::test]
    async fn other_paths_and_requests_carry_no_proxy_status() {
        let mut request = request(Version::HTTP_3);
        *request.uri_mut() = "https://proxy.example/elsewhere".parse().unwrap();
        let response = service().serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(proxy_error(&response), None);

        let plain = Request::builder()
            .uri("https://proxy.example/")
            .body(Body::empty())
            .unwrap();
        let response = service().serve(plain).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(proxy_error(&response), None);
    }

    #[tokio::test]
    async fn a_refused_target_reports_the_policy() {
        // Loopback by IP literal: refused before any socket exists.
        let response = service().serve(request(Version::HTTP_2)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            proxy_error(&response),
            Some((
                "proxy.example".into(),
                ProxyErrorType::DestinationIpProhibited
            ))
        );
    }
}
