use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
    sync::atomic::{AtomicUsize, Ordering},
};

use parking_lot::Mutex;
use rama_core::futures::{Stream, stream};
use rama_dns::client::{DenyAllDnsResolver, EmptyDnsResolver};
use rama_http::{Method, headers::ProxyStatusEntry};
use rama_net::{
    address::{Domain, Host, ProxyAddress},
    client::{ConnectionError, EstablishedClientConnection},
    user::UserId,
};
use rama_udp::UdpPacketSocket;

use super::*;
use crate::connect_udp::{
    ConnectUdpAction, ConnectUdpLimits, ConnectUdpRule, ConnectUdpRules, PrincipalKey,
    connect_udp_request,
};

const VERSIONS: [Version; 3] = [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3];

fn service() -> ConnectUdpService {
    ConnectUdpService::try_new(Executor::default(), None).unwrap()
}

fn request(version: Version) -> Request {
    request_to(Host::LOCALHOST_IPV4, version)
}

fn request_to(host: Host, version: Version) -> Request {
    let proxy = ProxyAddress::try_from("masque://proxy.example:443").unwrap();
    let target = ConnectUdpTarget::new(host, NonZeroU16::MIN);
    connect_udp_request(&proxy, &target, version).unwrap()
}

fn named_target() -> Host {
    Host::Name(Domain::from_static("udp.example"))
}

/// A resolver that never answers.
#[derive(Debug)]
struct SilentResolver;

impl DnsAddressResolver for SilentResolver {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::pending()
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::pending()
    }
}

/// The proxy and error type of a refusal's `Proxy-Status`, which carries nothing else: no
/// next hop, details or DNS codes that could reveal a target or the proxy's network.
fn proxy_error(response: &Response) -> Option<(Box<str>, ProxyErrorType)> {
    let status: ProxyStatus = response.headers().typed_get()?;
    assert_eq!(status.entries().len(), 1);
    let entry = &status.entries()[0];
    let error = entry.error.clone()?;
    assert_eq!(
        *entry,
        ProxyStatusEntry::error(&*entry.proxy, error.clone())
    );
    Some((entry.proxy.clone(), error))
}

/// No response header mentions any of `secrets`.
fn assert_no_header_mentions(response: &Response, secrets: &[&str]) {
    for (name, value) in response.headers() {
        let value = String::from_utf8_lossy(value.as_bytes());
        for secret in secrets {
            assert!(!value.contains(secret), "{name}: {value} mentions {secret}");
        }
    }
}

/// A resolver answering every IPv4 lookup with `addresses`, counting the lookups.
#[derive(Debug)]
struct ListResolver {
    addresses: Vec<Ipv4Addr>,
    lookups: AtomicUsize,
}

impl ListResolver {
    fn new(addresses: &[&str]) -> Self {
        Self {
            addresses: addresses.iter().map(|ip| ip.parse().unwrap()).collect(),
            lookups: AtomicUsize::new(0),
        }
    }
}

impl DnsAddressResolver for ListResolver {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        stream::iter(self.addresses.clone().into_iter().map(Ok))
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::empty()
    }
}

/// Records the addresses it is asked for; connects to `redirect` instead when set, or fails
/// as unreachable when `unreachable`.
#[derive(Debug, Clone, Default)]
struct TestConnector {
    requested: Arc<Mutex<Vec<SocketAddress>>>,
    redirect: Option<SocketAddress>,
    unreachable: bool,
}

impl Service<ConnectRequest> for TestConnector {
    type Output = EstablishedClientConnection<UdpPacketSocket, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, mut input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let Host::Address(ip) = input.authority.host else {
            panic!("the proxy connects to resolved addresses only");
        };
        let requested = SocketAddress::new(ip, input.authority.port);
        self.requested.lock().push(requested);
        if self.unreachable {
            return Err(ConnectionError::transport(
                BoxError::from("unreachable"),
                ConnectionErrorKind::Unavailable,
            ));
        }
        if let Some(redirect) = self.redirect {
            input.authority = redirect.into();
        }
        UdpConnector::new()
            .serve(input)
            .await
            .map_err(|error| ConnectionError::transport(error, ConnectionErrorKind::Other))
    }
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
async fn failed_resolution_gets_502_dns_error_before_any_tunnel() {
    // An erroring resolver and one without any address both fail the lookup.
    for version in VERSIONS {
        for response in [
            service()
                .with_resolver(DenyAllDnsResolver::new())
                .serve(request_to(named_target(), version))
                .await
                .unwrap(),
            service()
                .with_resolver(EmptyDnsResolver::new())
                .serve(request_to(named_target(), version))
                .await
                .unwrap(),
        ] {
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{version:?}");
            assert_eq!(
                proxy_error(&response),
                Some(("proxy.example".into(), ProxyErrorType::DnsError)),
                "{version:?}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn slow_resolution_gets_504_dns_timeout() {
    for version in VERSIONS {
        let response = service()
            .with_resolver(SilentResolver)
            .with_dns_timeout(Duration::from_secs(2))
            .serve(request_to(named_target(), version))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::GATEWAY_TIMEOUT,
            "{version:?}"
        );
        assert_eq!(
            proxy_error(&response),
            Some(("proxy.example".into(), ProxyErrorType::DnsTimeout)),
            "{version:?}"
        );
    }
}

/// Draft-03 clients (`CONNECT-UDP` method, target in the authority, `Datagram-Flow-Id`)
/// are refused as something other than CONNECT-UDP, never read as a tunnel.
#[tokio::test]
async fn draft_03_request_shapes_are_refused() {
    let method = Method::from_bytes(b"CONNECT-UDP").unwrap();
    let matcher = ConnectUdpRequestMatcher::try_new(None).unwrap();
    for version in VERSIONS {
        let uri = if version == Version::HTTP_11 {
            "udp.example:443"
        } else {
            "https://udp.example:443"
        };
        let mut request = Request::builder()
            .method(method.clone())
            .version(version)
            .uri(uri)
            .header("datagram-flow-id", "2")
            .body(Body::empty())
            .unwrap();
        if version == Version::HTTP_11 {
            request
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_static("udp.example:443"));
        }
        assert_eq!(
            matcher.match_request(&request),
            Err(ConnectUdpRequestError::NotConnectUdp),
            "{version:?}"
        );
        let response = service()
            .with_resolver(DenyAllDnsResolver::new())
            .serve(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{version:?}");
        assert_eq!(proxy_error(&response), None, "{version:?}");
    }

    // The draft-03 method with a current upgrade token is a malformed CONNECT-UDP request.
    let mut request = request(Version::HTTP_11);
    *request.method_mut() = method;
    assert_eq!(
        matcher.match_request(&request),
        Err(ConnectUdpRequestError::MalformedRequestLine)
    );
    let response = service().serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        proxy_error(&response),
        Some(("proxy.example".into(), ProxyErrorType::HttpRequestError))
    );
}

#[tokio::test]
async fn one_lookup_and_the_first_allowed_address_is_dialed() {
    // A mixed answer: the private address is skipped, never connected.
    let resolver = Arc::new(ListResolver::new(&["10.0.0.1", "127.0.0.1", "127.0.0.2"]));
    let connector = TestConnector::default();
    let loopback_only = |destination: &ConnectUdpDestination<'_>| {
        destination.address.ip_addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    let service = service()
        .with_policy(loopback_only)
        .with_resolver(resolver.clone())
        .with_connector(connector.clone());
    let response = service
        .serve(request_to(named_target(), Version::HTTP_2))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(
        *connector.requested.lock(),
        ["127.0.0.1:1".parse::<SocketAddress>().unwrap()]
    );
}

#[tokio::test]
async fn a_socket_connected_elsewhere_is_refused() {
    let connector = TestConnector {
        redirect: Some("127.0.0.1:2".parse().unwrap()),
        ..Default::default()
    };
    let response = service()
        .with_policy(DestinationScopePolicy::allow_private())
        .with_connector(connector.clone())
        .serve(request(Version::HTTP_3))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        proxy_error(&response),
        Some(("proxy.example".into(), ProxyErrorType::ProxyInternalError))
    );
    assert_no_header_mentions(&response, &["127.0.0.1", "127.0.0.2"]);
}

#[tokio::test]
async fn refusals_name_neither_target_nor_resolved_address() {
    let resolved = Arc::new(ListResolver::new(&["10.9.8.7"]));
    let secrets = ["udp.example", "10.9.8.7"];
    let cases = [
        (
            service()
                .with_resolver(resolved.clone())
                .serve(request_to(named_target(), Version::HTTP_2))
                .await
                .unwrap(),
            ProxyErrorType::DestinationIpProhibited,
        ),
        (
            service()
                .with_resolver(DenyAllDnsResolver::new())
                .serve(request_to(named_target(), Version::HTTP_2))
                .await
                .unwrap(),
            ProxyErrorType::DnsError,
        ),
        (
            service()
                .with_policy(DestinationScopePolicy::allow_private())
                .with_resolver(resolved.clone())
                .with_connector(TestConnector {
                    unreachable: true,
                    ..Default::default()
                })
                .serve(request_to(named_target(), Version::HTTP_2))
                .await
                .unwrap(),
            ProxyErrorType::DestinationIpUnroutable,
        ),
        (
            service()
                .with_policy(DestinationScopePolicy::allow_private())
                .with_resolver(resolved.clone())
                .with_connector(TestConnector {
                    redirect: Some("127.0.0.1:2".parse().unwrap()),
                    ..Default::default()
                })
                .serve(request_to(named_target(), Version::HTTP_2))
                .await
                .unwrap(),
            ProxyErrorType::ProxyInternalError,
        ),
    ];
    for (response, error) in cases {
        assert_eq!(
            proxy_error(&response),
            Some(("proxy.example".into(), error.clone())),
            "{error:?}"
        );
        assert_no_header_mentions(&response, &secrets);
    }
}

#[tokio::test]
async fn translated_targets_are_judged_by_the_ipv4_they_carry() {
    let literal = |ip: &str| Host::Address(ip.parse().unwrap());
    let deny_8888 = ConnectUdpRules::new(ConnectUdpAction::Allow)
        .with_rule(ConnectUdpRule::deny().with_network("8.8.8.8/32".parse().unwrap()));
    let connector = TestConnector::default();
    let prefix = TranslationPrefix::try_new("64:ff9b:1::/96".parse().unwrap()).unwrap();
    let service = service()
        .with_policy((DestinationScopePolicy::new(), deny_8888))
        .with_connector(connector.clone())
        .with_translation_prefix(prefix);

    // Refused before any socket: a denied IPv4 through NAT64, a private one through the
    // proxy's own prefix.
    for target in ["64:ff9b::808:808", "64:ff9b:1::a00:1"] {
        let response = service
            .serve(request_to(literal(target), Version::HTTP_3))
            .await
            .unwrap();
        assert_eq!(
            proxy_error(&response),
            Some((
                "proxy.example".into(),
                ProxyErrorType::DestinationIpProhibited
            )),
            "{target}"
        );
    }
    assert!(connector.requested.lock().is_empty());

    // The proxy's own address inside its prefix is refused, on any port.
    let request = request_to(literal("64:ff9b:1::808:404"), Version::HTTP_3);
    request.extensions().insert(SocketInfo::new(
        Some("[64:ff9b:1::808:404]:443".parse().unwrap()),
        "[2001:db8::1]:50000".parse().unwrap(),
    ));
    let response = service.serve(request).await.unwrap();
    assert_eq!(
        proxy_error(&response),
        Some((
            "proxy.example".into(),
            ProxyErrorType::DestinationIpProhibited
        ))
    );
    assert!(connector.requested.lock().is_empty());

    // A public IPv4 behind the proxy's own prefix is dialed at the translated address.
    _ = service
        .serve(request_to(literal("64:ff9b:1::808:404"), Version::HTTP_3))
        .await
        .unwrap();
    assert_eq!(
        *connector.requested.lock(),
        ["[64:ff9b:1::808:404]:1".parse::<SocketAddress>().unwrap()]
    );
}

#[tokio::test]
async fn policies_see_the_authenticated_user() {
    let only_john = |destination: &ConnectUdpDestination<'_>| {
        destination
            .extensions
            .get_ref::<UserId>()
            .is_some_and(|user| user == "john")
    };
    let connector = TestConnector::default();
    let service = service()
        .with_policy(only_john)
        .with_connector(connector.clone());
    let response = service.serve(request(Version::HTTP_2)).await.unwrap();
    assert_eq!(
        proxy_error(&response),
        Some((
            "proxy.example".into(),
            ProxyErrorType::DestinationIpProhibited
        ))
    );
    let request = request(Version::HTTP_2);
    request
        .extensions()
        .insert(UserId::Username("john".to_owned()));
    let response = service.serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(connector.requested.lock().len(), 1);
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

/// The service's tunnel places all returned, within a few scheduler turns.
async fn assert_released<X, K>(limits: &ConnectUdpLimits<X, K>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while limits.live_tunnels() > 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("every tunnel place was given back");
}

#[tokio::test]
async fn a_full_proxy_refuses_with_connection_limit_reached() {
    let limits = ConnectUdpLimits::new().with_max_tunnels(1);
    let held = limits.try_acquire(PrincipalKey::ANONYMOUS).unwrap();
    let connector = TestConnector::default();
    let response = service()
        .with_policy(DestinationScopePolicy::allow_private())
        .with_connector(connector.clone())
        .with_limits(limits.clone())
        .serve(request(Version::HTTP_2))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        proxy_error(&response),
        Some((
            "proxy.example".into(),
            ProxyErrorType::ConnectionLimitReached
        ))
    );
    assert!(
        connector.requested.lock().is_empty(),
        "refused before any socket"
    );
    drop(held);
    assert_eq!(limits.live_tunnels(), 0);
}

#[tokio::test]
async fn every_refusal_gives_the_tunnel_place_back() {
    let limits = ConnectUdpLimits::new().with_max_tunnels(1);
    let base = || service().with_limits(limits.clone());
    let responses = [
        // Policy.
        base().serve(request(Version::HTTP_2)).await.unwrap(),
        // DNS.
        base()
            .with_resolver(DenyAllDnsResolver::new())
            .serve(request_to(named_target(), Version::HTTP_2))
            .await
            .unwrap(),
        // Connector failure.
        base()
            .with_policy(DestinationScopePolicy::allow_private())
            .with_connector(TestConnector {
                unreachable: true,
                ..Default::default()
            })
            .serve(request(Version::HTTP_2))
            .await
            .unwrap(),
        // A socket connected elsewhere.
        base()
            .with_policy(DestinationScopePolicy::allow_private())
            .with_connector(TestConnector {
                redirect: Some("127.0.0.1:2".parse().unwrap()),
                ..Default::default()
            })
            .serve(request(Version::HTTP_2))
            .await
            .unwrap(),
    ];
    for response in responses {
        assert!(!response.status().is_success(), "{}", response.status());
        assert_eq!(limits.live_tunnels(), 0);
    }
}

#[tokio::test]
async fn a_request_cancelled_while_resolving_gives_its_place_back() {
    let limits = ConnectUdpLimits::new().with_max_tunnels(1);
    let service = service()
        .with_resolver(SilentResolver)
        .with_limits(limits.clone());
    let mut serving = Box::pin(service.serve(request_to(named_target(), Version::HTTP_3)));
    assert!(rama_core::futures::poll!(serving.as_mut()).is_pending());
    assert_eq!(limits.live_tunnels(), 1);
    drop(serving);
    assert_eq!(limits.live_tunnels(), 0);
}

#[tokio::test]
async fn a_tunnel_whose_upgrade_fails_gives_its_place_back() {
    let limits = ConnectUdpLimits::new().with_max_tunnels(1);
    // Accepted, but this request was never served by a connection that can upgrade.
    let response = service()
        .with_policy(DestinationScopePolicy::allow_private())
        .with_connector(TestConnector::default())
        .with_limits(limits.clone())
        .serve(request(Version::HTTP_2))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_released(&limits).await;
}

#[tokio::test]
async fn tunnels_are_counted_per_authenticated_user() {
    let limits = ConnectUdpLimits::new().with_max_tunnels_per_principal(1);
    let held = limits
        .try_acquire(PrincipalKey::user(&UserId::Username("john".to_owned())))
        .unwrap();
    let service = service()
        .with_policy(DestinationScopePolicy::allow_private())
        .with_connector(TestConnector::default())
        .with_limits(limits.clone());
    let as_user = |name: &str| {
        let request = request(Version::HTTP_2);
        request
            .extensions()
            .insert(UserId::Username(name.to_owned()));
        request
    };
    let response = service.serve(as_user("john")).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let response = service.serve(as_user("jane")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    drop(held);
    assert_released(&limits).await;
}

/// RFC 9298 §3: "In IPv4, the Don't Fragment (DF) bit MUST be set, if possible". The service's
/// default egress connector sets it where the platform can, and reports it.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_vendor = "apple",
    windows
))]
#[tokio::test]
async fn the_default_egress_socket_never_fragments() {
    let target: SocketAddress = "127.0.0.1:9".parse().unwrap();
    let EstablishedClientConnection { conn, .. } = UdpConnector::new()
        .serve(ConnectRequest::new(target.into()))
        .await
        .unwrap();
    assert!(!conn.capabilities().may_fragment);
}

#[tokio::test]
async fn a_keyer_of_its_own_decides_the_principal() {
    // Tenants named by a header a trusted proxy in front sets; no header, no tunnel.
    let limits = ConnectUdpLimits::new()
        .with_max_tunnels_per_principal(1)
        .with_keyer(|request: &Request| {
            Ok::<_, BoxError>(
                request
                    .headers()
                    .get("x-tenant")
                    .and_then(|tenant| tenant.to_str().ok())
                    .map(str::to_owned),
            )
        });
    let service = service()
        .with_policy(DestinationScopePolicy::allow_private())
        .with_connector(TestConnector::default())
        .with_limits(limits.clone());
    let for_tenant = |tenant: Option<&'static str>| {
        let mut request = request(Version::HTTP_2);
        if let Some(tenant) = tenant {
            request
                .headers_mut()
                .insert("x-tenant", HeaderValue::from_static(tenant));
        }
        request
    };

    let response = service.serve(for_tenant(None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        proxy_error(&response),
        Some(("proxy.example".into(), ProxyErrorType::HttpRequestDenied))
    );

    let held = limits.try_acquire("acme".to_owned()).unwrap();
    let response = service.serve(for_tenant(Some("acme"))).await.unwrap();
    assert_eq!(
        proxy_error(&response),
        Some((
            "proxy.example".into(),
            ProxyErrorType::ConnectionLimitReached
        ))
    );
    let response = service.serve(for_tenant(Some("globex"))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    drop(held);
    assert_released(&limits).await;
}

#[tokio::test]
async fn a_failing_keyer_refuses_with_an_internal_error() {
    let limits = ConnectUdpLimits::new()
        .with_max_tunnels_per_principal(1)
        .with_keyer(|_: &Request| Err::<Option<u64>, BoxError>("no key store".into()));
    let response = service()
        .with_limits(limits.clone())
        .serve(request(Version::HTTP_3))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        proxy_error(&response),
        Some(("proxy.example".into(), ProxyErrorType::ProxyInternalError))
    );
    assert_no_header_mentions(&response, &["no key store"]);
    assert_eq!(limits.live_tunnels(), 0);
}

#[tokio::test]
async fn without_per_principal_limits_the_keyer_is_never_asked() {
    // Only a total cap: no principal is needed, so a keyer without a key does not refuse.
    let asked = Arc::new(AtomicUsize::new(0));
    let counted = asked.clone();
    let limits = ConnectUdpLimits::new()
        .with_max_tunnels(1)
        .with_keyer(move |_: &Request| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok::<Option<u64>, BoxError>(None)
        });
    let response = service()
        .with_policy(DestinationScopePolicy::allow_private())
        .with_connector(TestConnector::default())
        .with_limits(limits.clone())
        .serve(request(Version::HTTP_2))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(asked.load(Ordering::SeqCst), 0);
    assert_released(&limits).await;
}

#[cfg(feature = "opentelemetry")]
mod metrics {
    use std::time::Duration;

    use rama_core::{ServiceInput, bytes::Bytes, service::service_fn};
    use rama_http::{
        datagram::SessionEvent,
        io::upgrade::{self, Upgraded},
    };
    use rama_udp::UdpPacketSocket;
    use tokio::{io::DuplexStream, net::UdpSocket};

    use super::*;
    use crate::connect_udp::telemetry::tests::metrics::{Collector, kv};

    type Client = HttpDatagramSession<ServiceInput<DuplexStream>>;

    /// Open a tunnel to `target` as user `john`, upgraded over an in-memory stream: the client's
    /// end of it.
    async fn open(
        service: &impl Service<Request, Output = Response, Error = Infallible>,
        target: SocketAddress,
    ) -> Client {
        let proxy = ProxyAddress::try_from("masque://proxy.example:443").unwrap();
        let target = ConnectUdpTarget::new(
            Host::Address(target.ip_addr),
            NonZeroU16::new(target.port).unwrap(),
        );
        let request = connect_udp_request(&proxy, &target, Version::HTTP_2).unwrap();
        request
            .extensions()
            .insert(UserId::Username("john".to_owned()));
        let (pending, on_upgrade) = upgrade::pending();
        request.extensions().insert(on_upgrade);
        let response = service.serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let (proxy_end, client_end) = tokio::io::duplex(64 * 1024);
        pending.fulfill(Upgraded::new(ServiceInput::new(proxy_end), Bytes::new()));
        HttpDatagramSession::with_config(ServiceInput::new(client_end), session_config())
    }

    async fn target() -> (UdpSocket, SocketAddress) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap().into();
        (socket, address)
    }

    fn context0(payload: &[u8]) -> Bytes {
        let mut encoded = vec![0x00];
        encoded.extend_from_slice(payload);
        Bytes::from(encoded)
    }

    /// Wait until the tunnels ended with `reason` add up to `count`.
    async fn ended(collector: &Collector, reason: &'static str, count: i64) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while collector.value("connect_udp.tunnel.closed", &[kv("reason", reason)]) < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no {count} tunnel(s) ended with {reason}"));
    }

    fn proxy(collector: &Collector, exec: Executor) -> ConnectUdpService {
        ConnectUdpService::try_new(exec, None)
            .unwrap()
            .with_policy(DestinationScopePolicy::allow_private())
            .with_limits(ConnectUdpLimits::new().with_max_tunnels_per_principal(8))
            .with_metrics(collector.metrics())
    }

    #[tokio::test]
    async fn a_tunnel_is_recorded_from_its_opening_to_its_end() {
        let collector = Collector::new();
        let service = proxy(&collector, Executor::default());
        let (target, address) = target().await;
        let mut client = open(&service, address).await;
        let user = kv("principal.kind", "user");
        assert_eq!(
            collector.value("connect_udp.tunnels.active", std::slice::from_ref(&user)),
            1
        );

        client.send_datagram(context0(b"ping")).await.unwrap();
        let mut buffer = [0; 64];
        let (len, from) = target.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..len], b"ping");
        target.send_to(b"pong!", from).await.unwrap();
        let Some(SessionEvent::Datagram { payload, .. }) = client.recv().await.unwrap() else {
            panic!("no datagram");
        };
        assert_eq!(payload, context0(b"pong!"));
        assert_eq!(
            collector.value("connect_udp.tunnel.closed", &[]),
            0,
            "recorded at its end only"
        );

        client.close().await.unwrap();
        ended(&collector, "closed", 1).await;
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 0);
        assert_eq!(
            collector.value("connect_udp.tunnel.closed", std::slice::from_ref(&user)),
            1
        );
        let datagrams =
            |name, outcome| collector.value(name, &[user.clone(), kv("outcome", outcome)]);
        assert_eq!(
            datagrams("connect_udp.datagrams.from_client", "forwarded"),
            1
        );
        assert_eq!(datagrams("connect_udp.datagrams.to_client", "returned"), 1);
        assert_eq!(collector.value("connect_udp.datagrams.from_client", &[]), 1);
        assert_eq!(collector.value("connect_udp.datagrams.to_client", &[]), 1);
        for (name, bytes) in [
            ("connect_udp.bytes.received", 4),
            ("connect_udp.bytes.forwarded", 4),
            ("connect_udp.bytes.returned", 5),
        ] {
            assert_eq!(
                collector.value(name, std::slice::from_ref(&user)),
                bytes,
                "{name}"
            );
        }
        assert!(
            collector
                .points("connect_udp.bytes.returned_dropped")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_failed_upgrade_and_a_failed_relay_are_recorded_as_such() {
        let collector = Collector::new();
        // Accepted, but never served by a connection that can upgrade.
        let response = proxy(&collector, Executor::default())
            .serve(request(Version::HTTP_2))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        ended(&collector, "upgrade_failed", 1).await;

        let failing = proxy(&collector, Executor::default()).with_relay(service_fn(
            |_: BridgeIo<ConnectUdpSocket, UdpPacketSocket>| async {
                Err::<(), BoxError>(BoxError::from("relay failed"))
            },
        ));
        let (_target, address) = target().await;
        let _client = open(&failing, address).await;
        ended(&collector, "relay_failed", 1).await;
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 0);
        assert_eq!(collector.value("connect_udp.tunnel.closed", &[]), 2);
    }

    #[tokio::test]
    async fn a_tunnel_cut_by_graceful_shutdown_is_cancelled() {
        let collector = Collector::new();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let shutdown = rama_core::graceful::Shutdown::new(async move {
            _ = stopped.await;
        });
        let service = proxy(&collector, Executor::graceful(shutdown.guard()));
        let (_target, address) = target().await;
        let _client = open(&service, address).await;
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 1);
        // The service's executor holds a guard of its own.
        drop(service);
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), shutdown.shutdown())
            .await
            .expect("the tunnel lets the shutdown finish");
        ended(&collector, "cancelled", 1).await;
        assert_eq!(collector.value("connect_udp.tunnel.closed", &[]), 1);
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 0);
    }

    /// The tunnel is recorded when its task ends, not when the last of its handles goes.
    #[tokio::test]
    async fn a_cancelled_tunnel_is_recorded_while_its_relay_keeps_a_sender() {
        let collector = Collector::new();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let shutdown = rama_core::graceful::Shutdown::new(async move {
            _ = stopped.await;
        });
        let kept = Arc::new(Mutex::new(None));
        let relay = service_fn({
            let kept = kept.clone();
            move |io: BridgeIo<ConnectUdpSocket, UdpPacketSocket>| {
                *kept.lock() = Some(io.0.create_sender());
                std::future::pending::<Result<(), BoxError>>()
            }
        });
        let service = proxy(&collector, Executor::graceful(shutdown.guard())).with_relay(relay);
        let (_target, address) = target().await;
        let _client = open(&service, address).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while kept.lock().is_none() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the relay runs");
        drop(service);
        stop.send(()).unwrap();

        ended(&collector, "cancelled", 1).await;
        assert!(kept.lock().is_some(), "the sender lives on");
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 0);
        drop(kept.lock().take());
        tokio::time::timeout(Duration::from_secs(10), shutdown.shutdown())
            .await
            .expect("the tunnel's pump ends once its last sender goes");
        assert_eq!(collector.value("connect_udp.tunnel.closed", &[]), 1, "once");
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 0);
    }

    #[tokio::test]
    async fn refusals_are_recorded_by_reason_and_foreign_requests_not_at_all() {
        let collector = Collector::new();
        // The default policy refuses loopback targets.
        let service = service().with_metrics(collector.metrics());
        let response = service.serve(request(Version::HTTP_2)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let mut elsewhere = request(Version::HTTP_2);
        *elsewhere.uri_mut() = "https://proxy.example/elsewhere".parse().unwrap();
        assert_eq!(
            service.serve(elsewhere).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let full = service
            .clone()
            .with_limits(ConnectUdpLimits::new().with_max_tunnels(0));
        full.serve(request(Version::HTTP_2)).await.unwrap();

        let refused = "connect_udp.tunnel.refused";
        assert_eq!(
            collector.value(refused, &[kv("reason", "destination_ip_prohibited")]),
            1
        );
        assert_eq!(
            collector.value(refused, &[kv("reason", "connection_limit_reached")]),
            1
        );
        assert_eq!(collector.value(refused, &[]), 2);
        assert!(collector.points("connect_udp.tunnels.active").is_empty());
    }
}
