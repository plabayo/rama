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
use crate::connect_udp::{ConnectUdpAction, ConnectUdpRule, ConnectUdpRules, connect_udp_request};

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
