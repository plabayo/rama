use std::num::NonZeroU16;

use rama_http::headers::CapsuleProtocol;
use rama_net::address::Host;

use super::*;

fn target(host: &str, port: u16) -> ConnectUdpTarget {
    ConnectUdpTarget::new(
        match host.parse() {
            Ok(ip) => Host::Address(ip),
            Err(_) => Host::Name(host.parse().unwrap()),
        },
        NonZeroU16::new(port).unwrap(),
    )
}

fn proxy(s: &str) -> ProxyAddress {
    s.parse().unwrap()
}

const VERSIONS: [Version; 3] = [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3];

#[test]
fn http1_request_is_a_get_upgrade() {
    let request = connect_udp_request(
        &proxy("masque://user:pass@proxy.example:4443"),
        &target("2001:db8::42", 443),
        Version::HTTP_11,
    )
    .unwrap();
    assert_eq!(request.method(), Method::GET);
    assert_eq!(
        request.uri().to_string(),
        "https://proxy.example:4443/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
    );
    let headers = request.headers();
    assert_eq!(headers[header::UPGRADE], "connect-udp");
    assert_eq!(headers[header::HOST], "proxy.example:4443");
    assert_eq!(
        headers.typed_get::<CapsuleProtocol>(),
        Some(CapsuleProtocol::ENABLED)
    );
    assert!(headers.contains_key(header::PROXY_AUTHORIZATION));
    assert!(!headers.contains_key(header::CONTENT_LENGTH));
}

#[test]
fn http2_and_http3_requests_use_extended_connect() {
    for version in [Version::HTTP_2, Version::HTTP_3] {
        let request = connect_udp_request(
            &proxy("masque://proxy.example/masque?h={target_host}&p={target_port}"),
            &target("192.0.2.6", 53),
            version,
        )
        .unwrap();
        assert_eq!(request.method(), Method::CONNECT, "{version:?}");
        assert_eq!(
            request.uri().to_string(),
            "https://proxy.example:443/masque?h=192.0.2.6&p=53"
        );
        assert_eq!(
            request
                .extensions()
                .get_ref::<Protocol>()
                .map(|p| p.as_str()),
            Some("connect-udp")
        );
        assert!(!request.headers().contains_key(header::UPGRADE));
        assert!(!request.headers().contains_key(header::HOST));
        assert!(!request.headers().contains_key(header::PROXY_AUTHORIZATION));
    }
}

#[test]
fn refuses_non_masque_proxies_and_old_versions() {
    let t = target("example.org", 443);
    assert_eq!(
        connect_udp_request(&proxy("https://proxy.example"), &t, Version::HTTP_2).unwrap_err(),
        ConnectUdpRequestError::NotMasque
    );
    assert_eq!(
        connect_udp_request(&proxy("masque://proxy.example"), &t, Version::HTTP_10).unwrap_err(),
        ConnectUdpRequestError::UnsupportedVersion(Version::HTTP_10)
    );
}

#[test]
fn built_requests_match_on_the_proxy() {
    for (proxy_address, server_template) in [
        ("masque://proxy.example", None),
        (
            "masque://proxy.example/masque?h={target_host}&p={target_port}",
            Some("/masque?h={target_host}&p={target_port}"),
        ),
        (
            "https://proxy.example/m{?target_host,target_port}",
            Some("/m{?target_host,target_port}"),
        ),
    ] {
        let server_template = server_template.map(|t| ProxyPathTemplate::try_new(t).unwrap());
        let matcher = ConnectUdpRequestMatcher::try_new(server_template.as_ref()).unwrap();
        for host in ["192.0.2.6", "2001:db8::42", "example.org"] {
            let target = target(host, 4433);
            for version in VERSIONS {
                let request = connect_udp_request(&proxy(proxy_address), &target, version).unwrap();
                assert_eq!(
                    matcher.match_request(&request),
                    Ok(target.clone()),
                    "{proxy_address} {host} {version:?}"
                );
            }
        }
    }
}

fn h1_request(builder: impl FnOnce(&mut Request<Body>)) -> Request<Body> {
    let mut request = Request::builder()
        .version(Version::HTTP_11)
        .uri("/.well-known/masque/udp/example.org/443/")
        .header(header::HOST, "proxy.example")
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "connect-udp")
        .body(Body::empty())
        .unwrap();
    builder(&mut request);
    request
}

#[test]
fn capsule_protocol_field_values_never_refuse_a_valid_request() {
    let matcher = ConnectUdpRequestMatcher::try_new(None).unwrap();
    for values in [
        &[][..],
        &["?1"][..],
        &["?0"][..],
        &["1"][..],
        &["garbage"][..],
        &["?1;unknown=1"][..],
        &["?1", "?1"][..],
    ] {
        let request = h1_request(|request| {
            for value in values {
                request
                    .headers_mut()
                    .append("capsule-protocol", HeaderValue::from_static(value));
            }
        });
        assert_eq!(
            matcher.match_request(&request),
            Ok(target("example.org", 443)),
            "{values:?}"
        );
    }
}

#[test]
fn classifies_refusals() {
    let matcher = ConnectUdpRequestMatcher::try_new(None).unwrap();
    let cases: [(Request<Body>, ConnectUdpRequestError); 7] = [
        (
            h1_request(|r| *r.method_mut() = Method::POST),
            ConnectUdpRequestError::MalformedRequestLine,
        ),
        (
            h1_request(|r| {
                r.headers_mut()
                    .append(header::HOST, HeaderValue::from_static("other.example"));
            }),
            ConnectUdpRequestError::MalformedRequestLine,
        ),
        (
            h1_request(|r| {
                *r.uri_mut() = "/.well-known/masque/tcp/example.org/443/".parse().unwrap()
            }),
            ConnectUdpRequestError::TemplateMismatch,
        ),
        (
            h1_request(|r| {
                *r.uri_mut() = "/.well-known/masque/udp/example.org/0/".parse().unwrap()
            }),
            ConnectUdpRequestError::InvalidTarget(ConnectUdpTargetError::InvalidPort),
        ),
        (
            h1_request(|r| {
                r.headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
            }),
            ConnectUdpRequestError::Malformed(CapsuleHandshakeError::ForbiddenField(
                header::CONTENT_LENGTH,
            )),
        ),
        (
            h1_request(|r| {
                r.headers_mut()
                    .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
            }),
            ConnectUdpRequestError::NotConnectUdp,
        ),
        (
            h1_request(|r| {
                r.headers_mut().remove(header::UPGRADE);
                r.headers_mut().remove(header::CONNECTION);
            }),
            ConnectUdpRequestError::NotConnectUdp,
        ),
    ];
    for (request, expected) in cases {
        assert_eq!(
            matcher.match_request(&request),
            Err(expected.clone()),
            "{expected}"
        );
    }
    assert_eq!(
        ConnectUdpRequestError::TemplateMismatch.status(),
        Some(StatusCode::NOT_FOUND)
    );
    assert_eq!(ConnectUdpRequestError::NotConnectUdp.status(), None);
}

fn response(status: StatusCode, upgrade: Option<&'static str>) -> Response<Body> {
    let mut response = Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap();
    if let Some(upgrade) = upgrade {
        response
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static(upgrade));
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    }
    response
}

#[test]
fn validates_responses() {
    validate_connect_udp_response(
        Version::HTTP_11,
        &response(StatusCode::SWITCHING_PROTOCOLS, Some("connect-udp")),
    )
    .unwrap();
    assert_eq!(
        validate_connect_udp_response(
            Version::HTTP_11,
            &response(StatusCode::SWITCHING_PROTOCOLS, Some("websocket"))
        ),
        Err(CapsuleHandshakeError::UpgradeMismatch)
    );
    assert_eq!(
        validate_connect_udp_response(Version::HTTP_11, &response(StatusCode::OK, None)),
        Err(CapsuleHandshakeError::Unsuccessful(StatusCode::OK))
    );
    for version in [Version::HTTP_2, Version::HTTP_3] {
        validate_connect_udp_response(version, &response(StatusCode::OK, None)).unwrap();
        assert_eq!(
            validate_connect_udp_response(version, &response(StatusCode::NO_CONTENT, None)),
            Err(CapsuleHandshakeError::ForbiddenStatus(
                StatusCode::NO_CONTENT
            ))
        );
        assert_eq!(
            validate_connect_udp_response(version, &response(StatusCode::NOT_FOUND, None)),
            Err(CapsuleHandshakeError::Unsuccessful(StatusCode::NOT_FOUND))
        );
    }
}
