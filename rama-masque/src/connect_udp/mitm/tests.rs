use super::*;
use rama_core::{io::BridgeIo, service::service_fn};
use rama_http::{
    Body,
    datagram::handshake::{capsule_response, prepare_capsule_request},
    header,
    io::upgrade::Upgraded,
    proto::ext::Protocol,
};
use std::time::Duration;

#[tokio::test]
async fn request_policy_selects_sessions_and_preserves_matcher_metadata() {
    use rama_core::{extensions::Extension, matcher::match_fn};
    #[derive(Debug, Clone, Extension)]
    struct SelectedDestination;
    let policy = match_fn(|ext: Option<&Extensions>, request: &Request| {
        let selected = request.uri().host_str().as_deref() == Some("proxy.example")
            && request.headers().get("x-allow-tunnel").is_some();
        if selected && let Some(ext) = ext {
            ext.insert(SelectedDestination);
        }
        selected
    });
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        for allowed in [false, true] {
            let mut input = request(version);
            if allowed {
                input
                    .headers_mut()
                    .insert("x-allow-tunnel", "yes".parse().unwrap());
            }
            let service = ConnectUdpMitmLayer::new()
                .with_matcher(policy.clone())
                .into_layer(service_fn(move |request: Request| async move {
                    assert_eq!(request.extensions().contains::<HttpDatagrams>(), allowed);
                    assert_eq!(
                        request.extensions().contains::<SelectedDestination>(),
                        allowed
                    );
                    Ok::<_, BoxError>(
                        capsule_response::<Body>(version, &Protocol::CONNECT_UDP).unwrap(),
                    )
                }));
            assert_eq!(
                service
                    .serve(input)
                    .await
                    .unwrap()
                    .extensions()
                    .contains::<HttpDatagrams>(),
                allowed
            );
            if version != Version::HTTP_3 {
                let mut input = request(version);
                if allowed {
                    input
                        .headers_mut()
                        .insert("x-allow-tunnel", "yes".parse().unwrap());
                }
                // The selected service is caller-owned; it need not be HttpDatagramRelay.
                let matched = ConnectUdpRelayRequestMatcher::new("custom relay")
                    .with_matcher(policy.clone())
                    .match_service(input)
                    .await
                    .unwrap();
                assert_eq!(
                    matched.input.extensions().contains::<HttpDatagrams>(),
                    allowed
                );
                if let Some(response_matcher) = matched.service {
                    assert!(allowed);
                    let selected = response_matcher
                        .into_match_service(
                            capsule_response::<Body>(version, &Protocol::CONNECT_UDP).unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(selected.service, Some("custom relay"));
                } else {
                    assert!(!allowed);
                }
            }
        }
    }
}

#[tokio::test]
async fn http_policy_can_refuse_selected_sessions_before_egress() {
    use rama_core::{layer::HijackLayer, matcher::match_fn};
    let service = (
        ConnectUdpMitmLayer::new(),
        HijackLayer::new(
            match_fn(|request: &Request| {
                request.uri().host_str().as_deref() == Some("proxy.example")
            }),
            service_fn(|_: Request| async {
                Ok::<_, BoxError>(
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::empty())
                        .unwrap(),
                )
            }),
        ),
    )
        .into_layer(service_fn(|_: Request| async {
            Err::<Response, BoxError>("denied session reached upstream".into())
        }));
    let response = service.serve(request(Version::HTTP_3)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!response.extensions().contains::<HttpDatagrams>());
}

fn request(version: Version) -> Request {
    let mut request = Request::get("https://proxy.example/custom?target=opaque")
        .version(version)
        .header(header::HOST, "proxy.example")
        .body(Body::empty())
        .unwrap();
    prepare_capsule_request(&mut request, Protocol::CONNECT_UDP).unwrap();
    request
}

#[tokio::test]
async fn custom_templates_and_each_carrier_are_selected_only_after_acceptance() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let service =
            ConnectUdpMitmLayer::new().into_layer(service_fn(move |request: Request| async move {
                assert!(request.extensions().contains::<HttpDatagrams>());
                assert_eq!(
                    request.uri().to_string(),
                    "https://proxy.example/custom?target=opaque"
                );
                Ok::<_, BoxError>(
                    capsule_response::<Body>(version, &Protocol::CONNECT_UDP).unwrap(),
                )
            }));
        let response = service.serve(request(version)).await.unwrap();
        assert!(response.extensions().contains::<HttpDatagrams>());
        if version != Version::HTTP_3 {
            let selected = ConnectUdpRelayRequestMatcher::default_with_exec(Executor::new())
                .match_service(request(version))
                .await
                .unwrap();
            assert!(selected.input.extensions().contains::<HttpDatagrams>());
            let response = selected
                .service
                .unwrap()
                .match_service(capsule_response::<Body>(version, &Protocol::CONNECT_UDP).unwrap())
                .await
                .unwrap();
            assert!(response.service.is_some());
        }
    }
}

#[tokio::test]
async fn successful_tunnel_responses_preserve_ignorable_fields() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        for (name, value) in [
            (header::CONTENT_LENGTH, "0"),
            (header::CONTENT_LENGTH, "123"),
            (header::TRANSFER_ENCODING, "chunked"),
            (header::CONTENT_TYPE, "text/plain"),
        ] {
            let response_name = name.clone();
            let response = move || {
                let mut response =
                    capsule_response::<Body>(version, &Protocol::CONNECT_UDP).unwrap();
                response
                    .headers_mut()
                    .insert(response_name.clone(), value.parse().unwrap());
                response
            };
            let service_response = response.clone();
            let service = ConnectUdpMitmLayer::new().into_layer(service_fn(move |_: Request| {
                std::future::ready(Ok::<_, BoxError>(service_response()))
            }));
            let output = service.serve(request(version)).await.unwrap();
            assert!(output.extensions().self_contains::<HttpDatagrams>());
            assert_eq!(output.headers().get(&name).unwrap(), value);
            if version != Version::HTTP_3 {
                let matcher = ConnectUdpRelayRequestMatcher::new("relay")
                    .match_service(request(version))
                    .await
                    .unwrap()
                    .service
                    .unwrap();
                for output in [
                    matcher.match_service(response()).await.unwrap(),
                    matcher.into_match_service(response()).await.unwrap(),
                ] {
                    assert_eq!(output.service, Some("relay"));
                    assert!(output.input.extensions().self_contains::<HttpDatagrams>());
                    assert_eq!(output.input.headers().get(&name).unwrap(), value);
                }
            }
        }
    }
}

#[tokio::test]
async fn refusals_are_not_marked_and_invalid_successes_fail() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        for status in [
            StatusCode::FORBIDDEN,
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            StatusCode::NO_CONTENT,
            StatusCode::RESET_CONTENT,
            StatusCode::PARTIAL_CONTENT,
        ] {
            let service =
                ConnectUdpMitmLayer::new().into_layer(service_fn(move |_: Request| async move {
                    Ok::<_, BoxError>(
                        Response::builder()
                            .version(version)
                            .status(status)
                            .body(Body::empty())
                            .unwrap(),
                    )
                }));
            let result = service.serve(request(version)).await;
            if status.is_success() {
                result.unwrap_err();
            } else {
                assert!(!result.unwrap().extensions().contains::<HttpDatagrams>());
            }
        }
    }
}

#[tokio::test]
async fn ordinary_requests_are_untouched_and_request_errors_belong_to_the_proxy() {
    let matcher = ConnectUdpRelayRequestMatcher::default_with_exec(Executor::new());
    assert!(
        matcher
            .match_service(Request::new(Body::empty()))
            .await
            .unwrap()
            .service
            .is_none()
    );
    let mut malformed = request(Version::HTTP_2);
    malformed
        .headers_mut()
        .insert(header::CONTENT_LENGTH, "4".parse().unwrap());
    assert!(
        matcher
            .match_service(malformed)
            .await
            .unwrap()
            .service
            .is_some()
    );
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let mut malformed = request(version);
        malformed
            .headers_mut()
            .insert(header::CONTENT_LENGTH, "0".parse().unwrap());
        let service =
            ConnectUdpMitmLayer::new().into_layer(service_fn(|request: Request| async move {
                let error = super::super::ConnectUdpRequestMatcher::try_new(None)
                    .unwrap()
                    .match_request(&request)
                    .unwrap_err();
                Ok::<_, BoxError>(
                    Response::builder()
                        .status(error.status().unwrap())
                        .body(Body::empty())
                        .unwrap(),
                )
            }));
        let response = service.serve(malformed).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.extensions().self_contains::<HttpDatagrams>());
    }
}

#[tokio::test]
async fn selected_h1_and_h2_relays_forward_capsules_and_abort_malformed_streams() {
    use rama_core::{ServiceInput, bytes::Bytes, io::AbortIo};
    use rama_http::{
        datagram::{HttpDatagramSession, SessionEvent, capsule::UnknownCapsules},
        proto::capsule::CapsuleType,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncWriteExt as _, duplex};
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let selected = ConnectUdpRelayRequestMatcher::default_with_exec(Executor::new())
            .match_service(request(version))
            .await
            .unwrap();
        let selected = selected
            .service
            .unwrap()
            .match_service(capsule_response::<Body>(version, &Protocol::CONNECT_UDP).unwrap())
            .await
            .unwrap()
            .service
            .unwrap();
        let (left, mut client_io) = duplex(32);
        let (right, origin) = duplex(32);
        let aborted = Arc::new(AtomicUsize::new(0));
        let left = ServiceInput::new(left);
        let right = ServiceInput::new(right);
        for io in [&left, &right] {
            let aborted = aborted.clone();
            io.extensions().insert(AbortIo::new(move || {
                aborted.fetch_add(1, Ordering::SeqCst);
            }));
        }
        let relay = tokio::spawn(async move {
            selected
                .serve(BridgeIo(
                    Upgraded::new(left, Bytes::new()),
                    Upgraded::new(right, Bytes::new()),
                ))
                .await
        });
        let mut config = super::super::session_config();
        config.capsules.unknown = UnknownCapsules::Forward;
        let mut client =
            HttpDatagramSession::with_config(ServiceInput::new(&mut client_io), config.clone());
        let mut origin = HttpDatagramSession::with_config(ServiceInput::new(origin), config);
        client
            .send_datagram(Bytes::from_static(b"\0payload"))
            .await
            .unwrap();
        assert!(
            matches!(origin.recv().await.unwrap(), Some(SessionEvent::Datagram { payload, .. }) if payload == b"\0payload"[..])
        );
        let unknown = CapsuleType::new(0x4242).unwrap();
        origin
            .send_capsule(unknown, Bytes::from_static(b"unknown"))
            .await
            .unwrap();
        assert!(
            matches!(client.recv().await.unwrap(), Some(SessionEvent::UnknownCapsule(header)) if header.ty == unknown)
        );
        assert_eq!(
            client.recv().await.unwrap(),
            Some(SessionEvent::UnknownCapsuleData(Bytes::from_static(
                b"unknown"
            )))
        );
        // A truncated reliable capsule is a framing error, not a lost UDP packet.
        drop(client);
        client_io.write_all(&[0, 3, 0, 1]).await.unwrap();
        client_io.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(aborted.load(Ordering::SeqCst), 2);
    }
}
