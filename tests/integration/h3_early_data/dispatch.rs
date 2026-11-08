//! Opt-in dispatch uses actual per-stream receipt and matching settings.
use super::*;
use rama::http::proto::h3::{FrameHeader, FrameType};
use rama::http::{
    layer::validate_request::early_data::require_confirmed,
    proto::ext::early_data::EarlyDataReceived,
};
use rama_core::bytes::BytesMut;
use rama_crypto::cert::{CertificateAuthorityData, LeafCertRequest, SelfSignedCaConfig};
use rama_http_core::{
    h3::qpack::{Encoder, EncoderConfig},
    server::conn::HeaderReadTimeout,
};
use rama_tls::{
    client::{ClientAuth, ClientAuthData},
    server::ClientVerifyMode,
};

#[derive(Clone, Copy, Debug)]
enum Dispatch {
    Enabled,
    Default,
    Mismatched,
}

#[tokio::test]
async fn dispatch_requires_opt_in_and_matching_context_and_retains_receipt() {
    for provider in Provider::enabled() {
        for dispatch in [Dispatch::Enabled, Dispatch::Default, Dispatch::Mismatched] {
            timeout(LIMIT, receipt(provider, dispatch)).await.unwrap();
        }
    }
}

async fn receipt(provider: Provider, dispatch: Dispatch) {
    let fixture = Fixture::new(provider, Version::V1).await;
    fixture.warm().await;
    fixture.gate.hold();
    let (client, server) = fixture.early_pair().await;
    let mut config = Config {
        early_dispatch: !matches!(dispatch, Dispatch::Default),
        ..Config::default()
    };
    if matches!(dispatch, Dispatch::Mismatched) {
        config.decoder.max_field_section_size /= 2;
    }
    let (mut receiver, server_driver) = server::handshake(server.clone(), config).unwrap();
    let _server_driver = Task::spawn(server_driver.run());
    let (sender, client_driver) =
        client::handshake::<Body, _>(client.clone(), early_config(), WeakScope::detached())
            .unwrap();
    let _client_driver = Task::spawn(client_driver.run());
    let mut early_sender = sender.clone();
    let sending =
        Task::spawn(async move { early_sender.send_request(request(Method::GET, "")).await });
    let stream = receiver.accept().await.unwrap();
    let mut resolving = pin!(stream.resolve());
    let resolved = if matches!(dispatch, Dispatch::Enabled) {
        let resolved = timeout(PROBE, &mut resolving)
            .await
            .expect("matching opt-in should dispatch early")
            .unwrap();
        assert!(!server.is_handshake_confirmed());
        let received = resolved
            .0
            .extensions()
            .get_ref::<EarlyDataReceived>()
            .unwrap();
        timeout(PROBE, received.confirmed()).await.unwrap_err();
        fixture.gate.release();
        received.confirmed().await.unwrap();
        resolved
    } else {
        assert!(timeout(PROBE, &mut resolving).await.is_err());
        fixture.gate.release();
        resolving.await.unwrap()
    };
    assert!(resolved.0.extensions().contains::<EarlyDataReceived>());
    assert!(server.is_handshake_confirmed());
    let receipt = resolved
        .0
        .extensions()
        .get_ref::<EarlyDataReceived>()
        .unwrap()
        .clone();
    let buffered_request = resolved.0;
    respond(resolved.1).await;
    assert_eq!(
        sending.join().await.unwrap().status(),
        rama::http::StatusCode::OK
    );

    // A later request on the same resumed connection must not inherit receipt.
    let mut sender = sender;
    let sending = Task::spawn(async move { sender.send_request(request(Method::GET, "")).await });
    let (request, response) = receiver.accept().await.unwrap().resolve().await.unwrap();
    assert!(!request.extensions().contains::<EarlyDataReceived>());
    respond(response).await;
    assert_eq!(
        sending.join().await.unwrap().status(),
        rama::http::StatusCode::OK
    );
    server.close(0u32, b"draining after confirmation");
    receipt.confirmed().await.unwrap();
    require_confirmed(buffered_request).await.unwrap();
}

#[tokio::test]
async fn matching_context_never_bypasses_the_service_alpn() {
    for provider in Provider::enabled() {
        timeout(LIMIT, async {
            let fixture = Fixture::new(provider, Version::V1).await;
            fixture.warm().await;
            fixture.gate.hold();
            let (client, server) = fixture.early_pair().await;
            let _sending = send(client, early_config(), request(Method::GET, ""));
            let config = Config {
                early_dispatch: true,
                application_protocol: b"another-protocol".as_slice().into(),
                ..Config::default()
            };
            let (mut receiver, driver) = server::handshake(server, config).unwrap();
            let _driver = Task::spawn(driver.run());
            let result = timeout(PROBE, receiver.accept().await.unwrap().resolve())
                .await
                .unwrap();
            assert!(result.is_err(), "the wrong ALPN reached the service");
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn early_dispatch_retains_admission_limits_cancellation_and_head_deadlines() {
    for provider in Provider::enabled() {
        timeout(LIMIT, async {
            let fixture = Fixture::new(provider, Version::V1).await;
            fixture.warm().await;
            fixture.gate.hold();
            let (client, server) = fixture.early_pair().await;
            let (mut first, _first_reply) = client.open_bi().await.unwrap();
            first.write_all(&[1]).await.unwrap(); // HEADERS without its length/payload.
            let (mut second, _second_reply) = client.open_bi().await.unwrap();
            second.write_all(&[1]).await.unwrap();
            let config = Config {
                early_dispatch: true,
                max_requests: 1,
                header_read_timeout: Some(HeaderReadTimeout {
                    grace: Duration::from_millis(20),
                    min_rate: u32::MAX,
                    ceiling: Duration::from_millis(100),
                }),
                ..Config::default()
            };
            let (mut receiver, driver) = server::handshake(server, config).unwrap();
            let _driver = Task::spawn(driver.run());
            let first = receiver.accept().await.unwrap();
            let mut accepting = Box::pin(receiver.accept());
            assert!(
                timeout(Duration::from_millis(20), &mut accepting)
                    .await
                    .is_err()
            );
            drop(first);
            let second = timeout(PROBE, accepting).await.unwrap().unwrap();
            assert!(timeout(PROBE * 2, second.resolve()).await.unwrap().is_err());
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn early_request_confirmation_wait_ends_at_the_transport_deadline() {
    for provider in Provider::enabled() {
        timeout(LIMIT, async {
            let mut config = EndpointConfig::try_with_rand_key().unwrap();
            config.handshake_timeout(Duration::from_secs(1)).unwrap();
            // Resumption tokens otherwise grant the endpoint's extra allowance.
            config.set_handshake_allowance(Duration::ZERO);
            let fixture =
                Fixture::with_configs(provider, Version::V1, 100, Some(config), Config::default())
                    .await;
            fixture.warm().await;
            fixture.gate.hold();
            let (client, server) = fixture.early_pair().await;
            let _sending = send(client, early_config(), request(Method::GET, ""));
            let config = Config {
                early_dispatch: true,
                ..Config::default()
            };
            let (mut receiver, driver) = server::handshake(server.clone(), config).unwrap();
            let _driver = Task::spawn(driver.run());
            let (request, _response) = receiver.accept().await.unwrap().resolve().await.unwrap();
            let receipt = request.extensions().get_ref::<EarlyDataReceived>().unwrap();
            assert!(
                timeout(Duration::from_secs(3), receipt.confirmed())
                    .await
                    .unwrap()
                    .is_err()
            );
            assert!(server.close_reason().is_some());
            assert!(!server.is_handshake_confirmed());
            assert_eq!(
                require_confirmed(request).await.unwrap_err().status(),
                rama::http::StatusCode::TOO_EARLY
            );
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn confirmed_dispatch_checks_alpn_even_before_the_driver_runs() {
    for provider in Provider::enabled() {
        timeout(LIMIT, async {
            let fixture = Fixture::new(provider, Version::V1).await;
            let (client, server) = fixture.full_pair().await;
            let _sending = send(client, Config::default(), request(Method::GET, ""));
            let config = Config {
                application_protocol: b"another-protocol".as_slice().into(),
                ..Config::default()
            };
            let (mut receiver, _driver) = server::handshake(server, config).unwrap();
            let result = timeout(PROBE, receiver.accept().await.unwrap().resolve())
                .await
                .unwrap();
            assert!(
                result.is_err(),
                "dispatch must not race the driver's ALPN check"
            );
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn unsafe_methods_and_extended_connect_wait_even_with_early_dispatch() {
    for provider in Provider::enabled() {
        for method in [Method::GET, Method::POST, Method::CONNECT] {
            timeout(LIMIT, dispatch_method(provider, method))
                .await
                .unwrap();
        }
    }
}

async fn dispatch_method(provider: Provider, method: Method) {
    let config = Config {
        early_dispatch: true,
        extended_connect: true,
        ..Config::default()
    };
    let fixture = Fixture::with_configs(provider, Version::V1, 100, None, config.clone()).await;
    let (warm_client, warm_server) = fixture.full_pair().await;
    let (mut warm_receiver, driver) = server::handshake(warm_server, config.clone()).unwrap();
    let _warm_driver = Task::spawn(driver.run());
    let warm = send(
        warm_client.clone(),
        Config::default(),
        request(Method::GET, ""),
    );
    serve(warm_receiver.accept().await.unwrap()).await;
    assert_eq!(warm.join().await.unwrap(), "served");
    warm_client.close(0u32, b"warm complete");
    fixture.gate.hold();
    let (client, server) = fixture.early_pair().await;
    let (mut output, _input) = client.open_bi().await.unwrap();
    let mut fields = vec![
        (b":method".as_slice(), method.as_str().as_bytes()),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
        (b":path", b"/early"),
    ];
    if method == Method::CONNECT {
        fields.push((b":protocol", b"connect-udp"));
    }
    let encoded = Encoder::new(EncoderConfig {
        max_table_capacity: 0,
        max_blocked_streams: 0,
        target_capacity: 0,
        ..Default::default()
    })
    .encode(u64::from(output.id()), fields)
    .unwrap();
    let mut bytes = BytesMut::new();
    FrameHeader::new(FrameType::HEADERS, encoded.len() as u64)
        .encode(&mut bytes)
        .unwrap();
    bytes.extend_from_slice(&encoded);
    output.write_all(&bytes).await.unwrap();
    output.finish().unwrap();
    let (mut receiver, _driver) = server::handshake(server.clone(), config).unwrap();
    // Static QPACK needs no peer driver; omitting it also isolates dispatch from SETTINGS.
    let mut resolving = pin!(receiver.accept().await.unwrap().resolve());
    let (request, _response) = if method.is_safe() {
        let result = timeout(PROBE, &mut resolving).await.unwrap().unwrap();
        assert!(!server.is_handshake_confirmed());
        fixture.gate.release();
        result
    } else {
        assert!(timeout(PROBE, &mut resolving).await.is_err());
        assert!(!server.is_handshake_confirmed());
        fixture.gate.release();
        let result = resolving.await.unwrap();
        assert!(server.is_handshake_confirmed());
        result
    };
    assert_eq!(request.method(), &method);
    assert!(request.extensions().contains::<EarlyDataReceived>());
}

#[tokio::test]
async fn client_identity_is_available_after_waited_and_default_dispatch() {
    for provider in Provider::enabled() {
        for early_dispatch in [false, true] {
            timeout(LIMIT, async {
                let mut fixture = Fixture::new(provider, Version::V1).await;
                let identity =
                    ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
                let authority =
                    CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
                let (cert_chain, private_key) = authority
                    .issue_client_leaf(LeafCertRequest::default())
                    .unwrap();
                let expected_leaf = cert_chain[0].clone();
                let server_tls = tls_server(&identity)
                    .with_client_verify(ClientVerifyMode::ClientAuth(
                        authority.certificate_chain().to_vec(),
                    ))
                    .with_store_client_cert_chain(true);
                fixture.client_tls = TlsClientConfig::new()
                    .with_alpn([b"h3".as_slice().into()].into_iter().collect())
                    .try_with_server_trust_anchors(identity.cert_chain)
                    .unwrap()
                    .with_client_auth(ClientAuth::Single(ClientAuthData {
                        cert_chain,
                        private_key,
                    }));
                let (mut client_config, mut server_config) =
                    provider.configurations(&fixture.client_tls, &server_tls, &Config::default());
                client_config.set_transport_config(fixture.transport.clone());
                server_config.set_transport_config(fixture.transport.clone());
                fixture.client_config = client_config;
                fixture.server.set_server_config(Some(server_config));
                fixture.warm().await;
                fixture.gate.hold();
                let (client, server) = fixture.early_pair().await;
                let (mut receiver, driver) = server::handshake(
                    server.clone(),
                    Config {
                        early_dispatch,
                        ..Config::default()
                    },
                )
                .unwrap();
                let _driver = Task::spawn(driver.run());
                let sending = send(client, early_config(), request(Method::GET, ""));
                let stream = receiver.accept().await.unwrap();
                let mut resolving = pin!(stream.resolve());
                let (request, response) = if early_dispatch {
                    let resolved = timeout(PROBE, &mut resolving).await.unwrap().unwrap();
                    assert!(!server.is_handshake_confirmed());
                    assert!(
                        server
                            .extensions()
                            .get_ref::<NegotiatedTlsParameters>()
                            .unwrap()
                            .peer_certificate_chain
                            .is_none()
                    );
                    let received = resolved
                        .0
                        .extensions()
                        .get_ref::<EarlyDataReceived>()
                        .unwrap();
                    timeout(PROBE, received.confirmed()).await.unwrap_err();
                    fixture.gate.release();
                    received.confirmed().await.unwrap();
                    resolved
                } else {
                    assert!(timeout(PROBE, &mut resolving).await.is_err());
                    fixture.gate.release();
                    resolving.await.unwrap()
                };
                assert!(request.extensions().contains::<EarlyDataReceived>());
                assert!(server.is_handshake_confirmed());
                assert_eq!(
                    server
                        .extensions()
                        .get_ref::<NegotiatedTlsParameters>()
                        .unwrap()
                        .peer_certificate_chain
                        .as_ref()
                        .unwrap()[0],
                    expected_leaf
                );
                respond(response).await;
                assert_eq!(sending.join().await.unwrap(), "served");
            })
            .await
            .unwrap();
        }
    }
}
