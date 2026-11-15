//! Server certificate checks after a server rejects Encrypted Client Hello.
//!
//! The rejecting server answers for the ECH public name: the client verifies
//! that certificate against the public name, then fails with `ECH_REJECTED`
//! so the caller can retry with the server's fresh ECH configs.

use rama_boring::{
    hpke::HpkeKey,
    pkey::PKey,
    ssl::{SslAcceptor, SslEchKeys, SslMethod},
    x509::X509,
};
use rama_core::{
    Service, ServiceInput, bytes::Bytes, extensions::ExtensionsRef, service::service_fn,
};
use rama_crypto::{
    cert::{GeneratedServerAuthConfig, generate_server_auth},
    pki_types::CertificateDer,
};
use rama_net::{
    address::{Domain, Host, HostWithPort},
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorTarget,
        EstablishedClientConnection, pool::ConnectionReuse,
    },
    tls::TargetEchConfig,
};
use rama_tls::client::{
    DistrustedServerKeys, DynTlsServerCertChainPolicy, EchRequirement, ServerCertChain,
    ServerVerifyMode, TlsClientConfig, TlsEchAccepted, TlsEncryptedClientHello,
    TlsServerCertChainPolicy, TlsServerCertPin, TlsServerCertPins, TlsServerTrust,
};

use crate::client::{BoringClientConfigExt as _, TlsConnector, TlsConnectorData, tls_connect};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::AsyncReadExt;

/// An ECHConfigList with public name `ech.com` (config id 0).
const ECH_CONFIG_LIST: &[u8] = &[
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0x00, 0x00, 0x20, 0x00, 0x20, 0xbb, 0x2f, 0x29, 0xe3, 0xe3,
    0x05, 0x7e, 0x04, 0x19, 0xd5, 0x2f, 0xc5, 0xf4, 0x41, 0x18, 0x77, 0x6f, 0x8d, 0xb6, 0x1c, 0xea,
    0x4f, 0xdf, 0x76, 0x07, 0x9b, 0x93, 0x60, 0x6c, 0x5a, 0x62, 0x48, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x03, 0x00, 0x07, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
];

/// The server's ECHConfig (config id 1), whose key cannot decrypt the list above.
const SERVER_ECH_CONFIG: &[u8] = &[
    0xfe, 0x0d, 0x00, 0x3a, 0x01, 0x00, 0x20, 0x00, 0x20, 0x7e, 0xfb, 0x5f, 0xee, 0xa2, 0xa2, 0x74,
    0xb3, 0xff, 0xfe, 0x69, 0x51, 0x9e, 0xfa, 0xe1, 0xfa, 0x49, 0x8c, 0x61, 0x2c, 0xfa, 0xd0, 0x0f,
    0x8c, 0x22, 0x87, 0x0e, 0xbc, 0xb0, 0x2d, 0x76, 0x25, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x03, 0x00, 0x07, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
];

const SERVER_ECH_KEY: &[u8] = &[
    0xa7, 0x35, 0x44, 0x24, 0x6c, 0xfe, 0xb0, 0x53, 0x4c, 0x62, 0x7e, 0xca, 0x2e, 0x11, 0x8f, 0x56,
    0x3c, 0xc0, 0x2e, 0x6a, 0xa2, 0xe7, 0xaf, 0x3a, 0x7d, 0xb4, 0x72, 0x13, 0x1e, 0x88, 0xb6, 0x85,
];

const ORIGIN: &str = "origin.example";

/// Connect to `origin.example` through a server that rejects the offered ECH
/// config and holds a certificate for the public name only. Returns the
/// client's handshake error, or `None` when the handshake completed.
async fn rejected_ech_handshake<F>(make_config: F) -> Option<String>
where
    F: FnOnce(&CertificateDer<'static>, &CertificateDer<'static>) -> TlsClientConfig,
{
    let (chain, key) = generate_server_auth(GeneratedServerAuthConfig::generated_ca_for(
        Domain::from_static("ech.com"),
    ))
    .unwrap();

    let mut ech_keys = SslEchKeys::builder().unwrap();
    ech_keys
        .add_key(
            true,
            SERVER_ECH_CONFIG,
            HpkeKey::dhkem_p256_sha256(SERVER_ECH_KEY).unwrap(),
        )
        .unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_der(&chain[0]).unwrap())
        .unwrap();
    acceptor
        .add_extra_chain_cert(X509::from_der(&chain[1]).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_der(key.secret_der()).unwrap())
        .unwrap();
    acceptor.set_ech_keys(&ech_keys.build()).unwrap();
    let acceptor = acceptor.build();

    let mut data = TlsConnectorData::try_from(
        &make_config(&chain[0], &chain[1]).with_server_name(Host::from_static(ORIGIN)),
    )
    .unwrap();
    data.config.set_ech_config_list(ECH_CONFIG_LIST).unwrap();

    let (client_io, server_io) = tokio::io::duplex(usize::MAX);
    let server = tokio::spawn(async move {
        _ = rama_boring_tokio::accept(&acceptor, server_io).await;
    });
    let outcome = tls_connect(ServiceInput::new(client_io), Some(data)).await;
    drop(server.await);
    outcome.err().map(|err| format!("{err:?}"))
}

fn platform_trusting(ca: &CertificateDer<'static>) -> TlsServerTrust {
    TlsServerTrust::platform_verifier()
        .try_with_additional_anchors([ca.clone()])
        .unwrap()
}

fn is_ech_rejected(error: Option<&str>) -> bool {
    error.is_some_and(|error| error.contains("ECH_REJECTED"))
}

#[tokio::test]
async fn platform_verification_authenticates_the_ech_public_name() {
    let error = rejected_ech_handshake(|_, ca| {
        TlsClientConfig::new().with_server_trust(platform_trusting(ca))
    })
    .await;
    assert!(is_ech_rejected(error.as_deref()), "{error:?}");
}

#[tokio::test]
async fn an_untrusted_ech_public_name_is_not_a_rejection() {
    let error =
        rejected_ech_handshake(|_, _| TlsClientConfig::new().with_platform_verifier()).await;
    assert!(error.is_some(), "the untrusted handshake completed");
    assert!(!is_ech_rejected(error.as_deref()), "{error:?}");
}

#[tokio::test]
async fn origin_pins_do_not_apply_to_the_ech_public_name() {
    let (other, _) = generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
    let pin = TlsServerCertPin::spki_sha256_of(&other[0]).unwrap();
    for platform in [true, false] {
        let error = rejected_ech_handshake(|_, ca| {
            let config =
                TlsClientConfig::new().with_server_cert_pins(TlsServerCertPins::new(pin.clone()));
            if platform {
                config.with_server_trust(platform_trusting(ca))
            } else {
                config.try_with_server_trust_anchors([ca.clone()]).unwrap()
            }
        })
        .await;
        assert!(
            is_ech_rejected(error.as_deref()),
            "platform={platform}: {error:?}"
        );
    }
}

#[derive(Debug, Clone, Default)]
struct RecordingServerName(std::sync::Arc<std::sync::OnceLock<Option<Host>>>);

impl TlsServerCertChainPolicy for RecordingServerName {
    fn check(&self, chain: &ServerCertChain<'_>) -> Result<(), rama_core::error::BoxError> {
        _ = self.0.set(chain.server_name().cloned());
        Ok(())
    }
}

#[tokio::test]
async fn chain_policies_judge_the_ech_public_name() {
    for platform in [true, false] {
        let recorder = RecordingServerName::default();
        let policy = DynTlsServerCertChainPolicy::new(recorder.clone());
        let error = rejected_ech_handshake(|_, ca| {
            let config = TlsClientConfig::new().with_server_cert_chain_policy(policy);
            if platform {
                config.with_server_trust(platform_trusting(ca))
            } else {
                config.try_with_server_trust_anchors([ca.clone()]).unwrap()
            }
        })
        .await;
        assert!(
            is_ech_rejected(error.as_deref()),
            "platform={platform}: {error:?}"
        );
        assert_eq!(
            recorder.0.get(),
            Some(&Some(Host::from_static("ech.com"))),
            "platform={platform}"
        );

        let error = rejected_ech_handshake(|_, ca| {
            TlsClientConfig::new()
                .with_server_trust(platform_trusting(ca))
                .with_server_cert_chain_policy(DynTlsServerCertChainPolicy::new(
                    DistrustedServerKeys::new().try_with_key_of(ca).unwrap(),
                ))
        })
        .await;
        assert!(
            !is_ech_rejected(error.as_deref()),
            "a distrusted key must not authenticate retry configs: {error:?}"
        );
    }
}

// Origin pins cannot authenticate the ECH public name when PKIX is disabled,
// even if a deny-only chain policy accepts the presented certificate.
#[tokio::test]
async fn pin_only_rejected_ech_cannot_authenticate_retry_configs() {
    let (other, _) = generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
    let pin = TlsServerCertPin::spki_sha256_of(&other[0]).unwrap();
    for scoped in [false, true] {
        for accepting_policy in [false, true] {
            let error = rejected_ech_handshake(|_, _| {
                let set = rama_tls::client::TlsServerCertPinSet::new(pin.clone());
                let set = if scoped {
                    set.with_server_name(Host::from_static("origin.example"))
                } else {
                    set
                };
                let config = TlsClientConfig::new()
                    .with_server_verify(rama_tls::client::ServerVerifyMode::Disable)
                    .with_server_cert_pins(TlsServerCertPins::new(set));
                if accepting_policy {
                    config.with_server_cert_chain_policy(RecordingServerName::default())
                } else {
                    config
                }
            })
            .await;
            assert!(
                error.is_some(),
                "pin-only ECH rejection completed successfully"
            );
            assert!(
                !is_ech_rejected(error.as_deref()),
                "pin-only config authenticated ECH retry configs: scoped={scoped}, policy={accepting_policy}, {error:?}"
            );
        }
    }
}

#[tokio::test]
async fn inapplicable_pins_preserve_explicitly_disabled_ech_verification() {
    let (other, _) = generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
    let pin = TlsServerCertPin::spki_sha256_of(&other[0]).unwrap();
    let error = rejected_ech_handshake(|_, _| {
        TlsClientConfig::new()
            .with_server_verify(rama_tls::client::ServerVerifyMode::Disable)
            .with_server_cert_pins(TlsServerCertPins::new(
                rama_tls::client::TlsServerCertPinSet::new(pin)
                    .with_server_name(Host::from_static("elsewhere.example")),
            ))
    })
    .await;
    assert!(is_ech_rejected(error.as_deref()), "{error:?}");
}

#[tokio::test]
async fn endpoint_ech_is_accepted_and_required_pool_reuse_works() {
    for (required, insecure) in [(false, false), (true, false), (false, true)] {
        for rewrite_transport_target in [false, true] {
            let (chain, key) = generate_server_auth(GeneratedServerAuthConfig::generated_ca_for(
                Domain::from_static(ORIGIN),
            ))
            .unwrap();
            let mut keys = SslEchKeys::builder().unwrap();
            keys.add_key(
                true,
                SERVER_ECH_CONFIG,
                HpkeKey::dhkem_p256_sha256(SERVER_ECH_KEY).unwrap(),
            )
            .unwrap();
            let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
            acceptor
                .set_certificate(&X509::from_der(&chain[0]).unwrap())
                .unwrap();
            acceptor
                .add_extra_chain_cert(X509::from_der(&chain[1]).unwrap())
                .unwrap();
            acceptor
                .set_private_key(&PKey::private_key_from_der(key.secret_der()).unwrap())
                .unwrap();
            acceptor.set_ech_keys(&keys.build()).unwrap();
            let acceptor = acceptor.build();
            let (client_io, server_io) = tokio::io::duplex(65536);
            let server = tokio::spawn(async move {
                rama_boring_tokio::accept(&acceptor, server_io)
                    .await
                    .unwrap()
            });
            let io = std::sync::Arc::new(tokio::sync::Mutex::new(Some(client_io)));
            let transport = service_fn(move |input: ConnectRequest| {
                let io = io.clone();
                async move {
                    if rewrite_transport_target {
                        input
                            .extensions()
                            .insert(ConnectorTarget("proxy.example:8443".parse().unwrap()));
                    }
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input,
                        conn: ServiceInput::new(io.lock().await.take().unwrap()),
                    })
                }
            });
            let base = if required {
                TlsClientConfig::new()
            } else {
                let captured = crate::client::tests::emitted_with(
                    &TlsClientConfig::new().with_encrypted_client_hello(true),
                );
                TlsClientConfig::new_from_client_hello(&captured)
            };
            let mut base = base
                .try_with_server_trust_anchors([chain[1].clone()])
                .unwrap();
            if insecure {
                base.set_server_verify(rama_tls::client::ServerVerifyMode::Disable);
            }
            let connector = TlsConnector::secure(transport).with_base_config(base);
            let target: HostWithPort = "origin.example:443".parse().unwrap();
            let input = ConnectRequest::new(target.clone());
            let mut config = (SERVER_ECH_CONFIG.len() as u16).to_be_bytes().to_vec();
            config.extend_from_slice(SERVER_ECH_CONFIG);
            input
                .extensions()
                .insert(TargetEchConfig::new(target, config));
            input
                .extensions()
                .insert(rama_net::tls::TargetEchServiceBinding {
                    target: input.authority.clone(),
                    reliant: true,
                    mandatory: false,
                });
            if required {
                input.extensions().insert(EchRequirement::Required);
            }
            let established = connector.serve(input).await.unwrap();
            assert_eq!(
                established.conn.extensions().get_ref::<TlsEchAccepted>(),
                Some(&TlsEchAccepted(true))
            );
            let next = rama_core::extensions::Extensions::new();
            next.insert(EchRequirement::Required);
            let reuse = established
                .conn
                .extensions()
                .get_ref::<ConnectionReuse>()
                .unwrap();
            if insecure {
                assert!(reuse.request_key(&next).is_none());
            } else {
                assert_eq!(reuse.request_key(&next).as_ref(), reuse.key());
            }
            drop(established);
            drop(server.await.unwrap());
        }
    }
}

#[tokio::test]
async fn required_ech_missing_or_disabled_fails_before_transport() {
    for disabled in [false, true] {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let transport = service_fn({
            let calls = calls.clone();
            move |input: ConnectRequest| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    let (io, _) = tokio::io::duplex(64);
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input,
                        conn: ServiceInput::new(io),
                    })
                }
            }
        });
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        input.extensions().insert(EchRequirement::Required);
        if disabled {
            input.extensions().insert(TlsEncryptedClientHello(false));
        }
        let error = TlsConnector::secure(transport)
            .serve(input)
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            rama_net::client::ConnectionErrorKind::InvalidInput
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn required_unsupported_configs_emit_no_clienthello() {
    // Well-framed unknown version: the native library accepts the list but
    // must reject it during selection rather than send a cleartext ClientHello.
    for explicit in [false, true] {
        let config = TlsClientConfig::new()
            .with_encrypted_client_hello(true)
            .with_server_name(Host::from_static(ORIGIN));
        if explicit {
            config.as_extensions().insert(EchRequirement::Required);
        } else {
            config
                .as_extensions()
                .insert(rama_net::tls::TargetEchServiceBinding {
                    target: "origin.example:443".parse().unwrap(),
                    reliant: true,
                    mandatory: false,
                });
        }
        let target: rama_net::address::HostWithPort = "origin.example:443".parse().unwrap();
        config.as_extensions().insert(TargetEchConfig::new(
            target.clone(),
            Bytes::from_static(b"\x00\x04\xff\xff\x00\x00"),
        ));
        let mut data = TlsConnectorData::try_from(&config).unwrap();
        data.configure_target_ech(config.as_extensions(), &target)
            .unwrap();
        let (client, mut server) = tokio::io::duplex(65536);
        drop(
            tls_connect(ServiceInput::new(client), Some(data))
                .await
                .unwrap_err(),
        );
        let mut first = [0u8; 1];
        assert_eq!(server.read(&mut first).await.unwrap(), 0);
    }
}

fn retry_test_server(
    name: &'static str,
    config_id: u8,
) -> (rama_boring::ssl::SslAcceptor, CertificateDer<'static>) {
    let (chain, key) = generate_server_auth(GeneratedServerAuthConfig::generated_ca_for(
        Domain::from_static(name),
    ))
    .unwrap();
    let mut config = SERVER_ECH_CONFIG.to_vec();
    config[4] = config_id;
    let mut keys = SslEchKeys::builder().unwrap();
    keys.add_key(
        true,
        &config,
        HpkeKey::dhkem_p256_sha256(SERVER_ECH_KEY).unwrap(),
    )
    .unwrap();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder
        .set_certificate(&X509::from_der(&chain[0]).unwrap())
        .unwrap();
    builder
        .add_extra_chain_cert(X509::from_der(&chain[1]).unwrap())
        .unwrap();
    builder
        .set_private_key(&PKey::private_key_from_der(key.secret_der()).unwrap())
        .unwrap();
    builder.set_ech_keys(&keys.build()).unwrap();
    (builder.build(), chain[1].clone())
}

#[tokio::test]
async fn connector_retries_authenticated_rejection_once_on_fresh_transport() {
    for (trusted, insecure, reject_twice) in [
        (true, false, false),
        (true, false, true),
        (false, false, false),
        (true, true, false),
    ] {
        let (first, first_ca) = retry_test_server("ech.com", 1);
        let (second, second_ca) = retry_test_server(
            if reject_twice { "ech.com" } else { ORIGIN },
            if reject_twice { 2 } else { 1 },
        );
        let servers = Arc::new([first, second]);
        let calls = Arc::new(AtomicUsize::new(0));
        let transport = service_fn({
            let calls = calls.clone();
            move |input: ConnectRequest| {
                let server = servers[calls.fetch_add(1, Ordering::SeqCst)].clone();
                async move {
                    let (client, server_io) = tokio::io::duplex(65536);
                    tokio::spawn(async move {
                        drop(rama_boring_tokio::accept(&server, server_io).await);
                    });
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input,
                        conn: ServiceInput::new(client),
                    })
                }
            }
        });
        let mut base = TlsClientConfig::new()
            .with_encrypted_client_hello(true)
            .try_with_server_trust_anchors(if trusted {
                vec![first_ca, second_ca]
            } else {
                vec![second_ca]
            })
            .unwrap();
        if insecure {
            base.set_server_verify(ServerVerifyMode::Disable);
        }
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        input.extensions().insert(TargetEchConfig::new(
            input.authority.clone(),
            Bytes::from_static(ECH_CONFIG_LIST),
        ));
        if !insecure {
            input.extensions().insert(EchRequirement::Required);
        }
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TlsConnector::secure(transport)
                .with_base_config(base)
                .serve(input),
        )
        .await
        .unwrap();
        assert_eq!(
            result.is_ok(),
            trusted && !insecure && !reject_twice,
            "trusted={trusted}, insecure={insecure}, twice={reject_twice}: {result:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if trusted && !insecure { 2 } else { 1 }
        );
    }
}

#[tokio::test]
async fn mirrored_final_intent_controls_bare_endpoint_reliance_before_dial() {
    for ech in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let transport = service_fn({
            let calls = calls.clone();
            move |_: ConnectRequest| {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<
                        EstablishedClientConnection<
                            ServiceInput<tokio::io::DuplexStream>,
                            ConnectRequest,
                        >,
                        _,
                    >(ConnectionError::local(
                        "test transport",
                        ConnectionErrorKind::Unavailable,
                    ))
                }
            }
        });
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        input
            .extensions()
            .insert(rama_net::tls::TargetEchServiceBinding {
                target: input.authority.clone(),
                reliant: true,
                mandatory: false,
            });
        // The profile compiler runs after discovery and installs ordinary TLS settings.
        let captured = crate::client::tests::emitted_with(
            &TlsClientConfig::new().with_encrypted_client_hello(ech),
        );
        TlsClientConfig::new_from_client_hello(&captured).write_to(input.extensions());
        let error = TlsConnector::secure(transport)
            .serve(input)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(!ech));
    }
}
