use std::sync::Arc;

use rama_core::{
    Layer, Service as _, ServiceInput, error::BoxError, extensions::ExtensionsRef,
    service::service_fn, telemetry::tracing,
};
use rama_crypto::{cert::generate_server_auth, pki_types::CertificateDer};
use rama_net::{
    address::{Domain, Host, HostWithPort},
    client::ConnectorTarget,
    stream::service::EchoService,
};
use rama_tls::{
    SecureTransport, SupportedGroup,
    client::{
        ServerVerifyMode, TlsClientConfig, TlsServerCertPin, TlsServerCertPinSet, TlsServerCertPins,
    },
    server::{
        CertificateAuthorityData, CertificateIdentity, CertificateKeyKind,
        GeneratedServerAuthConfig, LeafCertConfig, LeafCertRequest, SelfSignedCaConfig,
        ServerAuthData, TlsServerConfig,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

use crate::{
    client::{BoringClientConfigExt as _, TlsConnectorData, tls_connect},
    server::{
        BoringServerConfigExt as _, CacheKind, ServerCertIssuerData, ServerCertIssuerKind,
        TlsAcceptorLayer,
    },
};

#[derive(Debug)]
struct ConnectionObservation {
    client_connected: bool,
    server: ServerObservation,
}

#[derive(Debug, PartialEq, Eq)]
enum ServerObservation {
    Failed,
    Connected { sni: Option<Domain> },
}

async fn observed_sni(
    stream: crate::TlsStream<ServiceInput<tokio::io::DuplexStream>>,
) -> Result<Option<Domain>, BoxError> {
    Ok(stream
        .extensions()
        .get_ref::<SecureTransport>()
        .and_then(SecureTransport::client_hello)
        .and_then(|hello| hello.ext_server_name())
        .cloned())
}

async fn connect_to_server(
    generated_auth: GeneratedServerAuthConfig,
    server_name: Host,
) -> ConnectionObservation {
    let (cert_chain, private_key) =
        generate_server_auth(generated_auth).expect("generated server auth");
    let trust_anchor = cert_chain.last().expect("certificate chain").clone();
    let server = TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
        cert_chain,
        private_key,
        ocsp: None,
    }))
    .with_store_client_hello(true)
    .into_layer(service_fn(observed_sni));

    let client_config = TlsConnectorData::try_from(
        &TlsClientConfig::new()
            .with_server_name(server_name)
            .try_with_server_trust_anchors([trust_anchor])
            .unwrap(),
    )
    .unwrap();

    let (stream_client, stream_server) = tokio::io::duplex(usize::MAX);
    let (server_result, client_result) = tokio::join!(
        server.serve(ServiceInput::new(stream_server)),
        tls_connect(ServiceInput::new(stream_client), Some(client_config)),
    );
    ConnectionObservation {
        client_connected: client_result.is_ok(),
        server: match server_result {
            Ok(sni) => ServerObservation::Connected { sni },
            Err(_) => ServerObservation::Failed,
        },
    }
}

async fn connect_to_ip_server(server_name: Host) -> ConnectionObservation {
    connect_to_server(
        GeneratedServerAuthConfig::GeneratedCa {
            ca: SelfSignedCaConfig::default(),
            leaf: LeafCertRequest {
                identities: vec![
                    CertificateIdentity::Ip(std::net::Ipv4Addr::LOCALHOST.into()),
                    CertificateIdentity::Ip(std::net::Ipv6Addr::LOCALHOST.into()),
                ],
                ..Default::default()
            },
        },
        server_name,
    )
    .await
}

async fn connect_to_pinned_server(
    matching_pin: bool,
    server_verify_mode: ServerVerifyMode,
    server_name: Host,
) -> bool {
    connect_to_pinned_server_with_pins(server_verify_mode, server_name, move |cert_chain| {
        if matching_pin {
            TlsServerCertPins::new(
                TlsServerCertPinSet::try_new([
                    CertificateDer::from(vec![9, 9, 9]),
                    cert_chain[0].clone(),
                ])
                .unwrap(),
            )
        } else {
            TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3]))
        }
    })
    .await
}

async fn connect_to_pinned_server_with_pins<F>(
    server_verify_mode: ServerVerifyMode,
    server_name: Host,
    make_pins: F,
) -> bool
where
    F: FnOnce(&[CertificateDer<'static>]) -> TlsServerCertPins,
{
    let (cert_chain, private_key) =
        generate_server_auth(GeneratedServerAuthConfig::default()).expect("generated server auth");
    let trust_anchor = cert_chain[1].clone();
    let pins = make_pins(&cert_chain);
    let server = TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
        cert_chain,
        private_key,
        ocsp: None,
    }))
    .into_layer(EchoService::new());

    let client_config = TlsConnectorData::try_from(
        &TlsClientConfig::new()
            .with_server_name(server_name)
            .with_server_cert_pins(pins)
            .with_server_verify(server_verify_mode)
            .try_with_server_trust_anchors([trust_anchor])
            .unwrap(),
    )
    .expect("client config");

    let (stream_client, stream_server) = tokio::io::duplex(usize::MAX);
    let handle = tokio::spawn(async move { server.serve(ServiceInput::new(stream_server)).await });
    let connected = match tls_connect(ServiceInput::new(stream_client), Some(client_config)).await {
        Ok(stream) => {
            drop(stream);
            true
        }
        Err(_) => false,
    };
    drop(handle.await);
    connected
}

#[tokio::test]
async fn ipv4_server_identity_matches_ip_subject_alt_name() {
    let observed = connect_to_ip_server(Host::from(std::net::Ipv4Addr::LOCALHOST)).await;
    assert!(observed.client_connected, "{observed:?}");
    assert_eq!(observed.server, ServerObservation::Connected { sni: None });
}

#[tokio::test]
async fn ipv6_server_identity_matches_ip_subject_alt_name() {
    let observed = connect_to_ip_server(Host::from(std::net::Ipv6Addr::LOCALHOST)).await;
    assert!(observed.client_connected, "{observed:?}");
    assert_eq!(observed.server, ServerObservation::Connected { sni: None });
}

#[tokio::test]
async fn mismatched_ip_server_identity_is_rejected() {
    let observed = connect_to_ip_server(Host::from(std::net::Ipv4Addr::new(127, 0, 0, 2))).await;
    assert!(!observed.client_connected, "{observed:?}");
}

#[tokio::test]
async fn dns_server_identity_is_sent_as_sni() {
    let observed = connect_to_server(
        GeneratedServerAuthConfig::default(),
        Host::from_static("localhost"),
    )
    .await;
    assert!(observed.client_connected, "{observed:?}");
    assert_eq!(
        observed.server,
        ServerObservation::Connected {
            sni: Some(Domain::from_static("localhost"))
        }
    );
}

#[tokio::test]
async fn self_signed_leaf_verifies_when_directly_trusted() {
    let observed = connect_to_server(
        GeneratedServerAuthConfig::SelfSignedLeaf(LeafCertRequest::default()),
        Host::from_static("localhost"),
    )
    .await;
    assert!(observed.client_connected, "{observed:?}");
    assert_eq!(
        observed.server,
        ServerObservation::Connected {
            sni: Some(Domain::from_static("localhost"))
        }
    );
}

#[tokio::test]
async fn provided_ca_issues_ip_leaf_from_target_without_sni() {
    let ca = CertificateAuthorityData::generate(SelfSignedCaConfig::default())
        .expect("generate certificate authority");
    let trust_anchor = ca.certificate_chain()[0].clone();
    let server_config = TlsServerConfig::new().with_cert_issuer(ServerCertIssuerData {
        kind: ServerCertIssuerKind::ProvidedCa {
            ca,
            leaf: LeafCertConfig {
                key_kind: CertificateKeyKind::EcP384,
                ..Default::default()
            },
        },
        cache_kind: CacheKind::Disabled,
        fallback_identity: None,
    });
    let server = TlsAcceptorLayer::new(server_config).into_layer(EchoService::new());

    let client_config = TlsConnectorData::try_from(
        &TlsClientConfig::new()
            .with_server_name(Host::LOCALHOST_IPV4)
            .try_with_server_trust_anchors([trust_anchor])
            .unwrap(),
    )
    .expect("client config");

    let (stream_client, stream_server) = tokio::io::duplex(usize::MAX);
    let server_input = ServiceInput::new(stream_server);
    server_input
        .extensions
        .insert(ConnectorTarget(HostWithPort::new(
            Host::LOCALHOST_IPV4,
            443,
        )));
    let server_handle = tokio::spawn(async move { server.serve(server_input).await });
    let client_result = tls_connect(ServiceInput::new(stream_client), Some(client_config)).await;
    assert!(client_result.is_ok(), "client failed: {client_result:?}");
    drop(client_result);
    let server_result = server_handle.await.expect("join TLS server");
    assert!(server_result.is_ok(), "server failed: {server_result:?}");
}

#[tokio::test]
async fn matching_server_cert_pin_connects() {
    assert!(
        connect_to_pinned_server(true, ServerVerifyMode::Auto, Host::from_static("localhost"))
            .await
    );
}

#[tokio::test]
async fn mismatched_server_cert_pin_is_rejected() {
    assert!(
        !connect_to_pinned_server(
            false,
            ServerVerifyMode::Auto,
            Host::from_static("localhost")
        )
        .await
    );
}

#[tokio::test]
async fn matching_server_cert_pin_still_checks_server_name() {
    assert!(
        !connect_to_pinned_server(
            true,
            ServerVerifyMode::Auto,
            Host::from_static("wrong.example")
        )
        .await
    );
}

#[tokio::test]
async fn matching_server_cert_pin_connects_without_child_verification() {
    assert!(
        connect_to_pinned_server(
            true,
            ServerVerifyMode::Disable,
            Host::from_static("localhost")
        )
        .await
    );
}

#[tokio::test]
async fn mismatched_server_cert_pin_is_rejected_without_child_verification() {
    assert!(
        !connect_to_pinned_server(
            false,
            ServerVerifyMode::Disable,
            Host::from_static("localhost")
        )
        .await
    );
}

#[tokio::test]
async fn mismatched_ip_scoped_pin_is_rejected_without_child_verification() {
    let server_name = Host::from(std::net::Ipv4Addr::LOCALHOST);
    let pin_scope = server_name.clone();

    let connected =
        connect_to_pinned_server_with_pins(ServerVerifyMode::Disable, server_name, move |_| {
            TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1, 2, 3]))
                    .with_server_name(pin_scope),
            )
        })
        .await;

    assert!(!connected);
}

#[tokio::test]
async fn unrelated_scoped_pin_set_delegates_to_default_verification() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |_| TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1, 2, 3]))
                    .with_server_name(Host::from_static("other.example"))
            ),
        )
        .await
    );
}

#[tokio::test]
async fn matching_any_applicable_pin_set_connects() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |cert_chain| TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1, 2, 3]))
                    .with_server_name(Host::from_static("localhost"))
            )
            .with_pin_set(
                TlsServerCertPinSet::new(cert_chain[0].clone())
                    .with_server_name(Host::from_static("localhost"))
            ),
        )
        .await
    );
}

#[tokio::test]
async fn matching_scoped_pin_set_rejects_a_mismatch() {
    assert!(
        !connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |_| TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1, 2, 3]))
                    .with_server_name(Host::from_static("localhost"))
            ),
        )
        .await
    );
}

#[tokio::test]
async fn unrelated_scoped_pin_set_is_not_a_check_when_verification_is_disabled() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Disable,
            Host::from_static("localhost"),
            |_| TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1, 2, 3]))
                    .with_server_name(Host::from_static("other.example"))
            ),
        )
        .await
    );
}

#[tokio::test]
async fn matching_spki_pin_connects() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |cert_chain| TlsServerCertPins::new(
                TlsServerCertPin::spki_sha256_of(&cert_chain[0]).unwrap()
            ),
        )
        .await
    );
}

#[tokio::test]
async fn mismatched_spki_pin_is_rejected() {
    assert!(
        !connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |cert_chain| TlsServerCertPins::new(
                // the CA's key pin does not match the leaf's key
                TlsServerCertPin::spki_sha256_of(&cert_chain[1]).unwrap()
            ),
        )
        .await
    );
}

#[tokio::test]
async fn matching_spki_pin_connects_without_child_verification() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Disable,
            Host::from_static("localhost"),
            |cert_chain| TlsServerCertPins::new(
                TlsServerCertPin::spki_sha256_of(&cert_chain[0]).unwrap()
            ),
        )
        .await
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_assumed_default_group_id_support() {
    let server = Arc::new(
        TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
                .expect("generated server auth"),
        )
        .into_layer(EchoService::new()),
    );

    for group in [
        // based on rama-boring-sys@patched: kDefaultSupportedGroupIds
        SupportedGroup::X25519MLKEM768,
        SupportedGroup::X25519,
        SupportedGroup::MLKEM1024,
        SupportedGroup::SECP256R1,
        SupportedGroup::SECP384R1,
        SupportedGroup::SECP521R1,
        SupportedGroup::X25519KYBER768DRAFT00,
        SupportedGroup::X25519KYBER512DRAFT00,
    ] {
        tracing::info!("test group: {group:?}");

        let (stream_client, stream_server) = tokio::io::duplex(usize::MAX);
        let handle = tokio::spawn({
            let server = server.clone();
            async move {
                server
                    .serve(ServiceInput::new(stream_server))
                    .await
                    .unwrap();
            }
        });

        let config = TlsConnectorData::try_from(
            &TlsClientConfig::new()
                .with_supported_groups(vec![group])
                .with_server_verify(ServerVerifyMode::Disable),
        )
        .unwrap();
        let mut stream = tls_connect(ServiceInput::new(stream_client), Some(config))
            .await
            .unwrap_or_else(|err| {
                panic!("failed to TLS connect with group {group:?}: {err}");
            });

        stream.write_all(b"Hello, Tls!").await.unwrap();
        let mut buffer = [0u8; 11];
        stream.read_exact(&mut buffer[..]).await.unwrap();
        assert_eq!(b"Hello, Tls!", &buffer[..]);

        drop(stream);
        handle.await.unwrap();
    }
}
