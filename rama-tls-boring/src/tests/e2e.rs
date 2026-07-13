use std::sync::Arc;

use rama_core::{Layer, Service as _, ServiceInput, telemetry::tracing};
use rama_crypto::{cert::self_signed_server_auth, pki_types::CertificateDer};
use rama_net::{address::Host, stream::service::EchoService};
use rama_tls::{
    SupportedGroup,
    client::{ServerVerifyMode, TlsClientConfig, TlsServerCertPins},
    server::{SelfSignedData, ServerAuthData, TlsServerConfig},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

use crate::{
    client::{BoringClientConfigExt as _, TlsConnectorData, tls_connect},
    server::TlsAcceptorLayer,
};

async fn connect_to_pinned_server(
    matching_pin: bool,
    server_verify_mode: ServerVerifyMode,
    server_name: Host,
) -> bool {
    connect_to_pinned_server_with_pins(server_verify_mode, server_name, move |cert_chain| {
        if matching_pin {
            TlsServerCertPins::try_new_set([
                CertificateDer::from(vec![9, 9, 9]),
                cert_chain[0].clone(),
            ])
            .unwrap()
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
        self_signed_server_auth(SelfSignedData::default()).expect("self-signed server auth");
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
async fn unrelated_scoped_pin_set_delegates_to_default_verification() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |_| TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3]))
                .for_server_name(Host::from_static("other.example")),
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
            |cert_chain| TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3]))
                .for_server_name(Host::from_static("localhost"))
                .with_pin(cert_chain[0].clone())
                .for_server_name(Host::from_static("localhost")),
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
            |_| TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3]))
                .for_server_name(Host::from_static("localhost")),
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
            |_| TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3]))
                .for_server_name(Host::from_static("other.example")),
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
                .try_with_self_signed(SelfSignedData::default())
                .expect("self-signed"),
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
