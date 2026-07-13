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
    core::x509::{X509, store::X509StoreBuilder},
    server::TlsAcceptorLayer,
};

async fn connect_to_pinned_server(
    matching_pin: bool,
    server_verify_mode: ServerVerifyMode,
    server_name: Host,
) -> bool {
    let (cert_chain, private_key) =
        self_signed_server_auth(SelfSignedData::default()).expect("self-signed server auth");
    let pins = if matching_pin {
        vec![CertificateDer::from(vec![9, 9, 9]), cert_chain[0].clone()]
    } else {
        vec![CertificateDer::from(vec![1, 2, 3])]
    };
    let ca = cert_chain[1].clone();
    let server = TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
        cert_chain,
        private_key,
        ocsp: None,
    }))
    .into_layer(EchoService::new());

    let mut store = X509StoreBuilder::new().expect("x509 store");
    store
        .add_cert(X509::from_der(ca.as_ref()).expect("parse CA"))
        .expect("add CA");
    let client_config = TlsConnectorData::try_from(
        &TlsClientConfig::new()
            .with_server_name(server_name)
            .with_server_cert_pins(TlsServerCertPins::try_new(pins).unwrap())
            .with_server_verify(server_verify_mode)
            .with_server_verify_cert_store(Arc::new(store.build())),
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
