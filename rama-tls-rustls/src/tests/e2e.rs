use rama_core::conversion::RamaTryFrom;
use rama_core::{Layer, Service as _, ServiceInput};
use rama_crypto::cert::self_signed_server_auth;
use rama_crypto::pki_types::{CertificateDer, ServerName};
use rama_net::{address::Host, stream::service::EchoService};
use rama_tls::{
    client::{
        ServerVerifyMode, TlsClientConfig, TlsServerCertPin, TlsServerCertPinSet, TlsServerCertPins,
    },
    server::{SelfSignedData, ServerAuthData, TlsServerConfig},
};

use crate::client::{RustlsTlsConnectorConfig, TlsConnectorData};
use crate::dep::tokio_rustls::TlsConnector as RustlsConnector;
use crate::server::TlsAcceptorLayer;

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
    crate::ensure_default_crypto_provider();

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

    let client_config = TlsClientConfig::new()
        .with_server_name(server_name.clone())
        .with_server_cert_pins(pins)
        .with_server_verify(server_verify_mode)
        .try_with_server_trust_anchors([trust_anchor])
        .unwrap();
    let connector_data = TlsConnectorData::try_from(RustlsTlsConnectorConfig::from_extensions(
        client_config.as_extensions(),
    ))
    .expect("client connector data");

    let (stream_client, stream_server) = tokio::io::duplex(usize::MAX);
    let handle = tokio::spawn(async move { server.serve(ServiceInput::new(stream_server)).await });
    let connector = RustlsConnector::from(connector_data.client_config);
    let tls_server_name = ServerName::rama_try_from(server_name).expect("tls server name");
    let connected = connector
        .connect(tls_server_name, stream_client)
        .await
        .is_ok();
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
