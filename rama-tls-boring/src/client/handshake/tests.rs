use rama_core::{ServiceInput, bytes::Bytes};
use rama_net::address::{Domain, Host};
use rama_tls::{
    ExtensionId,
    client::{ServerVerifyMode, TlsClientConfig},
    server::{
        CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData,
        TlsServerConfig,
    },
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::{client::BoringClientConfigExt as _, server::TlsAcceptorData};

#[test]
fn preparation_requires_an_authenticated_identity() {
    let data = TlsConnectorData::try_from(&TlsClientConfig::new()).unwrap();
    let error = PreparedClient::try_from(data).unwrap_err();
    assert!(error.to_string().contains("server identity required"));

    // The existing explicit low-level opt-out remains available.
    let data = TlsConnectorData::try_from(
        &TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
    )
    .unwrap();
    PreparedClient::try_from(data).unwrap();
}

#[test]
fn preparation_checks_native_shape_before_a_transport_exists() {
    let config = TlsClientConfig::new()
        .with_server_name(Host::from_static("prepared.test"))
        .with_extension_bodies(vec![(ExtensionId::SERVER_NAME, Bytes::new())]);
    let error = TlsConnectorData::try_from(&config)
        .and_then(PreparedClient::try_from)
        .unwrap_err();
    assert!(error.to_string().contains("ClientHello shape"), "{error}");
}

fn server_auth() -> ServerAuthData {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::GeneratedCa {
        ca: Default::default(),
        leaf: LeafCertRequest {
            config: Default::default(),
            identities: [CertificateIdentity::Dns(Domain::from_static(
                "prepared.test",
            ))]
            .into_iter()
            .collect(),
        },
    })
    .unwrap()
}

#[tokio::test]
async fn prepared_session_connects_with_the_configured_trust_and_identity() {
    let auth = server_auth();
    let config = TlsClientConfig::new()
        .with_server_name(Host::from_static("prepared.test"))
        .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
        .unwrap();
    let data = TlsConnectorData::try_from(&config).unwrap();
    let mut prepared = PreparedClient::try_from(data).unwrap();
    let marker = Ssl::new_ex_index::<bool>().unwrap();
    prepared.ssl.set_ex_data(marker, true);
    let server = TlsAcceptorData::try_from(&TlsServerConfig::new().with_single_cert(auth))
        .unwrap()
        .into_static_acceptor_builder()
        .unwrap()
        .build();

    // The transport is created only after native preparation has succeeded.
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let server = async move {
        let mut stream = rama_boring_tokio::accept(&server, server_io).await.unwrap();
        stream.write_all(b"server").await.unwrap();
        let mut received = [0; 6];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"client");
    };
    let client = async move {
        let mut stream = prepared
            .connect(ServiceInput::new(client_io))
            .await
            .unwrap();
        let mut received = [0; 6];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"server");
        assert_eq!(
            stream.ssl_ref().ex_data(marker),
            Some(&true),
            "the prepared native session and its attached state must survive"
        );
        stream.write_all(b"client").await.unwrap();
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn preparation_preserves_peer_authentication_failures() {
    for trust_server in [false, true] {
        let auth = server_auth();
        let mut config =
            TlsClientConfig::new().with_server_name(Host::from_static(if trust_server {
                "other.test"
            } else {
                "prepared.test"
            }));
        if trust_server {
            config = config
                .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
                .unwrap();
        }
        let prepared =
            PreparedClient::try_from(TlsConnectorData::try_from(&config).unwrap()).unwrap();
        let server = TlsAcceptorData::try_from(&TlsServerConfig::new().with_single_cert(auth))
            .unwrap()
            .into_static_acceptor_builder()
            .unwrap()
            .build();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                async move {
                    // The peer may observe a certificate alert or stream closure.
                    _ = rama_boring_tokio::accept(&server, server_io).await;
                },
                async move {
                    let Err(error) = prepared.connect(ServiceInput::new(client_io)).await else {
                        panic!("prepared session accepted an untrusted or mismatched peer");
                    };
                    assert!(matches!(error, TlsConnectError::Handshake { .. }));
                    drop(error);
                }
            );
        })
        .await
        .unwrap();
    }
}
