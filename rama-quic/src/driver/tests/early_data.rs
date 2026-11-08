//! Metadata available to early connection users, before the driver is polled.

use super::*;
use crate::{ClientConfig, ServerConfig};
use rama_crypto::cert::{CertificateAuthorityData, LeafCertRequest, SelfSignedCaConfig};
use rama_tls::{
    client::{ClientAuth, ClientAuthData, TlsClientConfig},
    server::{ClientVerifyMode, TlsServerConfig},
};

#[tokio::test]
async fn incoming_early_handle_publishes_alpn_before_driver_runs() {
    timeout(Duration::from_secs(5), async {
        let endpoint = endpoint();
        let outgoing = endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap();
        let mut incoming = endpoint.accept().await.unwrap();
        // A post-quantum key share spreads the ClientHello over two Initials.
        incoming.client_hello().await.unwrap();
        let (connection, established) = incoming
            .accept()
            .unwrap()
            .into_0rtt()
            .expect("server connections permit early handles");

        // This current-thread runtime has not yielded since accept constructed
        // the server driver. Early HTTP dispatch must already see its ALPN.
        assert!(!connection.is_handshake_confirmed());
        let parameters = connection
            .extensions()
            .get_arc::<NegotiatedTlsParameters>()
            .expect("early handle publishes the negotiated protocol synchronously");
        assert!(parameters.application_layer_protocol.is_some());

        let (outgoing, established) = join!(outgoing, established);
        outgoing.unwrap();
        assert!(established.unwrap());
        endpoint.close(0u32, b"done");
        endpoint.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn early_metadata_defers_client_identity_until_authenticated() {
    timeout(Duration::from_secs(10), async {
        let identity = test_helpers::identity();
        let server_leaf = identity.cert_chain[0].clone();
        let authority = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
        let (cert_chain, private_key) = authority
            .issue_client_leaf(LeafCertRequest::default())
            .unwrap();
        let leaf = cert_chain[0].clone();
        let server_tls = TlsServerConfig::new()
            .with_server_auth(identity.clone())
            .with_alpn([b"rama-quic-test".as_slice().into()].into_iter().collect())
            .with_client_verify(ClientVerifyMode::ClientAuth(
                authority.certificate_chain().to_vec(),
            ))
            .with_store_client_cert_chain(true);
        let client_tls = TlsClientConfig::new()
            .with_store_server_cert_chain(true)
            .with_alpn([b"rama-quic-test".as_slice().into()].into_iter().collect())
            .try_with_server_trust_anchors(identity.cert_chain)
            .unwrap()
            .with_client_auth(ClientAuth::Single(ClientAuthData {
                cert_chain,
                private_key,
            }));
        let mut endpoint = Endpoint::build(rama_core::graceful::WeakScope::detached())
            .with_server_config(
                ServerConfig::try_from_rama_tls(&server_tls, test_helpers::options()).unwrap(),
            )
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        endpoint.set_default_client_config(
            ClientConfig::try_from_rama_tls(&client_tls, test_helpers::options()).unwrap(),
        );

        // The second connection can carry identity remembered in a session ticket.
        for _ in 0..2 {
            let outgoing = endpoint
                .connect(endpoint.local_addr().unwrap(), "localhost")
                .unwrap();
            let mut incoming = endpoint.accept().await.unwrap();
            incoming.client_hello().await.unwrap();
            let (server, established) = incoming
                .accept()
                .unwrap()
                .into_0rtt()
                .expect("server early handle");
            let provisional = server
                .extensions()
                .get_arc::<NegotiatedTlsParameters>()
                .unwrap();
            assert!(provisional.application_layer_protocol.is_some());
            assert!(provisional.peer_certificate_chain.is_none());
            let (client, established) = join!(outgoing, established);
            let client = client.unwrap();
            assert_eq!(
                client
                    .extensions()
                    .get_ref::<NegotiatedTlsParameters>()
                    .unwrap()
                    .peer_certificate_chain
                    .as_ref()
                    .unwrap()[0],
                server_leaf
            );
            assert!(established.unwrap());
            let authenticated = server
                .extensions()
                .get_arc::<NegotiatedTlsParameters>()
                .unwrap();
            assert_eq!(
                authenticated.peer_certificate_chain.as_ref().unwrap()[0],
                leaf
            );

            // Receipt of server application data also delivers the preceding session ticket.
            let mut send = server.open_uni().await.unwrap();
            send.write_all(b"ticket").await.unwrap();
            send.finish().unwrap();
            let mut receive = client.accept_uni().await.unwrap();
            assert_eq!(receive.read_to_end(64).await.unwrap(), b"ticket");
            client.close(0u32, b"next");
            endpoint.wait_idle().await;
        }
        endpoint.close(0u32, b"done");
        endpoint.shutdown().await;
    })
    .await
    .unwrap();
}
