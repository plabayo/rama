//! A server that refuses resumption hands out nothing a later connection can resume.

use super::*;
use crate::{
    ClientConfig, Connection, ServerConfig,
    tls::{ServerSessionPolicy, TlsConfigError, TlsOptions},
};
use rama_core::rt::Executor;
use rama_tls::{
    client::TlsClientConfig,
    server::{ServerAuthData, TlsServerConfig},
};

fn tls(identity: &ServerAuthData) -> (TlsServerConfig, TlsClientConfig) {
    let alpn = || [b"rama-quic-test".as_slice().into()].into_iter().collect();
    let server = TlsServerConfig::new()
        .with_alpn(alpn())
        .with_server_auth(identity.clone());
    let client = TlsClientConfig::new()
        .with_alpn(alpn())
        .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
        .unwrap();
    (server, client)
}

#[tokio::test]
async fn a_fresh_server_completes_every_handshake_in_full() {
    for (policy, resumes) in [
        (ServerSessionPolicy::Resume, true),
        (ServerSessionPolicy::Fresh, false),
    ] {
        timeout(Duration::from_secs(10), async {
            let (server_tls, client_tls) = tls(&test_helpers::identity());
            let mut endpoint = Endpoint::build(Executor::new())
                .with_server_config(
                    ServerConfig::try_from_rama_tls(
                        &server_tls,
                        TlsOptions::default().with_server_sessions(policy),
                    )
                    .unwrap(),
                )
                .bind_address(SocketAddress::local_ipv4(0))
                .await
                .unwrap();
            endpoint.set_default_client_config(
                ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default()).unwrap(),
            );
            let mut resumed = Vec::new();
            for _ in 0..2 {
                let outgoing = endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost")
                    .unwrap();
                let incoming = async { endpoint.accept().await.unwrap().await.unwrap() };
                let (client, server) = join!(outgoing, incoming);
                let client = client.unwrap();
                // Receipt of server application data also delivers any preceding session ticket.
                let mut send = server.open_uni().await.unwrap();
                send.write_all(b"ticket").await.unwrap();
                send.finish().unwrap();
                let mut receive = client.accept_uni().await.unwrap();
                assert_eq!(receive.read_to_end(64).await.unwrap(), b"ticket");
                let resumption = |connection: &Connection| {
                    connection
                        .extensions()
                        .get_ref::<NegotiatedTlsParameters>()
                        .unwrap()
                        .resumed
                };
                resumed.push((resumption(&client), resumption(&server)));
                client.close(0u32, b"next");
                endpoint.wait_idle().await;
            }
            let expected = (Some(resumes), Some(resumes));
            assert_eq!(
                resumed,
                [(Some(false), Some(false)), expected],
                "{policy:?}"
            );
            endpoint.close(0u32, b"done");
            endpoint.shutdown().await;
        })
        .await
        .unwrap();
    }
}

#[test]
fn server_early_data_needs_resumption() {
    let (server_tls, _) = tls(&test_helpers::identity());
    let options = test_helpers::options().with_server_sessions(ServerSessionPolicy::Fresh);
    assert!(matches!(
        ServerConfig::try_from_rama_tls(&server_tls, options),
        Err(TlsConfigError::EarlyDataWithoutResumption)
    ));
}
