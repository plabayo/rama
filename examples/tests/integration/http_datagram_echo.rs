//! HTTP Datagrams over HTTP/3: example executables and the public client stack.
use super::utils;
use rama::{
    Service as _,
    bytes::Bytes,
    crypto::pem::PemEncode as _,
    extensions::ExtensionsRef as _,
    http::{
        Body, Request, Version,
        client::{EasyHttpConnectorBuilder, Http3Connector},
        datagram::{
            DatagramTransport, HttpDatagramSession, SessionEvent, ViolationPolicy,
            handshake::{prepare_capsule_request, validate_capsule_response},
        },
        io::upgrade::handle_upgrade,
        proto::ext::{HttpDatagrams, Protocol},
    },
    rt::Executor,
    tls::{client::TlsClientConfig, server::ServerAuthData},
    utils::fs::tempdir,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{fs, process::Command, time::timeout};

const LIMIT: Duration = Duration::from_secs(30);
const TOKEN: Protocol = Protocol::from_static("x-datagram-echo");

#[tokio::test]
#[ignore]
async fn test_http_datagram_echo() {
    utils::init_tracing();
    let directory = tempdir().unwrap();
    let auth = ServerAuthData::new_self_signed_leaf(Default::default()).unwrap();
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    fs::write(&cert, auth.cert_chain[0].to_pem()).await.unwrap();
    fs::write(&key, auth.private_key.to_pem()).await.unwrap();
    let mut server = utils::ExampleRunner::capturing(
        "http_datagram_echo",
        None,
        [
            "server",
            "--listen",
            "127.0.0.1:0",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ],
    );
    let line = server
        .wait_for_line("HTTP datagram echo listening on ", LIMIT)
        .await;
    let address: SocketAddr = line
        .split("listening on ")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let url = format!("https://localhost:{}/echo", address.port());

    let output = timeout(
        LIMIT,
        Command::new(env!("CARGO_BIN_EXE_http_datagram_echo"))
            .kill_on_drop(true)
            .env("RUST_LOG", "http_datagram_echo=info")
            .args(["client", "--ca"])
            .arg(&cert)
            .args(["--url", &url, "--datagram", "alpha", "--datagram", "beta"])
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    let said = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{said}");
    for datagram in ["alpha", "beta"] {
        assert!(
            said.contains(&format!("HTTP datagram echo: {datagram}")),
            "{said}"
        );
    }

    // The public client stack exposes the native carrier through the pooled connection.
    let tls = TlsClientConfig::new()
        .try_with_server_trust_anchors(auth.cert_chain.clone())
        .unwrap();
    let client_builder = EasyHttpConnectorBuilder::new()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_proxy_support();
    #[cfg(feature = "rustls")]
    let client_builder = client_builder.with_tls_support_using_rustls(tls.clone());
    #[cfg(all(not(feature = "rustls"), feature = "boring"))]
    let client_builder = client_builder.with_tls_support_using_boringssl(tls.clone());
    let client = client_builder
        .with_default_http_connector(Executor::new())
        .with_http3_support(
            Http3Connector::builder(Executor::new())
                .with_tls_config(tls)
                .build()
                .await
                .unwrap(),
        )
        .with_default_connection_pool()
        .build_client();
    for round in 0..2u8 {
        let mut request = Request::builder()
            .version(Version::HTTP_3)
            .uri(url.as_str())
            .body(Body::empty())
            .unwrap();
        prepare_capsule_request(&mut request, TOKEN).unwrap();
        request.extensions().insert(HttpDatagrams);
        let response = timeout(LIMIT, client.serve(request))
            .await
            .unwrap()
            .unwrap();
        validate_capsule_response(
            Version::HTTP_3,
            &TOKEN,
            &response,
            ViolationPolicy::default(),
        )
        .unwrap();
        let mut session = HttpDatagramSession::new(handle_upgrade(&response).await.unwrap());
        let native = session.native().expect("HTTP/3 publishes a native carrier");
        assert!(native.channel().max_payload_size().is_some());
        // Native delivery may lose a datagram on real UDP; retry until one echo returns.
        let echoed = timeout(LIMIT, async {
            loop {
                assert_eq!(
                    session
                        .send_datagram(Bytes::from(vec![round]))
                        .await
                        .unwrap(),
                    DatagramTransport::Native
                );
                let received =
                    tokio::time::timeout(Duration::from_millis(500), session.recv()).await;
                if let Ok(Ok(Some(SessionEvent::Datagram { payload, transport }))) = received {
                    return (payload, transport);
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            echoed,
            (Bytes::from(vec![round]), DatagramTransport::Native)
        );
        session.close().await.unwrap();
        assert_eq!(timeout(LIMIT, session.recv()).await.unwrap().unwrap(), None);
    }
    drop(client);

    let status = server.interrupt_within(Duration::from_secs(20)).await;
    assert!(status.success(), "{}", server.said());
    assert_eq!(
        server.said().matches("accepted HTTP/3 connection").count(),
        2,
        "the executable and the pooled library client each use one connection: {}",
        server.said()
    );
}
