//! WebSockets over HTTP/3: example executables and the public client API.
use super::utils;
use rama::{
    crypto::pem::PemEncode as _,
    extensions::Extensions,
    futures::StreamExt as _,
    http::{
        client::{EasyHttpConnectorBuilder, Http3Connector},
        ws::{Message, handshake::client::HttpClientWebSocketExt as _},
    },
    rt::Executor,
    tls::{client::TlsClientConfig, server::ServerAuthData},
    utils::fs::tempdir,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    fs,
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::Command,
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(30);

#[tokio::test]
#[ignore]
async fn test_ws_over_h3() {
    utils::init_tracing();
    let directory = tempdir().unwrap();
    let auth = ServerAuthData::new_self_signed_leaf(Default::default()).unwrap();
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    fs::write(&cert, auth.cert_chain[0].to_pem()).await.unwrap();
    fs::write(&key, auth.private_key.to_pem()).await.unwrap();
    let mut server = utils::ExampleRunner::capturing(
        "ws_over_h3",
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
        .wait_for_line("WebSocket over HTTP/3 listening on ", LIMIT)
        .await;
    let address: SocketAddr = line
        .split("listening on ")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let url = format!("wss://localhost:{}/echo", address.port());

    // The example client executable.
    let output = timeout(
        LIMIT,
        Command::new(env!("CARGO_BIN_EXE_ws_over_h3"))
            .kill_on_drop(true)
            .env("RUST_LOG", "ws_over_h3=info")
            .args(["client", "--ca"])
            .arg(&cert)
            .args(["--url", &url, "--message", "one", "--message", "two"])
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
    assert!(
        said.contains("WebSocket over HTTP/3 close handshake completed"),
        "{said}"
    );
    for message in ["one", "two"] {
        assert!(
            said.contains(&format!("WebSocket echo over HTTP/3: {message}")),
            "{said}"
        );
    }

    // The public library client: two sockets multiplexed on one pooled connection.
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
    let mut first = timeout(
        LIMIT,
        client
            .websocket_h3(url.as_str())
            .handshake(Extensions::new()),
    )
    .await
    .unwrap()
    .unwrap();
    let mut second = timeout(
        LIMIT,
        client
            .websocket_h3(url.as_str())
            .handshake(Extensions::new()),
    )
    .await
    .unwrap()
    .unwrap();
    for (socket, text) in [(&mut first, "first"), (&mut second, "second")] {
        socket.send_message(Message::text(text)).await.unwrap();
    }
    for (socket, text) in [(&mut second, "second"), (&mut first, "first")] {
        let echo = timeout(LIMIT, socket.recv_message())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echo.into_text().unwrap(), text);
    }
    // Binary frames, a large (fragmented on the wire) message and ping/pong.
    first
        .send_message(Message::binary(vec![0xab; 256 * 1024]))
        .await
        .unwrap();
    let echo = timeout(LIMIT, first.recv_message()).await.unwrap().unwrap();
    assert_eq!(echo.into_data().len(), 256 * 1024);
    // Both close handshakes complete: the server replies, then ends its stream with FIN.
    for socket in [&mut first, &mut second] {
        socket.close(None).await.unwrap();
        let reply = timeout(LIMIT, socket.next()).await.unwrap();
        assert!(matches!(reply, Some(Ok(Message::Close(_)))), "{reply:?}");
    }
    // On the wire: nothing but a FIN after the reply; a reset would fail this read.
    let mut io = first.into_inner().into_inner();
    let mut rest = Vec::new();
    timeout(LIMIT, io.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(rest.is_empty());
    // Best effort: the finished server may already have stopped reading (STOP_SENDING).
    _ = io.shutdown().await;
    assert!(timeout(LIMIT, second.next()).await.unwrap().is_none());
    drop((io, second, client));

    let status = server.interrupt_within(Duration::from_secs(20)).await;
    assert!(status.success(), "{}", server.said());
    assert_eq!(
        server.said().matches("accepted HTTP/3 connection").count(),
        2,
        "the executable and the pooled library client each use one connection: {}",
        server.said()
    );
}
