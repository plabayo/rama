use rama::{
    extensions::Extensions,
    http::{
        client::EasyHttpWebClient, headers::SecWebSocketProtocol,
        ws::handshake::client::HttpClientWebSocketExt,
    },
    net::address::SocketAddress,
    tcp::client::default_tcp_connect,
    telemetry::tracing,
    udp::UdpSocket,
};

#[cfg(feature = "boring")]
use ::{
    rama::{
        net::client::{ConnectorService, EstablishedClientConnection},
        net::tls::client::ServerVerifyMode,
        tcp::client::{Request as TcpRequest, service::TcpConnector},
        tls::boring::client::{TlsConnector, TlsConnectorDataBuilder},
    },
    std::sync::Arc,
};

use super::utils;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
#[ignore]
async fn test_http_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::echo(63101, "http");

    let lines = utils::RamaService::http(vec!["--http1.1", "http://127.0.0.1:63101"]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");

    let lines =
        utils::RamaService::http(vec!["http://127.0.0.1:63101", "foo:bar", "a=4", "q==1"]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(lines.contains(r##""method":"POST""##), "lines: {lines:?}");
    assert!(lines.contains(r##""foo","bar""##), "lines: {lines:?}");
    assert!(
        lines.contains(r##""content-type","application/json""##),
        "lines: {lines:?}",
    );
    assert!(lines.contains(r##""a":"4""##), "lines: {lines:?}");
    assert!(lines.contains(r##""path":"/""##), "lines: {lines:?}");
    assert!(lines.contains(r##""query":"q=1""##), "lines: {lines:?}");

    // test default WS protocol

    let client = EasyHttpWebClient::default();

    let mut ws = client
        .websocket("ws://127.0.0.1:63101")
        .handshake(Extensions::default())
        .await
        .expect("ws handshake to work");
    ws.send_message("Cheerios".into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        "Cheerios",
        ws.recv_message()
            .await
            .expect("echo ws message to be received")
            .into_text()
            .expect("echo ws message to be a text message")
            .as_str()
    );

    // and also one of the other protocols

    let mut ws = client
        .websocket("ws://127.0.0.1:63101")
        .with_protocols(SecWebSocketProtocol::new("echo-upper"))
        .handshake(Extensions::default())
        .await
        .expect("ws handshake to work");
    ws.send_message("Cheerios".into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        "CHEERIOS",
        ws.recv_message()
            .await
            .expect("echo ws message to be received")
            .into_text()
            .expect("echo ws message to be a text message")
            .as_str()
    );
}

#[tokio::test]
#[ignore]
async fn test_tcp_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::echo(63110, "tcp");

    let mut stream = None;
    for i in 0..5 {
        let extensions = Extensions::new();
        match default_tcp_connect(&extensions, ([127, 0, 0, 1], 63110).into()).await {
            Ok((s, _)) => {
                stream = Some(s);
                break;
            }
            Err(e) => {
                tracing::error!("connect_tcp error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(500 + 250 * i)).await;
            }
        }
    }
    let mut stream = stream.expect("connect to tcp listener");

    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[cfg(feature = "boring")]
#[tokio::test]
#[ignore]
async fn test_tls_tcp_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::echo(63111, "tls");

    let mut stream = None;
    for i in 0..5 {
        let extensions = Extensions::new();
        let connector = TlsConnector::secure(TcpConnector::new()).with_connector_data(Arc::new(
            TlsConnectorDataBuilder::new().with_server_verify_mode(ServerVerifyMode::Disable),
        ));
        match connector
            .connect(TcpRequest::new(([127, 0, 0, 1], 63111).into(), extensions))
            .await
        {
            Ok(EstablishedClientConnection { conn, .. }) => {
                stream = Some(conn);
                break;
            }
            Err(e) => {
                tracing::error!("tls(tcp) connect error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(500 + 250 * i)).await;
            }
        }
    }
    let mut stream = stream.expect("connect to tls-tcp listener");

    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[tokio::test]
#[ignore]
async fn test_udp_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::echo(63112, "udp");
    let socket = UdpSocket::bind(SocketAddress::local_ipv4(63113))
        .await
        .unwrap();

    for i in 0..5 {
        match socket.connect(SocketAddress::local_ipv4(63112)).await {
            Ok(_) => break,
            Err(e) => {
                tracing::error!("UdpSocket::connect error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(500 + 250 * i)).await;
            }
        }
    }

    socket.send(b"hello").await.unwrap();
    let mut buf = [0; 5];
    socket.recv(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[cfg(feature = "boring")]
#[tokio::test]
#[ignore]
async fn test_https_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::echo(63103, "https");

    let lines = utils::RamaService::http(vec!["https://127.0.0.1:63103", "foo:bar", "a=4", "q==1"])
        .unwrap();

    // same http test as the plain text version
    assert!(lines.contains("HTTP/2.0 200 OK"), "lines: {lines:?}");
    assert!(lines.contains(r##""method":"POST""##), "lines: {lines:?}");
    assert!(lines.contains(r##""foo","bar""##), "lines: {lines:?}");
    assert!(
        lines.contains(r##""content-type","application/json""##),
        "lines: {lines:?}",
    );
    assert!(lines.contains(r##""a":"4""##), "lines: {lines:?}");
    assert!(lines.contains(r##""path":"/""##), "lines: {lines:?}");
    assert!(lines.contains(r##""query":"q=1""##), "lines: {lines:?}");
    assert!(lines.contains(r##""query":"q=1""##), "lines: {lines:?}");

    // do test however that we now also get tls info
    assert!(lines.contains(r##""cipher_suites""##), "lines: {lines:?}");

    // test default WS protocol

    let client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(Some(Arc::new(
            TlsConnectorDataBuilder::new_http_1()
                .with_server_verify_mode(ServerVerifyMode::Disable),
        )))
        .build();

    let mut ws = client
        .websocket("wss://127.0.0.1:63103")
        .handshake(Extensions::default())
        .await
        .expect("ws handshake to work");
    ws.send_message("Cheerios".into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        "Cheerios",
        ws.recv_message()
            .await
            .expect("echo ws message to be received")
            .into_text()
            .expect("echo ws message to be a text message")
            .as_str()
    );

    // and also one of the other protocols

    let mut ws = client
        .websocket("wss://127.0.0.1:63103")
        .with_protocols(SecWebSocketProtocol::new("echo-upper"))
        .handshake(Extensions::default())
        .await
        .expect("ws handshake to work");
    ws.send_message("Cheerios".into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        "CHEERIOS",
        ws.recv_message()
            .await
            .expect("echo ws message to be received")
            .into_text()
            .expect("echo ws message to be a text message")
            .as_str()
    );
}

#[cfg(feature = "boring")]
#[tokio::test]
#[ignore]
async fn test_https_forced_version() {
    utils::init_tracing();

    let _guard = utils::RamaService::echo(63104, "https");

    struct Test {
        cli_flag: &'static str,
        version_response: &'static str,
        tls_alpn: &'static str,
    }

    let tests = [
        Test {
            cli_flag: "--http1.0",
            version_response: "HTTP/1.0 200 OK",
            tls_alpn: "http/1.0",
        },
        Test {
            cli_flag: "--http1.1",
            version_response: "HTTP/1.1 200 OK",
            tls_alpn: "http/1.1",
        },
        Test {
            cli_flag: "--http2",
            version_response: "HTTP/2.0 200 OK",
            tls_alpn: "h2",
        },
    ];

    for test in tests.iter() {
        let tls_alpn = format!(
            r#"{{"data":["{}"],"id":"APPLICATION_LAYER_PROTOCOL_NEGOTIATION (0x0010)"}}"#,
            test.tls_alpn
        );

        let lines = utils::RamaService::http(vec![
            test.cli_flag,
            "https://127.0.0.1:63104",
            "foo:bar",
            "a=4",
            "q==1",
        ])
        .unwrap();

        assert!(
            lines.contains(test.version_response),
            "cli flag {}, didn't find '{}' lines: {:?}",
            test.cli_flag,
            test.version_response,
            lines
        );
        assert!(
            lines.contains(&tls_alpn),
            "cli flag {}, didn't find '{}' lines: {:?}",
            test.cli_flag,
            tls_alpn,
            lines
        );
    }
}
