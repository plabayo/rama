use super::utils;
use rama::{extensions::Extensions, tcp::client::default_tcp_connect, telemetry::tracing};
use tokio::io::AsyncReadExt as _;

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

#[tokio::test]
#[ignore]
async fn test_http_ip() {
    utils::init_tracing();
    let _guard = utils::RamaService::serve_ip(63100, false, false);
    test_http_ip_inner("http://127.0.0.1:63100");
}

#[cfg(feature = "boring")]
#[tokio::test]
#[ignore]
async fn test_https_ip() {
    utils::init_tracing();
    let _guard = utils::RamaService::serve_ip(63118, false, true);
    test_http_ip_inner("https://127.0.0.1:63118");
}

fn test_http_ip_inner(addr: &'static str) {
    // default: txt
    let lines = utils::RamaService::http(vec!["--http1.1", addr]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"));
    assert!(lines.contains("content-type: text/plain; charset=utf-8"));
    assert!(
        lines.split("\r\n").any(|line| line.contains("127.0.0.1")),
        "txt; lines: {lines}"
    );

    // json
    let lines = utils::RamaService::http(vec!["--http1.1", addr, "-H", "accept: application/json"])
        .unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"));
    assert!(lines.contains("content-type: application/json"));
    assert!(lines.contains(r##""127.0.0.1""##), "json; lines: {lines}");

    // html
    let lines =
        utils::RamaService::http(vec!["--http1.1", addr, "-H", "accept: text/html"]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"));
    assert!(lines.contains("content-type: text/html; charset=utf-8"));
    assert!(
        lines.contains("<code>127.0.0.1</code>"),
        "html; lines: {lines}"
    );
}

#[tokio::test]
#[ignore]
async fn test_tcp_ip() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_ip(63119, true, false);

    let mut stream = None;
    for i in 0..5 {
        let extensions = Extensions::new();
        match default_tcp_connect(&extensions, ([127, 0, 0, 1], 63119).into()).await {
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
    let mut stream = stream.expect("connect to tls-tcp listener");

    let mut buf = [0; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, &[127, 0, 0, 1]);
}

#[cfg(feature = "boring")]
#[tokio::test]
#[ignore]
async fn test_tls_tcp_ip() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_ip(63120, true, true);

    let mut stream = None;
    for i in 0..5 {
        let extensions = Extensions::new();
        let connector = TlsConnector::secure(TcpConnector::new()).with_connector_data(Arc::new(
            TlsConnectorDataBuilder::new().with_server_verify_mode(ServerVerifyMode::Disable),
        ));
        match connector
            .connect(TcpRequest::new(([127, 0, 0, 1], 63120).into(), extensions))
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

    let mut buf = [0; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, &[127, 0, 0, 1]);
}
