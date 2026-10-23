use rama::net::address::HostWithPort;
use rama::net::client::ConnectRequest;
use rama::{extensions::Extensions, tcp::client::default_tcp_connect, telemetry::tracing};
use rama::{
    net::client::{ConnectorService, EstablishedClientConnection},
    tcp::client::service::TcpConnector,
    tls::boring::client::TlsConnector,
    tls::client::{ServerVerifyMode, TlsClientConfig},
};
use tokio::io::AsyncReadExt as _;

use super::utils;

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_http_ip() {
    utils::init_tracing();
    let server = utils::RamaService::serve_ip(0, false, false);
    let port = server.port();
    test_http_ip_inner(&format!("http://127.0.0.1:{port}"));
}

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_https_ip() {
    utils::init_tracing();
    let server = utils::RamaService::serve_ip(0, false, true);
    let port = server.port();
    test_http_ip_inner(&format!("https://127.0.0.1:{port}"));
}

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_http3_ip() {
    utils::init_tracing();
    let server = utils::RamaService::serve_ip(0, false, true);
    let port = server.port();

    let lines =
        utils::RamaService::http(vec!["--http3", &format!("https://127.0.0.1:{port}")]).unwrap();
    assert!(lines.contains("* using HTTP/3.0"), "lines: {lines}");
    assert!(lines.contains("HTTP/3.0 200 OK"), "lines: {lines}");
    assert!(
        lines.split("\r\n").any(|line| line.contains("127.0.0.1")),
        "lines: {lines}"
    );

    // TCP responses advertise HTTP/3 on the same port.
    let lines =
        utils::RamaService::http(vec!["--http2", &format!("https://127.0.0.1:{port}")]).unwrap();
    assert!(lines.contains("HTTP/2.0 200 OK"), "lines: {lines}");
    assert!(
        lines.contains(&format!(r#"alt-svc: h3=":{port}"; ma=86400"#)),
        "lines: {lines}"
    );
}

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_https_ip_without_http3() {
    utils::init_tracing();
    let server =
        utils::RamaService::serve_ip_with_args(0, false, true, &["--http-version", "h1,h2"]);
    let port = server.port();

    let lines =
        utils::RamaService::http(vec!["--http2", &format!("https://127.0.0.1:{port}")]).unwrap();
    assert!(lines.contains("HTTP/2.0 200 OK"), "lines: {lines}");
    assert!(!lines.contains("alt-svc"), "lines: {lines}");

    let (success, _, stderr) = utils::RamaService::run_capture(&[
        "-k",
        "--http3",
        "--connect-timeout",
        "2",
        &format!("https://127.0.0.1:{port}"),
    ])
    .unwrap();
    assert!(!success, "no HTTP/3 without h3 in --http-version: {stderr}");
}

fn test_http_ip_inner(addr: &str) {
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
#[ignore = "spawns rama processes"]
async fn test_tcp_ip() {
    utils::init_tracing();

    let server = utils::RamaService::serve_ip(0, true, false);
    let port = server.port();

    let mut stream = None;
    for i in 0..5 {
        let extensions = Extensions::new();
        match default_tcp_connect(&extensions, HostWithPort::local_ipv4(port)).await {
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

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_tls_tcp_ip() {
    utils::init_tracing();

    let server = utils::RamaService::serve_ip(0, true, true);
    let port = server.port();

    let mut stream = None;
    for i in 0..5 {
        let connector = TlsConnector::secure(TcpConnector::new())
            .with_base_config(TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable));
        match connector
            .connect(ConnectRequest::new(HostWithPort::local_ipv4(port)))
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
