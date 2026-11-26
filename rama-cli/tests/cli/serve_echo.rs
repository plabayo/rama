use base64::Engine;
use rama::graceful::WeakScope;
use rama::net::client::ConnectRequest;
use rama::{
    Layer as _,
    crypto::pki_types::{CertificateDer, PrivateKeyDer},
    error::{BoxError, ErrorContext as _},
    futures::StreamExt as _,
    http::{
        headers::StrictTransportSecurity,
        layer::{
            compression::CompressionLayer, cors, map_response_body::MapResponseBodyLayer,
            required_header::AddRequiredResponseHeadersLayer, set_header::SetResponseHeaderLayer,
            trace::TraceLayer,
        },
        server::HttpServer,
        service::web::{
            Router,
            extract::{Json, State},
        },
        tls::{CertOrderInput, CertOrderOutput},
        ws::Message,
    },
    net::address::{Domain, SocketAddress},
    proxy::haproxy::server::HaProxyLayer,
    tcp::server::TcpListener,
    tls::{
        boring::{
            core::{
                pkey::{PKey, Private},
                x509::X509,
            },
            server::TlsAcceptorLayer,
        },
        server::{
            CertificateIdentity, CertificateSubject, LeafCertConfig, LeafCertRequest,
            SelfSignedCaConfig, ServerAuthData, TlsServerConfig,
        },
    },
    udp::bind_udp_with_address,
};
use rama::{
    Service as _,
    extensions::{Extensions, ExtensionsRef as _},
    http::{
        Body, Request, StatusCode,
        body::util::BodyExt as _,
        client::EasyHttpWebClient,
        conn::HttpOrigin,
        headers::SecWebSocketProtocol,
        layer::{
            alt_svc::{AltSvcCache, SendAltUsed},
            error_handling::ErrorHandlerLayer,
        },
        ws::handshake::client::{ClientWebSocket, HttpClientWebSocketExt},
    },
    layer::ArcLayer,
    net::address::HostWithPort,
    tcp::client::default_tcp_connect,
    telemetry::tracing,
    utils::str::non_empty_str,
};
use rama::{
    net::client::{ConnectorService, EstablishedClientConnection},
    tcp::client::service::TcpConnector,
    tls::boring::client::TlsConnector,
    tls::client::{ServerVerifyMode, TlsClientConfig},
};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::utils;

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_http_echo() {
    utils::init_tracing();

    let server = utils::RamaService::serve_echo(0, utils::EchoMode::Http);
    let port = server.port();

    let lines =
        utils::RamaService::http(vec!["--http1.1", &format!("http://127.0.0.1:{port}")]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");

    let lines = utils::RamaService::http(vec![
        &format!("http://127.0.0.1:{port}?q=1"),
        "-H",
        "foo: bar",
        "-d",
        r##"{"a":4}"##,
        "--json",
    ])
    .unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(lines.contains(r##""method":"POST""##), "lines: {lines:?}");
    assert!(lines.contains(r##""foo","bar""##), "lines: {lines:?}");
    assert!(
        lines.contains(r##""content-type","application/json""##),
        "lines: {lines:?}",
    );
    assert!(
        lines.contains(/*{"a":4}*/ "7b2261223a347d"),
        "lines: {lines:?}"
    );
    assert!(lines.contains(r##""path":"/""##), "lines: {lines:?}");
    assert!(lines.contains(r##""query":"q=1""##), "lines: {lines:?}");

    // test default WS protocol

    let client = EasyHttpWebClient::default();

    let mut ws = client
        .websocket(format!("ws://127.0.0.1:{port}"))
        .with_header("user-agent", REPORT_UA)
        .handshake(Extensions::default())
        .await
        .expect("ws handshake to work");
    assert_fingerprint_report(&ws, "HTTP/1.1", "ge11", None);
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
        .websocket(format!("ws://127.0.0.1:{port}"))
        .with_protocols(SecWebSocketProtocol::new(non_empty_str!("echo-upper")))
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

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_http_multipart_form() {
    utils::init_tracing();

    let server = utils::RamaService::serve_echo(0, utils::EchoMode::Http);
    let port = server.port();

    let lines = utils::RamaService::http(vec![
        &format!("http://127.0.0.1:{port}"),
        "-F",
        "username=glen",
        "-F",
        "language=rust;type=text/plain",
    ])
    .unwrap();

    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(lines.contains(r##""method":"POST""##), "lines: {lines:?}");
    assert!(
        lines.contains(r##""content-type","multipart/form-data;"##),
        "lines: {lines:?}",
    );
    // Body bytes are echoed as hex; assert known field bytes are present.
    // "glen" -> 676c656e, "rust" -> 72757374
    assert!(lines.contains("676c656e"), "lines: {lines:?}");
    assert!(lines.contains("72757374"), "lines: {lines:?}");
    // Content-Disposition + name="username" appears in the part header bytes.
    // "name=\"username\"" -> hex
    let needle = rama::utils::fmt::hex("name=\"username\"").to_string();
    assert!(lines.contains(&needle), "needle={needle} lines: {lines:?}");
}

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_http_data_inmemory_emits_content_length() {
    // Regression: literal `--data` items should ship with a precise
    // Content-Length, not chunked, so middleware/peers see exact framing.
    utils::init_tracing();

    let server = utils::RamaService::serve_echo(0, utils::EchoMode::Http);
    let port = server.port();

    let lines = utils::RamaService::http(vec![
        &format!("http://127.0.0.1:{port}"),
        "-d",
        "name=John",
        "-d",
        "age=32",
    ])
    .unwrap();

    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(lines.contains(r##""method":"POST""##), "lines: {lines:?}");
    // Default content type for `-d` is form-urlencoded.
    assert!(
        lines.contains(r##""content-type","application/x-www-form-urlencoded""##),
        "lines: {lines:?}",
    );
    // "name=John&age=32" is 16 bytes.
    assert!(
        lines.contains(r##""content-length","16""##),
        "lines: {lines:?}",
    );
}

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_tcp_echo() {
    utils::init_tracing();

    let server = utils::RamaService::serve_echo(0, utils::EchoMode::Tcp);
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
    let mut stream = stream.expect("connect to tcp listener");

    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_tls_tcp_echo() {
    utils::init_tracing();

    let server = utils::RamaService::serve_echo(0, utils::EchoMode::Tls);
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

    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_udp_echo() {
    utils::init_tracing();

    let server = utils::RamaService::serve_echo(0, utils::EchoMode::Udp);
    let port = server.port();
    let socket = bind_udp_with_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();

    for i in 0..5 {
        match socket
            .connect(SocketAddress::local_ipv4(port).into_std())
            .await
        {
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

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_https_echo() {
    utils::init_tracing();

    let server = utils::RamaService::serve_echo(0, utils::EchoMode::Https);
    let port = server.port();

    let lines = utils::RamaService::http(vec![
        &format!("https://127.0.0.1:{port}?q=1"),
        "-H",
        "foo: bar",
        "-d",
        r##"{"a":4}"##,
        "--json",
    ])
    .unwrap();

    // same http test as the plain text version
    assert!(lines.contains("HTTP/2.0 200 OK"), "lines: {lines:?}");
    assert!(lines.contains(r##""method":"POST""##), "lines: {lines:?}");
    assert!(lines.contains(r##""foo","bar""##), "lines: {lines:?}");
    assert!(
        lines.contains(r##""content-type","application/json""##),
        "lines: {lines:?}",
    );
    assert!(
        lines.contains(/*{"a":4}*/ "7b2261223a347d"),
        "lines: {lines:?}"
    );
    assert!(lines.contains(r##""path":"/""##), "lines: {lines:?}");
    assert!(lines.contains(r##""query":"q=1""##), "lines: {lines:?}");
    assert!(lines.contains(r##""query":"q=1""##), "lines: {lines:?}");

    // do test however that we now also get tls info
    assert!(lines.contains(r##""cipher_suites""##), "lines: {lines:?}");

    // test default WS protocol

    let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_proxy_support()
        .with_tls_support_using_boringssl(
            TlsClientConfig::new()
                .with_alpn_http_1()
                .with_server_verify(ServerVerifyMode::Disable),
        )
        .with_default_http_connector()
        .without_connection_pool()
        .build_client();

    let mut ws = client
        .websocket(format!("wss://127.0.0.1:{port}"))
        .with_header("user-agent", REPORT_UA)
        .handshake(Extensions::default())
        .await
        .expect("ws handshake to work");
    assert_fingerprint_report(&ws, "HTTP/1.1", "ge11", Some("t13"));
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
        .websocket(format!("wss://127.0.0.1:{port}"))
        .with_protocols(SecWebSocketProtocol::new(non_empty_str!("echo-upper")))
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

    // Extended CONNECT over HTTP/2 (RFC 8441)
    let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_proxy_support()
        .with_tls_support_using_boringssl(
            TlsClientConfig::new()
                .with_alpn_http_auto()
                .with_server_verify(ServerVerifyMode::Disable),
        )
        .with_default_http_connector()
        .without_connection_pool()
        .build_client();
    let mut ws = client
        .websocket_h2(format!("wss://127.0.0.1:{port}"))
        .with_header("user-agent", REPORT_UA)
        .handshake(Extensions::default())
        .await
        .expect("ws over h2 handshake to work");
    assert_fingerprint_report(&ws, "HTTP/2.0", "co20", Some("t13"));
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
}

/// A client with an Alt-Svc cache is moved to the advertised HTTP/2 alternative, which
/// authenticates the origin with the same certificate.
#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_https_echo_moves_to_h2_alternative() {
    utils::init_tracing();

    let free_port = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("free port")
            .port()
    };
    // Two listeners: name the origin's port so the harness finds the right one.
    let (origin_port, alt_port) = (free_port(), free_port());
    let server = utils::RamaService::serve_echo_with_args(
        origin_port,
        utils::EchoMode::Https,
        &[
            "--http-version",
            "h1,h2",
            "--alt-svc-h2-bind",
            &format!("127.0.0.1:{alt_port}"),
        ],
    );
    let port = server.port();

    let certificate = X509::from_pem(include_bytes!("./utils/example_tls.crt"))
        .expect("example certificate")
        .to_der()
        .expect("certificate DER");
    let tls = TlsClientConfig::default_http()
        .try_with_server_trust_anchors([CertificateDer::from(certificate)])
        .expect("trust anchor")
        .with_server_verify(ServerVerifyMode::Auto);
    let cache = AltSvcCache::default();
    // The example certificate names plabayo.tech, served here on loopback.
    let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
        .with_default_transport_connector()
        .with_dns_address_resolver(vec![IpAddr::from([127, 0, 0, 1])])
        .without_proxy_support()
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector()
        .with_default_connection_pool()
        .with_alt_svc_cache(cache.clone())
        .build_client();
    let origin = HttpOrigin::new(
        rama::net::Protocol::HTTPS,
        format!("plabayo.tech:{origin_port}")
            .parse()
            .expect("origin"),
    )
    .expect("origin");

    let mut seen = Vec::new();
    for _ in 0..2 {
        let request = Request::builder()
            .uri(format!("https://plabayo.tech:{port}/"))
            .body(Body::empty())
            .expect("request");
        request.extensions().insert(SendAltUsed::new());
        let response = client.serve(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["alt-svc"],
            format!("h2=\":{alt_port}\"; ma=86400").as_str()
        );
        let report: serde_json::Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("report body")
                .to_bytes(),
        )
        .expect("JSON report");
        let alt_used = report["http"]["headers"]
            .as_array()
            .expect("headers")
            .iter()
            .find(|header| header[0] == "alt-used")
            .map(|header| header[1].as_str().unwrap_or_default().to_owned());
        seen.push(alt_used);
        assert!(cache.lookup(&origin).is_some(), "learned the advertisement");
    }
    assert_eq!(seen[0], None);
    assert_eq!(
        seen[1].as_deref(),
        Some(format!("plabayo.tech:{alt_port}").as_str())
    );
}

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_http3_echo() {
    utils::init_tracing();

    let mut server = utils::RamaService::serve_echo(0, utils::EchoMode::Https);
    let port = server.port();
    let h3_port = server.http3_port();

    let lines = utils::RamaService::http(vec![
        "--http3",
        &format!("https://127.0.0.1:{h3_port}?q=1"),
        "-H",
        "foo: bar",
        "-d",
        r##"{"a":4}"##,
        "--json",
    ])
    .unwrap();
    assert!(lines.contains("* using HTTP/3.0"), "lines: {lines:?}");
    assert!(lines.contains("HTTP/3.0 200 OK"), "lines: {lines:?}");
    assert!(lines.contains(r##""method":"POST""##), "lines: {lines:?}");
    assert!(lines.contains(r##""foo","bar""##), "lines: {lines:?}");
    assert!(lines.contains(r##""query":"q=1""##), "lines: {lines:?}");

    // TCP responses advertise HTTP/3 on its own port.
    let lines =
        utils::RamaService::http(vec!["--http2", &format!("https://127.0.0.1:{port}")]).unwrap();
    assert!(
        lines.contains(&format!(r#"alt-svc: h3=":{h3_port}"; ma=86400"#)),
        "lines: {lines:?}"
    );

    // WebSockets over HTTP/3 (RFC 9220)
    let tls = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_proxy_support()
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector()
        .without_connection_pool()
        .build_client();
    let mut ws = client
        .websocket_h3(format!("wss://127.0.0.1:{h3_port}"))
        .with_header("user-agent", REPORT_UA)
        .handshake(Extensions::default())
        .await
        .expect("ws over h3 handshake to work");
    assert_fingerprint_report(&ws, "HTTP/3.0", "co30", Some("q13"));
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
    ws.close(None).await.expect("ws close to be sent");
    while let Some(message) = ws.next().await {
        if matches!(message, Ok(Message::Close(_)) | Err(_)) {
            break;
        }
    }
}

fn assert_contains(lines: &str, needle: &str, cli_flag: &str) {
    if !rama::utils::str::submatch_ignore_ascii_case(lines, needle) {
        eprintln!("Assertion failed for cli flag: {cli_flag}");
        eprintln!("Missing expected line: '{needle}'");
        eprintln!("All lines:");
        eprintln!("------------------");
        dump_debug_lines(lines);
        eprintln!("------------------");
        panic!("expected line not found");
    }
}

fn dump_debug_lines(lines: &str) {
    const CHUNK: usize = 400;
    for (i, line) in lines.lines().enumerate() {
        if line.len() <= CHUNK {
            eprintln!("{:04} | {}", i + 1, line);
            continue;
        }

        for (j, chunk) in line.as_bytes().chunks(CHUNK).enumerate() {
            eprintln!(
                "{:04}.{:02} | {}",
                i + 1,
                j + 1,
                String::from_utf8_lossy(chunk)
            );
        }
    }
}

fn assert_contains_tls_alpn(lines: &str, alpn: &str, cli_flag: &str) {
    let id = "APPLICATION_LAYER_PROTOCOL_NEGOTIATION (0x0010)";
    let variants = [
        format!(r#"{{"data":["{alpn}"],"id":"{id}"}}"#),
        format!(r#"{{"id":"{id}","data":["{alpn}"]}}"#),
    ];

    if variants
        .iter()
        .any(|needle| rama::utils::str::submatch_ignore_ascii_case(lines, needle))
    {
        return;
    }

    eprintln!("Assertion failed for cli flag: {cli_flag}");
    eprintln!("Missing expected ALPN extension for protocol: '{alpn}'");
    eprintln!("Accepted variants:");
    for variant in variants {
        eprintln!("  - {variant}");
    }
    eprintln!("All lines:");
    eprintln!("------------------");
    dump_debug_lines(lines);
    eprintln!("------------------");
    panic!("expected ALPN extension not found");
}

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_https_forced_version() {
    utils::init_tracing();

    let server = utils::RamaService::serve_echo(0, utils::EchoMode::Https);
    let port = server.port();

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
        let lines = utils::RamaService::http(vec![
            test.cli_flag,
            &format!("https://127.0.0.1:{port}?q=1"),
            "-H",
            "foo: bar",
            "-d",
            r##"{"a":4}"##,
            "--json",
        ])
        .unwrap();

        assert_contains(&lines, test.version_response, test.cli_flag);
        assert_contains_tls_alpn(&lines, test.tls_alpn, test.cli_flag);
    }
}

#[ignore = "spawns rama processes"]
#[tokio::test]
async fn test_https_with_remote_tls_cert_issuer() {
    const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    const DOMAIN_TLS_ECHO_CERTS: Domain = Domain::from_static("localhost");

    utils::init_tracing();

    let (ca_issuer_cert, ca_issuer_key) =
        rama::crypto::cert::boring::generate_certificate_authority_x509(
            &SelfSignedCaConfig::default(),
        )
        .unwrap();
    let (issuer_server_cert, issuer_server_key) =
        rama::crypto::cert::boring::issue_leaf_certificate(
            &LeafCertRequest {
                config: LeafCertConfig {
                    subject: CertificateSubject {
                        organisation_name: Some(DOMAIN_TLS_ECHO_CERTS.to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                identities: vec![CertificateIdentity::Dns(DOMAIN_TLS_ECHO_CERTS)],
            },
            &ca_issuer_cert,
            &ca_issuer_key,
        )
        .unwrap();

    let rama_remote_tls_ca = ca_issuer_cert.to_pem().unwrap();

    let tls_acceptor_data = TlsServerConfig::new()
        .with_single_cert(ServerAuthData {
            private_key: PrivateKeyDer::try_from(issuer_server_key.private_key_to_der().unwrap())
                .unwrap(),
            cert_chain: vec![
                CertificateDer::from(issuer_server_cert.to_der().unwrap()),
                CertificateDer::from(ca_issuer_cert.to_der().unwrap()),
            ],

            ocsp: None,
        })
        .with_alpn_http_auto();

    #[derive(Debug, Clone)]
    struct CaInfo {
        crt: X509,
        key: PKey<Private>,
    }

    let http_svc = (
        ArcLayer::new(),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        TraceLayer::new_for_http(),
        CompressionLayer::new(),
        cors::CorsLayer::permissive(),
        SetResponseHeaderLayer::if_not_present_typed(
            StrictTransportSecurity::including_subdomains_for_max_seconds(31536000),
        ),
        AddRequiredResponseHeadersLayer::new(),
        ErrorHandlerLayer::new(),
    )
        .into_layer(
            Router::new_with_state(CaInfo {
                crt: ca_issuer_cert,
                key: ca_issuer_key,
            })
            .with_post(
                "/order",
                async |State(CaInfo {
                           crt: ca_crt,
                           key: ca_key,
                       }): State<CaInfo>,
                       Json(CertOrderInput { domain }): Json<CertOrderInput>| {
                    // NOTE this is a very basic and bad impl of a tls issuer,
                    // do not do something like this in production... ever...

                    let (crt, key) = rama::crypto::cert::boring::issue_leaf_certificate(
                        &LeafCertRequest {
                            config: LeafCertConfig {
                                subject: CertificateSubject {
                                    organisation_name: Some(domain.to_string()),
                                    ..Default::default()
                                },
                                ..Default::default()
                            },
                            identities: vec![CertificateIdentity::Dns(domain)],
                        },
                        &ca_crt,
                        &ca_key,
                    )
                    .context("generate cert for order")?;

                    let mut crt_chain = crt.to_pem().context("server crt to pem")?;
                    crt_chain.extend(ca_crt.to_pem().context("ca cert to pem")?);
                    let crt_pem_base64 = BASE64.encode(crt_chain);

                    let key_pem_base64 =
                        BASE64.encode(key.private_key_to_pem_pkcs8().context("key to pem pkcs8")?);

                    Ok::<_, BoxError>(Json(CertOrderOutput {
                        crt_pem_base64,
                        key_pem_base64,
                    }))
                },
            ),
        );

    let crt_issuer_https_svc = (
        HaProxyLayer::new().with_peek(true),
        TlsAcceptorLayer::new(tls_acceptor_data),
    )
        .into_layer(HttpServer::auto(WeakScope::detached()).service(http_svc));

    tracing::info!("spawning tcp listener for remote tls issuer");

    let tpc_listener = TcpListener::bind_address("[::1]:0", WeakScope::detached())
        .await
        .unwrap();

    tracing::info!("spawning tokio task for remote tls https");

    let issuer_port = tpc_listener.local_addr().unwrap().port();
    tokio::spawn(tpc_listener.serve(crt_issuer_https_svc));

    tracing::info!("start echo service via rama cli");

    let server = utils::RamaService::serve_echo(
        0,
        utils::EchoMode::HttpsWithCertIssuer {
            remote_addr: format!("https://{DOMAIN_TLS_ECHO_CERTS}:{issuer_port}/order"),
            remote_ca: Some(rama_remote_tls_ca),
            remote_auth: None, // please use proper authentication in production, even for internal networks
        },
    );

    let port = server.port();

    #[derive(Debug)]
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

    for test in tests.into_iter() {
        tokio::task::spawn_blocking(move || {
            tracing::info!("run test: {test:?}");

            let lines = utils::RamaService::http(vec![
                test.cli_flag,
                &format!("https://localhost:{port}?q=1"),
                "-H",
                "foo: bar",
                "-d",
                r##"{"a":4}"##,
                "--json",
            ])
            .unwrap();

            assert_contains(&lines, test.version_response, test.cli_flag);
            assert_contains_tls_alpn(&lines, test.tls_alpn, test.cli_flag);
        })
        .await
        .unwrap();
    }
}

/// A fingerprint header of a WebSocket handshake response, if present.
fn fingerprint<S>(ws: &ClientWebSocket<S>, name: &str) -> Option<String> {
    ws.response()
        .headers
        .get(format!("x-rama-fingerprint-{name}"))
        .map(|value| value.to_str().expect("ASCII header").to_owned())
}

/// The headers name this handshake: its version, method, user agent and fingerprints.
fn assert_fingerprint_report<S>(
    ws: &ClientWebSocket<S>,
    version: &str,
    ja4h: &str,
    ja4: Option<&str>,
) {
    let method = if version == "HTTP/1.1" {
        "GET"
    } else {
        "CONNECT"
    };
    assert_eq!(fingerprint(ws, "http-version").as_deref(), Some(version));
    assert_eq!(fingerprint(ws, "http-method").as_deref(), Some(method));
    assert_eq!(fingerprint(ws, "ua").as_deref(), Some(REPORT_UA));
    let hash = fingerprint(ws, "ja4h").expect("ja4h");
    assert!(hash.starts_with(ja4h), "{hash}");
    let verbose = fingerprint(ws, "ja4h-verbose").expect("ja4h verbose");
    assert!(verbose.contains("sec-websocket-version"), "{verbose}");
    // The test User-Agent names no embedded profile.
    assert_eq!(fingerprint(ws, "ja4h-profile"), None);
    assert_eq!(fingerprint(ws, "ja4h-matched"), None);
    match ja4 {
        Some(prefix) => {
            let hash = fingerprint(ws, "ja4").expect("ja4");
            assert!(hash.starts_with(prefix), "{hash}");
        }
        None => assert_eq!(fingerprint(ws, "ja4"), None),
    }
}

const REPORT_UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
