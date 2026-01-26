use rama::{
    error::ErrorContext as _,
    extensions::Extensions,
    http::{
        client::EasyHttpWebClient, headers::SecWebSocketProtocol,
        ws::handshake::client::HttpClientWebSocketExt,
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::client::default_tcp_connect,
    telemetry::tracing,
    udp::bind_udp,
    utils::str::non_empty_str,
};
use rama_net::address::HostWithPort;

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

#[ignore]
#[tokio::test]
async fn test_http_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_echo(63101, utils::EchoMode::Http);

    let lines = utils::RamaService::http(vec!["--http1.1", "http://127.0.0.1:63101"]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");

    let lines = utils::RamaService::http(vec![
        "http://127.0.0.1:63101?q=1",
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

#[ignore]
#[tokio::test]
async fn test_tcp_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_echo(63110, utils::EchoMode::Tcp);

    let mut stream = None;
    for i in 0..5 {
        let extensions = Extensions::new();
        match default_tcp_connect(
            &extensions,
            HostWithPort::local_ipv4(63110),
            Executor::default(),
        )
        .await
        {
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

#[ignore]
#[tokio::test]
#[cfg(feature = "boring")]
async fn test_tls_tcp_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_echo(63111, utils::EchoMode::Tls);

    let mut stream = None;
    for i in 0..5 {
        let connector = TlsConnector::secure(TcpConnector::new(Executor::default()))
            .with_connector_data(Arc::new(
                TlsConnectorDataBuilder::new().with_server_verify_mode(ServerVerifyMode::Disable),
            ));
        match connector
            .connect(TcpRequest::new(([127, 0, 0, 1], 63111).into()))
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

#[ignore]
#[tokio::test]
async fn test_udp_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_echo(63112, utils::EchoMode::Udp);
    let socket = bind_udp(SocketAddress::local_ipv4(63113)).await.unwrap();

    for i in 0..5 {
        match socket
            .connect(SocketAddress::local_ipv4(63112).into_std())
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

#[ignore]
#[tokio::test]
#[cfg(feature = "boring")]
async fn test_https_echo() {
    use rama::rt::Executor;

    utils::init_tracing();

    let _guard = utils::RamaService::serve_echo(63103, utils::EchoMode::Https);

    let lines = utils::RamaService::http(vec![
        "https://127.0.0.1:63103?q=1",
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

    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(Some(Arc::new(
            TlsConnectorDataBuilder::new_http_1()
                .with_server_verify_mode(ServerVerifyMode::Disable),
        )))
        .with_default_http_connector(Executor::default())
        .build_client();

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

#[ignore]
#[tokio::test]
#[cfg(feature = "boring")]
async fn test_https_forced_version() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_echo(63104, utils::EchoMode::Https);

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
            "https://127.0.0.1:63104?q=1",
            "-H",
            "foo: bar",
            "-d",
            r##"{"a":4}"##,
            "--json",
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

#[ignore]
#[tokio::test]
#[cfg(all(feature = "boring", feature = "http-full"))]
async fn test_https_with_remote_tls_cert_issuer() {
    use ::base64::Engine;
    use ::rama::{
        Layer as _,
        error::OpaqueError,
        http::{
            Body,
            headers::StrictTransportSecurity,
            layer::{
                compression::CompressionLayer, cors, map_response_body::MapResponseBodyLayer,
                required_header::AddRequiredResponseHeadersLayer,
                set_header::SetResponseHeaderLayer, trace::TraceLayer,
            },
            server::HttpServer,
            service::web::{
                Router,
                extract::{Json, State},
            },
            tls::{CertOrderInput, CertOrderOutput},
        },
        net::{
            address::Domain,
            tls::{
                ApplicationProtocol, DataEncoding,
                server::{SelfSignedData, ServerAuth, ServerAuthData, ServerConfig},
            },
        },
        proxy::haproxy::server::HaProxyLayer,
        rt::Executor,
        tcp::server::TcpListener,
        tls::boring::{
            core::{
                pkey::{PKey, Private},
                x509::X509,
            },
            server::{TlsAcceptorLayer, utils as boring_server_utils},
        },
    };

    const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    const DOMAIN_TLS_ECHO_CERTS: Domain = Domain::from_static("localhost");

    utils::init_tracing();

    let (ca_issuer_cert, ca_issuer_key) =
        boring_server_utils::self_signed_server_ca(&SelfSignedData::default()).unwrap();
    let (issuer_server_cert, issuer_server_key) =
        boring_server_utils::self_signed_server_auth_gen_cert(
            &SelfSignedData {
                organisation_name: Some(DOMAIN_TLS_ECHO_CERTS.to_string()),
                common_name: Some(DOMAIN_TLS_ECHO_CERTS),
                subject_alternative_names: Some(vec![DOMAIN_TLS_ECHO_CERTS.to_string()]),
            },
            &ca_issuer_cert,
            &ca_issuer_key,
        )
        .unwrap();

    let rama_remote_tls_ca = ca_issuer_cert.to_pem().unwrap();

    let tls_acceptor_data = ServerConfig {
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
        ..ServerConfig::new(ServerAuth::Single(ServerAuthData {
            private_key: DataEncoding::Der(issuer_server_key.private_key_to_der().unwrap()),
            cert_chain: DataEncoding::DerStack(vec![
                issuer_server_cert.to_der().unwrap(),
                ca_issuer_cert.to_der().unwrap(),
            ]),
            ocsp: None,
        }))
    }
    .try_into()
    .unwrap();

    #[derive(Debug, Clone)]
    struct CaInfo {
        crt: X509,
        key: PKey<Private>,
    }

    let http_svc = (
        MapResponseBodyLayer::new(Body::new),
        TraceLayer::new_for_http(),
        CompressionLayer::new(),
        cors::CorsLayer::permissive(),
        SetResponseHeaderLayer::if_not_present_typed(
            StrictTransportSecurity::including_subdomains_for_max_seconds(31536000),
        ),
        AddRequiredResponseHeadersLayer::new(),
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

                    let (crt, key) = boring_server_utils::self_signed_server_auth_gen_cert(
                        &SelfSignedData {
                            organisation_name: Some(domain.to_string()),
                            common_name: Some(domain.clone()),
                            subject_alternative_names: Some(vec![domain.to_string()]),
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

                    Ok::<_, OpaqueError>(Json(CertOrderOutput {
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
        .into_layer(HttpServer::auto(Executor::default()).service(Arc::new(http_svc)));

    tracing::info!("spawning tcp listener for remote tls issuer");

    let tpc_listener = TcpListener::bind("[::1]:63132", Executor::default())
        .await
        .unwrap();

    tracing::info!("spawning tokio task for remote tls https");

    tokio::spawn(tpc_listener.serve(crt_issuer_https_svc));

    tracing::info!("start echo service via rama cli");

    let _guard = utils::RamaService::serve_echo(
        63131,
        utils::EchoMode::HttpsWithCertIssuer {
            remote_addr: format!("https://{DOMAIN_TLS_ECHO_CERTS}:63132/order"),
            remote_ca: Some(rama_remote_tls_ca),
            remote_auth: None, // please use proper authentication in production, even for internal networks
        },
    );

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

            let tls_alpn = format!(
                r#"{{"data":["{}"],"id":"APPLICATION_LAYER_PROTOCOL_NEGOTIATION (0x0010)"}}"#,
                test.tls_alpn
            );

            let lines = utils::RamaService::http(vec![
                test.cli_flag,
                "https://localhost:63131?q=1",
                "-H",
                "foo: bar",
                "-d",
                r##"{"a":4}"##,
                "--json",
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
        })
        .await
        .unwrap();
    }
}
