use rama::{
    http::{
        Version,
        client::{DefaultHttpWebClient, masque_quic_transport},
        conn::TargetHttpVersion,
        core::h3::connection::Config as H3Config,
    },
    net::{
        address::{Host, HostWithPort},
        client::{ConnectorTarget, EstablishedClientConnection, ProxyRoute},
        socket::opts::SocketOptions,
        stream::Socket as _,
        tls::ApplicationProtocol,
    },
    proxy::masque::connect_udp::{ConnectUdpConnector, ConnectUdpSocket, MaybeTunneledSocket},
    quic::{
        Connection, ConnectionError, DEFAULT_SOCKET_BUFFER_SIZE, Endpoint, NegotiatedTlsParameters,
        ServerConfig, TransportConfig,
        client::{QuicConnector, QuicEndpointConnector, SharedQuicEndpoint},
        tls::{BoringTlsProvider, TlsOptions},
    },
    udp::{
        DatagramSenderExt as _, DatagramSocket as _, DatagramSocketExt as _, SendDatagram,
        UdpSocketConfig, proxy::UdpConnector,
    },
};
use tokio::{net::UdpSocket, sync::mpsc};

use super::*;

/// A proxy started from `args` on loopback, sharing `shutdown`.
async fn proxy_with(shutdown: &rama::graceful::Shutdown, args: &[&str]) -> std::net::SocketAddr {
    let bind = loopback_bind_address().to_string();
    let mut argv = vec!["test", "--bind", bind.as_str()];
    argv.extend_from_slice(args);
    let cli = TestCli::parse_from(argv);
    start_proxy(shutdown.guard(), cli.proxy).await.0
}

fn shutdown_pair() -> (tokio::sync::oneshot::Sender<()>, rama::graceful::Shutdown) {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    (shutdown_tx, shutdown)
}

/// A loopback UDP server answering every datagram with the same payload.
async fn udp_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; 65536];
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            _ = socket.send_to(&buffer[..len], from).await;
        }
    });
    (address, task)
}

/// A client to a MASQUE proxy with a self-signed certificate.
fn masque_client()
-> impl Service<Request, Output = Response, Error = rama::error::extra::OpaqueError> + Clone {
    let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
    DefaultHttpWebClient::try_default_masque_proxy_client_using_boringssl(Executor::default(), tls)
        .unwrap()
}

/// A CONNECT-UDP tunnel to `target` through `proxy` over `version`.
async fn tunnel(
    proxy: &str,
    target: std::net::SocketAddr,
    version: Version,
) -> Result<ConnectUdpSocket, BoxError> {
    let connector =
        ConnectUdpConnector::new(UdpConnector::new(), masque_client(), Executor::default())
            .with_version(version);
    let request = ConnectRequest::new(HostWithPort::from(target));
    request
        .extensions
        .insert(ProxyRoute::Proxy(proxy.parse().unwrap()));
    let EstablishedClientConnection { conn, .. } =
        timeout(Duration::from_secs(10), connector.serve(request)).await??;
    match conn {
        MaybeTunneledSocket::Tunneled(socket) => Ok(socket),
        MaybeTunneledSocket::Direct(_) => Err(BoxError::from_static_str("not tunneled")),
    }
}

async fn echo(socket: &mut ConnectUdpSocket, payload: &[u8]) {
    let peer = socket.peer_addr().unwrap();
    socket
        .create_sender()
        .send(SendDatagram::new(peer, payload))
        .await
        .unwrap();
    let mut buffer = vec![0; 2048];
    let metadata = timeout(Duration::from_secs(5), socket.recv(&mut buffer))
        .await
        .expect("echo within 5s")
        .unwrap();
    assert_eq!(&buffer[..metadata.len], payload);
}

const VERSIONS: [Version; 3] = [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3];

/// Outer authentication belongs to the front CONNECT. The requests decoded
/// inside that tunnel have an independent proxy-auth exchange, without MASQUE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_preserves_inner_http_proxy_credentials_and_challenges() {
    use rama::{
        ServiceInput,
        http::{client::http_connect, header},
        tls::boring::client::{TlsConnectorData, tls_connect},
    };
    use tokio::io::AsyncWriteExt as _;
    timeout(Duration::from_secs(30), async {
        let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::new()).await.unwrap();
        let own = listener.local_addr().unwrap();
        let (seen, mut requests) = mpsc::unbounded_channel();
        let inner = HttpServer::auto(Executor::new()).service(service_fn(move |request: Request| {
            let credential = request.headers().get(header::PROXY_AUTHORIZATION).cloned();
            seen.send(credential.clone()).unwrap();
            async move {
                let mut response = Response::new(Body::from("inner proxy"));
                if credential.as_ref().map(HeaderValue::as_bytes) != Some(b"Basic aW5uZXI6c2VjcmV0".as_slice()) {
                    *response.status_mut() = StatusCode::PROXY_AUTHENTICATION_REQUIRED;
                    response.headers_mut().insert(header::PROXY_AUTHENTICATE, HeaderValue::from_static("Basic realm=inner"));
                }
                Ok::<_, Infallible>(response)
            }
        }));
        let tls = TlsServerConfig::new().try_with_generated_server_auth(GeneratedServerAuthConfig::default()).unwrap().with_alpn_http_auto();
        let origin = tokio::spawn(listener.serve(TlsAcceptorService::new(tls, inner, false)));
        let (shutdown_tx, shutdown) = shutdown_pair();
        let front = proxy_with(&shutdown, &["--mitm", "--proxy-auth", "outer:x"]).await;
        for version in [Version::HTTP_11, Version::HTTP_2] {
            for credential in [None, Some("Basic aW5uZXI6d3Jvbmc="), Some("Basic aW5uZXI6c2VjcmV0")] {
                let mut stream = tokio::net::TcpStream::connect(front).await.unwrap();
                stream.write_all(format!("CONNECT {own} HTTP/1.1\r\nHost: {own}\r\nProxy-Authorization: Basic b3V0ZXI6eA==\r\n\r\n").as_bytes()).await.unwrap();
                assert!(read_raw_http_head(&mut stream).await.starts_with("HTTP/1.1 200"));
                let tls = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable)
                    .with_server_name(Host::from_static("localhost"))
                    .with_alpn([if version == Version::HTTP_2 { ApplicationProtocol::HTTP_2 } else { ApplicationProtocol::HTTP_11 }].into_iter().collect());
                let stream = tls_connect(ServiceInput::new(stream), Some(TlsConnectorData::try_from(&tls).unwrap())).await.unwrap();
                let mut request = Request::get("http://destination.example/resource").version(version).body(Body::empty()).unwrap();
                request.extensions().insert(TargetHttpVersion(version));
                if let Some(credential) = credential { request.headers_mut().insert(header::PROXY_AUTHORIZATION, HeaderValue::from_static(credential)); }
                let connection = http_connect::<_, _, Body>(stream, request, Executor::new()).await.unwrap();
                let response = connection.conn.serve(connection.input).await.unwrap();
                assert_eq!(requests.recv().await.unwrap(), credential.map(HeaderValue::from_static), "outer credentials must never enter the inner exchange");
                if credential == Some("Basic aW5uZXI6c2VjcmV0") {
                    assert_eq!(response.status(), StatusCode::OK);
                } else {
                    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
                    assert_eq!(response.headers().get(header::PROXY_AUTHENTICATE).unwrap(), "Basic realm=inner");
                }
                assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "inner proxy");
            }
        }
        shutdown_proxy(shutdown_tx, shutdown).await;
        origin.abort();
    }).await.unwrap();
}

/// The inner proxy has independent credentials and an arbitrary URI template.
/// The front accepts the outer CONNECT/CONNECT-UDP, then intercepts TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_relays_a_clients_own_authenticated_masque_session() {
    use rama::{
        ServiceInput,
        http::{
            client::http_connect, core::h3::client, datagram::HttpDatagramSession,
            io::upgrade::handle_upgrade, proto::ext::HttpDatagrams,
        },
        proxy::masque::connect_udp::{
            ConnectUdpTarget, connect_udp_request, session_config, validate_connect_udp_response,
        },
        tls::boring::client::{TlsConnectorData, tls_connect},
    };
    use tokio::io::AsyncWriteExt as _;
    let (target, echo_task) = udp_echo().await;
    let (shutdown_tx, shutdown) = shutdown_pair();
    let own = proxy_with(
        &shutdown,
        &[
            "--protocol",
            "masque",
            "--masque-allow-private",
            "--proxy-auth",
            "inner:secret",
            "--masque-template",
            "/custom{?target_host,target_port}",
        ],
    )
    .await;
    let front = proxy_with(
        &shutdown,
        &[
            "--protocol",
            "masque",
            "--masque-allow-private",
            "--mitm",
            "--proxy-auth",
            "outer:x",
        ],
    )
    .await;
    let front_tcp = proxy_with(
        &shutdown,
        &["--protocol", "http", "--mitm", "--proxy-auth", "outer:x"],
    )
    .await;
    for version in VERSIONS {
        for (credential, malformed) in [
            ("inner:wrong", false),
            ("inner:secret", false),
            ("inner:secret", true),
        ] {
            let proxy = format!(
                "masque://{credential}@localhost:{}/custom{{?target_host,target_port}}",
                own.port()
            )
            .parse()
            .unwrap();
            let target_spec = ConnectUdpTarget::new(
                Host::from(target.ip()),
                std::num::NonZeroU16::new(target.port()).unwrap(),
            );
            let mut request = connect_udp_request(&proxy, &target_spec, version).unwrap();
            request.headers_mut().insert(
                rama::http::header::PROXY_AUTHORIZATION,
                if credential == "inner:secret" {
                    "Basic aW5uZXI6c2VjcmV0"
                } else {
                    "Basic aW5uZXI6d3Jvbmc="
                }
                .parse()
                .unwrap(),
            );
            if malformed {
                request.headers_mut().insert(
                    rama::http::header::CONTENT_LENGTH,
                    HeaderValue::from_static("0"),
                );
            }
            request.extensions().insert(HttpDatagrams);
            request.extensions().insert(TargetHttpVersion(version));
            let tls = TlsClientConfig::new()
                .with_server_verify(ServerVerifyMode::Disable)
                .with_server_name(Host::from_static("localhost"));
            let mut endpoint = None;
            let mut driver = None;
            let response = if version == Version::HTTP_3 {
                let socket = tunnel(&format!("masque://outer:x@{front}"), own, Version::HTTP_3)
                    .await
                    .unwrap();
                let ep = Endpoint::build(Executor::new())
                    .with_datagram_socket(socket)
                    .unwrap();
                let mut config = rama::quic::ClientConfig::try_from_rama_tls_with_provider(
                    &tls.with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect()),
                    TlsOptions::default(),
                    &BoringTlsProvider,
                )
                .unwrap();
                config.set_transport_config(Arc::new(masque_quic_transport()));
                let connection = ep
                    .connect_with(config, own, "localhost")
                    .unwrap()
                    .await
                    .unwrap();
                let (mut client, task) =
                    client::handshake::<Body>(connection, H3Config::default(), Executor::new())
                        .unwrap();
                driver = Some(tokio::spawn(task.run()));
                endpoint = Some(ep);
                client.send_request(request).await.unwrap().map(Body::new)
            } else {
                let mut stream = tokio::net::TcpStream::connect(front_tcp).await.unwrap();
                stream
                    .write_all(format!("CONNECT {own} HTTP/1.1\r\nHost: {own}\r\nProxy-Authorization: Basic b3V0ZXI6eA==\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
                assert!(
                    read_raw_http_head(&mut stream)
                        .await
                        .starts_with("HTTP/1.1 200")
                );
                let tls = tls.with_alpn(
                    [if version == Version::HTTP_2 {
                        ApplicationProtocol::HTTP_2
                    } else {
                        ApplicationProtocol::HTTP_11
                    }]
                    .into_iter()
                    .collect(),
                );
                let stream = tls_connect(
                    ServiceInput::new(stream),
                    Some(TlsConnectorData::try_from(&tls).unwrap()),
                )
                .await
                .unwrap();
                let connection = http_connect::<_, _, Body>(stream, request, Executor::new())
                    .await
                    .unwrap();
                connection.conn.serve(connection.input).await.unwrap()
            };
            if malformed {
                assert_eq!(
                    response.status(),
                    StatusCode::BAD_REQUEST,
                    "{version:?}: inner request error must be preserved"
                );
            } else if credential == "inner:wrong" {
                assert_eq!(
                    response.status(),
                    StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                    "{version:?}"
                );
                assert!(
                    response
                        .headers()
                        .contains_key(rama::http::header::PROXY_AUTHENTICATE),
                    "inner challenge survives interception"
                );
            } else {
                if let Err(error) = validate_connect_udp_response(version, &response) {
                    let headers = response.headers().clone();
                    let body = response.into_body().collect().await.unwrap().to_bytes();
                    panic!("{version:?}: {error:?}; headers={headers:?}; body={body:?}");
                }
                let mut socket = ConnectUdpSocket::new(
                    &Executor::new(),
                    HttpDatagramSession::with_config(
                        handle_upgrade(&response).await.unwrap(),
                        session_config(),
                    ),
                    SocketAddress::local_ipv4(0),
                    target.into(),
                    Default::default(),
                );
                echo(&mut socket, b"client's own authenticated tunnel").await;
            }
            if let Some(endpoint) = endpoint {
                endpoint.close(0u32, b"done");
                endpoint.shutdown().await;
            }
            if let Some(driver) = driver {
                driver.abort();
            }
        }
    }
    shutdown_proxy(shutdown_tx, shutdown).await;
    echo_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_egress_through_a_masque_upstream_uses_connect_with_its_credential() {
    let (origin, origin_task) = spawn_credential_reporting_origin().await;
    let (shutdown_tx, shutdown) = shutdown_pair();
    // The MASQUE vendor's TCP side: an HTTPS proxy requiring its own credential.
    let upstream = proxy_with(
        &shutdown,
        &["--protocol", "https", "--proxy-auth", "vendor:secret"],
    )
    .await;

    for (credential, works) in [("vendor:secret", true), ("vendor:wrong", false)] {
        let upstream_arg = format!("masque://{credential}@{upstream}");
        let front = proxy_with(
            &shutdown,
            &[
                "--protocol",
                "http",
                "--upstream-proxy",
                upstream_arg.as_str(),
                "--upstream-proxy-insecure",
            ],
        )
        .await;
        for tunnel in [false, true] {
            let label = format!("{credential} tunnel={tunnel}");
            match fetch(origin, &format!("http://{front}"), tunnel).await {
                Ok((status, body)) if works => {
                    assert_eq!(status, StatusCode::OK, "{label}");
                    assert_eq!(body, "no credential", "{label}");
                }
                Ok((status, _)) => assert!(!status.is_success(), "{label}: {status}"),
                Err(error) => assert!(!works, "{label}: {error:?}"),
            }
        }
    }

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_ingress_tunnels_udp_on_every_carrier_and_tcp_with_connect() {
    let (target, echo_task) = udp_echo().await;
    let (origin, origin_task) = spawn_credential_reporting_origin().await;
    let (shutdown_tx, shutdown) = shutdown_pair();
    let proxy = proxy_with(
        &shutdown,
        &["--protocol", "masque", "--masque-allow-private"],
    )
    .await;
    let address = format!("masque://{proxy}");
    for version in VERSIONS {
        let mut socket = tunnel(&address, target, version)
            .await
            .unwrap_or_else(|error| panic!("{version:?}: {error:?}"));
        echo(&mut socket, b"through the MASQUE ingress").await;
    }
    // TCP on the same route: ordinary CONNECT.
    let (status, body) = fetch(origin, &address, true).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "no credential");

    shutdown_proxy(shutdown_tx, shutdown).await;
    echo_task.abort();
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_ingress_refuses_private_targets_by_default() {
    let (target, echo_task) = udp_echo().await;
    let (shutdown_tx, shutdown) = shutdown_pair();
    let proxy = proxy_with(&shutdown, &["--protocol", "masque"]).await;
    for version in VERSIONS {
        let error = tunnel(&format!("masque://{proxy}"), target, version)
            .await
            .unwrap_err();
        assert!(
            format!("{error:?}").contains("refused"),
            "{version:?}: {error:?}"
        );
    }
    shutdown_proxy(shutdown_tx, shutdown).await;
    echo_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_tunnels_select_connect_udp_and_connect() {
    let (target, echo_task) = udp_echo().await;
    let (origin, origin_task) = spawn_credential_reporting_origin().await;
    let (shutdown_tx, shutdown) = shutdown_pair();
    let udp_only = proxy_with(
        &shutdown,
        &[
            "--protocol",
            "masque",
            "--masque-allow-private",
            "--masque-tunnels",
            "connect-udp",
        ],
    )
    .await;
    let tcp_only = proxy_with(
        &shutdown,
        &[
            "--protocol",
            "masque",
            "--masque-allow-private",
            "--masque-tunnels",
            "connect",
        ],
    )
    .await;
    for version in VERSIONS {
        let mut socket = tunnel(&format!("masque://{udp_only}"), target, version)
            .await
            .unwrap();
        echo(&mut socket, b"udp allowed").await;
        tunnel(&format!("masque://{tcp_only}"), target, version)
            .await
            .unwrap_err();
    }
    fetch(origin, &format!("masque://{udp_only}"), true)
        .await
        .unwrap_err();
    let (status, _) = fetch(origin, &format!("masque://{tcp_only}"), true)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);

    shutdown_proxy(shutdown_tx, shutdown).await;
    echo_task.abort();
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_ingress_requires_the_proxy_credential() {
    let (target, echo_task) = udp_echo().await;
    let (shutdown_tx, shutdown) = shutdown_pair();
    let proxy = proxy_with(
        &shutdown,
        &[
            "--protocol",
            "masque",
            "--masque-allow-private",
            "--proxy-auth",
            "john:secret",
        ],
    )
    .await;
    for version in VERSIONS {
        for credential in ["", "john:wrong@"] {
            let error = tunnel(&format!("masque://{credential}{proxy}"), target, version)
                .await
                .unwrap_err();
            assert!(
                format!("{error:?}").contains("407"),
                "{version:?} {credential:?}: {error:?}"
            );
        }
        let mut socket = tunnel(&format!("masque://john:secret@{proxy}"), target, version)
            .await
            .unwrap();
        echo(&mut socket, b"authorized").await;
    }
    shutdown_proxy(shutdown_tx, shutdown).await;
    echo_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dedicated_masque_bind_serves_its_custom_template_in_both_proxy_forms() {
    let (target, echo_task) = udp_echo().await;
    let (shutdown_tx, shutdown) = shutdown_pair();
    let cli = TestCli::parse_from([
        "test",
        "--masque-bind",
        "127.0.0.1:0",
        "--masque-allow-private",
        "--masque-template",
        "/masque?h={target_host}&p={target_port}",
    ]);
    let (proxy, _) = start_proxy(shutdown.guard(), cli.proxy).await;
    let template = "/masque?h={target_host}&p={target_port}";
    for version in VERSIONS {
        for scheme in ["masque", "https"] {
            let mut socket = tunnel(&format!("{scheme}://{proxy}{template}"), target, version)
                .await
                .unwrap_or_else(|error| panic!("{scheme} {version:?}: {error:?}"));
            echo(&mut socket, b"custom template").await;
        }
        // The default template is not this proxy's.
        tunnel(&format!("masque://{proxy}"), target, version)
            .await
            .unwrap_err();
    }
    shutdown_proxy(shutdown_tx, shutdown).await;
    echo_task.abort();
}

#[test]
fn an_invalid_masque_template_is_refused_at_startup() {
    TestCli::try_parse_from(["test", "--masque-template", "/masque/{target_host}"]).unwrap_err();
    let cli = TestCli::parse_from([
        "test",
        "--masque-template",
        "/masque/{target_host}/{target_port}/",
    ]);
    assert!(cli.proxy.masque_template.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_ingress_chains_udp_to_a_masque_upstream_and_never_bypasses_another() {
    let (target, echo_task) = udp_echo().await;
    let (shutdown_tx, shutdown) = shutdown_pair();
    let upstream = proxy_with(
        &shutdown,
        &[
            "--protocol",
            "masque",
            "--masque-allow-private",
            "--proxy-auth",
            "vendor:secret",
        ],
    )
    .await;
    let upstream_arg = format!("masque://vendor:secret@{upstream}");
    let front = proxy_with(
        &shutdown,
        &[
            "--protocol",
            "masque",
            "--masque-allow-private",
            "--upstream-proxy",
            upstream_arg.as_str(),
            "--upstream-proxy-insecure",
        ],
    )
    .await;
    for version in VERSIONS {
        let mut socket = tunnel(&format!("masque://{front}"), target, version)
            .await
            .unwrap_or_else(|error| panic!("{version:?}: {error:?}"));
        echo(&mut socket, b"through two MASQUE proxies").await;
    }

    // The upstream's `https://` form with its template is a MASQUE upstream as well.
    let https_upstream = format!(
        "https://vendor:secret@{upstream}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
    );
    let front = proxy_with(
        &shutdown,
        &[
            "--protocol",
            "masque",
            "--masque-allow-private",
            "--upstream-proxy",
            https_upstream.as_str(),
            "--upstream-proxy-insecure",
        ],
    )
    .await;
    let mut socket = tunnel(&format!("masque://{front}"), target, Version::HTTP_3)
        .await
        .unwrap();
    echo(&mut socket, b"through an https template upstream").await;

    // An upstream that cannot carry UDP refuses CONNECT-UDP instead of going direct.
    for upstream in [format!("http://{upstream}"), format!("socks5://{upstream}")] {
        let front = proxy_with(
            &shutdown,
            &[
                "--protocol",
                "masque",
                "--masque-allow-private",
                "--upstream-proxy",
                upstream.as_str(),
            ],
        )
        .await;
        for version in VERSIONS {
            tunnel(&format!("masque://{front}"), target, version)
                .await
                .unwrap_err();
        }
    }

    shutdown_proxy(shutdown_tx, shutdown).await;
    echo_task.abort();
}

/// An HTTP/3 origin on every loopback address, answering every request; with its endpoint.
async fn h3_origin() -> (u16, Endpoint) {
    let (port, endpoint, _connections) = h3_origin_reporting_connections().await;
    (port, endpoint)
}

/// [`h3_origin`], reporting each connection: `None` once accepted, then why it closed.
async fn h3_origin_reporting_connections() -> (
    u16,
    Endpoint,
    mpsc::UnboundedReceiver<Option<ConnectionError>>,
) {
    let tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .unwrap();
    let endpoint = bind_dual_stack_http3(&tls).await;
    let port = endpoint.local_addr().unwrap().port();
    let h3 = HttpServer::new_http3(Executor::default()).service(service_fn(
        async |_request: Request| Ok::<_, Infallible>(Response::new(Body::from("h3 origin"))),
    ));
    let (report, connections) = mpsc::unbounded_channel();
    tokio::spawn(endpoint.clone().serve(
        Executor::default(),
        service_fn(move |connection: Connection| {
            let report = report.clone();
            let h3 = h3.clone();
            async move {
                _ = report.send(None);
                let watched = connection.clone();
                tokio::spawn(async move { report.send(Some(watched.closed().await)) });
                h3.serve(connection).await
            }
        }),
    ));
    (port, endpoint, connections)
}

/// An HTTP/3 endpoint on `[::]` that also takes IPv4: dual-stack is not the platform default
/// everywhere (Windows), and the tests reach the origin over both families.
async fn bind_dual_stack_http3(tls: &TlsServerConfig) -> Endpoint {
    let tls = tls
        .clone()
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut transport = TransportConfig::default();
    H3Config::default()
        .configure_transport(&mut transport)
        .unwrap();
    let mut config = ServerConfig::try_from_rama_tls_with_provider(
        &tls,
        TlsOptions::default(),
        &BoringTlsProvider,
    )
    .unwrap();
    config.set_transport_config(Arc::new(transport));
    let socket = UdpSocketConfig::default().with_min_buffer_size(DEFAULT_SOCKET_BUFFER_SIZE);
    let options = SocketOptions {
        only_v6: Some(false),
        ..socket.socket_options().clone()
    };
    Endpoint::build(Executor::default())
        .with_server_config(config)
        .bind_address_with_socket_config(
            SocketAddress::default_ipv6(0),
            socket.with_socket_options(options),
        )
        .await
        .unwrap()
}

/// The QUIC endpoints of a client whose MASQUE routes tunnel through CONNECT-UDP.
fn tunneling_endpoints() -> QuicEndpointConnector<
    ConnectUdpConnector<
        impl Service<Request, Output = Response, Error = rama::error::extra::OpaqueError> + Clone,
        UdpConnector,
    >,
> {
    QuicEndpointConnector::new(
        ConnectUdpConnector::new(UdpConnector::new(), masque_client(), Executor::default()),
        Executor::default(),
    )
}

/// A QUIC connection to the origin, directly or through `proxy`, keeping the peer's chain.
async fn origin_connection(port: u16, proxy: Option<&str>) -> Connection {
    let tls = TlsClientConfig::new()
        .with_server_verify(ServerVerifyMode::Disable)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
        .with_store_server_cert_chain(true);
    let request = ConnectRequest::new(HostWithPort::localhost_domain_with_port(port));
    let established = if let Some(proxy) = proxy {
        request
            .extensions
            .insert(ProxyRoute::Proxy(proxy.parse().unwrap()));
        QuicConnector::new(tunneling_endpoints(), tls, Arc::new(BoringTlsProvider))
            .serve(request)
            .await
    } else {
        request
            .extensions
            .insert(ConnectorTarget(HostWithPort::local_ipv4(port)));
        QuicConnector::new(
            SharedQuicEndpoint::managed(Executor::default()),
            tls,
            Arc::new(BoringTlsProvider),
        )
        .serve(request)
        .await
    };
    established.unwrap().conn
}

/// The leaf certificate the client sees for the origin, directly or through `proxy`.
async fn origin_leaf(port: u16, proxy: Option<&str>) -> Vec<u8> {
    let connection = origin_connection(port, proxy).await;
    let leaf = connection
        .extensions()
        .get_ref::<NegotiatedTlsParameters>()
        .and_then(|tls| tls.peer_certificate_chain.as_ref())
        .and_then(|chain| chain.first())
        .unwrap()
        .to_vec();
    connection.close(0u32, b"done");
    leaf
}

/// GET the origin over HTTP/3 through `proxy`.
async fn h3_get_through(port: u16, proxy: &str) -> Bytes {
    let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
    let client = DefaultHttpWebClient::try_default_masque_using_boringssl(
        Executor::default(),
        tls.clone(),
        tls,
    )
    .unwrap();
    let request = Request::builder()
        .version(Version::HTTP_3)
        .uri(format!("https://localhost:{port}/"))
        .body(Body::empty())
        .unwrap();
    request
        .extensions()
        .insert(ProxyRoute::Proxy(proxy.parse().unwrap()));
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_3));
    let response = timeout(Duration::from_secs(10), client.serve(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await.unwrap().to_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_terminates_tunneled_quic_in_scope_and_forwards_the_rest_untouched() {
    let (port, origin) = h3_origin().await;
    let direct = origin_leaf(port, None).await;
    let (shutdown_tx, shutdown) = shutdown_pair();
    let upstream = proxy_with(
        &shutdown,
        &["--protocol", "masque", "--masque-allow-private"],
    )
    .await;
    let upstream = format!("masque://{upstream}");
    for (args, intercepted) in [
        (&["--masque-allow-private"][..], false),
        (&["--masque-allow-private", "--mitm"][..], true),
        (
            &[
                "--masque-allow-private",
                "--mitm",
                "--mitm-deny",
                "localhost",
            ][..],
            false,
        ),
        (
            &[
                "--masque-allow-private",
                "--mitm",
                "--mitm-allow",
                "other.example",
            ][..],
            false,
        ),
        (
            &[
                "--masque-allow-private",
                "--mitm",
                "--mitm-allow",
                "localhost",
            ][..],
            true,
        ),
        // MITM egress: the terminated connection leaves through a MASQUE upstream.
        (
            &[
                "--masque-allow-private",
                "--mitm",
                "--upstream-proxy",
                upstream.as_str(),
                "--upstream-proxy-insecure",
            ][..],
            true,
        ),
    ] {
        let mut argv = vec!["--protocol", "masque"];
        argv.extend_from_slice(args);
        let proxy = format!("masque://{}", proxy_with(&shutdown, &argv).await);
        let leaf = origin_leaf(port, Some(&proxy)).await;
        assert_eq!(leaf != direct, intercepted, "{args:?}");
        assert_eq!(h3_get_through(port, &proxy).await, "h3 origin", "{args:?}");
    }
    shutdown_proxy(shutdown_tx, shutdown).await;
    origin.close(0u32, b"done");
}

/// On shutdown, a connection MITM egress tunnels through a MASQUE upstream closes before the
/// connection to that upstream, so the origin learns of the close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_egress_closes_its_tunneled_connection_before_the_upstream_one() {
    let (port, origin, mut connections) = h3_origin_reporting_connections().await;
    let (upstream_tx, upstream_shutdown) = shutdown_pair();
    let upstream = proxy_with(
        &upstream_shutdown,
        &["--protocol", "masque", "--masque-allow-private"],
    )
    .await;
    let upstream = format!("masque://{upstream}");
    // Three runs: both closes start at the same shutdown, so a wrong order only races.
    for run in 0..3 {
        let (shutdown_tx, shutdown) = shutdown_pair();
        let front = proxy_with(
            &shutdown,
            &[
                "--protocol",
                "masque",
                "--masque-allow-private",
                "--mitm",
                "--upstream-proxy",
                upstream.as_str(),
                "--upstream-proxy-insecure",
            ],
        )
        .await;
        let front = format!("masque://{front}");
        let client = origin_connection(port, Some(&front)).await;
        let accepted = timeout(Duration::from_secs(5), connections.recv()).await;
        assert!(
            matches!(accepted, Ok(Some(None))),
            "run {run}: {accepted:?}"
        );

        shutdown_proxy(shutdown_tx, shutdown).await;
        // Loaded CI runners take seconds; a lost close is never `ApplicationClosed`.
        let closed = timeout(Duration::from_secs(8), connections.recv()).await;
        assert!(
            matches!(
                closed,
                Ok(Some(Some(ConnectionError::ApplicationClosed(_))))
            ),
            "run {run}: {closed:?}"
        );
        drop(client);
    }
    shutdown_proxy(upstream_tx, upstream_shutdown).await;
    origin.close(0u32, b"done");
}

#[test]
fn masque_connections_outlive_a_quiet_tunnel() {
    // RFC 9298 §3.1: a tunnel's own idle close comes no sooner than two minutes.
    let idle = masque_quic_transport().get_max_idle_timeout().unwrap();
    assert!(idle > Duration::from_mins(2), "{idle:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "waits out QUIC's default idle timeout, nightly"]
async fn a_quiet_tunnel_resumes_after_the_default_quic_idle_timeout() {
    let (target, echo_task) = udp_echo().await;
    let (shutdown_tx, shutdown) = shutdown_pair();
    let upstream = proxy_with(
        &shutdown,
        &["--protocol", "masque", "--masque-allow-private"],
    )
    .await;
    let upstream_arg = format!("masque://{upstream}");
    let front = proxy_with(
        &shutdown,
        &[
            "--protocol",
            "masque",
            "--masque-allow-private",
            "--upstream-proxy",
            upstream_arg.as_str(),
            "--upstream-proxy-insecure",
        ],
    )
    .await;
    let mut direct = tunnel(&upstream_arg, target, Version::HTTP_3)
        .await
        .unwrap();
    let mut chained = tunnel(&format!("masque://{front}"), target, Version::HTTP_3)
        .await
        .unwrap();
    echo(&mut direct, b"before").await;
    echo(&mut chained, b"before").await;
    tokio::time::sleep(Duration::from_secs(35)).await;
    echo(&mut direct, b"after a quiet half minute").await;
    echo(&mut chained, b"after a quiet half minute").await;
    shutdown_proxy(shutdown_tx, shutdown).await;
    echo_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_shutdown_ends_live_tunnels() {
    let (target, echo_task) = udp_echo().await;
    let (port, origin) = h3_origin().await;
    for mitm in [false, true] {
        let (shutdown_tx, shutdown) = shutdown_pair();
        let mut args = vec!["--protocol", "masque", "--masque-allow-private"];
        if mitm {
            args.push("--mitm");
        }
        let proxy = format!("masque://{}", proxy_with(&shutdown, &args).await);
        let mut tunnels = Vec::new();
        for version in VERSIONS {
            let mut socket = tunnel(&proxy, target, version).await.unwrap();
            echo(&mut socket, b"live").await;
            tunnels.push(socket);
        }
        // A tunneled QUIC connection, terminated under --mitm.
        let connection = origin_connection(port, Some(&proxy)).await;
        let started = std::time::Instant::now();
        shutdown_proxy(shutdown_tx, shutdown).await;
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "mitm={mitm}: {:?}",
            started.elapsed()
        );
        drop((tunnels, connection));
    }
    echo_task.abort();
    origin.close(0u32, b"done");
}
