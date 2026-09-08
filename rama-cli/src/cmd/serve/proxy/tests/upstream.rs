use super::*;

#[test]
fn upstream_forward_proxy_options_are_explicit() {
    let cli = TestCli::parse_from([
        "test",
        "--upstream-proxy",
        "http://pu:pp@proxy.example:8080",
        "--no-upstream-proxy-forward-auth",
        "--upstream-proxy-tunnel",
    ]);
    assert!(cli.proxy.no_upstream_proxy_forward_auth);
    assert!(cli.proxy.upstream_proxy_tunnel);
    assert!(cli.proxy.upstream_proxy.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_client_isolates_upstream_proxy_407() {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(
        listener.serve(HttpServer::auto(Executor::default()).service(service_fn(
            |request: Request| async move {
                assert_eq!(
                    request.uri().to_string(),
                    "http://origin.example/upstream-challenge"
                );
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                        .header("proxy-authenticate", "Basic realm=upstream-secret")
                        .header("proxy-authentication-info", "nextnonce=upstream-secret")
                        .body(Body::from("upstream-secret-body"))
                        .unwrap(),
                )
            },
        ))),
    );
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(
            Some(format!("http://{proxy_address}").parse().unwrap()),
            false,
            &[],
        )
        .unwrap(),
        icap: None,
    });

    let response = client
        .serve(
            Request::builder()
                .uri("http://origin.example/upstream-challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(!response.headers().contains_key("proxy-authenticate"));
    assert!(!response.headers().contains_key("proxy-authentication-info"));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        !body
            .windows(b"upstream-secret".len())
            .any(|w| w == b"upstream-secret")
    );

    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_client_can_disable_automatic_upstream_proxy_auth() {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(
        listener.serve(HttpServer::auto(Executor::default()).service(service_fn(
            |request: Request| async move {
                assert_eq!(
                    request.uri().to_string(),
                    "http://origin.example/no-upstream-auth"
                );
                assert!(
                    !request
                        .headers()
                        .contains_key(rama::http::header::PROXY_AUTHORIZATION)
                );
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            },
        ))),
    );
    let mut proxy: ProxyAddress = format!("http://{proxy_address}").parse().unwrap();
    proxy.credential = Some(rama::net::user::ProxyCredential::Basic(
        rama::net::user::Basic::try_from("pu:pp").unwrap(),
    ));
    let upstream = UpstreamProxyConfig::new(Some(proxy), false, &[])
        .unwrap()
        .with_forward_proxy_auth(false);
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream,
        icap: None,
    });

    let response = client
        .serve(
            Request::builder()
                .uri("http://origin.example/no-upstream-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_client_authenticates_plaintext_upstream_proxy_by_default() {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(
        listener.serve(HttpServer::auto(Executor::default()).service(service_fn(
            |request: Request| async move {
                assert_eq!(
                    request.uri().to_string(),
                    "http://origin.example/upstream-auth"
                );
                assert_eq!(
                    request.headers()[rama::http::header::PROXY_AUTHORIZATION],
                    "Basic cHU6cHA="
                );
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            },
        ))),
    );
    let mut proxy: ProxyAddress = format!("http://{proxy_address}").parse().unwrap();
    proxy.credential = Some(rama::net::user::ProxyCredential::Basic(
        rama::net::user::Basic::try_from("pu:pp").unwrap(),
    ));
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(Some(proxy), false, &[]).unwrap(),
        icap: None,
    });

    let response = client
        .serve(
            Request::builder()
                .uri("http://origin.example/upstream-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_client_can_tunnel_plaintext_without_leaking_proxy_auth() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket_address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let connect = read_raw_http_head(&mut stream).await;
        assert!(connect.starts_with("CONNECT origin.example:80 HTTP/1.1\r\n"));
        assert!(
            connect
                .to_ascii_lowercase()
                .contains("proxy-authorization: basic chu6cha=")
        );
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        let origin = read_raw_http_head(&mut stream).await;
        assert!(origin.starts_with("GET /inside HTTP/1.1\r\n"));
        assert!(!origin.to_ascii_lowercase().contains("proxy-authorization:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let mut proxy: ProxyAddress = format!("http://{socket_address}").parse().unwrap();
    proxy.credential = Some(rama::net::user::ProxyCredential::Basic(
        rama::net::user::Basic::try_from("pu:pp").unwrap(),
    ));
    let upstream = UpstreamProxyConfig::new(Some(proxy), false, &[])
        .unwrap()
        .with_tunnel_plaintext_http(true);
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream,
        icap: None,
    });

    let response = client
        .serve(
            Request::builder()
                .uri("http://origin.example/inside")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    timeout(Duration::from_secs(5), proxy_task)
        .await
        .expect("proxy task timed out")
        .expect("proxy task failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_http_client_applies_connect_timeout_to_tls_handshake() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let listener_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        _ = accepted_tx.send(());
        std::future::pending::<()>().await;
        drop(socket);
    });
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: Some(Duration::from_millis(50)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        icap: None,
    });
    let started = tokio::time::Instant::now();
    let response = timeout(
        Duration::from_secs(2),
        client.serve(
            Request::builder()
                .uri(format!("https://{address}/"))
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("forward HTTP client ignored its connect timeout")
    .unwrap();
    assert!(response.status().is_server_error());
    assert!(started.elapsed() >= Duration::from_millis(25));
    timeout(Duration::from_secs(1), accepted_rx)
        .await
        .expect("client did not reach the stalled TLS peer")
        .unwrap();
    listener_task.abort();
}
