use rama::net::{Protocol, stream::SocketInfo};

use super::*;

#[test]
fn default_is_shared_http_and_socks5_on_loopback_8080() {
    let cli = TestCli::parse_from(["test"]);
    let listeners = resolve_listeners(&cli.proxy);
    assert_eq!(
        listeners
            .iter()
            .find(|(address, _)| *address == default_bind())
            .map(|(_, protocols)| protocols),
        Some(&BTreeSet::from([
            ProxyProtocol::Http,
            ProxyProtocol::Socks5,
        ]))
    );
    assert!(!cli.proxy.lazy_connect);
    assert!(!cli.proxy.no_upstream_proxy_forward_auth);
    assert!(!cli.proxy.upstream_proxy_tunnel);
    assert!(cli.proxy.mitm.is_none());
    assert_eq!(cli.proxy.body_limit, 0);
    assert_eq!(cli.proxy.capture_total_limit, DEFAULT_CAPTURE_TOTAL_LIMIT);
    assert_eq!(cli.proxy.capture_websocket_messages, 10_000);
    assert!(cli.proxy.icap.is_none());
    assert!(cli.proxy.icap_reqmod);
    assert!(cli.proxy.icap_respmod);
    assert_eq!(cli.proxy.icap_preview, DEFAULT_ICAP_PREVIEW_BYTES);
    assert!(!cli.proxy.icap_allow_204);
    assert!(!cli.proxy.icap_allow_206);
    assert_eq!(cli.proxy.icap_connections, DEFAULT_ICAP_CONNECTIONS);
    assert_eq!(cli.proxy.icap_timeout.get(), DEFAULT_ICAP_TIMEOUT_SECS);
    assert_eq!(cli.proxy.icap_idle_timeout, DEFAULT_ICAP_IDLE_TIMEOUT_SECS);
    assert!(!cli.proxy.icap_insecure);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_http_and_socks5_listener_forwards_end_to_end() {
    let (origin, origin_task) = spawn_plain_origin("shared-proxy-ok").await;
    let proxy_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str()]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    for scheme in ["http", "socks5h"] {
        let proxy = format!("{scheme}://{proxy_address}");
        let (status, body) = get_via_proxy(origin, &proxy).await;
        assert_eq!(status, StatusCode::OK, "proxy scheme {scheme}");
        assert_eq!(body, "shared-proxy-ok", "proxy scheme {scheme}");
    }

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_proxy_listener_forwards_end_to_end() {
    let (origin, origin_task) = spawn_plain_origin("https-proxy-ok").await;
    let proxy_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str(), "--protocol", "https"]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let proxy = format!("https://{proxy_address}");
    let (status, body) = get_via_proxy(origin, &proxy).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "https-proxy-ok");

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_mitm_dashboard_http_and_socks5_share_a_listener_end_to_end() {
    let (origin, origin_task) = spawn_plain_origin("shared-dashboard-ok").await;
    let proxy_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str(), "--mitm"]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    for scheme in ["http", "socks5h"] {
        let (status, body) = get_via_proxy(origin, &format!("{scheme}://{proxy_address}")).await;
        assert_eq!(status, StatusCode::OK, "proxy scheme {scheme}");
        assert_eq!(body, "shared-dashboard-ok", "proxy scheme {scheme}");
    }

    let client = EasyHttpWebClient::default();
    let response = client
        .serve(
            Request::builder()
                .uri(format!("http://{proxy_address}/"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    response.into_body().collect().await.unwrap();
    let response = client
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{proxy_address}/"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("'unsafe-eval'")
    );
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("Rama Proxy Inspector"));
    let session = dashboard_session_id(&html);
    let response = client
        .serve(dashboard_request(
            Request::builder()
                .uri(format!(
                    "http://{proxy_address}/events?datastar=%7B%22session%22%3A%22{session}%22%7D"
                ))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = next_sse_event(&mut events).await;
    assert!(event.contains(&origin.to_string()));
    assert!(event.contains("1 req ·"));
    assert!(!event.contains("0 req ·"));
    drop(events);
    drop(client);

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_http_summary_includes_ingress_and_egress_socket_addresses() {
    let (origin, origin_task) = spawn_plain_origin("socket-summary").await;
    let store = crate::cmd::serve::proxy::capture::test_store(
        8,
        8,
        mib_u64(1),
        Arc::new(UserAgentDatabase::try_embedded().unwrap()),
    )
    .unwrap();
    let ingress_local: SocketAddress = "127.0.0.1:8080".parse().unwrap();
    let ingress_peer: SocketAddress = "127.0.0.1:54321".parse().unwrap();
    let connection_id = store
        .begin_connection_if_enabled(
            Some(SocketInfo::new(Some(ingress_local), ingress_peer)),
            Protocol::HTTP,
            None,
        )
        .unwrap();
    store.confirm_connection(connection_id);
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: Some(store.clone()),
        inspection: store.inspection_state(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: None,
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        icap: None,
    });
    let request = Request::builder()
        .uri(format!("http://{origin}/socket-summary"))
        .extension(ConnectionId(connection_id))
        .body(Body::empty())
        .unwrap();
    let response = client.serve(request).await.unwrap();
    response.into_body().collect().await.unwrap();

    let details = store.details(1).await.unwrap();
    let connection = details.connection.as_ref().unwrap();
    assert_eq!(connection.local_address, Some(ingress_local));
    assert_eq!(connection.peer_address, Some(ingress_peer));
    let upstream = details.metadata.upstream.get_ref::<SocketInfo>().unwrap();
    assert!(upstream.local_addr().is_some());
    assert_eq!(upstream.peer_addr(), origin);
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_har_controller_records_proxy_traffic_end_to_end() {
    let (origin, origin_task) = spawn_plain_origin("har-proxy-ok").await;
    let directory = rama::utils::fs::tempdir().unwrap();
    let path = directory.path().join("proxy.har");
    let har = HarController::default();
    har.start(path.clone()).await.unwrap();
    let upstream = UpstreamProxyConfig::new(None, false, &[]).unwrap();
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: har.clone(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: None,
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream,
        icap: None,
    });
    let response = client
        .serve(
            Request::builder()
                .uri(format!("http://{origin}/har-e2e"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "har-proxy-ok"
    );
    har.stop().await;

    let document: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
    let entries = document["log"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["request"]["url"],
        format!("http://{origin}/har-e2e")
    );
    assert_eq!(entries[0]["response"]["status"], 200);
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_connect_is_mitm_relayed_end_to_end() {
    let origin_listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
            .await
            .unwrap();
    let origin_address = origin_listener.local_addr().unwrap();
    let origin_tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .unwrap()
        .with_alpn_http_auto();
    let origin_http =
        HttpServer::auto(Executor::default()).service(service_fn(|_request: Request| async move {
            Ok::<_, Infallible>(Response::new(Body::from("mitm-roundtrip-ok")))
        }));
    let origin_task = tokio::spawn(origin_listener.serve(TlsAcceptorService::new(
        origin_tls,
        origin_http,
        false,
    )));

    let proxy_address = reserve_loopback_address();
    let ui_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let mitm_arg = format!("--mitm={ui_address}");
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str(), mitm_arg.as_str()]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let tls_config = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let request = Request::builder()
        .uri(format!("https://{origin_address}/ping"))
        .extension(ProxyRoute::Proxy(
            format!("http://{proxy_address}").parse().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), client.serve(request))
        .await
        .expect("MITM request timed out")
        .expect("MITM request failed");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "mitm-roundtrip-ok"
    );

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test]
async fn http2_blocking_and_connection_release_preserve_sibling_streams() {
    use rama::{
        http::{
            Version,
            client::http_connect,
            core::h2,
            inspect::control::{Config, ControlConnection, Decision, ResponseSpec},
            proxy::mitm::HttpMitmRelay,
        },
        io::BridgeIo,
        layer::ArcLayer,
        net::test_utils::client::MockSocket,
        rt::Executor,
    };
    let store = capture::test_store(
        8,
        8,
        kib_u64(1),
        Arc::new(UserAgentDatabase::try_embedded().unwrap()),
    )
    .unwrap();
    let control = store.control();
    control
        .configure(
            0,
            Config {
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
    let (client_io, ingress_io) = tokio::io::duplex(kib(64));
    let (egress_io, origin_io) = tokio::io::duplex(kib(64));
    let calls = Arc::new(AtomicUsize::new(0));
    let origin_calls = calls.clone();
    let origin = tokio::spawn(async move {
        let mut connection = h2::server::handshake(MockSocket::new(origin_io))
            .await
            .unwrap();
        while let Some(Ok((_, mut reply))) = connection.accept().await {
            origin_calls.fetch_add(1, Ordering::Relaxed);
            reply
                .send_response(
                    Response::builder()
                        .header("x-upstream", "yes")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
        }
    });
    let ingress = MockSocket::new(ingress_io);
    let id = store
        .begin_connection_if_enabled(None, Protocol::HTTPS, None)
        .unwrap();
    ingress.extensions().insert(ConnectionId(id));
    ingress.extensions().insert(ControlConnection::new(id));
    let middleware = CaptureHttpLayer::new(Some(store.clone()));
    let relay = tokio::spawn(async move {
        Box::pin(
            HttpMitmRelay::new(Executor::default())
                .with_http_middleware((middleware, ArcLayer::new()))
                .serve(BridgeIo(ingress, MockSocket::new(egress_io))),
        )
        .await
        .unwrap();
    });
    let request = |path: &str| {
        Request::builder()
            .uri(format!("https://origin.test/{path}"))
            .version(Version::HTTP_2)
            .body(Body::empty())
            .unwrap()
    };
    let conn = Arc::new(
        http_connect(
            MockSocket::new(client_io),
            request("setup"),
            Executor::default(),
        )
        .await
        .unwrap()
        .conn,
    );
    let first_conn = conn.clone();
    let first_request = request("blocked");
    let first = tokio::spawn(async move { first_conn.serve(first_request).await.unwrap() });
    let first_id = approval_id(&store, Direction::Ingress).await;
    let second_conn = conn.clone();
    let second_request = request("replacement");
    let second = tokio::spawn(async move { second_conn.serve(second_request).await.unwrap() });
    let mut changes = control.subscribe_changes();
    tokio::time::timeout(Duration::from_secs(3), async {
        while control.snapshot().pending.len() != 2 {
            changes.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    control.resolve(first_id, Decision::Block).unwrap();
    let response = first.await.unwrap();
    assert_eq!(response.status().as_u16(), 403);
    assert!(!response.headers().contains_key("connection"));
    response.into_body().collect().await.unwrap();
    assert!(!second.is_finished());
    let second_id = approval_id(&store, Direction::Ingress).await;
    assert_eq!(control.pending(second_id).unwrap().connection, id);
    control.resolve(second_id, Decision::forward()).unwrap();
    let response_id = approval_id(&store, Direction::Egress).await;
    control
        .resolve(
            response_id,
            Decision::Respond {
                response: ResponseSpec::error(StatusCode::SERVICE_UNAVAILABLE, "locally replaced"),
            },
        )
        .unwrap();
    let response = second.await.unwrap();
    assert_eq!(response.status().as_u16(), 503);
    assert!(!response.headers().contains_key("connection"));
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "locally replaced"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let third_conn = conn.clone();
    let third_request = request("release");
    let third = tokio::spawn(async move { third_conn.serve(third_request).await.unwrap() });
    let id = approval_id(&store, Direction::Ingress).await;
    control
        .resolve(
            id,
            Decision::Connection {
                headers: None,
                status: None,
                payload: None,
            },
        )
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), third)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.headers()["x-upstream"], "yes");
    response.into_body().collect().await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), conn.serve(request("future")))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    response.into_body().collect().await.unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 3);
    assert!(control.snapshot().pending.is_empty());
    drop(conn);
    relay.abort();
    origin.abort();
}
