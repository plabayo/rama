use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_max_connections_clamps_concurrent_icap_transactions() {
    let icap_state = Arc::new(ProxyTestIcapState {
        peer_max_connections: Some(1),
        delay: Some(Duration::from_millis(30)),
        ..Default::default()
    });
    let (icap_address, icap_task) = spawn_proxy_test_icap_with_state(icap_state.clone()).await;
    let (origin, origin_task) = spawn_plain_origin("connection-limit-ok").await;
    let cli = TestCli::parse_from(vec![
        "test".to_owned(),
        "--icap".to_owned(),
        format!("icap://{icap_address}/adapt"),
        "--icap-connections".to_owned(),
        "4".to_owned(),
    ]);
    let tcp_options = Arc::new(SocketOptions::default_tcp());
    let icap = build_icap_adaptation(
        &cli.proxy,
        tcp_options.clone(),
        Some(Duration::from_secs(2)),
    )
    .unwrap();
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options,
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        icap,
    });
    let request = || {
        Request::builder()
            .uri(format!("http://{origin}/limited"))
            .body(Body::empty())
            .unwrap()
    };

    let exchange = || async {
        let response = client.serve(request()).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, body)
    };
    let (first, second) = Box::pin(timeout(Duration::from_secs(5), async {
        tokio::join!(exchange(), exchange())
    }))
    .await
    .expect("requests queued by Max-Connections did not make progress");
    for (status, body) in [first, second] {
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "connection-limit-ok");
    }
    assert_eq!(icap_state.max_active.load(Ordering::SeqCst), 1);

    origin_task.abort();
    icap_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_http_and_socks5_mitm_apply_icap_reqmod_and_respmod() {
    let (icap_address, icap_task, _icap_state) = spawn_proxy_test_icap().await;
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
        HttpServer::auto(Executor::default()).service(service_fn(|request: Request| async move {
            assert_eq!(request.headers()["x-rama-icap-reqmod"], "yes");
            assert!(
                !request
                    .headers()
                    .contains_key(rama::http::header::PROXY_AUTHORIZATION)
            );
            Ok::<_, Infallible>(Response::new(Body::from("mitm-icap-ok")))
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
    let icap_uri = format!("icap://{icap_address}/adapt");
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        proxy_arg.as_str(),
        mitm_arg.as_str(),
        "--icap",
        icap_uri.as_str(),
    ]);
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
    for scheme in ["http", "socks5h"] {
        let response = timeout(
            Duration::from_secs(10),
            client.serve(
                Request::builder()
                    .uri(format!("https://{origin_address}/icap"))
                    .extension(ProxyRoute::Proxy(
                        format!("{scheme}://{proxy_address}").parse().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("ICAP-adapted {scheme} MITM request timed out"))
        .unwrap_or_else(|error| panic!("ICAP-adapted {scheme} MITM request failed: {error}"));
        assert_eq!(response.status(), StatusCode::OK, "proxy scheme {scheme}");
        assert_eq!(
            response.headers()["x-rama-icap-respmod"],
            "yes",
            "proxy scheme {scheme}",
        );
        assert!(
            !response
                .headers()
                .contains_key(rama::http::header::PROXY_AUTHENTICATE),
            "proxy scheme {scheme}",
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "mitm-icap-ok",
            "proxy scheme {scheme}",
        );
    }
    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
    icap_task.abort();
}
