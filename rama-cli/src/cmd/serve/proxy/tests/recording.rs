use rama::http::Method;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pausing_inspector_tunnels_origin_tls_without_capturing_until_resumed() {
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
            Ok::<_, Infallible>(Response::new(Body::from("pause-roundtrip-ok")))
        }));
    let origin_task = tokio::spawn(origin_listener.serve(TlsAcceptorService::new(
        origin_tls,
        origin_http,
        false,
    )));

    let proxy_address = reserve_loopback_address();
    let ui_address = reserve_loopback_address();
    let directory = rama::utils::fs::tempdir().unwrap();
    let ca_path = directory.path().join("pause-proxy-ca.pem");
    let proxy_arg = proxy_address.to_string();
    let mitm_arg = format!("--mitm={ui_address}");
    let ca_arg = ca_path.to_string_lossy().into_owned();
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        proxy_arg.as_str(),
        mitm_arg.as_str(),
        "--mitm-ca-cert",
        ca_arg.as_str(),
    ]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let dashboard_client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(TlsClientConfig::default_http())
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let dashboard = dashboard_client
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{ui_address}/"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let dashboard = dashboard.into_body().collect().await.unwrap().to_bytes();
    let dashboard = String::from_utf8(dashboard.to_vec()).unwrap();
    let session = dashboard_session_id(&dashboard).to_owned();

    let ca_pem = tokio::fs::read(&ca_path).await.unwrap();
    let trust_anchor = CertificateDer::from_pem_slice(&ca_pem).unwrap();
    let trusted_tls = TlsClientConfig::new()
        .try_with_server_trust_anchors([trust_anchor])
        .unwrap();
    let trusted_client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(trusted_tls)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let insecure_tls = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let insecure_client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(insecure_tls)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    // Use a DNS identity so the generated MITM leaf can be verified against
    // the exported proxy CA. The origin still resolves to this loopback test
    // listener and presents its independently generated self-signed leaf.
    let target = format!("https://localhost:{}/pause", origin_address.port());
    let proxy_route = || ProxyRoute::Proxy(format!("http://{proxy_address}").parse().unwrap());
    let request = || {
        Request::builder()
            .uri(target.as_str())
            .extension(proxy_route())
            .body(Body::empty())
            .unwrap()
    };

    let response = trusted_client.serve(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await.unwrap();

    let control = |path: &str| {
        dashboard_request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{ui_address}{path}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "session": session }).to_string(),
                ))
                .unwrap(),
        )
    };
    let paused = dashboard_client
        .serve(control("/api/inspection/pause"))
        .await
        .unwrap();
    assert_eq!(paused.status(), StatusCode::NO_CONTENT);

    // The origin certificate is no longer replaced by the inspector CA.
    timeout(Duration::from_secs(10), trusted_client.serve(request()))
        .await
        .unwrap()
        .unwrap_err();
    let response = insecure_client.serve(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "pause-roundtrip-ok"
    );

    let response = dashboard_client
        .serve(dashboard_request(
            Request::builder()
                .uri(format!(
                    "http://{ui_address}/events?datastar=%7B%22session%22%3A%22{session}%22%7D"
                ))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = next_sse_event(&mut events).await;
    assert!(event.contains("data-inspection-paused=\"true\""));
    assert!(event.contains("<span>Requests</span><strong>1</strong>"));
    drop(events);

    let resumed = dashboard_client
        .serve(control("/api/inspection/resume"))
        .await
        .unwrap();
    assert_eq!(resumed.status(), StatusCode::NO_CONTENT);
    let response = trusted_client.serve(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await.unwrap();

    let response = dashboard_client
        .serve(dashboard_request(
            Request::builder()
                .uri(format!(
                    "http://{ui_address}/events?datastar=%7B%22session%22%3A%22{session}%22%7D"
                ))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = next_sse_event(&mut events).await;
    assert!(event.contains("data-inspection-paused=\"false\""));
    assert!(event.contains("<span>Requests</span><strong>2</strong>"));
    drop(events);

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[test]
fn machine_readiness_uses_the_same_capability_as_the_human_link() {
    TestCli::try_parse_from(["test", "--inspect-json"]).unwrap_err();
    let cli = TestCli::try_parse_from([
        "test",
        "--mitm",
        "--inspect-json",
        "--mitm-scope",
        "selected",
    ])
    .unwrap();
    assert!(cli.proxy.inspect_json);
    let ready = inspector_ready("[::1]:8123".parse().unwrap(), "example-token");
    assert_eq!(ready["event"], "rama.inspector.ready");
    assert_eq!(ready["api_url"], "http://[::1]:8123/api");
    assert_eq!(
        ready["inspector_url"],
        "http://[::1]:8123/?token=example-token"
    );
    assert_eq!(ready["authorization"]["token"], "example-token");
}
