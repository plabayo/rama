use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_interception_holds_upgrade_and_websocket_data_but_not_control_frames() {
    use serde_json::json;
    let (origin, origin_task) = spawn_websocket_origin().await;
    let address = reserve_loopback_address();
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        &address.to_string(),
        &format!("--mitm={address}"),
        "--intercept",
    ]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();
    let dashboard = EasyHttpWebClient::default();
    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{address}/"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let session = dashboard_session_id(&String::from_utf8_lossy(&html)).to_owned();
    let client = proxy_websocket_client();
    let extensions = Extensions::new();
    extensions.insert(ProxyRoute::Proxy(
        format!("http://{address}").parse().unwrap(),
    ));
    let handshake = tokio::spawn(async move {
        client
            .websocket(format!("ws://{origin}/echo"))
            .handshake(extensions)
            .await
            .unwrap()
    });
    for direction in ["ingress", "egress"] {
        let state = wait_interception(address, &session, 1).await;
        let pending = &state["control"]["pending"][0];
        assert_eq!(pending["direction"], direction);
        assert!(!handshake.is_finished());
        let results = interception_api(
            address,
            &session,
            "/api/control/decision",
            Some(json!({"ids": [pending["id"]], "decision": {"action": "forward"}})),
        )
        .await;
        assert!(results[0]["error"].is_null(), "{results}");
    }
    let mut socket = timeout(Duration::from_secs(2), handshake)
        .await
        .unwrap()
        .unwrap();
    socket
        .send_message(Message::text("original"))
        .await
        .unwrap();
    let state = wait_interception(address, &session, 1).await;
    let pending = &state["control"]["pending"][0];
    assert_eq!(pending["protocol"], "ws");
    assert_eq!(pending["direction"], "ingress");
    socket
        .send_message(Message::Ping(rama::bytes::Bytes::from_static(b"alive")))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::Pong(rama::bytes::Bytes::from_static(b"alive"))
    );
    interception_api(address, &session, "/api/control/decision", Some(json!({"ids": [pending["id"]], "decision": {"action": "forward", "payload": "edited upstream"}}))).await;
    let state = wait_interception(address, &session, 1).await;
    let pending = &state["control"]["pending"][0];
    assert_eq!(pending["direction"], "egress");
    let message = interception_api(
        address,
        &session,
        &format!("/api/control/pending/{}", pending["id"]),
        None,
    )
    .await;
    assert_eq!(message["payload"], "edited upstream");
    interception_api(address, &session, "/api/control/decision", Some(json!({"ids": [pending["id"]], "decision": {"action": "forward", "payload": "edited downstream"}}))).await;
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("edited downstream")
    );

    socket
        .send_message(Message::binary(vec![0, 255, 3]))
        .await
        .unwrap();
    let state = wait_interception(address, &session, 1).await;
    let pending = &state["control"]["pending"][0];
    interception_api(
        address,
        &session,
        "/api/control/decision",
        Some(json!({"ids": [pending["id"]], "decision": {"action": "drop"}})),
    )
    .await;
    wait_interception(address, &session, 0).await;
    socket
        .send_message(Message::text("release connection"))
        .await
        .unwrap();
    let state = wait_interception(address, &session, 1).await;
    let pending = &state["control"]["pending"][0];
    let connection = pending["connection"].clone();
    interception_api(
        address,
        &session,
        "/api/control/decision",
        Some(json!({"ids": [pending["id"]], "decision": {"action": "connection"}})),
    )
    .await;
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("release connection")
    );
    socket
        .send_message(Message::text("future messages also pass"))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("future messages also pass")
    );
    interception_api(
        address,
        &session,
        &format!("/api/control/resume/{connection}"),
        Some(json!({})),
    )
    .await;
    socket
        .send_message(Message::text("cancel this pending message"))
        .await
        .unwrap();
    wait_interception(address, &session, 1).await;
    socket.send_message(Message::Close(None)).await.unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::Close(_)
    ));
    wait_interception(address, &session, 0).await;
    drop(socket);
    // Pause ends an already inspected idle WebSocket, then new upgraded
    // connections relay raw bytes without recording or approval rules.
    interception_api(
        address,
        &session,
        "/api/control/forward-all",
        Some(json!({})),
    )
    .await;
    let connect = || async {
        let extensions = Extensions::new();
        extensions.insert(ProxyRoute::Proxy(
            format!("http://{address}").parse().unwrap(),
        ));
        proxy_websocket_client()
            .websocket(format!("ws://{origin}/echo"))
            .handshake(extensions)
            .await
            .unwrap()
    };
    let mut socket = connect().await;
    socket
        .send_message(Message::text("before pause"))
        .await
        .unwrap();
    assert_eq!(
        socket.recv_message().await.unwrap(),
        Message::text("before pause")
    );
    interception_api(address, &session, "/api/inspection/pause", Some(json!({}))).await;
    let closed = timeout(Duration::from_secs(2), socket.recv_message())
        .await
        .unwrap();
    assert!(closed.is_err() || matches!(closed, Ok(Message::Close(_))));
    let paused = interception_api(address, &session, "/api/control", None).await;
    assert_eq!(paused["control"]["recording"], false);
    let mut socket = connect().await;
    socket
        .send_message(Message::text("raw while paused"))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("raw while paused")
    );
    let after = wait_interception(address, &session, 0).await;
    assert_eq!(after["control"]["hosts"], paused["control"]["hosts"]);
    drop(socket);
    _ = shutdown_tx.send(());
    shutdown
        .shutdown_with_limit(Duration::from_secs(2))
        .await
        .unwrap();
    origin_task.abort();
}
