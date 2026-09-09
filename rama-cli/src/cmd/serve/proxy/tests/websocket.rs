use rama::http::Method;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_handshakes_support_each_icap_direction() {
    let (icap_address, icap_task, icap_state) = spawn_proxy_test_icap().await;
    let (origin, origin_task) = spawn_websocket_origin().await;

    for (reqmod, respmod) in [(true, false), (false, true), (true, true)] {
        let proxy_address = reserve_loopback_address();
        let proxy_arg = proxy_address.to_string();
        let icap_uri = format!("icap://{icap_address}/adapt");
        let reqmod_arg = format!("--icap-reqmod={reqmod}");
        let respmod_arg = format!("--icap-respmod={respmod}");
        let cli = TestCli::parse_from([
            "test",
            "--bind",
            proxy_arg.as_str(),
            "--icap",
            icap_uri.as_str(),
            reqmod_arg.as_str(),
            respmod_arg.as_str(),
        ]);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown = rama::graceful::Shutdown::new(async move {
            _ = shutdown_rx.await;
        });
        run(shutdown.guard(), cli.proxy).await.unwrap();

        let reqmod_before = icap_state.reqmod_calls.load(Ordering::SeqCst);
        let respmod_before = icap_state.respmod_calls.load(Ordering::SeqCst);
        let client = proxy_websocket_client();
        let extensions = Extensions::new();
        extensions.insert(ProxyRoute::Proxy(
            format!("http://{proxy_address}").parse().unwrap(),
        ));
        let mut websocket = client
            .websocket(format!("ws://{origin}/echo"))
            .with_header(
                rama::http::header::PROXY_AUTHORIZATION,
                "Basic downstream-secret",
            )
            .handshake(extensions)
            .await
            .unwrap();

        assert_eq!(
            websocket
                .response()
                .headers
                .contains_key("x-rama-icap-respmod"),
            respmod,
        );
        assert!(
            !websocket
                .response()
                .headers
                .contains_key(rama::http::header::PROXY_AUTHENTICATE)
        );
        websocket
            .send_message(Message::text("ICAP WebSocket round trip"))
            .await
            .unwrap();
        assert_eq!(
            websocket.recv_message().await.unwrap(),
            Message::text("ICAP WebSocket round trip")
        );
        assert_eq!(
            icap_state.reqmod_calls.load(Ordering::SeqCst) > reqmod_before,
            reqmod,
        );
        assert_eq!(
            icap_state.respmod_calls.load(Ordering::SeqCst) > respmod_before,
            respmod,
        );
        assert!(icap_state.proxy_authorization_seen.load(Ordering::SeqCst) > 0);

        drop(websocket);
        drop(client);
        shutdown_proxy(shutdown_tx, shutdown).await;
    }

    origin_task.abort();
    icap_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_mitm_websocket_handshake_supports_icap() {
    let (icap_address, icap_task, icap_state) = spawn_proxy_test_icap().await;
    let (origin, origin_task) = spawn_tls_websocket_origin().await;
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

    let client = proxy_websocket_client();
    let extensions = Extensions::new();
    extensions.insert(ProxyRoute::Proxy(
        format!("socks5h://{proxy_address}").parse().unwrap(),
    ));
    let mut websocket = client
        .websocket(format!("wss://{origin}/echo"))
        .handshake(extensions)
        .await
        .unwrap();

    assert_eq!(websocket.response().headers["x-rama-icap-respmod"], "yes");
    assert!(
        !websocket
            .response()
            .headers
            .contains_key(rama::http::header::PROXY_AUTHENTICATE)
    );
    websocket
        .send_message(Message::text("ICAP WSS over SOCKS5"))
        .await
        .unwrap();
    assert_eq!(
        websocket.recv_message().await.unwrap(),
        Message::text("ICAP WSS over SOCKS5")
    );
    assert!(icap_state.reqmod_calls.load(Ordering::SeqCst) > 0);
    assert!(icap_state.respmod_calls.load(Ordering::SeqCst) > 0);

    drop(websocket);
    drop(client);
    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
    icap_task.abort();
}

#[tokio::test]
async fn websocket_inspector_records_and_relays_messages() {
    let store = crate::cmd::serve::proxy::capture::test_store(
        8,
        8,
        4,
        Arc::new(UserAgentDatabase::try_embedded().unwrap()),
    )
    .unwrap();
    let capture_service = CaptureHttpLayer::new(Some(store.clone())).into_layer(service_fn(
        async |_request: Request| Ok::<_, Infallible>(Response::new(Body::empty())),
    ));
    capture_service
        .serve(Request::new(Body::empty()))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let extensions = rama::extensions::Extensions::new();
    extensions.insert(HttpExchangeId(1));
    let output = inspect_websocket_event(
        Some(store.clone()),
        WebSocketRelayEventInput {
            direction: WebSocketRelayDirection::Ingress,
            event: WebSocketRelayEvent::Data(WebSocketRelayMessage::Text(
                "websocket-payload".into(),
            )),
            extensions,
        },
    )
    .await
    .unwrap();

    assert!(matches!(
        output.messages.as_slice(),
        [WebSocketRelayMessage::Text(message)] if message.as_str() == "websocket-payload"
    ));
    let extensions = rama::extensions::Extensions::new();
    extensions.insert(HttpExchangeId(1));
    let ping = inspect_websocket_event(
        Some(store.clone()),
        WebSocketRelayEventInput {
            direction: WebSocketRelayDirection::Egress,
            event: WebSocketRelayEvent::Ping(rama::bytes::Bytes::from_static(b"heartbeat")),
            extensions,
        },
    )
    .await
    .unwrap();
    assert!(
        ping.messages.is_empty(),
        "control events are observation-only"
    );
    let details = store.details(1).await.unwrap();
    assert!(
        store
            .websocket_details(1, 0, 100)
            .await
            .unwrap()
            .messages
            .is_empty(),
        "oversized WebSocket messages must not be persisted as partial messages"
    );
    assert_eq!(details.summary.request_bytes, 17);
    assert_eq!(details.summary.response_bytes, 9);
    assert!(details.summary.request_truncated);
    assert!(details.summary.response_truncated);
    assert!(matches!(
        store.replay_websocket_message(1, 0).await,
        Err(capture::WebSocketReplayError::MessageNotFound)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_proxy_inspector_exposes_and_replays_live_websocket_messages() {
    let (origin, origin_task) = spawn_websocket_origin().await;
    let proxy_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let mitm_arg = format!("--mitm={proxy_address}");
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str(), mitm_arg.as_str()]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let insecure = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl_config(insecure.clone())
        .with_proxy_support()
        .with_tls_support_using_boringssl(insecure)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let extensions = Extensions::new();
    extensions.insert(ProxyRoute::Proxy(
        format!("http://{proxy_address}").parse().unwrap(),
    ));
    let mut websocket = client
        .websocket(format!("ws://{origin}/echo"))
        .handshake(extensions)
        .await
        .unwrap();

    websocket
        .send_message(Message::text("captured websocket request"))
        .await
        .unwrap();
    assert_eq!(
        websocket.recv_message().await.unwrap(),
        Message::text("captured websocket request")
    );

    let dashboard = EasyHttpWebClient::default();
    let replay_dashboard = EasyHttpWebClient::default();
    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{proxy_address}/"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    let session = dashboard_session_id(&html);
    let signals = format!("datastar=%7B%22session%22%3A%22{session}%22%7D");
    let signal_body = format!(r#"{{"session":"{session}"}}"#);
    let response = replay_dashboard
        .serve(dashboard_request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{proxy_address}/api/focus/request/1"))
                .body(Body::from(signal_body.clone()))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{proxy_address}/events?{signals}"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = next_sse_event(&mut events).await;
    assert!(event.contains("WebSocket traffic"), "{event}");
    assert!(event.contains("captured websocket request"), "{event}");
    assert!(event.contains("Client → Server"));
    assert!(event.contains("Server → Client"));
    assert!(event.contains("Replay to server"));
    assert!(event.contains("connection-state alive"));
    drop(events);

    let response = replay_dashboard
        .serve(dashboard_request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{proxy_address}/api/websocket/1/replay/0"))
                .body(Body::from(signal_body))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        timeout(Duration::from_secs(2), websocket.recv_message())
            .await
            .expect("replayed WebSocket message was not echoed")
            .unwrap(),
        Message::text("captured websocket request")
    );

    let closure_dashboard = EasyHttpWebClient::default();
    let response = closure_dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{proxy_address}/events?{signals}"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut closure_events = response.into_body();
    _ = next_sse_event(&mut closure_events).await;
    drop(websocket);
    let closed_event = timeout(Duration::from_secs(2), async {
        loop {
            let event = next_sse_event(&mut closure_events).await;
            if event.contains("connection-state closed") {
                break event;
            }
        }
    })
    .await
    .expect("closed WebSocket remained marked alive");
    assert_eq!(closed_event.matches("Replay off").count(), 1);
    assert!(!closed_event.contains("connection closed · replay unavailable"));
    drop(closure_events);
    drop(closure_dashboard);
    drop(replay_dashboard);
    drop(dashboard);
    drop(client);
    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_wss_inspector_captures_first_message_in_both_directions() {
    let (origin, origin_task) = spawn_tls_websocket_origin().await;
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

    let insecure = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl_config(insecure.clone())
        .with_proxy_support()
        .with_tls_support_using_boringssl(insecure)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let extensions = Extensions::new();
    extensions.insert(ProxyRoute::Proxy(
        format!("http://{proxy_address}").parse().unwrap(),
    ));
    let mut websocket = client
        .websocket(format!("wss://{origin}/echo"))
        .handshake(extensions)
        .await
        .unwrap();

    websocket
        .send_message(Message::text("first client message"))
        .await
        .unwrap();
    assert_eq!(
        websocket.recv_message().await.unwrap(),
        Message::text("first client message")
    );

    let dashboard = EasyHttpWebClient::default();
    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{ui_address}/"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    let session = dashboard_session_id(&html);
    let signal_body = format!(r#"{{"session":"{session}"}}"#);
    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{ui_address}/api/focus/request/1"))
                .body(Body::from(signal_body))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let signals = format!("datastar=%7B%22session%22%3A%22{session}%22%7D");
    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{ui_address}/events?{signals}"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = next_sse_event(&mut events).await;
    assert!(event.contains("WSS exchange #1"), "{event}");
    assert!(event.contains("messages 1–2 of 2"), "{event}");
    assert!(event.contains("Client → Server"), "{event}");
    assert!(event.contains("Server → Client"), "{event}");
    assert!(event.contains("first client message"), "{event}");
    assert!(!event.contains("Client hello"), "{event}");
    assert!(!event.contains("Client ↔ inspector"), "{event}");
    assert!(!event.contains("Inspector ↔ server"), "{event}");

    drop(events);
    let connection_dashboard = EasyHttpWebClient::default();
    let response = connection_dashboard
        .serve(dashboard_request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{ui_address}/api/focus/connection/1"))
                .body(Body::from(format!(r#"{{"session":"{session}"}}"#)))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = connection_dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{ui_address}/events?{signals}"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut connection_events = response.into_body();
    let connection_event = next_sse_event(&mut connection_events).await;
    assert!(
        connection_event.contains("connection-focus"),
        "{connection_event}"
    );
    assert!(
        connection_event.contains("connection-state alive focus-state"),
        "{connection_event}"
    );
    assert!(!connection_event.contains("detail-overview-label\">Ended"));
    assert!(
        connection_event.contains("Client hello"),
        "{connection_event}"
    );
    assert!(
        connection_event.contains("Client ↔ inspector"),
        "{connection_event}"
    );
    assert!(
        connection_event.contains("Inspector ↔ server"),
        "{connection_event}"
    );
    drop(connection_events);
    drop(connection_dashboard);
    drop(websocket);
    drop(dashboard);
    drop(client);
    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test]
async fn websocket_inspector_replays_live_text_and_binary_in_original_direction() {
    let store = crate::cmd::serve::proxy::capture::test_store(
        8,
        8,
        kib_u64(4),
        Arc::new(UserAgentDatabase::try_embedded().unwrap()),
    )
    .unwrap();
    let capture_service = CaptureHttpLayer::new(Some(store.clone())).into_layer(service_fn(
        async |_request: Request| Ok::<_, Infallible>(Response::new(Body::empty())),
    ));
    capture_service
        .serve(
            Request::builder()
                .uri("http://example.test/socket")
                .header("upgrade", "websocket")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let (relay_ingress_io, peer_ingress_io) = duplex(rama::utils::octets::kib(16));
    let (relay_egress_io, peer_egress_io) = duplex(rama::utils::octets::kib(16));
    let relay_ingress = MockSocket::new(relay_ingress_io);
    let relay_egress = MockSocket::new(relay_egress_io);
    relay_ingress.extensions().insert(HttpExchangeId(1));
    relay_egress.extensions().insert(HttpExchangeId(1));
    let relay_store = store.clone();
    let relay_service = WebSocketRelayEventService::new(service_fn(move |input| {
        inspect_websocket_event(Some(relay_store.clone()), input)
    }))
    .with_message_injection(true);
    let relay = tokio::spawn(async move {
        Box::pin(relay_service.serve(BridgeIo(relay_ingress, relay_egress))).await
    });
    let mut peer_ingress =
        AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_io), Role::Client, None).await;
    let mut peer_egress =
        AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_io), Role::Server, None).await;

    peer_ingress
        .send_message(Message::text("client text"))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_egress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("client text")
    );
    store.replay_websocket_message(1, 0).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_egress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("client text")
    );

    peer_egress
        .send_message(Message::binary(rama::bytes::Bytes::from_static(
            b"server binary",
        )))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_ingress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::binary(rama::bytes::Bytes::from_static(b"server binary"))
    );

    store
        .send_websocket_message(
            1,
            WebSocketRelayDirection::Ingress,
            WebSocketRelayMessage::Text("custom to server".into()),
        )
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_egress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("custom to server")
    );
    store
        .send_websocket_message(
            1,
            WebSocketRelayDirection::Egress,
            WebSocketRelayMessage::Binary(Bytes::from_static(b"custom to client")),
        )
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_ingress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::binary(rama::bytes::Bytes::from_static(b"custom to client"))
    );
    store.replay_websocket_message(1, 2).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_ingress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::binary(rama::bytes::Bytes::from_static(b"server binary"))
    );

    store
        .record_websocket_message(
            1,
            CapturedWebSocketMessage::new(
                WebSocketRelayDirection::Ingress,
                WebSocketMessageKind::Ping,
                Bytes::from(b"control".to_vec()),
            ),
        )
        .await;
    assert!(matches!(
        store.replay_websocket_message(1, 6).await,
        Err(capture::WebSocketReplayError::ControlFrame)
    ));
    let details = store.websocket_details(1, 0, 100).await.unwrap();
    assert!(details.replay_active);
    assert_eq!(
        details
            .messages
            .iter()
            .filter(|record| matches!(
                record,
                CapturedWebSocketMessage {
                    origin: WebSocketMessageOrigin::Replay,
                    ..
                }
            ))
            .count(),
        2
    );
    assert_eq!(
        details
            .messages
            .iter()
            .filter(|record| matches!(
                record,
                CapturedWebSocketMessage {
                    origin: WebSocketMessageOrigin::Injected,
                    ..
                }
            ))
            .count(),
        2
    );

    drop(peer_ingress);
    drop(peer_egress);
    relay.await.unwrap().unwrap();
    assert!(matches!(
        store.replay_websocket_message(1, 0).await,
        Err(capture::WebSocketReplayError::ConnectionClosed)
    ));
    assert!(
        !store
            .websocket_details(1, 0, 100)
            .await
            .unwrap()
            .replay_active
    );
}
