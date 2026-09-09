use rama::{
    http::{Version, header, layer::har::spec::LogFile, server::HttpServer},
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        stream::SocketInfo,
    },
    service::service_fn,
    tcp::server::TcpListener,
};

use super::*;
use crate::cmd::serve::proxy::capture::{CaptureHttpLayer, ConnectionId};

#[test]
fn captured_request_transport_header_policy_is_explicit() {
    let captured = ReplayRequest {
        method: Method::POST,
        url: "https://example.test/upload".parse().unwrap(),
        version: Version::HTTP_2,
        protocol: Protocol::HTTPS,
        headers: test_headers([
            ("host".to_owned(), "example.test".to_owned()),
            ("content-length".to_owned(), "4".to_owned()),
            ("proxy-authorization".to_owned(), "Basic secret".to_owned()),
            ("x-captured".to_owned(), "yes".to_owned()),
        ]),
        body: Bytes::from_static(b"body"),
        metadata: Default::default(),
    };

    let (preserved, body, _) = build_captured_request(captured.clone(), false).unwrap();
    assert_eq!(preserved.version(), Version::HTTP_2);
    assert_eq!(preserved.headers().len(), 4);
    assert_eq!(body.as_ref(), b"body");

    let (stripped, _, _) = build_captured_request(captured, true).unwrap();
    assert_eq!(stripped.headers().len(), 1);
    assert_eq!(stripped.headers()["x-captured"], "yes");
}

#[test]
fn websocket_control_events_are_visible_but_not_replayable() {
    let mut details = test_details(vec![]);
    details.websocket.messages = vec![CapturedWebSocketMessage {
        at: jiff::Timestamp::now(),
        direction: WebSocketRelayDirection::Egress,
        kind: WebSocketMessageKind::Close,
        data: Bytes::from("going away"),
        close_code: Some(1001.into()),
        origin: WebSocketMessageOrigin::Peer,
    }]
    .into_iter()
    .map(Into::into)
    .collect();
    details.websocket.total = details.websocket.messages.len();
    details.summary.protocol = Protocol::WSS;
    details.websocket.replay_active = true;

    let rendered = render_details(&details).into_string();
    assert!(rendered.contains("close"));
    assert!(rendered.contains("code 1001"));
    assert!(rendered.contains("control · observation only"));
    assert!(rendered.contains("going away"));
    assert!(!rendered.contains("Replay with profile"));
    assert!(!rendered.contains("/api/websocket/1/replay/"));
}

#[tokio::test]
async fn request_rows_distinguish_response_lifecycle_and_offer_inline_replay() {
    let state = test_state();
    let connection_id = state
        .capture
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    state.capture.confirm_connection(connection_id);
    state.ensure_session("known");
    let success = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(service_fn(
        async |_request: Request| Ok::<_, Infallible>(Response::new(Body::from("response"))),
    ));
    let request = Request::builder()
        .uri("http://example.test/streaming")
        .extension(ConnectionId(connection_id))
        .body(Body::empty())
        .unwrap();
    let response = success.serve(request).await.unwrap();

    let streaming = state.render_live("known", 0).await;
    assert!(streaming.contains("data-response-state=\"streaming\""));
    assert!(streaming.contains("200 OK"));
    assert!(streaming.contains("response-spinner"));
    assert!(streaming.contains("/api/replay/1"));
    assert!(streaming.contains("replay-inline"));
    assert!(streaming.contains(">Replay</button>"));

    response.into_body().collect().await.unwrap();
    let failed = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(service_fn(
        async |_request: Request| Err::<Response<Body>, _>("origin failed"),
    ));
    let request = Request::builder()
        .uri("http://example.test/failed")
        .extension(ConnectionId(connection_id))
        .body(Body::empty())
        .unwrap();
    failed.serve(request).await.unwrap_err();

    let completed = state.render_live("known", 1).await;
    assert!(completed.contains("data-response-state=\"finished\""));
    assert!(completed.contains("200 OK"));
    assert!(completed.contains("data-response-state=\"no-response\""));
    assert!(completed.contains("No response"));
    assert!(!completed.contains("· complete"));
}

#[tokio::test]
async fn selected_connections_and_requests_export_har_and_copy_as_curl() {
    let state = test_state();
    state.ensure_session("known");
    let first_connection = state
        .capture
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    state.capture.confirm_connection(first_connection);
    let second_connection = state
        .capture
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    state.capture.confirm_connection(second_connection);
    let service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(service_fn(
        async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::CREATED)
                    .header("content-type", "text/plain")
                    .body(Body::from("response-body"))
                    .unwrap(),
            )
        },
    ));
    for (connection, url, body) in [
        (
            first_connection,
            "http://first.example.test/path?q=one",
            "first-body",
        ),
        (
            second_connection,
            "http://second.example.test/submit",
            "second-body",
        ),
    ] {
        service
            .serve(
                Request::builder()
                    .method(Method::POST)
                    .uri(url)
                    .header("content-type", "text/plain")
                    .header("x-captured", "yes")
                    .header("proxy-connection", "keep-alive")
                    .header("proxy-authorization", "Basic c2VjcmV0")
                    .extension(ConnectionId(connection))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }
    let web_socket_connection = state
        .capture
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    state.capture.confirm_connection(web_socket_connection);
    let web_socket_service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
        service_fn(async |_request: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header("connection", "upgrade")
                    .header("upgrade", "websocket")
                    .body(Body::empty())
                    .unwrap(),
            )
        }),
    );
    web_socket_service
        .serve(
            Request::builder()
                .uri("http://socket.example.test/chat")
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .extension(ConnectionId(web_socket_connection))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    state
        .capture
        .record_websocket_message(
            3,
            CapturedWebSocketMessage::new(
                WebSocketRelayDirection::Ingress,
                WebSocketMessageKind::Text,
                Bytes::from(b"hello websocket".to_vec()),
            ),
        )
        .await;
    state
        .capture
        .record_websocket_message(
            3,
            CapturedWebSocketMessage::new(
                WebSocketRelayDirection::Egress,
                WebSocketMessageKind::Binary,
                Bytes::from(vec![0, 1, 255]),
            ),
        )
        .await;
    state
        .capture
        .record_websocket_message(
            3,
            CapturedWebSocketMessage::new(
                WebSocketRelayDirection::Ingress,
                WebSocketMessageKind::Ping,
                Bytes::from(b"control".to_vec()),
            ),
        )
        .await;
    {
        let mut sessions = state.sessions.write();
        let session = sessions.get_mut("known").unwrap();
        session.selected_connections.insert(first_connection);
        session.selected.insert(2);
        session.selected.insert(3);
    }

    let rendered = state.render_live("known", 0).await;
    assert!(rendered.contains("/api/har/export?session=known"));
    assert!(rendered.contains("data-har-export"));
    assert!(rendered.contains("data-copy-curl=\"/api/capture/1/curl\""));

    let response = export_har(
        State(state.clone()),
        Query(ExportQuery {
            session: Some(NonEmptyStr::try_from("known").unwrap()),
            ids: None,
            connection_ids: None,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        response.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment; filename=\"rama-proxy-selection-")
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json = std::str::from_utf8(&body).unwrap();
    assert!(json.contains("\"send\":0"), "{json}");
    assert!(json.contains("\"wait\":"), "{json}");
    assert!(json.contains("\"receive\":"), "{json}");
    let log: LogFile = serde_json::from_slice(&body).unwrap();
    assert_eq!(log.log.entries.len(), 3);
    assert_eq!(
        log.log.entries[0].request.url,
        "http://first.example.test/path?q=one"
    );
    assert_eq!(
        log.log.entries[0]
            .request
            .post_data
            .as_ref()
            .and_then(|data| data.text.as_deref()),
        Some("first-body")
    );
    assert_eq!(log.log.entries[0].response.status, 201);
    assert_eq!(
        log.log.entries[0].response.content.text.as_deref(),
        Some("response-body")
    );
    assert_eq!(log.log.entries[0].connection.as_deref(), Some("1"));
    assert_eq!(log.log.entries[1].connection.as_deref(), Some("2"));
    assert_eq!(
        log.log.entries[2].resource_type.as_deref(),
        Some("websocket")
    );
    let web_socket_messages = log.log.entries[2].web_socket_messages.as_ref().unwrap();
    assert_eq!(web_socket_messages.len(), 2);
    assert_eq!(
        web_socket_messages[0].r#type,
        rama::http::layer::har::spec::WebSocketMessageType::Send
    );
    assert_eq!(web_socket_messages[0].data, "hello websocket");
    assert_eq!(
        web_socket_messages[1].opcode,
        rama::http::layer::har::spec::WebSocketMessageOpcode::BINARY
    );
    assert_eq!(web_socket_messages[1].data, "AAH/");

    let response = export_har(
        State(state.clone()),
        Query(ExportQuery {
            session: None,
            ids: Some("2, invalid, 2".to_owned()),
            connection_ids: Some(format!(" {first_connection} ")),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let log: LogFile = serde_json::from_slice(&body).unwrap();
    assert_eq!(log.log.entries.len(), 2);
    assert_eq!(log.log.entries[0].connection.as_deref(), Some("1"));
    assert_eq!(log.log.entries[1].connection.as_deref(), Some("2"));

    let response = request_curl(State(state), Path(IdPath { id: 1 })).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; charset=utf-8"
    );
    let command = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let command_prefix = if cfg!(windows) {
        "& (Get-Command curl -CommandType Application).Source"
    } else {
        "curl"
    };
    assert!(command.starts_with(command_prefix), "{command}");
    assert!(
        command.contains("http://first.example.test/path?q=one"),
        "{command}"
    );
    assert!(command.contains("x-captured: yes"), "{command}");
    assert!(command.contains("first-body"), "{command}");
    assert!(!command.to_ascii_lowercase().contains("proxy-connection"));
    assert!(!command.to_ascii_lowercase().contains("proxy-authorization"));
}

#[tokio::test]
async fn websocket_replay_handler_enforces_session_and_maps_capture_state() {
    let state = test_state();
    state.ensure_session("known");
    let request = Request::builder()
        .uri("http://example.test/socket")
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "upgrade")
        .body(Body::empty())
        .unwrap();
    let capture_service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
        service_fn(async |_request: Request| Ok::<_, Infallible>(Response::new(Body::empty()))),
    );
    capture_service
        .serve(request)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let exchange_id = 1;
    state
        .capture
        .record_websocket_message(
            exchange_id,
            CapturedWebSocketMessage::new(
                WebSocketRelayDirection::Ingress,
                WebSocketMessageKind::Text,
                Bytes::from(b"replay me".to_vec()),
            ),
        )
        .await;
    state
        .capture
        .record_websocket_message(
            exchange_id,
            CapturedWebSocketMessage::new(
                WebSocketRelayDirection::Ingress,
                WebSocketMessageKind::Ping,
                Bytes::from(b"control".to_vec()),
            ),
        )
        .await;
    let signals = |session: &str| {
        ReadSignals(UiSignals {
            session: NonEmptyStr::try_from(session).ok(),
            ..Default::default()
        })
    };
    let path = |id, index| Path(WebSocketMessagePath { id, index });

    assert_eq!(
        replay_websocket_message(
            State(state.clone()),
            path(exchange_id, 0),
            signals("unknown")
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        replay_websocket_message(State(state.clone()), path(exchange_id, 0), signals("known"))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        replay_websocket_message(State(state.clone()), path(exchange_id, 1), signals("known"))
            .await
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        replay_websocket_message(
            State(state.clone()),
            path(exchange_id, 99),
            signals("known")
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        replay_websocket_message(State(state), path(999, 0), signals("known"))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_honors_disabled_forward_proxy_auth() {
    assert_replay_forward_proxy_auth(Some("upstream:secret"), false, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_uses_configured_forward_proxy_auth() {
    assert_replay_forward_proxy_auth(
        Some("upstream:secret"),
        true,
        Some("Basic dXBzdHJlYW06c2VjcmV0"),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_without_configured_forward_proxy_auth_does_not_reuse_captured_auth() {
    assert_replay_forward_proxy_auth(None, true, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_honors_plaintext_proxy_tunnel_without_leaking_auth() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let connect = read_http_head(&mut stream).await;
        assert!(connect.starts_with("CONNECT origin.example:80 HTTP/1.1\r\n"));
        assert!(
            connect
                .to_ascii_lowercase()
                .contains("proxy-authorization: basic dxbzdhjlyw06c2vjcmv0")
        );
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        let origin = read_http_head(&mut stream).await;
        assert!(origin.starts_with("GET /replay HTTP/1.1\r\n"));
        assert!(!origin.to_ascii_lowercase().contains("proxy-authorization:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let mut proxy: ProxyAddress = format!("http://{proxy_address}").parse().unwrap();
    proxy.credential = Some(rama::net::user::ProxyCredential::Basic(
        rama::net::user::Basic::try_from("upstream:secret").unwrap(),
    ));
    let upstream = UpstreamProxyConfig::new(Some(proxy), false, &[])
        .unwrap()
        .with_tunnel_plaintext_http(true);
    let state = test_state_with_upstream(8, 8, &upstream);
    capture_request_for_replay(&state, "http://origin.example/replay").await;

    assert_eq!(replay_captured(&state, 1).await.unwrap(), 200);
    tokio::time::timeout(Duration::from_secs(5), proxy_task)
        .await
        .expect("proxy task timed out")
        .expect("proxy task failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_isolates_forward_proxy_auth_challenge() {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(
        listener.serve(HttpServer::auto(Executor::default()).service(service_fn(
            |_: Request| async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                        .header("proxy-authenticate", "Basic realm=upstream-secret")
                        .body(Body::from("upstream-secret-body"))
                        .unwrap(),
                )
            },
        ))),
    );
    let upstream = UpstreamProxyConfig::new(
        Some(format!("http://{proxy_address}").parse().unwrap()),
        false,
        &[],
    )
    .unwrap();
    let state = test_state_with_upstream(8, 8, &upstream);
    capture_request_for_replay(&state, "http://origin.example/replay").await;

    let error = replay_captured(&state, 1).await.unwrap_err();
    assert!(!error.to_string().contains("upstream-secret"), "{error}");
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_sends_captured_body_without_hop_by_hop_or_proxy_credentials() {
    let origin = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let origin_address = origin.local_addr().unwrap();
    let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(1);
    let origin_task = tokio::spawn(origin.serve(HttpServer::auto(Executor::default()).service(
        service_fn(move |request: Request| {
            let observed_tx = observed_tx.clone();
            async move {
                let leaked_headers = ["connection", "x-remove", "proxy-authorization"]
                    .into_iter()
                    .filter(|name| request.headers().contains_key(*name))
                    .collect::<Vec<_>>();
                let body = request.into_body().collect().await.unwrap().to_bytes();
                observed_tx.send((leaked_headers, body)).await.unwrap();
                Ok::<_, Infallible>(Response::new(Body::from("replayed")))
            }
        }),
    )));

    let state = test_state();
    let capture = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(service_fn(
        async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
        },
    ));
    capture
        .serve(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{origin_address}/replay"))
                .header("connection", "x-remove")
                .header("x-remove", "secret")
                .header("proxy-authorization", "Basic c2VjcmV0")
                .body(Body::from("captured-body"))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    assert_eq!(replay_captured(&state, 1).await.unwrap(), 200);
    let (leaked, body) = observed_rx.recv().await.unwrap();
    assert!(leaked.is_empty(), "leaked replay headers: {leaked:?}");
    assert_eq!(body, "captured-body");
    let snapshot = state
        .capture
        .snapshot_limited_for_connections(
            &CaptureFilter::default(),
            &BTreeSet::new(),
            0,
            usize::MAX,
            usize::MAX,
        )
        .await;
    assert_eq!(snapshot.exchanges.len(), 2);
    assert_eq!(snapshot.connections.len(), 1);
    assert_eq!(
        snapshot.connections[0].label.as_deref(),
        Some("Replay of request #1")
    );
    assert!(!snapshot.connections[0].active);
    assert_eq!(
        snapshot.exchanges[1].status,
        Some(StatusCode::from_u16(200).unwrap())
    );
    state.ensure_session("known");
    let rendered = state.render_live("known", 0).await;
    assert!(rendered.contains(&format!("Inspector replay → {origin_address}")));
    assert!(!rendered.contains("unknown → unknown"));
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_reuses_connections_only_within_the_same_capture_source() {
    let origin = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let address = origin.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(3);
    let origin_task = tokio::spawn(origin.serve(HttpServer::auto(Executor::default()).service(
        service_fn(move |request: Request| {
            let tx = tx.clone();
            async move {
                let peer = request
                    .extensions()
                    .get_ref::<SocketInfo>()
                    .unwrap()
                    .peer_addr();
                request.into_body().collect().await.unwrap();
                tx.send(peer).await.unwrap();
                Ok::<_, Infallible>(Response::new(Body::from("replayed")))
            }
        }),
    )));
    let state = test_state();
    let capture = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(service_fn(
        async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
        },
    ));
    for _ in 0..2 {
        let source = state
            .capture
            .begin_connection_if_enabled(None, Protocol::HTTP, None)
            .unwrap();
        state.capture.confirm_connection(source);
        capture
            .serve(
                Request::builder()
                    .uri(format!("http://{address}/replay"))
                    .extension(ConnectionId(source))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        for id in [1, 1, 2] {
            assert_eq!(
                replay_captured(&state.clone(), id).await.unwrap(),
                StatusCode::OK
            );
        }
        let first = rx.recv().await.unwrap();
        let reused = rx.recv().await.unwrap();
        let separate = rx.recv().await.unwrap();
        assert_eq!(
            first, reused,
            "cloned dashboard states must share the replay pool"
        );
        assert_ne!(
            first, separate,
            "different captured connections must not share TLS profiles"
        );
    })
    .await;
    origin_task.abort();
    result.expect("replay pool test timed out");
}

#[test]
fn websocket_send_signals_reject_unknown_variants() {
    for json in [
        r#"{"websocket_direction":"incoming","websocket_kind":"text"}"#,
        r#"{"websocket_direction":"ingress","websocket_kind":"ping"}"#,
        r#"{"websocket_direction":"ingress","websocket_kind":""}"#,
    ] {
        serde_json::from_str::<UiSignals>(json).unwrap_err();
    }
    let signals: UiSignals =
        serde_json::from_str(r#"{"websocket_direction":"egress","websocket_kind":"binary"}"#)
            .unwrap();
    assert_eq!(
        signals.websocket_direction,
        Some(WebSocketRelayDirection::Egress)
    );
    assert!(matches!(
        signals.websocket_kind,
        Some(WebSocketSendKind::Binary)
    ));
}

#[tokio::test]
async fn websocket_send_requires_direction_and_kind() {
    for signals in [
        UiSignals::default(),
        UiSignals {
            websocket_direction: Some(WebSocketRelayDirection::Ingress),
            ..Default::default()
        },
        UiSignals {
            websocket_kind: Some(WebSocketSendKind::Text),
            ..Default::default()
        },
    ] {
        let response = send_websocket_message(
            State(test_state()),
            Path(IdPath { id: 1 }),
            ReadSignals(signals),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
