use rama::{http::Method, net::Protocol};

use super::*;

#[test]
fn index_uses_one_persistent_datastar_endpoint_and_external_assets() {
    let rendered = render_index("abc123").into_string();
    assert!(rendered.contains("data-init=\"@get('/events')\""));
    assert_eq!(rendered.matches("@get('/events')").count(), 1);
    assert!(rendered.contains("/assets/datastar.js"));
    assert!(rendered.contains("/assets/har.js"));
    assert!(rendered.contains("/assets/details.js"));
    assert!(rendered.contains("/assets/live.js"));
    assert!(rendered.contains("/assets/preferences.js"));
    assert!(rendered.contains("data-inspector-session=\"abc123\""));
    assert!(LIVE_JS.contains("history.pushState"));
    assert!(LIVE_JS.contains("popstate"));
    assert!(LIVE_JS.contains("/api/focus/"));
    assert!(rendered.contains("/assets/style.css"));
    assert!(rendered.contains("/assets/rama-logo.svg"));
    assert!(rendered.contains("rel=\"icon\""));
    assert!(rendered.contains("type=\"image/svg+xml\""));
    assert!(!rendered.contains("ラマ"));
    assert!(rendered.contains("Rama Proxy Inspector"));
    assert!(rendered.contains("class=\"brand\" href=\"/\" data-inspector-focus=\"overview\""));
    assert!(rendered.contains("id=\"connection-status\""));
    assert!(rendered.contains(">connecting</span>"));
    assert!(rendered.contains("@post('/api/inspection/pause')"));
    assert!(rendered.contains("@post('/api/inspection/resume')"));
    assert!(rendered.contains("data-indicator:inspection_busy"));
    assert!(rendered.contains("id=\"live-heartbeat\""));
    assert!(!rendered.contains("encrypted-at-rest capture"));
    for signal in [
        "connection_id",
        "endpoint",
        "user_agent",
        "method",
        "status",
        "protocol",
    ] {
        assert!(rendered.contains(&format!("data-bind:{signal}")));
    }
    assert!(rendered.contains("Reset filters"));
    assert!(rendered.contains("MITM domain scope"));
    assert!(rendered.contains("data-mitm-policy=\"allow\""));
    assert!(rendered.contains("data-mitm-policy=\"deny\""));
    assert!(PREFERENCES_JS.contains("window.localStorage"));
    assert!(PREFERENCES_JS.contains("/api/mitm-policy"));
    assert!(LIVE_JS.contains("data-connection-page-action"));
    assert!(rendered.contains("id=\"clear-captures-dialog\""));
    assert!(rendered.contains("Clear captured traffic?"));
    assert!(rendered.contains("@post('/api/captures/clear')"));
    for signal in ["websocket_direction", "websocket_kind", "websocket_payload"] {
        assert!(rendered.contains(&format!("data-signals:{signal}")));
    }
    assert!(!rendered.contains("data-signals:har_path"));
    assert!(!rendered.contains("HAR output file"));
    assert!(rendered.contains("name=\"har-download\""));
    assert!(!HAR_JS.contains("showSaveFilePicker"));
    assert!(HAR_JS.contains("browser-download"));
    assert!(!rendered.contains("<style>"));
    for protocol in ["HTTP", "HTTPS", "WS", "WSS", "Other"] {
        assert!(rendered.contains(&format!(">{protocol}</option>")));
    }
    assert!(!rendered.contains(">SOCKS5</option>"));
}

#[tokio::test]
async fn connection_history_is_windowed_to_one_hundred_rows() {
    fn pager_button<'a>(html: &'a str, action: &str) -> &'a str {
        let marker = format!("data-connection-page-action=\"{action}\"");
        let marker_index = html.find(&marker).unwrap();
        let start = html[..marker_index].rfind("<button").unwrap();
        let end = marker_index + html[marker_index..].find('>').unwrap();
        &html[start..=end]
    }

    let state = test_state_with_limits(256, 8);
    for _ in 0..105 {
        let id = state
            .capture
            .begin_connection_if_enabled(None, Protocol::HTTP, None)
            .unwrap();
        state.capture.confirm_connection(id);
    }
    state.ensure_session("known");

    let newest = state.render_live("known", 0).await;
    assert_eq!(newest.matches("<article class=\"connection").count(), 100);
    assert!(newest.contains("1–100 of 105"));
    assert!(newest.contains("data-connection-page=\"0\""));
    assert!(newest.contains("data-has-older=\"true\""));
    assert!(!pager_button(&newest, "older").contains(" disabled"));
    assert!(pager_button(&newest, "newer").contains(" disabled"));
    assert!(!newest.contains("disabled=\"false\""));

    assert_eq!(
        older_connections(
            State(state.clone()),
            ReadSignals(UiSignals {
                session: NonEmptyStr::try_from("known").ok(),
                ..Default::default()
            }),
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let older = state.render_live("known", 1).await;
    assert_eq!(older.matches("<article class=\"connection").count(), 5);
    assert!(older.contains("101–105 of 105"));
    assert!(older.contains("data-connection-page=\"1\""));
    assert!(older.contains("data-has-newer=\"true\""));
    assert!(!pager_button(&older, "newer").contains(" disabled"));
    assert!(pager_button(&older, "older").contains(" disabled"));

    let cursor = state.session("known").connection_cursors[1];
    let before_insert = state
        .capture
        .snapshot_limited_before_connection(
            &CaptureFilter::default(),
            &BTreeSet::new(),
            cursor,
            MAX_VISIBLE_CONNECTIONS,
            MAX_VISIBLE_EXCHANGES,
        )
        .await
        .connections
        .into_iter()
        .map(|connection| connection.id)
        .collect::<Vec<_>>();
    let new_id = state
        .capture
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    state.capture.confirm_connection(new_id);
    let after_insert = state
        .capture
        .snapshot_limited_before_connection(
            &CaptureFilter::default(),
            &BTreeSet::new(),
            cursor,
            MAX_VISIBLE_CONNECTIONS,
            MAX_VISIBLE_EXCHANGES,
        )
        .await
        .connections
        .into_iter()
        .map(|connection| connection.id)
        .collect::<Vec<_>>();
    assert_eq!(after_insert, before_insert);
    let refreshed_older = state.render_live("known", 2).await;
    assert_eq!(
        refreshed_older
            .matches("<article class=\"connection")
            .count(),
        5
    );

    assert_eq!(
        newer_connections(
            State(state.clone()),
            ReadSignals(UiSignals {
                session: NonEmptyStr::try_from("known").ok(),
                ..Default::default()
            }),
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(state.session("known").connection_page, 0);
}

#[tokio::test]
async fn connection_rows_support_session_local_multi_selection() {
    let state = test_state();
    let first = state
        .capture
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    let second = state
        .capture
        .begin_connection_if_enabled(None, Protocol::HTTPS, None)
        .unwrap();
    state.capture.confirm_connection(first);
    state.capture.confirm_connection(second);
    state.capture.finish_connection(first);
    state.ensure_session("known");
    state
        .sessions
        .write()
        .get_mut("known")
        .unwrap()
        .selected_connections
        .insert(first);

    let rendered = state.render_live("known", 0).await;
    assert!(rendered.contains(&format!("/api/connection/{first}")));
    assert!(rendered.contains(&format!("/api/connection/{second}")));
    assert!(rendered.contains("aria-pressed=\"true\""));
    assert!(rendered.contains("connection-state closed"));
    assert!(rendered.contains("connection-state alive"));
    assert!(rendered.contains("started "));
    assert!(rendered.contains("unknown → unknown"));
    assert!(rendered.contains("1 selected"));
    assert!(rendered.contains("1 connection(s)"));
    assert!(rendered.contains("/api/profiles.json?session=known"));
    assert!(rendered.contains("/api/connections/clear"));
}

#[tokio::test]
async fn overview_numbers_only_confirmed_proxy_connections() {
    let state = test_state();
    let dashboard = state
        .capture
        .begin_connection_if_enabled(None, Protocol::from_static("classifying"), None)
        .unwrap();
    assert!(state.capture.discard_connection_if_empty(dashboard));
    let proxy = state
        .capture
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    state.capture.confirm_connection(proxy);
    state.ensure_session("known");
    let service =
        CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(rama::service::service_fn(
            async |_request: Request| Ok::<_, Infallible>(Response::new(Body::empty())),
        ));
    service
        .serve(
            Request::builder()
                .uri("http://example.test/")
                .extension(ConnectionId(proxy))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let rendered = state.render_live("known", 0).await;
    assert!(rendered.contains("aria-label=\"Select connection #1\""));
    assert!(!rendered.contains("aria-label=\"Select connection #2\""));
    assert!(rendered.contains("conn #1"));
    assert!(rendered.contains(&format!("/api/connection/{proxy}")));
}

#[tokio::test]
async fn focused_connection_and_request_views_are_session_local_and_live() {
    let state = test_state();
    let connection_id = state
        .capture
        .begin_connection_if_enabled(None, Protocol::HTTPS, None)
        .unwrap();
    state.capture.confirm_connection(connection_id);
    state.ensure_session("known");
    let service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
        rama::service::service_fn(async |_request: Request| {
            Ok::<_, Infallible>(Response::new(Body::from("focused response")))
        }),
    );
    service
        .serve(
            Request::builder()
                .uri("https://example.test/focused")
                .extension(ConnectionId(connection_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let signals = || {
        ReadSignals(UiSignals {
            session: NonEmptyStr::try_from("known").ok(),
            ..Default::default()
        })
    };

    assert_eq!(
        focus_connection(
            State(state.clone()),
            Path(IdPath { id: connection_id }),
            signals(),
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let connection = state.render_live("known", 0).await;
    assert!(connection.contains("connection-focus"));
    assert!(connection.contains("Connection #1"));
    assert!(connection.contains("Requests · 1"));
    assert!(
        connection.contains("data-inspector-focus=\"request\""),
        "{connection}"
    );
    assert!(connection.contains("https://example.test/focused"));

    assert_eq!(
        focus_request(State(state.clone()), Path(IdPath { id: 1 }), signals(),).await,
        StatusCode::NO_CONTENT
    );
    let request = state.render_live("known", 1).await;
    assert!(request.contains("request-focus"));
    assert!(request.contains("GET request #1"));
    assert!(request.contains("data-inspector-back"));
    assert!(request.contains("class=\"breadcrumbs\""));
    assert!(request.contains("data-inspector-focus=\"overview\""));
    assert!(request.contains("data-inspector-focus=\"connection\""));
    assert!(request.contains("Request headers"));
    assert_eq!(
        older_websocket_messages(State(state.clone()), Path(IdPath { id: 1 }), signals(),).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(state.session("known").websocket_pages.get(&1), Some(&1));

    assert_eq!(
        clear_focus(State(state.clone()), signals()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(state.session("known").focus, UiFocus::Overview);
    assert!(
        state
            .render_live("known", 2)
            .await
            .contains("class=\"workspace\"")
    );
}

#[tokio::test]
async fn direct_focus_query_initializes_the_new_dashboard_session() {
    let state = test_state();
    let response = index(
        State(state.clone()),
        Query(FocusQuery {
            connection: Some(3),
            request: Some(9),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(state.sessions.read().len(), 1);
    assert!(
        state
            .sessions
            .read()
            .values()
            .all(|session| session.focus == UiFocus::Request(9))
    );
}

#[tokio::test]
async fn focused_connection_is_not_retired_by_the_overview_display_limit() {
    let state = test_state_with_limits(MAX_VISIBLE_CONNECTIONS + 1, 8);
    let oldest = state
        .capture
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    state.capture.confirm_connection(oldest);
    for _ in 0..MAX_VISIBLE_CONNECTIONS {
        let id = state
            .capture
            .begin_connection_if_enabled(None, Protocol::HTTP, None)
            .unwrap();
        state.capture.confirm_connection(id);
    }
    state.ensure_session("known");
    assert_eq!(
        focus_connection(
            State(state.clone()),
            Path(IdPath { id: oldest }),
            ReadSignals(UiSignals {
                session: NonEmptyStr::try_from("known").ok(),
                ..Default::default()
            }),
        )
        .await,
        StatusCode::NO_CONTENT
    );

    let rendered = state.render_live("known", 0).await;
    assert!(rendered.contains(&format!("Connection #{oldest}")));
    assert!(!rendered.contains("Connection unavailable"));
}

#[tokio::test]
async fn capture_body_handler_streams_only_the_requested_bounded_direction() {
    let state = test_state();
    let service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
        rama::service::service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::from("response-body")))
        }),
    );
    service
        .serve(Request::new(Body::from("request-body")))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let response = capture_body(
        State(state.clone()),
        Path(BodyPath {
            id: 1,
            direction: "request".into(),
        }),
        Query(BodyQuery {
            limit: Some(4),
            download: false,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "requ"
    );

    let response = capture_body(
        State(state),
        Path(BodyPath {
            id: 1,
            direction: "response".into(),
        }),
        Query(BodyQuery {
            limit: None,
            download: true,
        }),
    )
    .await;
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"response-1.body\""
    );
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "response-body"
    );
}

#[tokio::test]
async fn dashboard_state_isolated_by_server_issued_session() {
    let state = test_state();
    state.ensure_session("known");
    let mut ui_changes = state.ui_changes.subscribe();

    let unknown = UiSignals {
        session: NonEmptyStr::try_from("unknown").ok(),
        search: "must-not-be-stored".into(),
        ..Default::default()
    };
    assert_eq!(
        update_filter(State(state.clone()), ReadSignals(unknown)).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(state.sessions.read().len(), 1);

    let known = UiSignals {
        session: NonEmptyStr::try_from("known").ok(),
        search: "payload".into(),
        method: "POST".parse().unwrap(),
        status: "2xx".into(),
        ..Default::default()
    };
    assert_eq!(
        update_filter(State(state.clone()), ReadSignals(known)).await,
        StatusCode::NO_CONTENT
    );
    let session = state.session("known");
    assert_eq!(session.filter.search, "payload");
    assert_eq!(session.filter.method, FilterValue::Value(Method::POST));
    assert_eq!(
        session.filter.status,
        FilterValue::Value(StatusQuery::Success)
    );
    tokio::time::timeout(Duration::from_secs(1), ui_changes.changed())
        .await
        .expect("dashboard change notification timed out")
        .unwrap();

    let signals = || {
        ReadSignals(UiSignals {
            session: NonEmptyStr::try_from("known").ok(),
            ..Default::default()
        })
    };
    assert_eq!(
        focus_request(State(state.clone()), Path(IdPath { id: 7 }), signals()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(state.session("known").focus, UiFocus::Request(7));
    assert_eq!(
        older_websocket_messages(State(state.clone()), Path(IdPath { id: 7 }), signals()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(state.session("known").websocket_pages.get(&7), Some(&1));
    assert_eq!(
        newer_websocket_messages(State(state.clone()), Path(IdPath { id: 7 }), signals()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(state.session("known").websocket_pages.get(&7), Some(&0));
    assert_eq!(
        clear_focus(State(state.clone()), signals()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(state.session("known").focus, UiFocus::Overview);
    assert_eq!(
        older_websocket_messages(State(state.clone()), Path(IdPath { id: 7 }), signals()).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        toggle_selected(State(state.clone()), Path(IdPath { id: 9 }), signals()).await,
        StatusCode::NO_CONTENT
    );
    assert!(state.session("known").selected.contains(&9));
    assert_eq!(
        toggle_connection(State(state.clone()), Path(IdPath { id: 3 }), signals()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        toggle_connection(State(state.clone()), Path(IdPath { id: 5 }), signals()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        state.session("known").selected_connections,
        BTreeSet::from([3, 5])
    );
    assert_eq!(
        clear_connections(State(state.clone()), signals()).await,
        StatusCode::NO_CONTENT
    );
    assert!(state.session("known").selected_connections.is_empty());

    toggle_connection(State(state.clone()), Path(IdPath { id: 7 }), signals()).await;
    assert_eq!(
        reset_filters(State(state.clone()), signals()).await,
        StatusCode::NO_CONTENT
    );
    let session = state.session("known");
    assert!(session.filter.search.is_empty());
    assert!(session.filter.method.is_empty());
    assert!(session.selected_connections.is_empty());

    let response = replay(
        State(state),
        Path(IdPath { id: 1 }),
        ReadSignals(UiSignals {
            session: NonEmptyStr::try_from("unknown").ok(),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dashboard_session_storage_is_bounded() {
    let state = test_state();
    state.ensure_session("z-first");
    for id in 1..MAX_UI_SESSIONS {
        state.ensure_session(&format!("session-{id:03}"));
    }
    state.ensure_session("a-newest");
    assert_eq!(state.sessions.read().len(), MAX_UI_SESSIONS);
    assert!(!state.has_session("z-first"));
    assert!(state.has_session("a-newest"));
}

#[tokio::test]
async fn events_streams_are_bounded_and_evicted_sessions_end() {
    let state = test_state();
    state.ensure_session("z-first");
    for id in 1..MAX_UI_SESSIONS {
        state.ensure_session(&format!("session-{id:03}"));
    }
    let dashboard = service(state.clone());
    let event_request = |session: &str| {
        Request::builder()
            .uri(format!(
                "/events?datastar=%7B%22session%22%3A%22{session}%22%7D"
            ))
            .body(Body::empty())
            .unwrap()
    };

    let evicted_stream = dashboard
        .serve(event_request("z-first"))
        .await
        .unwrap()
        .into_body();
    let mut streams = Vec::with_capacity(MAX_UI_EVENT_STREAMS - 1);
    for _ in 1..MAX_UI_EVENT_STREAMS {
        let response = dashboard.serve(event_request("session-001")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        streams.push(response.into_body());
    }
    let response = dashboard.serve(event_request("session-001")).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    state.ensure_session("a-newest");
    let mut evicted_stream = evicted_stream;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), evicted_stream.frame())
            .await
            .expect("revoked session stream did not terminate")
            .is_none()
    );
    drop(streams);
}

#[tokio::test]
async fn events_stream_emits_an_initial_datastar_patch_for_known_session() {
    let state = test_state();
    state.ensure_session("stream-session");
    let dashboard = service(state);
    let request = Request::builder()
        .uri("/events?datastar=%7B%22session%22%3A%22stream-session%22%7D")
        .body(Body::empty())
        .unwrap();
    let response = dashboard.serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");

    let mut body = response.into_body();
    let frame = tokio::time::timeout(Duration::from_secs(2), body.frame())
        .await
        .expect("initial dashboard event timed out")
        .expect("dashboard event stream ended")
        .expect("dashboard event stream failed");
    let data = frame.into_data().expect("SSE frame is data");
    let event = String::from_utf8_lossy(&data);
    assert!(event.contains("event: datastar-patch-elements"));
    assert!(event.contains("id=\"live\""));

    let frame = tokio::time::timeout(Duration::from_secs(1), body.frame())
        .await
        .expect("live heartbeat timed out")
        .expect("dashboard event stream ended")
        .expect("dashboard event stream failed");
    let data = frame.into_data().expect("heartbeat SSE frame is data");
    let event = String::from_utf8_lossy(&data);
    assert!(event.contains("event: datastar-patch-elements"));
    assert!(event.contains("id=\"live-heartbeat\""));
    assert!(event.contains("data-sequence=\"1\""));

    let response = dashboard
        .serve(
            Request::builder()
                .uri("/events?datastar=%7B%22session%22%3A%22unknown%22%7D")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dashboard_request_bodies_have_an_application_limit() {
    let dashboard = service(test_state());
    let response = dashboard
        .serve(
            Request::builder()
                .method(Method::POST)
                .uri("/api/mitm-policy")
                .header("content-type", "application/json")
                .body(Body::from(vec![b'a'; MAX_DASHBOARD_REQUEST_BODY + 1]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn events_coalesce_capture_control_and_ui_changes_before_full_render() {
    let state = test_state();
    state.ensure_session("rate-session");
    let response = service(state.clone())
        .serve(
            Request::builder()
                .uri("/events?datastar=%7B%22session%22%3A%22rate-session%22%7D")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut body = response.into_body();
    body.frame().await.unwrap().unwrap();
    let connection = crate::cmd::serve::proxy::control::ControlConnection::new(1);
    let host = "example.test".parse().unwrap();
    let mut previous = tokio::time::Instant::now();
    for source in 0..6 {
        for _ in 0..32 {
            match source % 3 {
                0 => state
                    .capture
                    .control()
                    .observe(&connection, &host, true, "scope", "included"),
                1 => {
                    state.ui_changes.send_modify(|revision| *revision += 1);
                }
                _ => state.capture.clear().await,
            }
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
                if String::from_utf8_lossy(&data).contains("id=\"live\"") {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(
            previous.elapsed() >= Duration::from_millis(90),
            "full render bypassed the shared deadline"
        );
        previous = tokio::time::Instant::now();
    }
}

#[tokio::test]
async fn slow_dashboard_renders_still_have_a_quiet_interval() {
    let mut state = test_state();
    state.render_delay = Duration::from_millis(150);
    state.ensure_session("slow-session");
    let mut body = service(state.clone())
        .serve(
            Request::builder()
                .uri("/events?datastar=%7B%22session%22%3A%22slow-session%22%7D")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body();
    body.frame().await.unwrap().unwrap();
    for _ in 0..2 {
        let previous = tokio::time::Instant::now();
        state.ui_changes.send_modify(|revision| *revision += 1);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
                if String::from_utf8_lossy(&data).contains("id=\"live\"") {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(
            previous.elapsed() >= Duration::from_millis(240),
            "slow renders must still leave time before beginning the next render"
        );
    }
}
