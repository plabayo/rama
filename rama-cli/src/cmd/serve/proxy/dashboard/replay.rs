use super::*;

pub(super) async fn request_curl(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
) -> Response {
    let captured = match state.capture.replay_request(id).await {
        Ok(captured) => captured,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
    };
    if matches!(captured.protocol.as_str(), "ws" | "wss") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "WebSocket handshakes cannot be represented as a replayable cURL command",
        );
    }
    let (request, body, _) = match build_captured_request(captured, false) {
        Ok(request) => request,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let (mut parts, ()) = request.into_parts();
    remove_hop_by_hop_request_headers(&mut parts.headers);
    remove_proxy_auth_request_headers(&mut parts.headers);
    let compatibility = if cfg!(windows) {
        curl::CurlScriptCompatibility::PowerShell
    } else {
        curl::CurlScriptCompatibility::Unix
    };
    match curl::try_cmd_string_for_request_parts_and_payload_with_options(
        &parts,
        &body,
        curl::CurlExportOptions::default().with_script_compatibility(compatibility),
        &curl::CurlScriptPayloadMode::Inline,
    ) {
        Ok(command) => Response::builder()
            .header("content-type", "text/plain; charset=utf-8")
            .header("cache-control", "no-store")
            .body(Body::from(command))
            .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error)),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

pub(super) async fn replay(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> Response {
    if !signals.session.is_empty() && !state.has_session(&signals.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = replay_captured(&state, id).await;
    state
        .capture
        .record_replay_result(
            id,
            result
                .as_ref()
                .map(|status| *status)
                .map_err(ToString::to_string),
        )
        .await;
    state.notify();
    match result {
        Ok(status) => Json(serde_json::json!({ "status": status })).into_response(),
        Err(error) => error_response(StatusCode::BAD_GATEWAY, error),
    }
}

pub(super) async fn replay_captured(
    state: &DashboardState,
    id: u64,
) -> Result<StatusCode, BoxError> {
    let captured = state.capture.replay_request(id).await?;
    let (request, body, tls_client_hello) = build_captured_request(captured, true)?;
    let (parts, ()) = request.into_parts();
    let mut request = Request::from_parts(parts, Body::from(body));
    if let Some(client_hello) = tls_client_hello {
        request.extensions().insert_arc(Arc::new(TlsProfile {
            client_hello,
            ws_client_config_overwrites: None,
        }));
    }
    let replay_connection = state.capture.begin_connection_if_enabled(
        None,
        rama::net::Protocol::from_static("replay"),
        Some(format!("Replay of request #{id}")),
    );
    if let Some(replay_connection) = replay_connection {
        state
            .capture
            .confirm_connection_if_enabled(replay_connection);
        request.extensions().insert(ConnectionId(replay_connection));
    }
    let _connection_guard = replay_connection
        .map(|replay_connection| state.capture.connection_guard(replay_connection));
    // Scrub the original hop metadata before emulation can normalize the
    // `Connection` field while retaining a header it named.
    remove_hop_by_hop_request_headers(request.headers_mut());
    let tls_config = rama::tls::client::TlsClientConfig::default_http();
    let transport =
        rama::tcp::client::service::TcpConnector::new().with_connector(state.tcp_options.clone());
    let client = rama::http::client::EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(transport)
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_default_http_connector(Executor::default())
        .with_default_connection_pool()
        .build_client()
        .with_forward_proxy_auth(state.upstream.forward_proxy_auth())
        .with_tunnel_plaintext_http(state.upstream.tunnel_plaintext_http())
        .with_isolate_forward_proxy_auth_error(true);
    let client = state.upstream.http_service(client);
    let client = RemoveRequestHeaderLayer::hop_by_hop().into_layer(client);
    let client = EmulateTlsProfileLayer::new().into_layer(client);
    let client = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(client);
    let response = client.serve(request).await.context("replay request")?;
    let status = response.status();
    let mut body = response.into_body();
    while let Some(frame) = body.frame().await {
        frame.context("drain replay response")?;
    }
    Ok(status)
}

pub(super) fn build_captured_request(
    captured: ReplayRequest,
    strip_transport_headers: bool,
) -> Result<(Request<()>, Bytes, Option<rama::tls::client::ClientHello>), BoxError> {
    let mut request = Request::builder()
        .method(captured.method)
        .version(captured.version)
        .uri(captured.url)
        .body(())?;
    *request.headers_mut() = captured.headers;
    if strip_transport_headers {
        for name in ["host", "content-length", "proxy-authorization"] {
            request.headers_mut().remove(name);
        }
    }
    let hello = captured
        .metadata
        .connection
        .get_ref::<TlsObservation>()
        .and_then(|tls| tls.client_hello.clone());
    Ok((request, captured.body, hello))
}

pub(super) fn error_response(status: StatusCode, error: impl std::fmt::Display) -> Response {
    (status, error.to_string()).into_response()
}
