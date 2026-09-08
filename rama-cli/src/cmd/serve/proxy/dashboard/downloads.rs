use super::*;

pub(super) async fn capture_json(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
) -> Response {
    let selected = match state.capture.exchange_capture(id) {
        Ok(selected) => selected,
        Err(error) => return error_response(StatusCode::NOT_FOUND, error),
    };
    let details = match selected.details().await {
        Ok(details) => details,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let websocket = match selected.records::<CapturedMessage>(0..usize::MAX).await {
        Ok(records) => records,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let mut response = Json(CaptureJson {
        http: &details,
        connection_tls: details.metadata.connection.get_ref(),
        upstream_tls: details.metadata.upstream.get_ref(),
        user_agent: details.metadata.exchange.get_ref(),
        websocket: &websocket,
    })
    .into_response();
    if let Ok(value) = format!("attachment; filename=\"rama-capture-{id}.json\"").parse() {
        response.headers_mut().insert("content-disposition", value);
    }
    response
}

pub(super) async fn capture_body(
    State(state): State<DashboardState>,
    Path(BodyPath { id, direction }): Path<BodyPath>,
    Query(query): Query<BodyQuery>,
) -> Response {
    let body = match direction.as_str() {
        "request" => CapturedBody::Request,
        "response" => CapturedBody::Response,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let limit = query.limit.map(|limit| limit.min(MAX_BODY_PREVIEW_LIMIT));
    match state.capture.body_stream(id, body, limit).await {
        Ok(stream) => {
            let mut response = Response::builder()
                .header("content-type", "application/octet-stream")
                .header("cache-control", "no-store")
                .header("x-content-type-options", "nosniff");
            if query.download {
                response = response.header(
                    "content-disposition",
                    format!("attachment; filename=\"{direction}-{id}.body\""),
                );
            }
            response
                .body(Body::from_stream(stream))
                .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))
        }
        Err(error) => error_response(StatusCode::NOT_FOUND, error),
    }
}

pub(super) async fn capture_websocket_message(
    State(state): State<DashboardState>,
    Path(WebSocketMessagePath { id, index }): Path<WebSocketMessagePath>,
) -> Response {
    match state.capture.websocket_message_stream(id, index) {
        Ok(stream) => Response::builder()
            .header("content-type", "application/octet-stream")
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .body(Body::from_stream(stream))
            .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error)),
        Err(error) => error_response(StatusCode::NOT_FOUND, error),
    }
}

pub(super) async fn replay_websocket_message(
    State(state): State<DashboardState>,
    Path(WebSocketMessagePath { id, index }): Path<WebSocketMessagePath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> Response {
    if !signals.session.is_empty() && !state.has_session(&signals.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.capture.replay_websocket_message(id, index).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(WebSocketReplayError::CaptureNotFound | WebSocketReplayError::MessageNotFound) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(WebSocketReplayError::ControlFrame | WebSocketReplayError::Truncated) => {
            StatusCode::UNPROCESSABLE_ENTITY.into_response()
        }
        Err(error @ WebSocketReplayError::InvalidMessage(_)) => {
            error_response(StatusCode::BAD_REQUEST, error)
        }
        Err(WebSocketReplayError::ConnectionClosed) => StatusCode::CONFLICT.into_response(),
        Err(error @ WebSocketReplayError::SendFailed(_)) => {
            error_response(StatusCode::BAD_GATEWAY, error)
        }
        Err(error @ WebSocketReplayError::InvalidCapture(_)) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, error)
        }
    }
}

pub(super) async fn send_websocket_message(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> Response {
    if !signals.session.is_empty() && !state.has_session(&signals.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let direction = match signals.websocket_direction.as_str() {
        "ingress" => WebSocketRelayDirection::Ingress,
        "egress" => WebSocketRelayDirection::Egress,
        _ => return error_response(StatusCode::BAD_REQUEST, "invalid WebSocket direction"),
    };
    let message = match signals.websocket_kind.as_str() {
        "text" => WebSocketRelayMessage::Text(signals.websocket_payload.into()),
        "binary" => match STANDARD.decode(&signals.websocket_payload) {
            Ok(data) => WebSocketRelayMessage::Binary(data.into()),
            Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
        },
        _ => return error_response(StatusCode::BAD_REQUEST, "invalid WebSocket message kind"),
    };
    match state
        .capture
        .send_websocket_message(id, direction, message)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(WebSocketReplayError::CaptureNotFound | WebSocketReplayError::MessageNotFound) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error @ WebSocketReplayError::InvalidMessage(_)) => {
            error_response(StatusCode::BAD_REQUEST, error)
        }
        Err(WebSocketReplayError::ConnectionClosed) => StatusCode::CONFLICT.into_response(),
        Err(error @ WebSocketReplayError::SendFailed(_)) => {
            error_response(StatusCode::BAD_GATEWAY, error)
        }
        Err(
            error @ (WebSocketReplayError::InvalidCapture(_)
            | WebSocketReplayError::ControlFrame
            | WebSocketReplayError::Truncated),
        ) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

pub(super) async fn download_ca(State(state): State<DashboardState>) -> Response {
    Response::builder()
        .header("content-type", "application/x-pem-file")
        .header(
            "content-disposition",
            "attachment; filename=\"rama-proxy-ca.pem\"",
        )
        .body(Body::from(state.ca_pem.as_ref().clone()))
        .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))
}

pub(super) async fn rama_logo() -> Response {
    Response::builder()
        .header("content-type", "image/svg+xml")
        .body(Body::from(RAMA_LOGO_SVG))
        .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))
}
