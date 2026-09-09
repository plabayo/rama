use super::*;

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
            let headers = Headers((
                CacheControl::new().with_no_store(),
                XContentTypeOptions::nosniff(),
            ));
            let response = (headers, OctetStream::new(stream));
            if query.download {
                (
                    Headers::single(ContentDisposition::attachment(&format!(
                        "{direction}-{id}.body"
                    ))),
                    response,
                )
                    .into_response()
            } else {
                response.into_response()
            }
        }
        Err(error) => error_response(StatusCode::NOT_FOUND, error),
    }
}

pub(super) async fn capture_websocket_message(
    State(state): State<DashboardState>,
    Path(WebSocketMessagePath { id, index }): Path<WebSocketMessagePath>,
) -> Response {
    match state.capture.websocket_message_stream(id, index) {
        Ok(stream) => (
            Headers((
                CacheControl::new().with_no_store(),
                XContentTypeOptions::nosniff(),
            )),
            OctetStream::new(stream),
        )
            .into_response(),
        Err(error) => error_response(StatusCode::NOT_FOUND, error),
    }
}

pub(super) async fn replay_websocket_message(
    State(state): State<DashboardState>,
    Path(WebSocketMessagePath { id, index }): Path<WebSocketMessagePath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> Response {
    if signals
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
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
        Err(WebSocketReplayError::TooLarge) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(WebSocketReplayError::Busy) => StatusCode::TOO_MANY_REQUESTS.into_response(),
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
    if signals
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(direction) = signals.websocket_direction else {
        return error_response(StatusCode::BAD_REQUEST, "missing WebSocket direction");
    };
    let Some(kind) = signals.websocket_kind else {
        return error_response(StatusCode::BAD_REQUEST, "missing WebSocket message kind");
    };
    let message = match kind {
        WebSocketSendKind::Text => WebSocketRelayMessage::Text(signals.websocket_payload.into()),
        WebSocketSendKind::Binary => match STANDARD.decode(&signals.websocket_payload) {
            Ok(data) => WebSocketRelayMessage::Binary(data.into()),
            Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
        },
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
        Err(WebSocketReplayError::TooLarge) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(WebSocketReplayError::Busy) => StatusCode::TOO_MANY_REQUESTS.into_response(),
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

pub(super) async fn download_ca(State(state): State<DashboardState>) -> impl IntoResponse {
    (
        Headers((
            ContentType::pem(),
            ContentDisposition::attachment("rama-proxy-ca.pem"),
        )),
        state.ca_pem.as_ref().clone(),
    )
}

pub(super) async fn rama_logo() -> impl IntoResponse {
    Svg(RAMA_LOGO_SVG)
}
