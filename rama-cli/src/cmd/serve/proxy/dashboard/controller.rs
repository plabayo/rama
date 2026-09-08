use super::*;

pub(super) async fn update_mitm_policy(
    State(state): State<DashboardState>,
    Json(update): Json<MitmPolicyUpdate>,
) -> Response {
    if update
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Err(error) = state
        .mitm_policy
        .update_scope(update.mode, &update.allow, &update.deny)
    {
        return error_response(StatusCode::BAD_REQUEST, error);
    }
    rama::telemetry::tracing::info!(
        allow_rules = update.allow.len(),
        deny_rules = update.deny.len(),
        "updated runtime MITM domain policy"
    );
    state.notify();
    StatusCode::NO_CONTENT.into_response()
}

pub(super) async fn control_state(
    State(state): State<DashboardState>,
    Query(query): Query<ControlQuery>,
) -> Response {
    if query
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut snapshot = state.capture.control().snapshot();
    for message in &mut snapshot.pending {
        message.connection_display_id = state.capture.connection_display_id(message.connection);
    }
    for connection in &mut snapshot.automatic_connections {
        connection.connection_display_id =
            state.capture.connection_display_id(connection.connection);
    }
    for host in &mut snapshot.hosts {
        host.eligible = state.mitm_policy.should_inspect_host(&host.host);
    }
    Json(serde_json::json!({ "control": snapshot, "scope": state.mitm_policy.snapshot() }))
        .into_response()
}

pub(super) async fn control_pending(
    State(state): State<DashboardState>,
    Path(id): Path<u64>,
    Query(query): Query<ControlQuery>,
) -> Response {
    if query
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.capture.control().pending(id) {
        Some(message) => {
            let mut message = message.as_ref().clone();
            message.connection_display_id = state.capture.connection_display_id(message.connection);
            Json(message).into_response()
        }
        None => StatusCode::CONFLICT.into_response(),
    }
}

pub(super) async fn control_from_capture(
    State(state): State<DashboardState>,
    Path(id): Path<u64>,
    Query(query): Query<ControlQuery>,
) -> Response {
    if query
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(details) = state.capture.inspector_view(id, 0, 0).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let url = &details.summary.url;
    let authority = url
        .authority()
        .map(|authority| authority.into_owned())
        .or_else(|| details.summary.endpoint.clone());
    let host = authority.as_ref().map(|authority| &authority.address.host);
    let path = url.path().map(|path| path.as_encoded_str());
    Json(serde_json::json!({"host": host, "path": path, "url": url, "method": details.summary.method, "protocol": details.summary.protocol})).into_response()
}

pub(super) async fn control_config(
    State(state): State<DashboardState>,
    Json(update): Json<ControlConfigUpdate>,
) -> Response {
    if update
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if update
        .apply_rule
        .is_some_and(|index| index >= update.config.rules.len())
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state
        .capture
        .control()
        .configure(update.revision, update.config)
    {
        Ok(()) => {
            if let Some(index) = update.apply_rule
                && let Err(error) = state
                    .capture
                    .control()
                    .apply_rule(index, update.revision + 1)
            {
                return error_response(StatusCode::CONFLICT, error);
            }
            state.notify();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
    }
}

pub(super) async fn control_decision(
    State(state): State<DashboardState>,
    Json(update): Json<ControlDecision>,
) -> Response {
    if update
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if update.ids.is_empty() || update.ids.len() > 256 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let results = update
        .ids
        .into_iter()
        .map(|id| {
            let result = state.capture.control().resolve(id, update.decision.clone());
            serde_json::json!({ "id": id, "error": result.err().map(|e| e.to_string()) })
        })
        .collect::<Vec<_>>();
    Json(results).into_response()
}

pub(super) async fn control_forward_all(
    State(state): State<DashboardState>,
    Json(query): Json<ControlQuery>,
) -> Response {
    if query
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.capture.control().stop_and_forward();
    StatusCode::NO_CONTENT.into_response()
}

pub(super) async fn control_resume(
    State(state): State<DashboardState>,
    Path(id): Path<u64>,
    Json(query): Json<ControlQuery>,
) -> Response {
    if query
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.capture.control().resume_connection(id);
    StatusCode::NO_CONTENT.into_response()
}

pub(super) async fn control_clear_hosts(
    State(state): State<DashboardState>,
    Json(query): Json<ControlQuery>,
) -> Response {
    if query
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.capture.control().clear_hosts();
    StatusCode::NO_CONTENT.into_response()
}
