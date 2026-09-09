use super::*;

pub(super) async fn pause_inspection(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    if signals
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND;
    }
    let _transition = state.recording_transition.lock().await;
    state.har.pause().await;
    if state.inspection.pause().await {
        state.capture.control().stop_and_forward();
        rama::telemetry::tracing::info!(
            "proxy inspector paused; MITM sessions closed and new traffic passes through"
        );
        state.notify();
    }
    StatusCode::NO_CONTENT
}

pub(super) async fn resume_inspection(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    if signals
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND;
    }
    let _transition = state.recording_transition.lock().await;
    if state.inspection.resume().await {
        rama::telemetry::tracing::info!("proxy inspector resumed");
        state.notify();
    }
    StatusCode::NO_CONTENT
}

pub(super) async fn clear_captures(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    if signals
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND;
    }
    state.capture.clear().await;
    for session in state.sessions.write().values_mut() {
        session.selected.clear();
        session.selected_connections.clear();
        session.websocket_pages.clear();
        session.connection_page = 0;
        session.connection_cursors.clear();
        session.next_connection_cursor = None;
        session.focus = UiFocus::Overview;
    }
    state.notify();
    StatusCode::NO_CONTENT
}
