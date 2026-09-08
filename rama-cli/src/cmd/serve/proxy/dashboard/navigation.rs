use super::*;

pub(super) async fn update_filter(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = signals
        .session
        .as_deref()
        .and_then(|id| sessions.get_mut(id))
    else {
        return StatusCode::NOT_FOUND;
    };
    session.filter = CaptureFilter {
        search: signals.search,
        connection_id: signals.connection_id,
        user_agent: signals.user_agent,
        endpoint: signals.endpoint,
        method: signals.method,
        status: signals.status,
        protocol: signals.protocol,
    };
    session.connection_page = 0;
    session.connection_cursors.clear();
    session.next_connection_cursor = None;
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

pub(super) async fn reset_filters(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = signals
        .session
        .as_deref()
        .and_then(|id| sessions.get_mut(id))
    else {
        return StatusCode::NOT_FOUND;
    };
    session.filter = CaptureFilter::default();
    session.selected_connections.clear();
    session.connection_page = 0;
    session.connection_cursors.clear();
    session.next_connection_cursor = None;
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

pub(super) async fn toggle_connection(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = signals
        .session
        .as_deref()
        .and_then(|id| sessions.get_mut(id))
    else {
        return StatusCode::NOT_FOUND;
    };
    if !session.selected_connections.remove(&id) {
        session.selected_connections.insert(id);
    }
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

pub(super) async fn clear_connections(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = signals
        .session
        .as_deref()
        .and_then(|id| sessions.get_mut(id))
    else {
        return StatusCode::NOT_FOUND;
    };
    session.selected_connections.clear();
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

pub(super) async fn older_connections(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    update_connection_page(&state, signals.session.as_deref(), true)
}

pub(super) async fn newer_connections(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    update_connection_page(&state, signals.session.as_deref(), false)
}

pub(super) fn update_connection_page(
    state: &DashboardState,
    session_id: Option<&str>,
    older: bool,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = session_id.and_then(|id| sessions.get_mut(id)) else {
        return StatusCode::NOT_FOUND;
    };
    if session.focus != UiFocus::Overview {
        return StatusCode::BAD_REQUEST;
    }
    if older {
        let Some(cursor) = session.next_connection_cursor else {
            return StatusCode::NO_CONTENT;
        };
        let next_page = session.connection_page.saturating_add(1);
        session.connection_cursors.truncate(next_page);
        if session.connection_cursors.len() < next_page {
            session.connection_cursors.resize(next_page, None);
        }
        session.connection_cursors.push(Some(cursor));
        session.connection_page = next_page;
        session.next_connection_cursor = None;
    } else {
        session.connection_page = session.connection_page.saturating_sub(1);
        session.next_connection_cursor = None;
    }
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

pub(super) fn set_focus(state: &DashboardState, signals: &UiSignals, focus: UiFocus) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = signals
        .session
        .as_deref()
        .and_then(|id| sessions.get_mut(id))
    else {
        return StatusCode::NOT_FOUND;
    };
    session.focus = focus;
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

pub(super) async fn clear_focus(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    set_focus(&state, &signals, UiFocus::Overview)
}

pub(super) async fn focus_connection(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    set_focus(&state, &signals, UiFocus::Connection(id))
}

pub(super) async fn focus_request(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    set_focus(&state, &signals, UiFocus::Request(id))
}

pub(super) async fn older_websocket_messages(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    update_websocket_page(&state, signals.session.as_deref(), id, true)
}

pub(super) async fn newer_websocket_messages(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    update_websocket_page(&state, signals.session.as_deref(), id, false)
}

pub(super) fn update_websocket_page(
    state: &DashboardState,
    session_id: Option<&str>,
    exchange_id: u64,
    older: bool,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = session_id.and_then(|id| sessions.get_mut(id)) else {
        return StatusCode::NOT_FOUND;
    };
    if session.focus != UiFocus::Request(exchange_id) {
        return StatusCode::BAD_REQUEST;
    }
    let page = session.websocket_pages.entry(exchange_id).or_default();
    *page = if older {
        page.saturating_add(1)
    } else {
        page.saturating_sub(1)
    };
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

pub(super) async fn toggle_selected(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = signals
        .session
        .as_deref()
        .and_then(|id| sessions.get_mut(id))
    else {
        return StatusCode::NOT_FOUND;
    };
    let selected = &mut session.selected;
    if !selected.remove(&id) {
        selected.insert(id);
    }
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}
