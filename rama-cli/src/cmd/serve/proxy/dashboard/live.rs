use super::*;

pub(super) async fn index(
    State(state): State<DashboardState>,
    Query(query): Query<FocusQuery>,
) -> Response {
    let mut token = [0_u8; 16];
    if let Err(error) = rama::tls::boring::core::rand::rand_bytes(&mut token) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, error);
    }
    let session = hex::encode(token);
    state.ensure_session(&session);
    if let Some(ui_session) = state.sessions.write().get_mut(&session) {
        ui_session.focus = query
            .request
            .map(UiFocus::Request)
            .or_else(|| query.connection.map(UiFocus::Connection))
            .unwrap_or_default();
    }
    render_index(&session).into_response()
}

pub(super) async fn events(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> Response {
    let Some(session) = signals.session else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !state.has_session(&session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(event_stream_permit) = state.event_streams.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let mut capture_changes = state.capture.subscribe_changes();
    let mut ui_changes = state.ui_changes.subscribe();
    let mut control_changes = state.capture.control().subscribe_changes();
    Sse::new(KeepAliveStream::new(
        KeepAlive::new(),
        stream_fn(move |mut yielder| async move {
            let _event_stream_permit = event_stream_permit;
            let mut heartbeat = tokio::time::interval(LIVE_HEARTBEAT_INTERVAL);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // `interval` ticks immediately once; consume that tick because the
            // initial full render carries heartbeat sequence zero.
            heartbeat.tick().await;
            let mut render_dashboard = true;
            let mut heartbeat_sequence = 0_u64;
            let mut next_render = tokio::time::Instant::now();
            loop {
                if !state.has_session(&session) {
                    break;
                }
                let html = if render_dashboard {
                    // All sources share one render deadline. Host observations
                    // are as frequent as capture events during inspected traffic.
                    tokio::time::sleep_until(next_render).await;
                    if !state.has_session(&session) {
                        break;
                    }
                    capture_changes.borrow_and_update();
                    control_changes.borrow_and_update();
                    ui_changes.borrow_and_update();
                    let html = state.render_live(&session, heartbeat_sequence).await;
                    // Keep a quiet interval even when rendering itself is slow.
                    next_render = tokio::time::Instant::now() + Duration::from_millis(100);
                    html
                } else {
                    render_live_heartbeat(heartbeat_sequence).into_string()
                };
                match dashboard_patch(html) {
                    Ok(event) => {
                        yielder.yield_item(Ok(event)).await;
                        heartbeat_sequence = heartbeat_sequence.wrapping_add(1);
                    }
                    Err(error) => {
                        yielder.yield_item(Err(error)).await;
                        break;
                    }
                }
                tokio::select! {
                    result = capture_changes.changed() => {
                        if result.is_err() {
                            break;
                        }
                        render_dashboard = true;
                    }
                    result = control_changes.changed() => {
                        if result.is_err() { break; }
                        render_dashboard = true;
                    }
                    result = ui_changes.changed() => {
                        if result.is_err() {
                            break;
                        }
                        render_dashboard = true;
                    }
                    _ = heartbeat.tick() => {
                        render_dashboard = false;
                    }
                }
            }
        }),
    ))
    .into_response()
}

pub(super) fn dashboard_patch(html: String) -> Result<Event<PatchElements>, BoxError> {
    let html = NonEmptyStr::try_from(html).context("render non-empty dashboard update")?;
    PatchElements::new(html)
        .try_into_sse_event()
        .context("build dashboard Datastar event")
}

pub(super) fn render_live_heartbeat(sequence: u64) -> impl IntoHtml {
    span!(
        id = "live-heartbeat",
        hidden = "",
        "data-sequence" = sequence
    )
}
