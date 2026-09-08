use super::*;

pub(super) fn render_live_panel(
    session_id: &str,
    heartbeat_sequence: u64,
    snapshot: &CaptureSnapshot,
    session: &UiSession,
    details: &BTreeMap<u64, InspectorDetails>,
    har: &crate::cmd::serve::proxy::har::HarStatus,
    live: &LiveStatus,
) -> String {
    match session.focus {
        UiFocus::Overview => render_overview_panel(
            session_id,
            heartbeat_sequence,
            snapshot,
            session,
            details,
            har,
            live,
        )
        .into_string(),
        UiFocus::Connection(id) => {
            render_connection_focus(heartbeat_sequence, id, snapshot, session, details, live)
        }
        UiFocus::Request(id) => {
            render_request_focus(heartbeat_sequence, id, snapshot, details, live)
        }
    }
}

pub(super) fn render_overview_panel(
    session_id: &str,
    heartbeat_sequence: u64,
    snapshot: &CaptureSnapshot,
    session: &UiSession,
    _details: &BTreeMap<u64, InspectorDetails>,
    har: &crate::cmd::serve::proxy::har::HarStatus,
    live: &LiveStatus,
) -> impl IntoHtml {
    let inspection_enabled = live.recording;
    let connection_offset = snapshot.connection_offset;
    let connection_start = if snapshot.connections.is_empty() {
        0
    } else {
        connection_offset.saturating_add(1)
    };
    let connection_end = connection_offset.saturating_add(snapshot.connections.len());
    let has_newer_connections = session.connection_page > 0;
    let has_older_connections = snapshot.next_connection_cursor.is_some();
    let connection_rows = snapshot.connections.iter().map(|connection| {
        let selected = session.selected_connections.contains(&connection.id);
        let select_label = if selected { "✓" } else { "+" };
        let state_label = if connection.active { "alive" } else { "closed" };
        let route = if connection.ingress_protocol == REPLAY_PROTOCOL {
            snapshot
                .exchanges
                .iter()
                .find(|exchange| exchange.connection_id == connection.id)
                .map(|exchange| {
                    format!(
                        "Inspector replay → {}",
                        optional_display(exchange.endpoint.as_ref())
                    )
                })
                .unwrap_or_else(|| "Inspector replay".to_owned())
        } else {
            format!(
                "{} → {}",
                optional_display(connection.peer_address.as_ref()),
                optional_display(connection.local_address.as_ref())
            )
        };
        let class = match (connection.active, selected) {
            (true, true) => "connection active selected",
            (true, false) => "connection active",
            (false, true) => "connection selected",
            (false, false) => "connection",
        };
        article!(
            class = class,
            div!(
                span!(class = "mono", format!("#{}", connection.display_id)),
                div!(
                    class = "connection-tags",
                    span!(class = "tag", display(&connection.ingress_protocol)),
                    span!(
                        class = if connection.active {
                            "connection-state alive"
                        } else {
                            "connection-state closed"
                        },
                        state_label
                    ),
                    button!(
                        r#type = "button",
                        class = if selected {
                            "select connection-select selected"
                        } else {
                            "select connection-select"
                        },
                        title = "Include all requests on this connection in exports",
                        "aria-label" = format!("Select connection #{}", connection.display_id),
                        "aria-pressed" = display(selected),
                        "data-on:click" = format!("@post('/api/connection/{}')", connection.id),
                        select_label
                    )
                )
            ),
            button!(
                r#type = "button",
                class = "connection-open",
                title = format!("Inspect connection #{}", connection.display_id),
                "data-inspector-focus" = "connection",
                "data-focus-id" = display(connection.id),
                strong!(route),
                connection
                    .label
                    .as_ref()
                    .map(|label| span!(class = "connection-label", label.clone())),
                time!(
                    datetime = display(connection.started_at),
                    format!("started {}", display_timestamp(&connection.started_at))
                ),
                small!(format!(
                    "{} req · {} ↓ · {} ↑",
                    connection.request_count,
                    format_bytes(connection.bytes_in),
                    format_bytes(connection.bytes_out)
                ))
            )
        )
    });
    let connection_window = format!(
        "{connection_start}–{connection_end} of {}",
        snapshot.total_connections
    );
    let connection_selection = if session.selected_connections.is_empty() {
        small!(connection_window).into_string()
    } else {
        div!(
            class = "connection-selection",
            span!(connection_window),
            span!(format!("{} selected", session.selected_connections.len())),
            button!(
                r#type = "button",
                class = "ghost compact",
                "data-on:click" = "@post('/api/connections/clear')",
                "Clear"
            )
        )
        .into_string()
    };
    let connection_pager = div!(
        class = "connection-pager",
        button!(
            r#type = "button",
            class = "ghost compact",
            disabled? = (!has_newer_connections).then_some(""),
            "data-connection-page-action" = "newer",
            "data-on:click" = "@post('/api/connections/newer')",
            "Newer"
        ),
        span!(format!(
            "Page {}",
            session.connection_page.saturating_add(1)
        )),
        button!(
            r#type = "button",
            class = "ghost compact",
            disabled? = (!has_older_connections).then_some(""),
            "data-connection-page-action" = "older",
            "data-on:click" = "@post('/api/connections/older')",
            "Older"
        )
    );
    let exchange_rows = snapshot.exchanges.iter().take(250).map(|exchange| {
        let pending = live.for_exchange(exchange.id).next();
        let is_selected = session.selected.contains(&exchange.id);
        let class = if exchange.active {
            "exchange active"
        } else {
            "exchange"
        };
        let select_class = if is_selected {
            "select selected"
        } else {
            "select"
        };
        let select_label = if is_selected { "✓" } else { "+" };
        let method = if matches!(
            exchange.protocol,
            rama::net::Protocol::WS | rama::net::Protocol::WSS
        ) {
            "WS"
        } else {
            exchange.method.as_str()
        };
        let replay_action = if matches!(
            exchange.protocol,
            rama::net::Protocol::WS | rama::net::Protocol::WSS
        ) {
            span!(class = "row-spacer").into_string()
        } else {
            button!(
                class = "ghost compact replay-inline",
                title = "Replay this request using only captured headers and TLS data",
                "data-on:click" = format!("@post('/api/replay/{}')", exchange.id),
                "Replay"
            )
            .into_string()
        };
        let identity = div!(
            class = "row-identity",
            button!(
                class = select_class,
                title = "Select this request for exports and approval actions",
                "data-on:click" = format!("@post('/api/select/{}')", exchange.id),
                select_label
            ),
            div!(
                class = "capture-ref",
                strong!(format!("#{}", exchange.id)),
                span!(format!("conn #{}", exchange.connection_display_id))
            )
        )
        .into_string();
        let target = div!(
            class = "target",
            strong!(exchange.endpoint.as_ref().map(display)),
            small!(display(&exchange.url))
        )
        .into_string();
        let protocol_state = div!(
            class = "exchange-protocol-state",
            PreEscaped(render_protocol_badge(exchange)),
            PreEscaped(
                pending
                    .map(approval_badge)
                    .unwrap_or_else(|| render_exchange_status(exchange))
            )
        )
        .into_string();
        let metrics = div!(
            class = "exchange-metrics",
            span!(class = "bytes", format_bytes(exchange.response_bytes)),
            time!(
                class = "exchange-time",
                datetime = display(exchange.started_at),
                display(display_timestamp(&exchange.started_at))
            )
        )
        .into_string();
        let actions = div!(
            class = "exchange-actions",
            PreEscaped(replay_action),
            (!matches!(
                exchange.protocol,
                rama::net::Protocol::WS | rama::net::Protocol::WSS
            ))
            .then(|| PreEscaped(render_curl_button(exchange.id, "cURL"))),
            button!(
                class = "ghost",
                "data-inspector-focus" = "request",
                "data-focus-id" = display(exchange.id),
                "aria-label" = format!("Open request #{}", exchange.id),
                "Open"
            )
        )
        .into_string();
        article!(
            id = format!("request-{}", exchange.id),
            "data-approval-id"? = pending.map(|message| display(message.id)),
            class = class,
            tabindex = "0",
            "aria-label" = format!("Open request #{}", exchange.id),
            "data-inspector-focus" = "request",
            "data-focus-id" = display(exchange.id),
            div!(
                class = "exchange-row",
                PreEscaped(identity),
                span!(class = "method", method),
                PreEscaped(target),
                PreEscaped(protocol_state),
                PreEscaped(metrics),
                PreEscaped(actions)
            ),
            PreEscaped(render_approval_slots(live.for_exchange(exchange.id)))
        )
    });
    let har_control = if har.active {
        form!(
            class = "har-control recording",
            method = "post",
            action = format!("/api/har/stop?session={session_id}"),
            target = "har-download",
            title = har.path.clone().unwrap_or_default(),
            span!(class = "record-dot"),
            span!(
                (if har.suspended {
                    "HAR paused"
                } else {
                    "HAR recording"
                })
                .to_owned()
            ),
            button!(
                r#type = "submit",
                class = "danger compact",
                "Stop & download"
            )
        )
        .into_string()
    } else {
        button!(
            r#type = "button",
            class = "ghost compact har-start",
            "data-har-action" = "start",
            "data-session" = session_id,
            title = "Record now; your browser will choose the save location when you stop",
            "Record HAR"
        )
        .into_string()
    };
    let fallback = render_pending_fallbacks(&live.pending, &snapshot.exchanges, None);
    let requests = div!(
        class = "exchange-list",
        exchange_rows.collect::<Vec<_>>(),
        PreEscaped(fallback),
    )
    .into_string();
    let selection_exports = match (session.selected_connections.len(), session.selected.len()) {
        (0, 0) => div!(
            class = "export",
            span!("Select connections or requests"),
            div!(
                class = "export-actions",
                button!(class = "ghost compact", disabled = true, "Export HAR"),
                button!(class = "ghost compact", disabled = true, "Export profiles")
            )
        )
        .into_string(),
        (connections, requests) => {
            let scope = match (connections, requests) {
                (0, requests) => format!("{requests} request(s)"),
                (connections, 0) => format!("{connections} connection(s)"),
                (connections, requests) => {
                    format!("{connections} connection(s) + {requests} request(s)")
                }
            };
            div!(
                class = "export",
                span!(scope),
                div!(
                    class = "export-actions",
                    a!(
                        class = "ghost link",
                        href = format!("/api/har/export?session={session_id}"),
                        target = "har-download",
                        "data-har-export" = "",
                        "Export HAR"
                    ),
                    a!(
                        class = "ghost link",
                        href = format!("/api/profiles.json?session={session_id}"),
                        target = "har-download",
                        "Export profiles"
                    )
                )
            )
            .into_string()
        }
    };
    section!(
        id = "live",
        class = if inspection_enabled {
            "live-shell"
        } else {
            "live-shell inspection-paused"
        },
        "data-inspection-paused" = display(!inspection_enabled),
        render_live_heartbeat(heartbeat_sequence),
        inspection_notice(inspection_enabled),
        div!(
            class = "stats",
            stat("Connections", snapshot.total_connections),
            stat("Active", snapshot.active_connections),
            stat("Requests", snapshot.total_requests),
            stat("Ingress", format_bytes(snapshot.bytes_in)),
            stat("Egress", format_bytes(snapshot.bytes_out)),
        ),
        div!(
            class = "workspace",
            aside!(
                div!(
                    class = "section-title",
                    h2!("Connections"),
                    PreEscaped(connection_selection)
                ),
                div!(
                    class = "connections",
                    tabindex = "0",
                    "aria-label" = "Captured connections",
                    "data-connection-page" = display(session.connection_page),
                    "data-has-newer" = display(has_newer_connections),
                    "data-has-older" = display(has_older_connections),
                    connection_rows.collect::<Vec<_>>(),
                    connection_pager
                )
            ),
            section!(
                class = "requests",
                div!(
                    class = "section-title",
                    h2!("Requests"),
                    div!(
                        class = "request-tools",
                        button!(
                            r#type = "button",
                            class = "danger-outline compact",
                            "data-open-clear" = "",
                            "Clear captures…"
                        ),
                        PreEscaped(har_control),
                        PreEscaped(selection_exports)
                    )
                ),
                render_approval_toolbar(),
                PreEscaped(requests),
                p!(
                    "data-request-empty" = "",
                    hidden = "",
                    "Waiting for matching traffic."
                )
            )
        )
    )
}
