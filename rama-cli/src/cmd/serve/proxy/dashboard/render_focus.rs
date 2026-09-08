use super::*;

pub(super) fn render_focus_header(
    title: String,
    subtitle: impl IntoHtml,
    parent_connection: Option<(u64, u64)>,
    state: Option<(&'static str, bool)>,
) -> impl IntoHtml {
    div!(
        class = "focus-header",
        div!(
            class = "focus-heading",
            button!(
                r#type = "button",
                class = "ghost focus-back",
                "data-inspector-back" = "",
                "← Back"
            ),
            div!(
                class = "focus-title",
                nav!(
                    class = "breadcrumbs",
                    "aria-label" = "Inspector location",
                    button!(
                        r#type = "button",
                        "data-inspector-focus" = "overview",
                        "Overview"
                    ),
                    parent_connection.map(|(id, display_id)| span!(
                        class = "breadcrumb-parent",
                        span!("aria-hidden" = "true", "›"),
                        button!(
                            r#type = "button",
                            "data-inspector-focus" = "connection",
                            "data-focus-id" = display(id),
                            format!("Connection #{display_id}")
                        )
                    )),
                    span!("aria-hidden" = "true", "›"),
                    span!("aria-current" = "page", title.clone()),
                ),
                h2!(title),
                p!(subtitle),
            )
        ),
        state.map(|(label, active)| span!(
            class = if active {
                "connection-state alive focus-state"
            } else {
                "connection-state closed focus-state"
            },
            label
        ))
    )
}

pub(super) fn inspection_notice(enabled: bool) -> Option<impl IntoHtml> {
    (!enabled).then(|| {
        aside!(
            class = "inspection-notice",
            role = "status",
            strong!("Inspector paused"),
            span!(
                "Inspection is paused. New traffic passes through without MITM, recording or traffic rules. Existing inspected connections are closed. Stored captures and completed HAR files are retained."
            )
        )
    })
}

pub(super) fn render_request_focus(
    heartbeat_sequence: u64,
    id: u64,
    snapshot: &CaptureSnapshot,
    details: &BTreeMap<u64, InspectorDetails>,
    live: &LiveStatus,
) -> String {
    let inspection_enabled = live.recording;
    let Some(detail) = details.get(&id) else {
        return section!(
            id = "live",
            class = if inspection_enabled {
                "live-shell focused inspector-focus"
            } else {
                "live-shell focused inspector-focus inspection-paused"
            },
            "data-inspection-paused" = display(!inspection_enabled),
            render_live_heartbeat(heartbeat_sequence),
            inspection_notice(inspection_enabled),
            render_focus_header(
                format!("Request #{id}"),
                "This capture is no longer retained.".to_owned(),
                None,
                None,
            ),
            render_approval_toolbar(),
            PreEscaped(render_approval_slots(live.for_exchange(id))),
            div!(
                class = "focus-empty",
                strong!("Request unavailable"),
                p!("It may have been cleared or retired by the capture limit.")
            ),
            render_approval_toolbar(),
            div!(
                class = "exchange-list",
                PreEscaped(render_pending_fallbacks(&live.pending, &[], Some(id)))
            )
        )
        .into_string();
    };
    let websocket = matches!(
        detail.summary.protocol,
        rama::net::Protocol::WS | rama::net::Protocol::WSS
    );
    let connection_display_id = snapshot
        .connections
        .iter()
        .find(|connection| connection.id == detail.summary.connection_id)
        .map(|connection| connection.display_id)
        .unwrap_or(detail.summary.connection_display_id);
    let title = if websocket {
        format!(
            "{} exchange #{}",
            detail.summary.protocol.as_str().to_ascii_uppercase(),
            id
        )
    } else {
        format!("{} request #{}", detail.summary.method, id)
    };
    section!(
        id = "live",
        class = if websocket {
            if inspection_enabled {
                "live-shell focused inspector-focus request-focus websocket-focus"
            } else {
                "live-shell focused inspector-focus request-focus websocket-focus inspection-paused"
            }
        } else if inspection_enabled {
            "live-shell focused inspector-focus request-focus"
        } else {
            "live-shell focused inspector-focus request-focus inspection-paused"
        },
        "data-inspection-paused" = display(!inspection_enabled),
        render_live_heartbeat(heartbeat_sequence),
        inspection_notice(inspection_enabled),
        render_focus_header(
            title,
            display(&detail.summary.url),
            Some((detail.summary.connection_id, connection_display_id)),
            Some((
                if detail.summary.active {
                    "streaming"
                } else {
                    "finished"
                },
                detail.summary.active,
            )),
        ),
        render_approval_toolbar(),
        article!(
            class = "focus-surface",
            PreEscaped(render_approval_slots(live.for_exchange(id))),
            render_details(detail)
        )
    )
    .into_string()
}

pub(super) fn render_connection_focus(
    heartbeat_sequence: u64,
    id: u64,
    snapshot: &CaptureSnapshot,
    session: &UiSession,
    details: &BTreeMap<u64, InspectorDetails>,
    live: &LiveStatus,
) -> String {
    let inspection_enabled = live.recording;
    let Some(connection) = snapshot
        .connections
        .iter()
        .find(|connection| connection.id == id)
    else {
        return section!(
            id = "live",
            class = if inspection_enabled {
                "live-shell focused inspector-focus"
            } else {
                "live-shell focused inspector-focus inspection-paused"
            },
            "data-inspection-paused" = display(!inspection_enabled),
            render_live_heartbeat(heartbeat_sequence),
            inspection_notice(inspection_enabled),
            render_focus_header(
                format!("Connection #{id}"),
                "This connection is no longer retained.".to_owned(),
                None,
                None,
            ),
            div!(
                class = "focus-empty",
                strong!("Connection unavailable"),
                p!("It may have been cleared or retired by the capture limit.")
            )
        )
        .into_string();
    };
    let route = connection_route(connection, &snapshot.exchanges);
    let selected = session.selected_connections.contains(&id);
    let select_label = if selected { "✓ Selected" } else { "+ Select" };
    let request_rows = snapshot
        .exchanges
        .iter()
        .filter(|exchange| exchange.connection_id == id)
        .map(|exchange| render_focused_request_row(exchange, live))
        .collect::<Vec<_>>();
    let tls_detail = details
        .values()
        .find(|detail| detail.summary.connection_id == id);
    section!(
        id = "live",
        class = if inspection_enabled {
            "live-shell focused inspector-focus connection-focus"
        } else {
            "live-shell focused inspector-focus connection-focus inspection-paused"
        },
        "data-inspection-paused" = display(!inspection_enabled),
        render_live_heartbeat(heartbeat_sequence),
        inspection_notice(inspection_enabled),
        render_focus_header(
            format!("Connection #{}", connection.display_id),
            route,
            None,
            Some((
                if connection.active { "alive" } else { "closed" },
                connection.active,
            )),
        ),
        article!(
            class = "focus-surface connection-detail",
            div!(
                class = "focus-actions",
                connection.label.as_ref().map(|label| span!(
                    class = "connection-label focus-connection-label",
                    label.clone()
                )),
                button!(
                    r#type = "button",
                    class = if selected {
                        "select selected"
                    } else {
                        "select"
                    },
                    title = "Include all requests on this connection in exports",
                    "aria-pressed" = display(selected),
                    "data-on:click" = format!("@post('/api/connection/{id}')"),
                    select_label
                ),
                a!(
                    class = "ghost link compact",
                    href = format!("/api/har/export?connection_ids={id}"),
                    target = "har-download",
                    "data-har-export" = "",
                    "Export HAR"
                )
            ),
            section!(
                class = "detail-overview connection-overview",
                overview_item("Protocol", &connection.ingress_protocol),
                overview_item(
                    "State",
                    if connection.active { "Alive" } else { "Closed" }.to_owned()
                ),
                connection
                    .peer_address
                    .as_ref()
                    .map(|address| overview_item("Client", address)),
                connection
                    .local_address
                    .as_ref()
                    .map(|address| overview_item("Proxy listener", address)),
                overview_item("Requests", connection.request_count),
                overview_item(
                    "Traffic",
                    format!(
                        "{} ↓  {} ↑",
                        format_bytes(connection.bytes_in),
                        format_bytes(connection.bytes_out)
                    )
                ),
                overview_item("Started", display_timestamp(&connection.started_at)),
                connection
                    .ended_at
                    .as_ref()
                    .map(|ended| overview_item("Ended", display_timestamp(ended))),
            ),
            tls_detail.map(render_connection_tls).map(PreEscaped),
            PreEscaped(
                section!(
                    class = "connection-requests",
                    div!(
                        class = "section-title",
                        h2!(format!("Requests · {}", request_rows.len())),
                        span!("Updates stream while this connection remains open")
                    ),
                    render_approval_toolbar(),
                    div!(
                        class = "exchange-list",
                        request_rows,
                        PreEscaped(render_pending_fallbacks(
                            &live.pending,
                            &snapshot.exchanges,
                            Some(id)
                        ))
                    ),
                    p!(
                        "data-request-empty" = "",
                        hidden = "",
                        "Waiting for matching traffic."
                    )
                )
                .into_string()
            )
        )
    )
    .into_string()
}

pub(super) fn connection_route(
    connection: &HttpConnectionSummary,
    exchanges: &[HttpExchangeSummary],
) -> String {
    if connection.ingress_protocol == REPLAY_PROTOCOL {
        exchanges
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
    }
}

pub(super) fn render_focused_request_row(
    exchange: &HttpExchangeSummary,
    live: &LiveStatus,
) -> impl IntoHtml {
    let pending = live.for_exchange(exchange.id).next();
    let method = if matches!(
        exchange.protocol,
        rama::net::Protocol::WS | rama::net::Protocol::WSS
    ) {
        "WS"
    } else {
        exchange.method.as_str()
    };
    article!(
        id = format!("request-{}", exchange.id),
        "data-approval-id"? = pending.map(|message| display(message.id)),
        class = if exchange.active {
            "exchange active focus-request-row"
        } else {
            "exchange focus-request-row"
        },
        tabindex = "0",
        role = "button",
        "data-inspector-focus" = "request",
        "data-focus-id" = display(exchange.id),
        div!(
            class = "exchange-row",
            div!(
                class = "capture-ref",
                strong!(format!("#{}", exchange.id)),
                span!(format!("conn #{}", exchange.connection_display_id))
            ),
            span!(class = "method", method),
            div!(
                class = "target",
                strong!(exchange.endpoint.as_ref().map(display)),
                small!(display(&exchange.url))
            ),
            PreEscaped(render_protocol_badge(exchange)),
            PreEscaped(
                pending
                    .map(approval_badge)
                    .unwrap_or_else(|| render_exchange_status(exchange))
            ),
            span!(class = "bytes", format_bytes(exchange.response_bytes)),
            time!(
                class = "exchange-time",
                datetime = display(exchange.started_at),
                display(display_timestamp(&exchange.started_at))
            ),
            span!(class = "focus-open-hint", "Open →")
        ),
        PreEscaped(render_approval_slots(live.for_exchange(exchange.id)))
    )
}
