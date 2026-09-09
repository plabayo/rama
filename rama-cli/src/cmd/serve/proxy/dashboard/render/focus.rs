use std::fmt;

use rama::{combinators::Either, net::Protocol, utils::fmt::display_fn};

use super::*;

pub(in crate::cmd::serve::proxy::dashboard) fn render_focus_header(
    title: impl fmt::Display + Clone,
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
                            "Connection #",
                            display_id
                        )
                    )),
                    span!("aria-hidden" = "true", "›"),
                    span!("aria-current" = "page", display(title.clone())),
                ),
                h2!(display(title)),
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

pub(in crate::cmd::serve::proxy::dashboard) fn inspection_notice(
    enabled: bool,
) -> Option<impl IntoHtml> {
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

pub(in crate::cmd::serve::proxy::dashboard) fn render_request_focus(
    heartbeat_sequence: u64,
    id: u64,
    snapshot: &CaptureSnapshot,
    details: &BTreeMap<u64, InspectorDetails>,
    live: &LiveStatus,
) -> impl IntoHtml {
    let inspection_enabled = live.recording;
    let Some(detail) = details.get(&id) else {
        return Either::A(section!(
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
                display_fn(move |f: &mut fmt::Formatter<'_>| write!(f, "Request #{id}")),
                "This capture is no longer retained.",
                None,
                None,
            ),
            render_approval_toolbar(),
            render_approval_slots(live.for_exchange(id)),
            div!(
                class = "focus-empty",
                strong!("Request unavailable"),
                p!("It may have been cleared or retired by the capture limit.")
            ),
            render_approval_toolbar(),
            div!(
                class = "exchange-list",
                render_pending_fallbacks(&live.pending, &[], Some(id))
            )
        ));
    };
    let websocket = matches!(detail.summary.protocol, Protocol::WS | Protocol::WSS);
    let connection_display_id = snapshot
        .connections
        .iter()
        .find(|connection| connection.id == detail.summary.connection_id)
        .map(|connection| connection.display_id)
        .unwrap_or(detail.summary.connection_display_id);
    let title = display_fn(move |f: &mut fmt::Formatter<'_>| {
        if websocket {
            write!(
                f,
                "{} exchange #{id}",
                uppercase(detail.summary.protocol.as_str())
            )
        } else {
            write!(f, "{} request #{id}", detail.summary.method)
        }
    });
    Either::B(section!(
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
            render_approval_slots(live.for_exchange(id)),
            render_details(detail)
        )
    ))
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_connection_focus(
    heartbeat_sequence: u64,
    id: u64,
    snapshot: &CaptureSnapshot,
    session: &UiSession,
    details: &BTreeMap<u64, InspectorDetails>,
    live: &LiveStatus,
) -> impl IntoHtml {
    let inspection_enabled = live.recording;
    let Some(connection) = snapshot
        .connections
        .iter()
        .find(|connection| connection.id == id)
    else {
        return Either::A(section!(
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
                display_fn(move |f: &mut fmt::Formatter<'_>| write!(f, "Connection #{id}")),
                "This connection is no longer retained.",
                None,
                None,
            ),
            div!(
                class = "focus-empty",
                strong!("Connection unavailable"),
                p!("It may have been cleared or retired by the capture limit.")
            )
        ));
    };
    let route = connection_route(connection, &snapshot.exchanges);
    let selected = session.selected_connections.contains(&id);
    let select_label = if selected { "✓ Selected" } else { "+ Select" };
    let request_rows = snapshot
        .exchanges
        .iter()
        .filter(move |exchange| exchange.connection_id == id)
        .map(|exchange| render_focused_request_row(exchange, live));
    let request_count = snapshot
        .exchanges
        .iter()
        .filter(|exchange| exchange.connection_id == id)
        .count();
    let tls_detail = details
        .values()
        .find(|detail| detail.summary.connection_id == id);
    Either::B(section!(
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
            display_fn(move |f: &mut fmt::Formatter<'_>| write!(
                f,
                "Connection #{}",
                connection.display_id
            )),
            display(route),
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
                connection
                    .label
                    .as_ref()
                    .map(|label| span!(class = "connection-label focus-connection-label", label)),
                button!(
                    r#type = "button",
                    class = if selected {
                        "select selected"
                    } else {
                        "select"
                    },
                    title = "Include all requests on this connection in exports",
                    "aria-pressed" = display(selected),
                    "data-on:click" = ("@post('/api/connection/", id, "')"),
                    select_label
                ),
                a!(
                    class = "ghost link compact",
                    href = ("/api/har/export?connection_ids=", id),
                    target = "har-download",
                    "data-har-export" = "",
                    "Export HAR"
                )
            ),
            section!(
                class = "detail-overview connection-overview",
                overview_item("Protocol", &connection.ingress_protocol),
                overview_item("State", if connection.active { "Alive" } else { "Closed" }),
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
                    display_fn(move |f: &mut fmt::Formatter<'_>| write!(
                        f,
                        "{} ↓  {} ↑",
                        format_bytes(connection.bytes_in),
                        format_bytes(connection.bytes_out)
                    ))
                ),
                overview_item("Started", display_timestamp(&connection.started_at)),
                connection
                    .ended_at
                    .as_ref()
                    .map(|ended| overview_item("Ended", display_timestamp(ended))),
            ),
            tls_detail.map(render_connection_tls),
            {
                section!(
                    class = "connection-requests",
                    div!(
                        class = "section-title",
                        h2!("Requests · ", request_count),
                        span!("Updates stream while this connection remains open")
                    ),
                    render_approval_toolbar(),
                    div!(
                        class = "exchange-list",
                        render_each(request_rows),
                        render_pending_fallbacks(&live.pending, &snapshot.exchanges, Some(id))
                    ),
                    p!(
                        "data-request-empty" = "",
                        hidden = "",
                        "Waiting for matching traffic."
                    )
                )
            }
        )
    ))
}

pub(in crate::cmd::serve::proxy::dashboard) fn connection_route(
    connection: &HttpConnectionSummary,
    exchanges: &[HttpExchangeSummary],
) -> impl fmt::Display {
    display_fn(move |f: &mut fmt::Formatter<'_>| {
        if connection.ingress_protocol == REPLAY_PROTOCOL {
            f.write_str("Inspector replay")?;
            if let Some(exchange) = exchanges
                .iter()
                .find(|exchange| exchange.connection_id == connection.id)
            {
                write!(f, " → {}", optional_display(exchange.endpoint.as_ref()))?;
            }
            Ok(())
        } else {
            write!(
                f,
                "{} → {}",
                optional_display(connection.peer_address.as_ref()),
                optional_display(connection.local_address.as_ref())
            )
        }
    })
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_focused_request_row(
    exchange: &HttpExchangeSummary,
    live: &LiveStatus,
) -> impl IntoHtml {
    let pending = live.for_exchange(exchange.id).next();
    let method = if matches!(exchange.protocol, Protocol::WS | Protocol::WSS) {
        "WS"
    } else {
        exchange.method.as_str()
    };
    article!(
        id = ("request-", exchange.id),
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
                strong!("#", exchange.id),
                span!("conn #", exchange.connection_display_id)
            ),
            span!(class = "method", method),
            div!(
                class = "target",
                strong!(exchange.endpoint.as_ref().map(display)),
                small!(display(&exchange.url))
            ),
            render_protocol_badge(exchange),
            if let Some(message) = pending {
                approval_badge(message)
            } else {
                render_exchange_status(exchange)
            },
            span!(
                class = "bytes",
                display(format_bytes(exchange.response_bytes))
            ),
            time!(
                class = "exchange-time",
                datetime = display(exchange.started_at),
                display(display_timestamp(&exchange.started_at))
            ),
            span!(class = "focus-open-hint", "Open →")
        ),
        render_approval_slots(live.for_exchange(exchange.id))
    )
}
