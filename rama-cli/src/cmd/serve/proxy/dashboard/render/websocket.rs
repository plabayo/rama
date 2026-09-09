use std::fmt;

use rama::{
    combinators::Either,
    http::{
        mime::{self, Mime},
        ws::inspect::{WebSocketMessageMetadata, WebSocketMessagePreview},
    },
};

use super::*;

pub(in crate::cmd::serve::proxy::dashboard) fn render_websocket_messages(
    details: &InspectorDetails,
) -> Option<impl IntoHtml> {
    let messages = &details.websocket.messages;
    if details.websocket.total == 0 && !details.websocket.replay_active {
        return None;
    }
    let end = details
        .websocket
        .total
        .saturating_sub(details.websocket.page * MAX_VISIBLE_WS_MESSAGES);
    let start = end.saturating_sub(messages.len());
    let cards = messages.iter().enumerate().map(
        move |(
            page_index,
            WebSocketMessagePreview {
                metadata:
                    WebSocketMessageMetadata {
                        at,
                        direction,
                        kind,
                        close_code,
                        origin,
                        payload_length,
                    },
                data,
            },
        )| {
            let message_index = start + page_index;
            let prefix = match std::str::from_utf8(data) {
                Err(error)
                    if error.error_len().is_none()
                        && *payload_length > data.len() as u64
                        && matches!(
                            kind,
                            WebSocketMessageKind::Text | WebSocketMessageKind::Close
                        ) =>
                {
                    &data[..error.valid_up_to()]
                }
                _ => data.as_ref(),
            };
            let (payload, _, inline_truncated) = websocket_payload(*kind, prefix);
            let prefix_truncated = *payload_length > prefix.len() as u64;
            let preview_truncated = inline_truncated || prefix_truncated;
            let ingress = *direction == WebSocketRelayDirection::Ingress;
            let is_control = matches!(
                kind,
                WebSocketMessageKind::Ping
                    | WebSocketMessageKind::Pong
                    | WebSocketMessageKind::Close
            );
            let capture_truncated = if ingress {
                details.summary.request_truncated
            } else {
                details.summary.response_truncated
            };
            let can_replay = !is_control && !capture_truncated && details.websocket.replay_active;
            let direction_label = if ingress {
                "Client → Server"
            } else {
                "Server → Client"
            };
            let class = match (ingress, is_control) {
                (true, true) => "ws-message ingress control",
                (true, false) => "ws-message ingress",
                (false, true) => "ws-message egress control",
                (false, false) => "ws-message egress",
            };
            let origin_class = match origin {
                WebSocketMessageOrigin::Replay => " replayed",
                WebSocketMessageOrigin::Injected => " injected",
                WebSocketMessageOrigin::Peer => "",
            };
            article!(
                class = (class, origin_class),
                "data-capture-container" = "",
                div!(
                    class = "ws-message-head",
                    strong!(direction_label),
                    span!(display(kind)),
                    close_code.map(|code| span!("code ", u16::from(code))),
                    span!(display(format_bytes(*payload_length))),
                    (*origin == WebSocketMessageOrigin::Replay)
                        .then(|| span!(class = "ws-replayed", "replayed")),
                    (*origin == WebSocketMessageOrigin::Injected)
                        .then(|| span!(class = "ws-injected", "custom")),
                    is_control.then(|| span!("control · observation only")),
                    can_replay.then(|| button!(
                        r#type = "button",
                        class = "ghost compact ws-replay",
                        "data-on:click" = (
                            "@post('/api/websocket/",
                            details.summary.id,
                            "/replay/",
                            message_index,
                            "')"
                        ),
                        if ingress {
                            "Replay to server"
                        } else {
                            "Replay to client"
                        }
                    )),
                    time!(display(at)),
                ),
                (!data.is_empty()).then(|| pre!(
                    display(payload),
                    (prefix_truncated && !inline_truncated).then_some("…")
                )),
                preview_truncated.then(|| div!(
                    class = "ws-full-message",
                    small!("Preview truncated."),
                    button!(
                        r#type = "button",
                        class = "ghost compact",
                        "data-capture-preview" = "",
                        "data-byte-limit" = MAX_BODY_PREVIEW_LIMIT,
                        "data-label" = "Preview first 64 KiB",
                        "data-url" = (
                            "/api/capture/",
                            details.summary.id,
                            "/websocket/",
                            message_index
                        ),
                        "data-payload-format" = if *kind == WebSocketMessageKind::Text {
                            "text"
                        } else {
                            "binary"
                        },
                        span!(class = "capture-spinner", "aria-hidden" = "true"),
                        span!("data-capture-label" = "", "Preview first 64 KiB")
                    ),
                    a!(
                        class = "ghost link",
                        href = (
                            "/api/capture/",
                            details.summary.id,
                            "/websocket/",
                            message_index
                        ),
                        download = ("websocket-", details.summary.id, "-", message_index, ".bin"),
                        "Download full message"
                    ),
                    pre!("data-capture-output" = "", hidden = "")
                ))
            )
        },
    );
    let range = if details.websocket.total == 0 {
        Either::A("No messages yet")
    } else {
        Either::B((
            "messages ",
            start + 1,
            "–",
            end,
            " of ",
            details.websocket.total,
        ))
    };
    let replay_state = (!details.websocket.replay_active).then(|| {
        span!(
            class = "ws-replay-state",
            title = "Replay is unavailable because this WebSocket connection is closed",
            "Replay off"
        )
    });
    let truncation_state =
        (details.summary.request_truncated || details.summary.response_truncated).then(|| {
            span!(
                class = "ws-capture-state",
                title = "Replay is unavailable for messages in a truncated capture direction",
                "Capture truncated"
            )
        });
    let composer = details.websocket.replay_active.then(|| {
        div!(
            class = "ws-composer",
            div!(
                class = "ws-composer-fields",
                label!(
                    span!("Destination"),
                    select!(
                        "data-bind:websocket_direction" = "",
                        option!(value = "ingress", "Upstream server"),
                        option!(value = "egress", "Downstream client")
                    )
                ),
                label!(
                    span!("Message type"),
                    select!(
                        "data-bind:websocket_kind" = "",
                        option!(value = "text", "Text"),
                        option!(value = "binary", "Binary (base64)")
                    )
                )
            ),
            label!(
                class = "ws-composer-payload",
                span!("Message payload"),
                textarea!(
                    rows = "3",
                    placeholder = "Text message, or base64 when Binary is selected",
                    "data-bind:websocket_payload" = ""
                )
            ),
            div!(
                class = "ws-composer-actions",
                small!(
                    "Injected application messages are captured and cannot create control frames."
                ),
                button!(
                    r#type = "button",
                    class = "primary compact",
                    "data-on:click" = ("@post('/api/websocket/", details.summary.id, "/send')"),
                    "Send message"
                )
            )
        )
    });
    Some(section!(
        class = "ws-messages",
        div!(
            class = "ws-messages-title",
            div!(
                h3!("WebSocket traffic"),
                span!(range),
                replay_state,
                truncation_state
            ),
            div!(
                class = "ws-page-actions",
                (start > 0).then(|| button!(
                    class = "ghost compact",
                    "data-on:click" = ("@post('/api/websocket/", details.summary.id, "/older')"),
                    "Older"
                )),
                (details.websocket.page > 0).then(|| button!(
                    class = "ghost compact",
                    "data-on:click" = ("@post('/api/websocket/", details.summary.id, "/newer')"),
                    "Newer"
                ))
            )
        ),
        composer,
        cards
    ))
}

pub(in crate::cmd::serve::proxy::dashboard) fn is_textual_content_type(
    content_type: &Mime,
) -> bool {
    content_type.type_() == mime::TEXT
        || matches!(
            content_type.subtype().as_str(),
            "json"
                | "json-seq"
                | "ndjson"
                | "x-ndjson"
                | "xml"
                | "javascript"
                | "x-javascript"
                | "graphql"
                | "x-www-form-urlencoded"
        )
        || content_type
            .suffix()
            .is_some_and(|suffix| matches!(suffix.as_str(), "json" | "xml"))
}

pub(in crate::cmd::serve::proxy::dashboard) fn websocket_payload(
    kind: WebSocketMessageKind,
    bytes: &[u8],
) -> (impl fmt::Display + '_, usize, bool) {
    let text = matches!(
        kind,
        WebSocketMessageKind::Text | WebSocketMessageKind::Close
    );
    let limit = if text {
        WS_TEXT_PREVIEW_LIMIT
    } else {
        WS_BINARY_PREVIEW_LIMIT
    };
    let preview = rama::utils::fmt::display_fn(move |f: &mut fmt::Formatter<'_>| {
        let end = bytes.len().min(limit);
        if text {
            match std::str::from_utf8(bytes) {
                Ok(value) => f.write_str(&value[..value.floor_char_boundary(end)])?,
                Err(_) => write!(f, "{}", rama::utils::fmt::hex(&bytes[..end]))?,
            }
        } else {
            write!(f, "{}", rama::utils::fmt::hex(&bytes[..end]))?;
        }
        if bytes.len() > limit {
            f.write_str("…")?;
        }
        Ok(())
    });
    (preview, bytes.len(), bytes.len() > limit)
}

pub(in crate::cmd::serve::proxy::dashboard) fn format_bytes(bytes: u64) -> impl fmt::Display {
    rama::utils::fmt::display_fn(move |f: &mut fmt::Formatter<'_>| {
        if bytes < kib_u64(1) {
            write!(f, "{bytes} B")
        } else if bytes < mib(1) as u64 {
            write!(f, "{:.1} KiB", bytes as f64 / kib(1) as f64)
        } else {
            write!(f, "{:.1} MiB", bytes as f64 / mib(1) as f64)
        }
    })
}

pub(in crate::cmd::serve::proxy::dashboard) fn display_timestamp(
    timestamp: &jiff::Timestamp,
) -> impl fmt::Display + '_ {
    timestamp.strftime("%F %T%.3f UTC")
}
