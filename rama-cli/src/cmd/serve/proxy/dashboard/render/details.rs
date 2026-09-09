use std::fmt;

use rama::{
    http::{HeaderMap, headers::HeaderMapExt as _, inspect::control::Direction},
    net::{Protocol, stream::SocketInfo},
    utils::fmt::display_fn,
};

use super::*;

pub(in crate::cmd::serve::proxy::dashboard) fn render_details(
    details: &InspectorDetails,
) -> impl IntoHtml {
    let request_head = details.records.iter().find_map(|record| match record {
        StoredRecord::RequestHead {
            method,
            url,
            version,
            headers,
            ..
        } => Some((method, url, version, headers)),
        _ => None,
    });
    let response_head = details.records.iter().find_map(|record| match record {
        StoredRecord::ResponseHead {
            status,
            version,
            headers,
            ..
        } => Some((*status, version, headers)),
        _ => None,
    });
    let request_headers = details
        .records
        .iter()
        .rev()
        .find_map(|record| match record {
            StoredRecord::Interception {
                kind: None,
                direction: Direction::Ingress,
                forwarded_headers: Some(headers),
                ..
            } => Some(headers),
            _ => None,
        })
        .or_else(|| request_head.map(|(_, _, _, headers)| headers));
    let response_headers = response_head.map(|(_, _, headers)| headers);
    let overview = section!(
        class = "detail-overview",
        overview_item("Request", &details.summary.method),
        overview_item(
            "Protocol",
            display_fn(move |f: &mut fmt::Formatter<'_>| write!(
                f,
                "{} · {}",
                uppercase(details.summary.protocol.as_str()),
                details.summary.http_version
            ))
        ),
        details
            .summary
            .endpoint
            .as_ref()
            .map(|endpoint| overview_item("Endpoint", endpoint)),
        overview_item(
            "Status",
            display_fn(|f: &mut fmt::Formatter<'_>| {
                match details.summary.status {
                    Some(status) => write!(f, "{status}"),
                    None => f.write_str("Pending"),
                }
            })
        ),
        overview_item(
            "Traffic",
            display_fn(move |f: &mut fmt::Formatter<'_>| write!(
                f,
                "{} ↑  {} ↓",
                format_bytes(details.summary.request_bytes),
                format_bytes(details.summary.response_bytes)
            ))
        ),
        details
            .connection
            .as_ref()
            .and_then(|connection| connection.peer_address.as_ref())
            .map(|address| overview_item("Ingress client", address)),
        details
            .connection
            .as_ref()
            .and_then(|connection| connection.local_address.as_ref())
            .map(|address| overview_item("Ingress proxy", address)),
        details
            .metadata
            .upstream
            .get_ref::<SocketInfo>()
            .and_then(|socket| socket.local_addr())
            .map(|address| overview_item("Egress proxy", address)),
        details
            .metadata
            .upstream
            .get_ref::<SocketInfo>()
            .map(|socket| socket.peer_addr())
            .map(|address| overview_item("Egress server", address)),
        overview_item(
            "Request started",
            display_timestamp(&details.summary.started_at)
        ),
        details
            .summary
            .response_started_at
            .as_ref()
            .map(|at| overview_item("Response started", display_timestamp(at))),
        details
            .summary
            .completed_at
            .as_ref()
            .map(|at| overview_item("Completed", display_timestamp(at))),
    );

    div!(
        class = "details",
        div!(
            class = "detail-top",
            div!(
                class = "detail-meta",
                span!("connection #", details.summary.connection_display_id),
                span!(display(uppercase(details.summary.protocol.as_str()))),
                span!(display(display_timestamp(&details.summary.started_at))),
                details
                    .metadata
                    .exchange
                    .get_ref::<UserAgentObservation>()
                    .and_then(|ua| ua.user_agent.as_ref())
                    .and_then(|ua| ua.ua_kind())
                    .map(|kind| span!(display(kind))),
            ),
            div!(
                class = "detail-actions",
                button!(
                    r#type = "button",
                    class = "ghost compact",
                    "data-create-traffic-rule" = display(details.summary.id),
                    "Create traffic rule…"
                ),
                (!matches!(details.summary.protocol, Protocol::WS | Protocol::WSS))
                    .then(|| render_curl_button(details.summary.id, "Copy as cURL")),
                (!matches!(details.summary.protocol, Protocol::WS | Protocol::WSS)).then(
                    || button!(
                        r#type = "button",
                        class = "ghost compact replay-focus",
                        "data-on:click" = ("@post('/api/replay/", details.summary.id, "')"),
                        "Replay request"
                    )
                ),
                a!(
                    class = "ghost link",
                    href = ("/api/har/export?ids=", details.summary.id),
                    target = "har-download",
                    "data-har-export" = "",
                    "Export HAR"
                ),
            )
        ),
        overview,
        request_head.map(|(method, url, version, _)| section!(
            class = "detail-card request-line",
            h3!("HTTP request"),
            code!(display(method), " ", display(url), " ", display(version))
        )),
        div!(
            class = "detail-columns",
            request_headers.map(|headers| render_headers(
                details.summary.id,
                "request",
                "Request headers",
                headers,
            )),
            response_head.map(|(status, version, headers)| render_headers(
                details.summary.id,
                "response",
                (
                    "Response headers · ",
                    status.as_u16(),
                    " ",
                    display(version)
                ),
                headers
            )),
        ),
        render_websocket_messages(details),
        render_http_fingerprint_card(details),
        div!(
            class = "detail-columns payload-columns",
            render_payload_card(
                details.summary.id,
                "request",
                details.summary.request_bytes,
                details.summary.request_truncated,
                request_headers,
            ),
            render_payload_card(
                details.summary.id,
                "response",
                details.summary.response_bytes,
                details.summary.response_truncated,
                response_headers,
            ),
        ),
        render_each(details.records.iter().filter_map(|record| match record {
            StoredRecord::Interception {
                direction,
                outcome,
                original_headers,
                original_status,
                original_payload,
                original_payload_length,
                ..
            } => Some(section!(
                class = "detail-card",
                h3!(display(direction), " · ", outcome),
                original_status.map(|status| p!("Original status: ", display(status))),
                details!(
                    summary!("Original headers / message"),
                    pre!(render_each(original_headers.ordered_iter().map(
                        |(name, value)| (name.as_str(), ": ", display(header_preview(value)), "\n")
                    ))),
                    original_payload.as_ref().map(|payload| {
                        div!(
                            pre!(display(payload)),
                            original_payload_length
                                .filter(|length| *length > payload.len() as u64)
                                .map(|length| p!(
                                    "Showing ",
                                    payload.len(),
                                    " of ",
                                    length,
                                    " bytes; the original payload preview is limited."
                                ))
                        )
                    })
                )
            )),
            _ => None,
        })),
        render_capture_outcomes(&details.records),
    )
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_headers(
    exchange_id: u64,
    direction: &str,
    title: impl IntoHtml,
    headers: &HeaderMap,
) -> impl IntoHtml {
    const MAX_HEADERS: usize = 128;
    let shown = headers.len().min(MAX_HEADERS);
    let target = ("headers-", exchange_id, "-", direction);
    section!(
        class = "detail-card header-card",
        div!(
            class = "card-title",
            h3!(title),
            div!(
                class = "header-tools",
                span!(headers.len(), " header(s)"),
                button!(
                    r#type = "button",
                    class = "ghost compact",
                    "data-copy-target" = target,
                    "Copy all"
                )
            )
        ),
        div!(
            id = target,
            class = "header-lines",
            render_each(
                headers
                    .ordered_iter()
                    .take(MAX_HEADERS)
                    .map(|(name, value)| div!(
                        class = "header-line",
                        code!(
                            span!(class = "header-name", name.as_str()),
                            ": ",
                            span!(display(header_preview(value)))
                        ),
                        button!(
                            r#type = "button",
                            class = "copy-header",
                            title = "Copy header as name: value",
                            "aria-label" = ("Copy ", name.as_str(), " header"),
                            "data-copy-header" = "",
                            "Copy"
                        )
                    ))
            )
        ),
        (shown < headers.len()).then(|| small!(
            headers.len() - shown,
            " additional header(s) omitted from the DOM; export HAR to inspect them."
        ))
    )
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_payload_card(
    id: u64,
    direction: &str,
    bytes: u64,
    truncated: bool,
    headers: Option<&HeaderMap>,
) -> Option<impl IntoHtml> {
    if bytes == 0 && !truncated {
        return None;
    }
    let content_type = headers
        .and_then(|headers| headers.typed_get::<ContentType>())
        .unwrap_or_else(ContentType::octet_stream);
    let textual = is_textual_content_type(content_type.mime());
    let payload_format = if textual { "text" } else { "binary" };
    let title = if direction == "request" {
        "Request payload"
    } else {
        "Response payload"
    };
    let preview_url = (
        "/api/capture/",
        id,
        "/body/",
        direction,
        "?limit=",
        MAX_BODY_PREVIEW_LIMIT,
    );
    Some(article!(
        class = "detail-card payload-card",
        "data-capture-container" = "",
        div!(
            class = "card-title",
            h3!(title),
            span!(display(format_bytes(bytes)))
        ),
        code!(display(content_type)),
        truncated.then(|| p!(
            class = "capture-warning",
            "Capture limit reached; the stored body is incomplete."
        )),
        div!(
            class = "payload-actions",
            button!(
                r#type = "button",
                class = "ghost",
                "data-capture-preview" = "",
                "data-byte-limit" = MAX_BODY_PREVIEW_LIMIT,
                "data-label" = "Preview first 64 KiB",
                "data-url" = preview_url,
                "data-payload-format" = payload_format,
                span!(class = "capture-spinner", "aria-hidden" = "true"),
                span!("data-capture-label" = "", "Preview first 64 KiB")
            ),
            a!(
                class = "ghost link",
                href = ("/api/capture/", id, "/body/", direction, "?download=true"),
                "Stream captured body"
            )
        ),
        pre!(
            "data-capture-output" = "",
            "aria-live" = "polite",
            hidden = ""
        )
    ))
}
