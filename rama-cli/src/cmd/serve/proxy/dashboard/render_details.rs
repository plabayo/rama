use super::*;

pub(super) fn render_details(details: &InspectorDetails) -> impl IntoHtml {
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
                direction,
                forwarded_headers: Some(headers),
                ..
            } if direction == "request" => Some(headers),
            _ => None,
        })
        .or_else(|| request_head.map(|(_, _, _, headers)| headers));
    let response_headers = response_head.map(|(_, _, headers)| headers);
    let overview = section!(
        class = "detail-overview",
        overview_item("Request", &details.summary.method),
        overview_item(
            "Protocol",
            format!(
                "{} · {}",
                details.summary.protocol.as_str().to_ascii_uppercase(),
                details.summary.http_version
            )
        ),
        details
            .summary
            .endpoint
            .as_ref()
            .map(|endpoint| overview_item("Endpoint", endpoint)),
        overview_item(
            "Status",
            rama::utils::fmt::display_fn(|f: &mut std::fmt::Formatter<'_>| {
                match details.summary.status {
                    Some(status) => write!(f, "{status}"),
                    None => f.write_str("Pending"),
                }
            })
        ),
        overview_item(
            "Traffic",
            format!(
                "{} ↑  {} ↓",
                format_bytes(details.summary.request_bytes),
                format_bytes(details.summary.response_bytes)
            )
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
            .get_ref::<rama::net::stream::SocketInfo>()
            .and_then(|socket| socket.local_addr())
            .map(|address| overview_item("Egress proxy", address)),
        details
            .metadata
            .upstream
            .get_ref::<rama::net::stream::SocketInfo>()
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
    )
    .into_string();

    div!(
        class = "details",
        div!(
            class = "detail-top",
            div!(
                class = "detail-meta",
                span!(format!(
                    "connection #{}",
                    details.summary.connection_display_id
                )),
                span!(details.summary.protocol.as_str().to_ascii_uppercase()),
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
                (!matches!(details.summary.protocol.as_str(), "ws" | "wss"))
                    .then(|| PreEscaped(render_curl_button(details.summary.id, "Copy as cURL"))),
                (!matches!(details.summary.protocol.as_str(), "ws" | "wss")).then(|| button!(
                    r#type = "button",
                    class = "ghost compact replay-focus",
                    "data-on:click" = format!("@post('/api/replay/{}')", details.summary.id),
                    "Replay request"
                )),
                a!(
                    class = "ghost link",
                    href = format!("/api/har/export?ids={}", details.summary.id),
                    target = "har-download",
                    "data-har-export" = "",
                    "Export HAR"
                ),
                a!(
                    class = "ghost link",
                    href = format!("/api/capture/{}.json", details.summary.id),
                    target = "har-download",
                    "Download capture JSON"
                ),
            )
        ),
        PreEscaped(overview),
        request_head.map(|(method, url, version, _)| section!(
            class = "detail-card request-line",
            h3!("HTTP request"),
            code!(format!("{method} {url} {version}"))
        )),
        div!(
            class = "detail-columns",
            request_headers.map(|headers| PreEscaped(render_headers(
                details.summary.id,
                "request",
                "Request headers",
                headers,
            ))),
            response_head.map(|(status, version, headers)| PreEscaped(render_headers(
                details.summary.id,
                "response",
                format_args!("Response headers · {} {version}", status.as_u16()),
                headers
            ))),
        ),
        render_websocket_messages(details).map(PreEscaped),
        render_http_fingerprint_card(details).map(PreEscaped),
        div!(
            class = "detail-columns payload-columns",
            render_payload_card(
                details.summary.id,
                "request",
                details.summary.request_bytes,
                details.summary.request_truncated,
                request_headers,
            )
            .map(PreEscaped),
            render_payload_card(
                details.summary.id,
                "response",
                details.summary.response_bytes,
                details.summary.response_truncated,
                response_headers,
            )
            .map(PreEscaped),
        ),
        details
            .records
            .iter()
            .filter_map(|record| match record {
                StoredRecord::Interception {
                    direction,
                    outcome,
                    original_headers,
                    original_status,
                    original_payload,
                    ..
                } => Some(section!(
                    class = "detail-card",
                    h3!(format!("{direction} · {outcome}")),
                    original_status.map(|status| p!(format!("Original status: {status}"))),
                    details!(
                        summary!("Original headers / message"),
                        pre!(serde_json::to_string_pretty(original_headers).unwrap_or_default()),
                        original_payload
                            .as_ref()
                            .map(|payload| pre!(display(payload)))
                    )
                )),
                _ => None,
            })
            .collect::<Vec<_>>(),
        render_capture_outcomes(&details.records).map(PreEscaped),
    )
}

pub(super) fn render_headers(
    exchange_id: u64,
    direction: &str,
    title: impl std::fmt::Display,
    headers: &rama::http::HeaderMap,
) -> String {
    const MAX_HEADERS: usize = 128;
    let shown = headers.len().min(MAX_HEADERS);
    let target = format!("headers-{exchange_id}-{direction}");
    section!(
        class = "detail-card header-card",
        div!(
            class = "card-title",
            h3!(display(title)),
            div!(
                class = "header-tools",
                span!(format!("{} header(s)", headers.len())),
                button!(
                    r#type = "button",
                    class = "ghost compact",
                    "data-copy-target" = target.clone(),
                    "Copy all"
                )
            )
        ),
        div!(
            id = target,
            class = "header-lines",
            render_each(headers.ordered_iter().take(MAX_HEADERS).map(|(name, value)| div!(
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
                    "aria-label" = format!("Copy {name} header"),
                    "data-copy-header" = "",
                    "Copy"
                )
            )))
        ),
        (shown < headers.len()).then(|| small!(format!(
            "{} additional header(s) omitted from the DOM; download the capture JSON to inspect them.",
            headers.len() - shown
        )))
    )
    .into_string()
}

pub(super) fn render_payload_card(
    id: u64,
    direction: &str,
    bytes: u64,
    truncated: bool,
    headers: Option<&rama::http::HeaderMap>,
) -> Option<String> {
    if bytes == 0 && !truncated {
        return None;
    }
    let content_type = header_value(headers, "content-type").unwrap_or("application/octet-stream");
    let textual = is_textual_content_type(content_type);
    let payload_format = if textual { "text" } else { "binary" };
    let title = if direction == "request" {
        "Request payload"
    } else {
        "Response payload"
    };
    let preview_url = format!("/api/capture/{id}/body/{direction}?limit={MAX_BODY_PREVIEW_LIMIT}");
    Some(
        article!(
            class = "detail-card payload-card",
            "data-capture-container" = "",
            div!(class = "card-title", h3!(title), span!(format_bytes(bytes))),
            code!(content_type.to_owned()),
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
                    "data-label" = "Preview first 64 KiB",
                    "data-url" = preview_url,
                    "data-payload-format" = payload_format,
                    span!(class = "capture-spinner", "aria-hidden" = "true"),
                    span!("data-capture-label" = "", "Preview first 64 KiB")
                ),
                a!(
                    class = "ghost link",
                    href = format!("/api/capture/{id}/body/{direction}?download=true"),
                    "Stream captured body"
                )
            ),
            pre!(
                "data-capture-output" = "",
                "aria-live" = "polite",
                hidden = ""
            )
        )
        .into_string(),
    )
}
