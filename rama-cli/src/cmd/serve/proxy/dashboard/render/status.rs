use std::fmt;

use rama::{combinators::Either, net::Protocol, utils::fmt::display_fn};

use super::*;

pub(in crate::cmd::serve::proxy::dashboard) fn render_protocol_badge(
    exchange: &HttpExchangeSummary,
) -> impl IntoHtml {
    let secure = exchange.protocol.is_secure();
    span!(
        class = match secure {
            true => "tag protocol secure",
            false => "tag protocol",
        },
        secure.then(|| span!(class = "protocol-lock", "aria-hidden" = "true", "🔒")),
        span!(display(uppercase(exchange.protocol.as_str()))),
        span!(class = "protocol-version", display(exchange.http_version))
    )
}

pub(in crate::cmd::serve::proxy::dashboard) fn stat(
    label: &'static str,
    value: impl fmt::Display,
) -> impl IntoHtml {
    div!(class = "stat", span!(label), strong!(display(value)))
}

pub(in crate::cmd::serve::proxy::dashboard) fn status_class(
    status: Option<StatusCode>,
) -> &'static str {
    match status.map(|status| status.as_u16()) {
        Some(200..=399) => "status ok",
        Some(400..=599) => "status error",
        _ => "status",
    }
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_exchange_status(
    exchange: &HttpExchangeSummary,
) -> impl IntoHtml {
    if let Some(decision) = &exchange.decision {
        return Either::A(span!(
            class = "status",
            title = decision,
            exchange.status.map(display),
            " · ",
            decision
        ));
    }
    let websocket = matches!(exchange.protocol, Protocol::WS | Protocol::WSS);
    let (fallback, suffix, class, state, indicator) = match (exchange.status, exchange.active) {
        (None, true) => (
            "Waiting for response",
            "Waiting for response headers",
            "status pending",
            "waiting",
            Some("response-spinner"),
        ),
        (None, false) => (
            "No response",
            "Connection closed before a response was received",
            "status error",
            "no-response",
            None,
        ),
        (Some(status), true) if websocket => (
            "",
            ", WebSocket connection is live",
            status_class(Some(status)),
            "live",
            Some("response-live-dot"),
        ),
        (Some(status), true) => (
            "",
            ", response body is still streaming",
            status_class(Some(status)),
            "streaming",
            Some("response-spinner"),
        ),
        (Some(status), false) => ("", "", status_class(Some(status)), "finished", None),
    };
    let label = display_fn(move |f: &mut fmt::Formatter<'_>| match exchange.status {
        Some(status) => write!(f, "{status}"),
        None => f.write_str(fallback),
    });
    let title = display_fn(move |f: &mut fmt::Formatter<'_>| {
        if let Some(status) = exchange.status {
            write!(f, "{status}")?;
        }
        f.write_str(suffix)
    });
    Either::B(span!(
        class = class,
        title = display(title),
        "aria-label" = display(title),
        "data-response-state" = state,
        indicator.map(|class| span!(class = class, "aria-hidden" = "true")),
        span!(class = "status-label", display(label))
    ))
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_curl_button(
    exchange_id: u64,
    label: &'static str,
) -> impl IntoHtml {
    button!(
        r#type = "button",
        class = "ghost compact",
        title = ("Copy request #", exchange_id, " as a cURL command"),
        "data-copy-curl" = ("/api/capture/", exchange_id, "/curl"),
        span!(class = "capture-spinner", "aria-hidden" = "true"),
        span!("data-copy-label" = "", label)
    )
}

pub(in crate::cmd::serve::proxy::dashboard) fn overview_item(
    label: &'static str,
    value: impl fmt::Display,
) -> impl IntoHtml {
    div!(
        class = "detail-overview-item",
        div!(
            class = "detail-overview-head",
            span!(class = "detail-overview-label", label),
            button!(
                r#type = "button",
                class = "detail-overview-copy",
                title = ("Copy ", label),
                "aria-label" = ("Copy ", label),
                "data-copy-overview" = "",
                "Copy"
            )
        ),
        strong!(class = "detail-overview-value", display(value))
    )
}
