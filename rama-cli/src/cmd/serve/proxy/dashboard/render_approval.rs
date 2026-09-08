use super::*;
use rama::http::inspect::control::HttpMessageDirection;

pub(super) fn approval_badge(message: &PendingSummary) -> String {
    span!(
        class = "approval-badge",
        match message.direction {
            HttpMessageDirection::Request => "Awaiting request approval",
            HttpMessageDirection::Response => "Awaiting response approval",
            _ => "Awaiting message approval",
        }
    )
    .into_string()
}

pub(super) fn render_approval_toolbar() -> impl IntoHtml {
    div!(
        id = "approval-toolbar",
        "data-ignore-morph" = "",
        class = "approval-toolbar",
        hidden = "",
        button!(
            r#type = "button",
            id = "approval-filter",
            class = "ghost compact",
            "aria-pressed" = "false",
            "data-inspector-focus" = "overview",
            "Awaiting approval (0)"
        ),
        div!(
            id = "approval-actions",
            class = "control-actions",
            hidden = "",
            button!(
                r#type = "button",
                class = "ghost compact",
                "data-bulk" = "forward",
                "Forward selected"
            ),
            button!(
                r#type = "button",
                class = "ghost compact",
                "data-bulk" = "block",
                "Block selected"
            ),
            button!(
                r#type = "button",
                id = "forward-all",
                class = "ghost compact",
                "Forward all and turn off"
            )
        ),
        p!(
            id = "approval-view-note",
            hidden = "",
            "Showing all queued traffic, oldest first, including traffic outside capture filters."
        ),
        div!(id = "automatic-connections")
    )
}

pub(super) fn render_pending_fallbacks(
    pending: &[PendingSummary],
    exchanges: &[HttpExchangeSummary],
    connection: Option<u64>,
) -> String {
    let retained = exchanges
        .iter()
        .map(|exchange| exchange.id)
        .collect::<BTreeSet<_>>();
    let mut groups = BTreeMap::<String, Vec<&PendingSummary>>::new();
    for message in pending.iter().filter(|message| {
        connection.is_none_or(|id| id == message.connection)
            && message.exchange.is_none_or(|id| !retained.contains(&id))
    }) {
        let key = message
            .exchange
            .map(|id| format!("request-{id}"))
            .unwrap_or_else(|| {
                if matches!(
                    message.direction,
                    HttpMessageDirection::Request | HttpMessageDirection::Response
                ) {
                    format!("unrecorded-{}", message.id)
                } else {
                    format!("unrecorded-connection-{}", message.connection)
                }
            });
        groups.entry(key).or_default().push(message);
    }
    groups
        .into_iter()
        .filter_map(|(key, messages)| {
            let first = messages.first()?;
            Some(
                article!(
                    id = key,
                    class = "exchange active temporary-request",
                    tabindex = "0",
                    "data-inspector-focus" = "request",
                    "data-approval-id" = display(first.id),
                    div!(
                        class = "exchange-row",
                        div!(
                            class = "capture-ref",
                            strong!(
                                first
                                    .exchange
                                    .map(|id| format!("#{id}"))
                                    .unwrap_or_else(|| "Unrecorded".to_owned())
                            ),
                            span!(
                                first
                                    .connection_display_id
                                    .map(|id| format!("conn #{id}"))
                                    .unwrap_or_else(|| format!("connection {}", first.connection))
                            )
                        ),
                        span!(class = "method", display(&first.method)),
                        div!(
                            class = "target",
                            strong!(display(&first.url)),
                            small!("Outside the current captured view")
                        ),
                        div!(
                            class = "exchange-protocol-state",
                            span!(first.protocol.as_str().to_uppercase()),
                            PreEscaped(approval_badge(first))
                        )
                    ),
                    PreEscaped(render_approval_slots(messages.into_iter()))
                )
                .into_string(),
            )
        })
        .collect()
}
