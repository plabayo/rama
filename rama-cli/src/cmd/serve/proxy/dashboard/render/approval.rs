use std::fmt;

use rama::http::inspect::control::Direction;

use super::*;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum ApprovalGroup {
    Request(u64),
    Unrecorded(u64),
    Connection(u64),
}

impl fmt::Display for ApprovalGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(id) => write!(f, "request-{id}"),
            Self::Unrecorded(id) => write!(f, "unrecorded-{id}"),
            Self::Connection(id) => write!(f, "unrecorded-connection-{id}"),
        }
    }
}

pub(in crate::cmd::serve::proxy::dashboard) fn approval_badge(
    message: &PendingSummary,
) -> impl IntoHtml {
    span!(
        class = "approval-badge",
        if message.kind.is_some() {
            "Awaiting message approval"
        } else {
            match message.direction {
                Direction::Ingress => "Awaiting request approval",
                Direction::Egress => "Awaiting response approval",
            }
        }
    )
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_approval_toolbar() -> impl IntoHtml {
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

pub(in crate::cmd::serve::proxy::dashboard) fn render_pending_fallbacks(
    pending: &[PendingSummary],
    exchanges: &[HttpExchangeSummary],
    connection: Option<u64>,
) -> impl IntoHtml {
    let retained = exchanges
        .iter()
        .map(|exchange| exchange.id)
        .collect::<BTreeSet<_>>();
    let mut groups = BTreeMap::<ApprovalGroup, Vec<&PendingSummary>>::new();
    for message in pending.iter().filter(|message| {
        connection.is_none_or(|id| id == message.connection)
            && message.exchange.is_none_or(|id| !retained.contains(&id))
    }) {
        let key = message
            .exchange
            .map(ApprovalGroup::Request)
            .unwrap_or_else(|| {
                if message.kind.is_none() {
                    ApprovalGroup::Unrecorded(message.id)
                } else {
                    ApprovalGroup::Connection(message.connection)
                }
            });
        groups.entry(key).or_default().push(message);
    }
    render_each(groups.into_iter().filter_map(|(key, messages)| {
        let first = messages.first()?;
        Some(article!(
            id = display(key),
            class = "exchange active temporary-request",
            tabindex = "0",
            "data-inspector-focus" = "request",
            "data-approval-id" = display(first.id),
            div!(
                class = "exchange-row",
                div!(
                    class = "capture-ref",
                    strong!(if let Some(id) = first.exchange {
                        ("#", id)
                    } else {
                        "Unrecorded"
                    }),
                    span!(if let Some(id) = first.connection_display_id {
                        ("conn #", id)
                    } else {
                        ("connection ", first.connection)
                    })
                ),
                span!(class = "method", display(&first.method)),
                div!(
                    class = "target",
                    strong!(display(&first.url)),
                    small!("Outside the current captured view")
                ),
                div!(
                    class = "exchange-protocol-state",
                    span!(display(uppercase(first.protocol.as_str()))),
                    approval_badge(first)
                )
            ),
            render_approval_slots(messages.into_iter())
        ))
    }))
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_approval_slots<'a>(
    pending: impl Iterator<Item = &'a PendingSummary>,
) -> impl IntoHtml {
    render_each(pending.map(|message| {
        div!(
            id = ("approval-item-", message.id),
            class = "approval-item",
            "data-pending-id" = message.id,
            div!(
                class = "approval-message-heading",
                input!(
                    r#type = "checkbox",
                    id = ("approval-select-", message.id),
                    "data-ignore-morph" = "",
                    "data-pending-select" = "",
                    value = message.id,
                    "aria-label" = (
                        "Select queued ",
                        display(&message.direction),
                        " #",
                        message.id
                    )
                ),
                button!(
                    r#type = "button",
                    class = "approval-open",
                    "data-edit-approval" = message.id,
                    "Edit ",
                    display(&message.direction),
                    " · approval #",
                    message.id
                ),
                message
                    .queued_at
                    .as_ref()
                    .map(|at| time!(datetime = display(at), display(display_timestamp(at))))
            ),
            div!(
                id = ("approval-slot-", message.id),
                "data-ignore-morph" = ""
            )
        )
    }))
}
