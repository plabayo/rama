use std::fmt;

use super::*;

fn fingerprint_row(label: &'static str, value: impl fmt::Display + Clone) -> impl IntoHtml {
    div!(
        class = "fingerprint-row",
        span!(label),
        code!(title = display(value.clone()), display(value))
    )
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_connection_fingerprint_card(
    summary: &HttpExchangeSummary,
) -> impl IntoHtml {
    let tls = summary.metadata.connection.get_ref::<TlsObservation>();
    let known = summary
        .metadata
        .exchange
        .get_ref::<UserAgentObservation>()
        .and_then(|ua| ua.known_fingerprint.as_ref());
    let ja3 = tls.and_then(|tls| tls.ja3.as_ref());
    let ja4 = tls.and_then(|tls| tls.ja4.as_ref());
    let peetprint = tls.and_then(|tls| tls.peetprint.as_ref());
    let user_agent = summary.user_agent.as_ref();
    (ja3.is_some()
        || ja4.is_some()
        || peetprint.is_some()
        || known.is_some()
        || user_agent.is_some())
    .then(|| {
        section!(
            class = "detail-card fingerprint-card",
            h3!("Client identity & TLS fingerprints"),
            div!(
                class = "fingerprint-grid",
                ja3.map(|value| fingerprint_row(
                    "JA3",
                    rama::utils::fmt::display_fn(move |f: &mut fmt::Formatter<'_>| write!(
                        f,
                        "{value:x}"
                    ))
                )),
                ja4.map(|value| fingerprint_row("JA4", value)),
                peetprint.map(|value| fingerprint_row("PeetPrint", value)),
                known.map(|value| fingerprint_row("Known profile", value)),
                user_agent.map(|value| fingerprint_row(
                    "User agent",
                    rama::utils::fmt::display_fn(move |f: &mut fmt::Formatter<'_>| write!(
                        f,
                        "{}",
                        rama::utils::fmt::utf8_or_hex(value.as_bytes())
                    ))
                )),
            )
        )
    })
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_http_fingerprint_card(
    details: &InspectorDetails,
) -> impl IntoHtml {
    let ja4h = details.summary.ja4h.as_ref();
    let akamai = details
        .connection
        .as_ref()
        .and_then(|connection| connection.akamai_h2.as_ref());
    (ja4h.is_some() || akamai.is_some()).then(|| {
        section!(
            class = "detail-card fingerprint-card",
            h3!("HTTP fingerprints"),
            div!(
                class = "fingerprint-grid",
                ja4h.map(|value| fingerprint_row("JA4H", value)),
                akamai.map(|value| fingerprint_row("Akamai HTTP/2", value)),
            )
        )
    })
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_capture_outcomes(
    records: &[StoredRecord],
) -> impl IntoHtml {
    let mut outcomes = records
        .iter()
        .filter_map(|record| match record {
            StoredRecord::RequestEnd { outcome } => Some(("Request", outcome.as_str())),
            StoredRecord::ResponseEnd { outcome } => Some(("Response", outcome.as_str())),
            StoredRecord::ReplayResult { status, error } => Some((
                "Last replay",
                error.as_deref().unwrap_or(if status.is_some() {
                    "complete"
                } else {
                    "failed"
                }),
            )),
            _ => None,
        })
        .peekable();
    outcomes.peek().is_some().then(|| {
        div!(
            class = "capture-outcomes",
            render_each(outcomes.map(|(label, outcome)| span!(label, ": ", outcome)))
        )
    })
}
