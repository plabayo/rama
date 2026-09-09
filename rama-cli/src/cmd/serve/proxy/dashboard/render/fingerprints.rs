use std::fmt;

use super::*;

pub(in crate::cmd::serve::proxy::dashboard) fn render_fingerprint_values(
    title: &'static str,
    values: &[(&'static str, Option<&dyn fmt::Display>)],
) -> Option<impl IntoHtml> {
    values.iter().any(|(_, value)| value.is_some()).then(|| {
        section!(
            class = "detail-card fingerprint-card",
            h3!(title),
            div!(
                class = "fingerprint-grid",
                values.iter().map(|(label, value)| value.map(|value| div!(
                    class = "fingerprint-row",
                    span!(*label),
                    code!(title = display(value), display(value))
                )))
            )
        )
    })
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_connection_fingerprint_card(
    summary: &HttpExchangeSummary,
) -> impl IntoHtml {
    move |output: &mut String| {
        let tls = summary.metadata.connection.get_ref::<TlsObservation>();
        let ja3 = tls.and_then(|tls| tls.ja3.as_ref()).map(|value| {
            rama::utils::fmt::display_fn(move |f: &mut fmt::Formatter<'_>| write!(f, "{value:x}"))
        });
        let user_agent = summary
            .user_agent
            .as_ref()
            .map(|value| rama::utils::fmt::utf8_or_hex(value.as_bytes()));
        render_fingerprint_values(
            "Client identity & TLS fingerprints",
            &[
                ("JA3", ja3.as_ref().map(|value| value as &dyn fmt::Display)),
                (
                    "JA4",
                    tls.and_then(|tls| tls.ja4.as_ref())
                        .map(|value| value as &dyn fmt::Display),
                ),
                (
                    "PeetPrint",
                    tls.and_then(|tls| tls.peetprint.as_ref())
                        .map(|value| value as &dyn fmt::Display),
                ),
                (
                    "Known profile",
                    summary
                        .metadata
                        .exchange
                        .get_ref::<UserAgentObservation>()
                        .and_then(|ua| ua.known_fingerprint.as_ref())
                        .map(|value| value as &dyn fmt::Display),
                ),
                (
                    "User agent",
                    user_agent.as_ref().map(|value| value as &dyn fmt::Display),
                ),
            ],
        )
        .escape_and_write(output);
    }
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_http_fingerprint_card(
    details: &InspectorDetails,
) -> impl IntoHtml {
    move |output: &mut String| {
        render_fingerprint_values(
            "HTTP fingerprints",
            &[
                (
                    "JA4H",
                    details
                        .summary
                        .ja4h
                        .as_ref()
                        .map(|value| value as &dyn fmt::Display),
                ),
                (
                    "Akamai HTTP/2",
                    details
                        .connection
                        .as_ref()
                        .and_then(|connection| connection.akamai_h2.as_ref())
                        .map(|value| value as &dyn fmt::Display),
                ),
            ],
        )
        .escape_and_write(output);
    }
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_capture_outcomes(
    records: &[StoredRecord],
) -> impl IntoHtml {
    move |output: &mut String| {
        let mut outcomes = records
            .iter()
            .filter_map(|record| match record {
                StoredRecord::RequestEnd { outcome } => Some((
                    "Request",
                    match outcome {
                        rama::http::CaptureOutcome::Complete => "complete",
                        rama::http::CaptureOutcome::Error => "error",
                        rama::http::CaptureOutcome::Aborted => "aborted",
                    },
                )),
                StoredRecord::ResponseEnd { outcome } => Some((
                    "Response",
                    match outcome {
                        rama::http::CaptureOutcome::Complete => "complete",
                        rama::http::CaptureOutcome::Error => "error",
                        rama::http::CaptureOutcome::Aborted => "aborted",
                    },
                )),
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
        outcomes
            .peek()
            .is_some()
            .then(|| {
                div!(
                    class = "capture-outcomes",
                    render_each(outcomes.map(|(label, outcome)| span!(label, ": ", outcome)))
                )
            })
            .escape_and_write(output);
    }
}
