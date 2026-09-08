use super::*;

pub(super) fn render_fingerprint_values(
    title: &'static str,
    values: &[(&'static str, Option<&dyn std::fmt::Display>)],
) -> Option<String> {
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
        .into_string()
    })
}

pub(super) fn render_connection_fingerprint_card(summary: &HttpExchangeSummary) -> Option<String> {
    let tls = summary.metadata.connection.get_ref::<TlsObservation>();
    let ja3 = tls.and_then(|tls| tls.ja3.as_ref()).map(|value| {
        rama::utils::fmt::display_fn(move |f: &mut std::fmt::Formatter<'_>| write!(f, "{value:x}"))
    });
    let user_agent = summary
        .user_agent
        .as_ref()
        .map(|value| rama::utils::fmt::utf8_or_hex(value.as_bytes()));
    render_fingerprint_values(
        "Client identity & TLS fingerprints",
        &[
            (
                "JA3",
                ja3.as_ref().map(|value| value as &dyn std::fmt::Display),
            ),
            (
                "JA4",
                tls.and_then(|tls| tls.ja4.as_ref())
                    .map(|value| value as &dyn std::fmt::Display),
            ),
            (
                "PeetPrint",
                tls.and_then(|tls| tls.peetprint.as_ref())
                    .map(|value| value as &dyn std::fmt::Display),
            ),
            (
                "Known profile",
                summary
                    .metadata
                    .exchange
                    .get_ref::<UserAgentObservation>()
                    .and_then(|ua| ua.known_fingerprint.as_ref())
                    .map(|value| value as &dyn std::fmt::Display),
            ),
            (
                "User agent",
                user_agent
                    .as_ref()
                    .map(|value| value as &dyn std::fmt::Display),
            ),
        ],
    )
}

pub(super) fn render_http_fingerprint_card(details: &InspectorDetails) -> Option<String> {
    render_fingerprint_values(
        "HTTP fingerprints",
        &[
            (
                "JA4H",
                details
                    .summary
                    .ja4h
                    .as_ref()
                    .map(|value| value as &dyn std::fmt::Display),
            ),
            (
                "Akamai HTTP/2",
                details
                    .connection
                    .as_ref()
                    .and_then(|connection| connection.akamai_h2.as_ref())
                    .map(|value| value as &dyn std::fmt::Display),
            ),
        ],
    )
}

pub(super) fn render_capture_outcomes(records: &[StoredRecord]) -> Option<String> {
    let outcomes = records
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
        .collect::<Vec<_>>();
    (!outcomes.is_empty()).then(|| {
        div!(
            class = "capture-outcomes",
            outcomes
                .into_iter()
                .map(|(label, outcome)| span!(format!("{label}: {outcome}")))
        )
        .into_string()
    })
}
