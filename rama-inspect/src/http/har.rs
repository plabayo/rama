//! Convert captured observations into HAR entries, independently of the export destination.
use super::capture::{CaptureDetails, StoredRecord, captured_header_value, captured_http_version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rama_core::error::{BoxError, ErrorContext as _};
use rama_http::layer::har::spec;
use std::net::SocketAddr;

/// Reconstruct a HAR entry from recorded traffic, preserving observed timings,
/// byte counters and WebSocket messages. No filesystem or GUI state is required.
pub fn captured_har_entry(details: CaptureDetails) -> Result<spec::Entry, BoxError> {
    let mut request_head = None;
    let mut response_head = None;
    let mut request_body = Vec::new();
    let mut response_body = Vec::new();
    let mut web_socket_messages = Vec::new();
    for record in details.records {
        match record {
            StoredRecord::RequestHead {
                method,
                url,
                version,
                headers,
                ..
            } => request_head = Some((method, url, version, headers)),
            StoredRecord::Interception {
                direction,
                forwarded_headers: Some(headers),
                ..
            } if direction == "request" => {
                if let Some((_, _, _, current)) = &mut request_head {
                    *current = headers;
                }
            }
            StoredRecord::RequestBody { data } => request_body.extend(
                BASE64
                    .decode(data)
                    .context("decode selected HAR request body")?,
            ),
            StoredRecord::ResponseHead {
                status,
                version,
                headers,
                ..
            } => response_head = Some((status, version, headers)),
            StoredRecord::ResponseBody { data } => response_body.extend(
                BASE64
                    .decode(data)
                    .context("decode selected HAR response body")?,
            ),
            StoredRecord::WebSocketMessage {
                at,
                direction,
                kind,
                data,
                ..
            } => {
                let message_type = if direction.eq_ignore_ascii_case("ingress") {
                    spec::WebSocketMessageType::Send
                } else {
                    spec::WebSocketMessageType::Receive
                };
                let timestamp = at
                    .parse::<jiff::Timestamp>()
                    .context("parse captured WebSocket message timestamp")?;
                let seconds = timestamp.as_millisecond() as f64 / 1_000.0;
                let message = match kind.as_str() {
                    "text" => Some(spec::WebSocketMessage::text(
                        message_type,
                        seconds,
                        String::from_utf8(
                            BASE64
                                .decode(data)
                                .context("decode selected HAR WebSocket text")?,
                        )
                        .context("decode selected HAR WebSocket UTF-8")?,
                    )),
                    "binary" => Some(spec::WebSocketMessage::new(
                        message_type,
                        seconds,
                        spec::WebSocketMessageOpcode::BINARY,
                        data,
                    )),
                    _ => None,
                };
                web_socket_messages.extend(message);
            }
            _ => {}
        }
    }

    let (method, mut url, request_version, request_headers) =
        request_head.context("captured request head missing for HAR export")?;
    if url.starts_with('/') {
        url = format!(
            "{}://{}{}",
            details.summary.protocol, details.summary.endpoint, url
        );
    }
    let request_version = captured_http_version(&request_version)?;
    let mut request_builder = rama_http::Request::builder()
        .method(
            method
                .parse::<rama_http::Method>()
                .context("parse selected HAR request method")?,
        )
        .uri(url)
        .version(request_version);
    for (name, value) in request_headers {
        request_builder = request_builder.header(name, captured_header_value(&value)?);
    }
    let (request_parts, ()) = request_builder
        .body(())
        .context("build selected HAR request")?
        .into_parts();
    let mut request = spec::Request::from_http_request_parts(&request_parts, &request_body, false)?;

    let web_socket = matches!(details.summary.protocol.as_str(), "ws" | "wss");
    let request_size = if web_socket {
        request_body.len() as u64
    } else {
        details.summary.request_bytes
    };
    request.body_size = byte_count(request_size);
    if details.summary.request_truncated && !web_socket {
        request.comment = Some("Body truncated by the inspector capture limit".into());
    }

    let response = match response_head {
        Some((status, version, headers)) => {
            let mut response_builder = rama_http::Response::builder()
                .status(status)
                .version(captured_http_version(&version)?);
            for (name, value) in headers {
                response_builder = response_builder.header(name, captured_header_value(&value)?);
            }
            let (response_parts, ()) = response_builder
                .body(())
                .context("build selected HAR response")?
                .into_parts();
            let mut response =
                spec::Response::from_http_response_parts(&response_parts, &response_body, false)?;
            let response_size = if web_socket {
                response_body.len() as u64
            } else {
                details.summary.response_bytes
            };
            response.body_size = byte_count(response_size);
            response.content.size = byte_count(response_size);
            if details.summary.response_truncated && !web_socket {
                response.comment = Some("Body truncated by the inspector capture limit".into());
            }
            response
        }
        None => spec::Response {
            status: 0,
            status_text: None,
            http_version: request_version.into(),
            cookies: Vec::new(),
            headers: Vec::new(),
            content: spec::Content {
                size: 0,
                compression: None,
                mime_type: None,
                text: None,
                encoding: None,
                comment: None,
            },
            redirect_url: None,
            headers_size: -1,
            body_size: -1,
            comment: Some("No response had been captured when this HAR was exported".into()),
        },
    };

    let started = details.summary.started_at;
    let response_started = details.summary.response_started_at;
    let completed = details.summary.completed_at.unwrap_or_else(|| {
        if details.summary.active {
            jiff::Timestamp::now()
        } else {
            response_started.unwrap_or(started)
        }
    });
    let wait = response_started
        .map(|response_started| elapsed_millis(started, response_started))
        .unwrap_or_else(|| elapsed_millis(started, completed));
    let receive = response_started
        .map(|response_started| elapsed_millis(response_started, completed))
        .unwrap_or_default();

    Ok(spec::Entry {
        page_ref: None,
        started_date_time: started,
        time: wait.saturating_add(receive),
        request,
        response,
        cache: spec::Cache::default(),
        timings: spec::Timings {
            wait,
            receive,
            ..Default::default()
        },
        server_ip_address: details
            .summary
            .egress_peer_address
            .as_deref()
            .and_then(|address| address.parse::<SocketAddr>().ok())
            .map(|address| address.ip()),
        connection: (details.summary.connection_display_id != 0)
            .then(|| details.summary.connection_display_id.to_string().into()),
        comment: Some(format!("Rama Proxy Inspector request #{}", details.summary.id).into()),
        resource_type: web_socket.then(|| "websocket".into()),
        web_socket_messages: web_socket.then_some(web_socket_messages),
    })
}

fn elapsed_millis(start: jiff::Timestamp, end: jiff::Timestamp) -> i64 {
    end.as_millisecond()
        .saturating_sub(start.as_millisecond())
        .max(0)
}

fn byte_count(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captured_har_time_and_size_conversions_are_bounded() {
        let start = "2026-08-23T12:00:00Z".parse().unwrap();
        let end = "2026-08-23T12:00:00.125Z".parse().unwrap();

        assert_eq!(elapsed_millis(start, end), 125);
        assert_eq!(elapsed_millis(end, start), 0);
        assert_eq!(byte_count(42), 42);
        assert_eq!(byte_count(u64::MAX), i64::MAX);
    }

    #[test]
    fn captured_har_entry_preserves_observed_timing_and_byte_totals() {
        let entry = captured_har_entry(CaptureDetails {
            summary: crate::http::capture::ExchangeSummary {
                decision: None,
                id: 7,
                connection_id: 11,
                connection_display_id: 3,
                started_at: "2026-08-23T12:00:00Z".parse().unwrap(),
                method: "POST".to_owned(),
                http_version: "HTTP/1.1".to_owned(),
                url: "https://example.test/upload".to_owned(),
                endpoint: "example.test".to_owned(),
                protocol: "https".to_owned(),
                ingress_local_address: None,
                ingress_peer_address: None,
                user_agent: None,
                user_agent_kind: None,
                status: Some(201),
                active: false,
                response_started_at: Some("2026-08-23T12:00:00.125Z".parse().unwrap()),
                completed_at: Some("2026-08-23T12:00:00.375Z".parse().unwrap()),
                egress_local_address: None,
                egress_peer_address: None,
                request_bytes: 42,
                response_bytes: 84,
                request_truncated: false,
                response_truncated: false,
                ja3: None,
                ja4: None,
                peetprint: None,
                ja4h: None,
                akamai_h2: None,
                known_fingerprint: None,
                has_emulation_profile: false,
            },
            records: vec![
                StoredRecord::RequestHead {
                    method: "POST".to_owned(),
                    url: "https://example.test/upload".to_owned(),
                    version: "HTTP/1.1".to_owned(),
                    headers: vec![(
                        "content-type".to_owned(),
                        "application/x-www-form-urlencoded".to_owned(),
                    )],
                    emulation_profile: None,
                    tls_client_hello: None,
                    ingress_tls: None,
                },
                StoredRecord::RequestBody {
                    data: BASE64.encode(b"a=b&c=hello+world"),
                },
                StoredRecord::ResponseHead {
                    status: 201,
                    version: "HTTP/1.1".to_owned(),
                    headers: Vec::new(),
                    egress_tls: None,
                },
            ],
        })
        .unwrap();

        assert_eq!(entry.time, 375);
        assert_eq!(entry.timings.send, 0);
        assert_eq!(entry.timings.wait, 125);
        assert_eq!(entry.timings.receive, 250);
        assert_eq!(entry.request.body_size, 42);
        let params = entry.request.post_data.unwrap().params.unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "a");
        assert_eq!(params[0].value.as_deref(), Some("b"));
        assert_eq!(params[1].name, "c");
        assert_eq!(params[1].value.as_deref(), Some("hello world"));
        assert_eq!(entry.response.body_size, 84);
        assert_eq!(entry.response.content.size, 84);
    }
}
