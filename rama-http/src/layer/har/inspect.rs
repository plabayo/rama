//! Convert captured observations into HAR entries, independently of the export destination.
use crate::inspect::capture::{CaptureDetails, StoredRecord};
use crate::layer::har::spec;
use rama_core::error::{BoxError, ErrorContext as _};
use rama_net::stream::SocketInfo;

/// Reconstruct a HAR entry from recorded traffic, preserving observed timings,
/// byte counters. Protocol adapters can attach their own HAR extensions. No filesystem or GUI state is required.
pub fn captured_har_entry(details: CaptureDetails) -> Result<spec::Entry, BoxError> {
    let mut request_head = None;
    let mut response_head = None;
    let mut request_body = Vec::new();
    let mut response_body = Vec::new();
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
            StoredRecord::RequestBody { data } => request_body.extend_from_slice(&data),
            StoredRecord::ResponseHead {
                status,
                version,
                headers,
                ..
            } => response_head = Some((status, version, headers)),
            StoredRecord::ResponseBody { data } => response_body.extend_from_slice(&data),
            _ => {}
        }
    }

    let (method, mut url, request_version, request_headers) =
        request_head.context("captured request head missing for HAR export")?;
    if url.scheme().is_none() && url.authority().is_none() {
        url = url
            .with_scheme(details.summary.protocol.clone())
            .with_authority(
                details
                    .summary
                    .endpoint
                    .clone()
                    .context("captured request authority missing")?,
            );
    }
    let mut captured_request = crate::Request::builder()
        .method(method)
        .uri(url)
        .version(request_version)
        .body(())?;
    *captured_request.headers_mut() = request_headers;
    let (request_parts, ()) = captured_request.into_parts();
    let mut request = spec::Request::from_http_request_parts(&request_parts, &request_body, false)?;

    let upgraded = response_head.as_ref().is_some_and(|(status, _, _)| {
        *status == crate::StatusCode::SWITCHING_PROTOCOLS
            || (request_version == crate::Version::HTTP_2
                && request_parts.method == crate::Method::CONNECT
                && status.is_success())
    });
    let request_size = if upgraded {
        request_body.len() as u64
    } else {
        details.summary.request_bytes
    };
    request.body_size = byte_count(request_size);
    if details.summary.request_truncated && !upgraded {
        request.comment = Some("Body truncated by the inspector capture limit".into());
    }

    let response = match response_head {
        Some((status, version, headers)) => {
            let mut captured_response = crate::Response::builder()
                .status(status)
                .version(version)
                .body(())?;
            *captured_response.headers_mut() = headers;
            let (response_parts, ()) = captured_response.into_parts();
            let mut response =
                spec::Response::from_http_response_parts(&response_parts, &response_body, false)?;
            let response_size = if upgraded {
                response_body.len() as u64
            } else {
                details.summary.response_bytes
            };
            response.body_size = byte_count(response_size);
            response.content.size = byte_count(response_size);
            if details.summary.response_truncated && !upgraded {
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
            .metadata
            .upstream
            .get_ref::<SocketInfo>()
            .map(|socket| socket.peer_addr().ip_addr),
        connection: (details.summary.connection_display_id != 0)
            .then(|| details.summary.connection_display_id.to_string().into()),
        comment: Some(format!("Rama Proxy Inspector request #{}", details.summary.id).into()),
        resource_type: None,
        web_socket_messages: None,
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

    #[tokio::test]
    async fn captured_har_entry_preserves_observed_timing_and_byte_totals() {
        use crate::inspect::capture::{CaptureConfig, CaptureHttpLayer, CaptureStore};
        use crate::{Body, Request, Response, body::util::BodyExt};
        use rama_core::{Layer, Service, service::service_fn};
        let store = CaptureStore::with_storage(
            rama_inspect::storage::Storage::new(rama_inspect::storage::MemoryStore::new(
                Default::default(),
            )),
            CaptureConfig::default(),
            Default::default(),
        );
        let service = CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(
            async |request: Request| {
                request.into_body().collect().await.unwrap();
                Ok::<_, std::convert::Infallible>(
                    Response::builder().status(201).body(Body::empty()).unwrap(),
                )
            },
        ));
        service
            .serve(
                Request::builder()
                    .method("POST")
                    .uri("https://example.test/upload")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("a=b&c=hello+world"))
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        let mut details = store.details(1).await.unwrap();
        details.summary.started_at = "2026-08-23T12:00:00Z".parse().unwrap();
        details.summary.response_started_at = Some("2026-08-23T12:00:00.125Z".parse().unwrap());
        details.summary.completed_at = Some("2026-08-23T12:00:00.375Z".parse().unwrap());
        details.summary.request_bytes = 42;
        details.summary.response_bytes = 84;
        let entry = captured_har_entry(details).unwrap();

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
