//! Convert captured observations into HAR entries, independently of the export destination.

use rama_core::error::{BoxError, ErrorContext as _};
use rama_inspect::Direction;
use rama_net::stream::SocketInfo;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    Method, StatusCode, Version,
    headers::{ContentType, HeaderMapExt},
    inspect::capture::{
        CaptureDetails, CapturedBody, CapturedBodySource, ExchangeCapture, StoredRecord,
    },
    layer::har::{
        spec,
        stream::{HarBody, HarEntryExtension, scan, write_entry},
    },
    request::Parts as RequestParts,
    response::Parts as ResponseParts,
};

impl HarBody for CapturedBodySource {
    async fn reader(&self) -> Result<impl AsyncRead + Unpin + Send, BoxError> {
        Ok(self.reader())
    }
}

/// Write one HAR entry directly to an asynchronous destination. Body memory is
/// bounded independently of capture size. A first pass determines UTF-8 encoding;
/// the second streams the same pinned record prefix. Cancellation may leave a
/// partial entry in the destination; callers publishing files should stage them.
pub async fn write_captured_har_entry<W: AsyncWrite + Unpin + Send>(
    writer: &mut W,
    capture: &ExchangeCapture,
    extension: &impl HarEntryExtension,
) -> Result<(), BoxError> {
    let details = capture.inspector_details().await?;
    let request = capture.body_source(CapturedBody::Request);
    let response = capture.body_source(CapturedBody::Response);
    let request_stats = scan(request.reader()).await?;
    let response_stats = scan(response.reader()).await?;
    let request_headers = details
        .records
        .iter()
        .rev()
        .find_map(|record| match record {
            StoredRecord::RequestHead { headers, .. }
            | StoredRecord::Interception {
                kind: None,
                direction: Direction::Ingress,
                forwarded_headers: Some(headers),
                ..
            } => Some(headers),
            _ => None,
        });
    let mime = request_headers
        .and_then(|headers| headers.typed_get::<ContentType>())
        .map(ContentType::into_mime);
    let mut entry = entry_metadata(details, request_stats.size(), response_stats.size())?;
    if request_stats.size() > 0 {
        entry.request.post_data = Some(spec::PostData {
            mime_type: mime,
            params: None,
            text: None,
            comment: None,
        });
    }
    write_entry(
        writer,
        &entry,
        &request,
        &request_stats,
        &response,
        &response_stats,
        extension,
    )
    .await
}

fn entry_metadata(
    details: CaptureDetails,
    request_size: u64,
    response_size: u64,
) -> Result<spec::Entry, BoxError> {
    let mut request_head = None;
    let mut response_head = None;
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
                kind: None,
                direction: Direction::Ingress,
                forwarded_headers: Some(headers),
                ..
            } => {
                if let Some((_, _, _, current)) = &mut request_head {
                    *current = headers;
                }
            }
            StoredRecord::ResponseHead {
                status,
                version,
                headers,
                ..
            } => response_head = Some((status, version, headers)),
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
    let mut request_parts = RequestParts::default();
    request_parts.method = method;
    request_parts.uri = url;
    request_parts.version = request_version;
    request_parts.headers = request_headers;
    let mut request = spec::Request::from_http_request_parts(&request_parts, &[], false)?;

    let upgraded = response_head.as_ref().is_some_and(|(status, _, _)| {
        *status == StatusCode::SWITCHING_PROTOCOLS
            || (request_version == Version::HTTP_2
                && request_parts.method == Method::CONNECT
                && status.is_success())
    });
    let request_size = if upgraded {
        request_size
    } else {
        details.summary.request_bytes
    };
    request.body_size = byte_count(request_size);
    if details.summary.request_truncated && !upgraded {
        request.comment = Some("Body truncated by the inspector capture limit".into());
    }

    let response = match response_head {
        Some((status, version, headers)) => {
            let mut response_parts = ResponseParts::default();
            response_parts.status = status;
            response_parts.version = version;
            response_parts.headers = headers;
            let mut response =
                spec::Response::from_http_response_parts(&response_parts, &[], false)?;
            let response_size = if upgraded {
                response_size
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
mod tests;
