use super::{HarObjectWriter, entry_metadata, form::write_params, spec};
use crate::{
    headers::{ContentType, HeaderMapExt},
    inspect::capture::{CapturedBody, CapturedBodySource, ExchangeCapture, StoredRecord},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rama_core::error::BoxError;
use rama_utils::octets::kib;
use std::future::Future;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

const CHUNK: usize = kib(8);

/// Optional protocol-owned HAR fields, written from typed values with backpressure.
/// `()` adds no fields.
pub trait HarEntryExtension: Sync {
    fn write_fields<W: AsyncWrite + Unpin + Send>(
        &self,
        writer: &mut HarObjectWriter<'_, W>,
        capture: &ExchangeCapture,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;
}
impl HarEntryExtension for () {
    async fn write_fields<W: AsyncWrite + Unpin + Send>(
        &self,
        _: &mut HarObjectWriter<'_, W>,
        _: &ExchangeCapture,
    ) -> Result<(), BoxError> {
        Ok(())
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
            StoredRecord::RequestHead { headers, .. } => Some(headers),
            StoredRecord::Interception {
                direction,
                forwarded_headers: Some(headers),
                ..
            } if direction == "request" => Some(headers),
            _ => None,
        });
    let mime = request_headers
        .and_then(|headers| headers.typed_get::<ContentType>())
        .map(ContentType::into_mime);
    let form = mime
        .as_ref()
        .is_some_and(|mime| mime.subtype() == crate::mime::WWW_FORM_URLENCODED);
    let mut entry = entry_metadata(details, request_stats.size, response_stats.size)?;
    if request_stats.size > 0 {
        entry.request.post_data = Some(spec::PostData {
            mime_type: mime,
            params: form.then(Vec::new),
            text: None,
            comment: None,
        });
    }
    write_entry(
        writer,
        &entry,
        capture,
        &request,
        &request_stats,
        &response,
        &response_stats,
        extension,
    )
    .await
}

#[expect(clippy::too_many_arguments)]
async fn write_entry<W: AsyncWrite + Unpin + Send>(
    writer: &mut W,
    entry: &spec::Entry,
    capture: &ExchangeCapture,
    request_body: &CapturedBodySource,
    request_stats: &BodyStats,
    response_body: &CapturedBodySource,
    response_stats: &BodyStats,
    extension: &impl HarEntryExtension,
) -> Result<(), BoxError> {
    let spec::Entry {
        page_ref,
        started_date_time,
        time,
        request,
        response,
        cache,
        timings,
        server_ip_address,
        connection,
        comment,
        resource_type,
        web_socket_messages,
    } = entry;
    let mut object = HarObjectWriter::begin(writer).await?;
    object.field("pageref", page_ref).await?;
    object.field("startedDateTime", started_date_time).await?;
    object.field("time", time).await?;
    write_request(
        object.streamed_field("request").await?,
        request,
        request_body,
        request_stats,
    )
    .await?;
    write_response(
        object.streamed_field("response").await?,
        response,
        response_body,
        response_stats,
    )
    .await?;
    object.field("cache", cache).await?;
    object.field("timings", timings).await?;
    object.field("serverIPAddress", server_ip_address).await?;
    object.field("connection", connection).await?;
    object.field("comment", comment).await?;
    if let Some(resource_type) = resource_type {
        object.field("_resourceType", resource_type).await?;
    }
    if let Some(messages) = web_socket_messages {
        object.array("_webSocketMessages", messages).await?;
    }
    extension.write_fields(&mut object, capture).await?;
    object.finish().await
}
async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request: &spec::Request,
    body: &CapturedBodySource,
    stats: &BodyStats,
) -> Result<(), BoxError> {
    let spec::Request {
        method,
        url,
        http_version,
        cookies,
        headers,
        query_string,
        post_data,
        headers_size,
        body_size,
        comment,
    } = request;
    let mut object = HarObjectWriter::begin(writer).await?;
    object.field("method", method).await?;
    object.field("url", url).await?;
    object.field("httpVersion", http_version).await?;
    object.array("cookies", cookies).await?;
    object.array("headers", headers).await?;
    object.array("queryString", query_string).await?;
    if let Some(post_data) = post_data {
        write_post_data(
            object.streamed_field("postData").await?,
            post_data,
            body,
            stats,
        )
        .await?;
    } else {
        object.field("postData", &post_data).await?;
    }
    object.field("headersSize", headers_size).await?;
    object.field("bodySize", body_size).await?;
    object.field("comment", comment).await?;
    object.finish().await
}
async fn write_post_data<W: AsyncWrite + Unpin>(
    writer: &mut W,
    post: &spec::PostData,
    body: &CapturedBodySource,
    stats: &BodyStats,
) -> Result<(), BoxError> {
    let spec::PostData {
        mime_type,
        params,
        text,
        comment,
    } = post;
    let mut object = HarObjectWriter::begin(writer).await?;
    object
        .field(
            "mimeType",
            &mime_type.as_ref().map(crate::mime::Mime::as_ref),
        )
        .await?;
    if params.is_some() {
        write_params(
            object.streamed_field("params").await?,
            BufReader::new(body.reader()),
        )
        .await?;
    } else {
        object.field("params", params).await?;
    }
    if stats.size > 0 {
        write_json_string(
            object.streamed_field("text").await?,
            body.reader(),
            stats.utf8,
        )
        .await?;
    } else {
        object.field("text", text).await?;
    }
    object.field("comment", comment).await?;
    object.finish().await
}
async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &spec::Response,
    body: &CapturedBodySource,
    stats: &BodyStats,
) -> Result<(), BoxError> {
    let spec::Response {
        status,
        status_text,
        http_version,
        cookies,
        headers,
        content,
        redirect_url,
        headers_size,
        body_size,
        comment,
    } = response;
    let mut object = HarObjectWriter::begin(writer).await?;
    object.field("status", status).await?;
    object.field("statusText", status_text).await?;
    object.field("httpVersion", http_version).await?;
    object.array("cookies", cookies).await?;
    object.array("headers", headers).await?;
    write_content(
        object.streamed_field("content").await?,
        content,
        body,
        stats,
    )
    .await?;
    object.field("redirectURL", redirect_url).await?;
    object.field("headersSize", headers_size).await?;
    object.field("bodySize", body_size).await?;
    object.field("comment", comment).await?;
    object.finish().await
}
async fn write_content<W: AsyncWrite + Unpin>(
    writer: &mut W,
    content: &spec::Content,
    body: &CapturedBodySource,
    stats: &BodyStats,
) -> Result<(), BoxError> {
    let spec::Content {
        size,
        compression,
        mime_type,
        text,
        encoding,
        comment,
    } = content;
    let mut object = HarObjectWriter::begin(writer).await?;
    object.field("size", size).await?;
    object.field("compression", compression).await?;
    object
        .field(
            "mimeType",
            &mime_type.as_ref().map(crate::mime::Mime::as_ref),
        )
        .await?;
    if stats.size > 0 {
        write_json_string(
            object.streamed_field("text").await?,
            body.reader(),
            stats.utf8,
        )
        .await?;
    } else {
        object.field("text", text).await?;
    }
    if stats.size > 0 && !stats.utf8 {
        object.field("encoding", "base64").await?;
    } else {
        object.field("encoding", encoding).await?;
    }
    object.field("comment", comment).await?;
    object.finish().await
}

struct BodyStats {
    size: u64,
    utf8: bool,
}
async fn scan(mut reader: impl AsyncRead + Unpin) -> Result<BodyStats, BoxError> {
    let mut stats = BodyStats {
        size: 0,
        utf8: true,
    };
    let mut buffer = [0; CHUNK + 3];
    let mut pending = 0;
    loop {
        let read = reader.read(&mut buffer[pending..CHUNK]).await?;
        if read == 0 {
            stats.utf8 &= pending == 0;
            return Ok(stats);
        }
        stats.size = stats.size.saturating_add(read as u64);
        let end = pending + read;
        pending = 0;
        if stats.utf8
            && let Err(error) = std::str::from_utf8(&buffer[..end])
        {
            if error.error_len().is_some() {
                stats.utf8 = false;
            } else {
                pending = end - error.valid_up_to();
                buffer.copy_within(error.valid_up_to()..end, 0);
            }
        }
    }
}

/// Stream one JSON string, escaping UTF-8 or encoding binary without a body-sized buffer.
pub async fn write_json_string<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut reader: impl AsyncRead + Unpin,
    utf8: bool,
) -> Result<(), BoxError> {
    writer.write_all(b"\"").await?;
    let mut buffer = [0; CHUNK + 3];
    // Allocate the reusable encoding buffer only for binary content. Keeping
    // it off the future also avoids inflating every caller's async state.
    let mut encoded = if utf8 {
        Vec::new()
    } else {
        vec![0; (CHUNK + 3).div_ceil(3) * 4]
    };
    let mut pending = 0;
    loop {
        let read = reader.read(&mut buffer[pending..CHUNK]).await?;
        let end = pending + read;
        if utf8 {
            let valid = match std::str::from_utf8(&buffer[..end]) {
                Ok(fragment) => {
                    escaped(writer, fragment).await?;
                    end
                }
                Err(error) if error.error_len().is_none() && read != 0 => {
                    escaped(writer, std::str::from_utf8(&buffer[..error.valid_up_to()])?).await?;
                    error.valid_up_to()
                }
                Err(error) => return Err(error.into()),
            };
            pending = end - valid;
            buffer.copy_within(valid..end, 0);
        } else {
            let complete = if read == 0 { end } else { end / 3 * 3 };
            let count = STANDARD.encode_slice(&buffer[..complete], &mut encoded)?;
            writer.write_all(&encoded[..count]).await?;
            pending = end - complete;
            buffer.copy_within(complete..end, 0);
        }
        if read == 0 {
            break;
        }
    }
    writer.write_all(b"\"").await?;
    Ok(())
}
pub(super) async fn escaped<W: AsyncWrite + Unpin>(
    writer: &mut W,
    text: &str,
) -> Result<(), BoxError> {
    let mut start = 0;
    for (index, byte) in text.bytes().enumerate() {
        if byte < 0x20 || byte == b'"' || byte == b'\\' {
            writer.write_all(&text.as_bytes()[start..index]).await?;
            match byte {
                b'"' => writer.write_all(b"\\\"").await?,
                b'\\' => writer.write_all(b"\\\\").await?,
                _ => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    writer
                        .write_all(&[
                            b'\\',
                            b'u',
                            b'0',
                            b'0',
                            HEX[usize::from(byte >> 4)],
                            HEX[usize::from(byte & 15)],
                        ])
                        .await?;
                }
            }
            start = index + 1;
        }
    }
    writer.write_all(&text.as_bytes()[start..]).await?;
    Ok(())
}
