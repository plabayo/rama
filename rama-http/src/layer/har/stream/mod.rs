//! Streaming serialization of HAR entries and bodies, independent of inspection.

use rama_core::error::BoxError;
use rama_utils::octets::kib;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader};

use super::spec;
use form::write_params;

mod form;
mod string;
pub use string::write_json_string;
mod writer;
pub use writer::HarObjectWriter;

/// A stable body that can be reopened for encoding detection and serialization.
/// Each reader must yield the same bytes. Implementations can borrow memory or
/// stream from files and other storage; no inspection dependency is required.
pub trait HarBody: Sync {
    fn reader(&self) -> impl AsyncRead + Unpin + Send;
}

impl HarBody for &[u8] {
    fn reader(&self) -> impl AsyncRead + Unpin + Send {
        *self
    }
}

const CHUNK: usize = kib(8);

/// Optional protocol-owned HAR fields, written from typed values with backpressure.
/// `()` adds no fields.
pub trait HarEntryExtension: Sync {
    fn write_fields<W: AsyncWrite + Unpin + Send>(
        &self,
        writer: &mut HarObjectWriter<'_, W>,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;
}

impl HarEntryExtension for () {
    async fn write_fields<W: AsyncWrite + Unpin + Send>(
        &self,
        _: &mut HarObjectWriter<'_, W>,
    ) -> Result<(), BoxError> {
        Ok(())
    }
}

/// Serialize a typed HAR entry with streamed bodies and protocol-owned extensions.
/// Metadata is serialized with Serde; only body fields require incremental JSON
/// escaping. A cancelled write may leave partial output, so stage published files.
pub async fn write_entry<W: AsyncWrite + Unpin + Send>(
    writer: &mut W,
    entry: &spec::Entry,
    request_body: &impl HarBody,
    request_stats: &BodyStats,
    response_body: &impl HarBody,
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
    extension.write_fields(&mut object).await?;
    object.finish().await
}

async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request: &spec::Request,
    body: &impl HarBody,
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
    body: &impl HarBody,
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
    body: &impl HarBody,
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
    body: &impl HarBody,
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

/// Length and encoding detected from a complete pass over a stable body.
#[derive(Debug, Clone, Copy)]
pub struct BodyStats {
    size: u64,
    utf8: bool,
}

impl BodyStats {
    /// Number of bytes observed during the scan.
    pub fn size(self) -> u64 {
        self.size
    }
}

/// Scan without retaining body data, including UTF-8 sequences split across reads.
pub async fn scan(mut reader: impl AsyncRead + Unpin) -> Result<BodyStats, BoxError> {
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

#[cfg(test)]
mod tests;
