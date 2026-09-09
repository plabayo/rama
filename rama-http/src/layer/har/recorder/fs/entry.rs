//! File-backed sources for the shared streaming HAR serializer.

use jiff::Timestamp;
use rama_core::{
    combinators::Either,
    error::{BoxError, ErrorContext as _},
    telemetry::tracing,
};
use rama_utils::fs::{TempPath, TempPathCleanup, safe_open};
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};

use crate::{
    layer::har::{
        spec,
        stream::{HarBody, HarEntryExtension, HarObjectWriter, scan, write_entry},
    },
    mime::Mime,
};

use super::{BodyArtifact, WebSocketArtifact, create_temp_file};

struct ArtifactBody<'a>(Option<&'a TempPath>);

impl HarBody for ArtifactBody<'_> {
    async fn reader(&self) -> Result<impl AsyncRead + Unpin + Send, BoxError> {
        match self.0 {
            Some(path) => Ok(Either::A(
                safe_open(path).await.context("open HAR body artifact")?,
            )),
            None => Ok(Either::B(tokio::io::empty())),
        }
    }
}

impl HarEntryExtension for Option<WebSocketArtifact> {
    async fn write_fields<W: AsyncWrite + Unpin + Send>(
        &self,
        writer: &mut HarObjectWriter<'_, W>,
    ) -> Result<(), BoxError> {
        if let Some(messages) = self {
            let mut file = BufReader::new(
                safe_open(&messages.path)
                    .await
                    .context("open WebSocket HAR artifact")?,
            );
            let writer = writer.streamed_field("_webSocketMessages").await?;
            writer.write_all(b"[").await?;
            tokio::io::copy(&mut file, writer)
                .await
                .context("copy WebSocket HAR messages")?;
            writer.write_all(b"]").await?;
        }
        Ok(())
    }
}

#[expect(clippy::too_many_arguments)]
pub(super) async fn build_entry_artifact(
    dir: PathBuf,
    started_date_time: Timestamp,
    elapsed_time: i64,
    mut request: spec::Request,
    request_mime_type: Option<Mime>,
    request_body: BodyArtifact,
    response: Option<(spec::Response, BodyArtifact)>,
    web_socket: Option<WebSocketArtifact>,
    temp_cleanup: TempPathCleanup,
) -> Result<TempPath, BoxError> {
    request.body_size = request_body.size;
    request.post_data = (request_body.size > 0).then(|| spec::PostData {
        mime_type: request_mime_type,
        params: None,
        text: None,
        comment: None,
    });

    let (response, response_body) = match response {
        Some((mut response, body)) => {
            response.body_size = body.size;
            response.content.size = body.size;
            response.content.text = None;
            response.content.encoding = None;
            (response, Some(body))
        }
        None => (
            spec::Response {
                status: 0,
                status_text: Some("".into()),
                http_version: request.http_version.clone(),
                cookies: Vec::new(),
                headers: Vec::new(),
                content: spec::Content {
                    size: 0,
                    compression: None,
                    mime_type: Some(crate::mime::APPLICATION_OCTET_STREAM),
                    text: None,
                    encoding: None,
                    comment: None,
                },
                redirect_url: Some("".into()),
                headers_size: -1,
                body_size: -1,
                comment: None,
            },
            None,
        ),
    };

    let entry = spec::Entry {
        page_ref: None,
        started_date_time,
        time: elapsed_time,
        request,
        response,
        cache: spec::Cache::default(),
        timings: spec::Timings::default(),
        server_ip_address: None,
        connection: None,
        comment: None,
        resource_type: web_socket.as_ref().map(|_| "websocket".into()),
        web_socket_messages: None,
    };

    let request_source = ArtifactBody(Some(&request_body.path));
    let response_source = ArtifactBody(response_body.as_ref().map(|body| &body.path));
    let request_stats = scan(request_source.reader().await?).await?;
    let response_stats = scan(response_source.reader().await?).await?;
    let (path, file) = create_temp_file(dir, "entry", temp_cleanup)
        .await
        .context("create private HAR entry artifact")?;
    // Buffer the serializer's small field writes; bodies remain streamed. Drop
    // the file before its path guard, including on cancellation and errors.
    let mut file = BufWriter::new(file);
    write_entry(
        &mut file,
        &entry,
        &request_source,
        &request_stats,
        &response_source,
        &response_stats,
        &web_socket,
    )
    .await?;
    file.flush().await.context("flush HAR entry artifact")?;
    tracing::trace!(
        request_outcome = ?request_body.outcome,
        response_outcome = ?response_body.as_ref().map(|body| body.outcome),
        "completed streaming HAR entry artifact"
    );
    Ok(path)
}
