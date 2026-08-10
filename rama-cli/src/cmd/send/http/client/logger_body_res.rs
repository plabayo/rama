use rama::{
    Service,
    error::{BoxError, ErrorContext},
    futures::StreamExt as _,
    http::{Body, Request, Response, StreamingBody, body::util::BodyExt},
    json::{
        JsonError,
        capture::{CaptureHandler, CaptureResult, CapturedValue, JsonCapturer},
        path::JsonPath,
    },
    utils::octets::mib,
};

use std::sync::Arc;

use super::super::feed::{self, FeedKind, FeedTuiCandidate};
use super::writer::Writer;

const SELECT_JSON_MAX_CAPTURE_BYTES: usize = mib(8);

#[derive(Debug, Clone)]
pub(super) struct ResponseBodyLogger<S> {
    pub(super) inner: S,
    pub(super) writer: Writer,
    /// When set, feed responses are passed through unwritten (tagged with
    /// [`FeedTuiCandidate`]) so the caller can render them in the reader.
    pub(super) feed_tui: bool,
    pub(super) json_selectors: Arc<[JsonPath]>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseBodyLogger<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError> + Send + Sync + 'static>
        + Send
        + 'static,
{
    type Error = BoxError;
    type Output = Response;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(req).await.into_box_error()?;

        let (parts, body) = res.into_parts();

        // A feed bound for an interactive terminal must reach the reader
        // unconsumed — don't write it, just tag it and pass the body through.
        if self.feed_tui
            && let Some(kind) = feed::feed_kind(&parts.headers)
        {
            parts.extensions.insert(FeedTuiCandidate {
                generic: kind == FeedKind::GenericXml,
            });
            let res = Response::from_parts(parts, Body::from_stream(body.into_data_stream()));
            return Ok(res);
        }

        // No JSON selection: stream the body straight to the writer in
        // constant memory. This is the large-download / `file://` path,
        // whose body must not be buffered whole.
        if self.json_selectors.is_empty() {
            let mut stream = std::pin::pin!(body.into_data_stream());
            while let Some(chunk) = stream.next().await {
                let chunk = chunk
                    .map_err(Into::into)
                    .context("read response body chunk")?;
                self.writer
                    .write_chunk(&chunk)
                    .await
                    .context("write response body chunk")?;
            }
            self.writer.flush().await.context("flush response body")?;
            // the caller only inspects status/headers here; the body was
            // already written, so hand back an empty one
            return Ok(Response::from_parts(parts, Body::empty()));
        }

        // JSON selection needs the whole body materialized to capture from.
        let bytes = body
            .collect()
            .await
            .context("collect res body as bytes")?
            .to_bytes();
        let selected = select_json_response_bytes(bytes.as_ref(), &self.json_selectors)
            .context("select JSON response bytes")?;
        self.writer
            .write_bytes(&selected)
            .await
            .context("write response bytes")?;

        Ok(Response::from_parts(parts, bytes.into()))
    }
}

fn select_json_response_bytes(input: &[u8], selectors: &[JsonPath]) -> Result<Vec<u8>, JsonError> {
    let mut capturer = JsonCapturer::new(
        selectors.iter().cloned(),
        SELECT_JSON_MAX_CAPTURE_BYTES,
        SelectedJson::default(),
    );
    capturer.write(input)?;
    capturer.end()?;
    Ok(capturer.into_handler().out)
}

#[derive(Debug, Default)]
struct SelectedJson {
    out: Vec<u8>,
}

impl CaptureHandler for SelectedJson {
    fn handle_capture(&mut self, value: CapturedValue<'_>) -> CaptureResult {
        self.out.extend_from_slice(value.as_raw_bytes());
        self.out.push(b'\n');
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(s: &str) -> JsonPath {
        s.parse().expect("valid JSONPath")
    }

    #[test]
    fn select_json_response_outputs_matches_as_lines() {
        let out = select_json_response_bytes(
            br#"{"users":[{"name":"Ada"},{"name":"Grace"}],"meta":{"count":2}}"#,
            &[path("$..name"), path("$.meta")],
        )
        .unwrap();

        assert_eq!(
            out,
            br#""Ada"
"Grace"
{"count":2}
"#
        );
    }

    #[test]
    fn select_json_response_outputs_empty_when_no_match() {
        let out = select_json_response_bytes(br#"{"name":"Ada"}"#, &[path("$.missing")]).unwrap();
        assert!(out.is_empty());
    }
}
