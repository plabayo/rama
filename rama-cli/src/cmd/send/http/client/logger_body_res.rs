use rama::{
    Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
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

use super::writer::Writer;
use crate::cmd::send::http::{
    DiscardedResponse,
    feed::{self, FeedKind, FeedTuiCandidate},
};

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
        let discard = req.extensions().contains::<DiscardedResponse>();
        let res = self.inner.serve(req).await.into_box_error()?;

        let (parts, body) = res.into_parts();

        // A feed bound for an interactive terminal must reach the reader
        // unconsumed — don't write it, just tag it and pass the body through.
        if !discard
            && self.feed_tui
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
        if discard || self.json_selectors.is_empty() {
            let mut stream = std::pin::pin!(body.into_data_stream());
            while let Some(chunk) = stream.next().await {
                let chunk = chunk
                    .map_err(Into::into)
                    .context("read response body chunk")?;
                if !discard {
                    self.writer
                        .write_chunk(&chunk)
                        .await
                        .context("write response body chunk")?;
                }
            }
            if !discard {
                self.writer.flush().await.context("flush response body")?;
            }
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
    use super::super::writer;
    use super::*;
    use crate::{Cli, CliCommands};
    use clap::Parser as _;
    use rama::{bytes::Bytes, futures::stream, service::service_fn, utils::fs::tempdir};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn path(s: &str) -> JsonPath {
        s.parse().expect("valid JSONPath")
    }

    #[tokio::test]
    async fn warmup_bodies_are_drained_without_output_json_selection_or_feed_rendering() {
        for (select_json, feed_tui) in [(false, false), (true, false), (false, true)] {
            let directory = tempdir().unwrap();
            let output = directory.path().join("response");
            let parsed = Cli::try_parse_from([
                "rama",
                "send",
                "--output",
                output.to_str().unwrap(),
                "https://example.test/",
            ])
            .unwrap();
            let Some(CliCommands::Send(config)) = parsed.cmds else {
                panic!("send command")
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let drained = Arc::new(AtomicBool::new(false));
            let completed = drained.clone();
            let inner = service_fn(move |_request: Request| {
                let warm = calls.fetch_add(1, Ordering::Relaxed) < 2;
                let completed = completed.clone();
                async move {
                    let body = if warm {
                        // Reading both chunks is insufficient: require the terminal EOF too.
                        Body::from_stream(stream::unfold(0, move |index| {
                            let completed = completed.clone();
                            async move {
                                let bytes = match index {
                                    0 => Bytes::from_static(b"warmup bytes "),
                                    1 => Bytes::from_static(b"are not JSON or a feed"),
                                    _ => {
                                        completed.store(true, Ordering::Relaxed);
                                        return None;
                                    }
                                };
                                Some((Ok::<_, BoxError>(bytes), index + 1))
                            }
                        }))
                    } else {
                        Body::from(r#"{"value":"main"}"#)
                    };
                    let mut response = Response::new(body);
                    if warm && feed_tui {
                        response
                            .headers_mut()
                            .insert("content-type", "application/rss+xml".parse().unwrap());
                    }
                    Ok::<_, BoxError>(response)
                }
            });
            let service = ResponseBodyLogger {
                inner,
                writer: writer::try_new(&config).await.unwrap(),
                feed_tui,
                json_selectors: if select_json {
                    vec![path("$.value")].into()
                } else {
                    Arc::default()
                },
            };
            for _ in 0..2 {
                drained.store(false, Ordering::Relaxed);
                let warmup = Request::new(Body::empty());
                warmup.extensions().insert(DiscardedResponse);
                let response = service.serve(warmup).await.unwrap();
                assert!(
                    drained.load(Ordering::Relaxed),
                    "warmup must reach response EOF"
                );
                assert_eq!(response.body().size_hint().exact(), Some(0));
                assert!(tokio::fs::read(&output).await.unwrap().is_empty());
            }
            service.serve(Request::new(Body::empty())).await.unwrap();
            let expected = if select_json {
                b"\"main\"\n".as_slice()
            } else {
                br#"{"value":"main"}"#.as_slice()
            };
            assert_eq!(tokio::fs::read(&output).await.unwrap(), expected);
        }
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
