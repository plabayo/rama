//! Middleware to write Http traffic in std format.
//!
//! Can be useful for cli / debug purposes.
//!
//! Built-in shared writers keep complete messages ordered through one output
//! task. Each message has capacity for one captured frame; a slow or long-lived
//! message therefore applies asynchronous backpressure to later body streams
//! instead of buffering their complete contents in memory. Use a per-message
//! writer when messages must be captured concurrently without sharing that
//! backpressure.

use crate::body::Frame;
use crate::{
    Body, BodyCaptureEvent, Request, Response, StreamingBody,
    body::util::BodyExt as _,
    io::{write_http_request_streaming, write_http_response_streaming},
};
use rama_core::{
    rt::Executor,
    telemetry::tracing::{self, Instrument},
};
use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::mpsc::{Receiver, Sender, UnboundedSender, channel, unbounded_channel},
};

mod file;
#[doc(inline)]
pub use file::PerMessageFileWriter;

mod request;
#[doc(inline)]
pub use request::{DoNotWriteRequest, RequestWriter, RequestWriterLayer, RequestWriterService};

mod response;
#[doc(inline)]
pub use response::{
    DoNotWriteResponse, ResponseWriter, ResponseWriterLayer, ResponseWriterService,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Http writer mode.
pub enum WriterMode {
    /// Print the entire request / response.
    All,
    /// Print only the headers of the request / response.
    Headers,
    /// Print only the body of the request / response.
    Body,
}

/// Resolve a [`WriterMode`] into `(write_headers, write_body)` flags.
pub(super) fn write_headers_body_flags(mode: Option<WriterMode>) -> (bool, bool) {
    match mode {
        Some(WriterMode::All) => (true, true),
        Some(WriterMode::Headers) => (true, false),
        Some(WriterMode::Body) => (false, true),
        None => (false, false),
    }
}

struct CaptureEventBody {
    receiver: Receiver<BodyCaptureEvent>,
    done: bool,
}

impl StreamingBody for CaptureEventBody {
    type Data = rama_core::bytes::Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.receiver).poll_recv(cx) {
            Poll::Ready(Some(BodyCaptureEvent::Frame(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(BodyCaptureEvent::End(outcome))) => {
                match outcome {
                    crate::CaptureOutcome::Complete => {}
                    crate::CaptureOutcome::Error | crate::CaptureOutcome::Aborted => {
                        tracing::warn!(
                            ?outcome,
                            "captured HTTP body ended before normal completion"
                        );
                    }
                }
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Ready(None) => {
                tracing::warn!("captured HTTP body channel closed without a terminal event");
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
}

pub(super) fn capture_body_channel() -> (Sender<BodyCaptureEvent>, Body) {
    // A shared writer serializes complete messages. Retain at most one frame
    // per waiting message and propagate writer backpressure to its live body.
    let (sender, receiver) = channel(1);
    (
        sender,
        Body::new(CaptureEventBody {
            receiver,
            done: false,
        }),
    )
}

/// Drive a bidirectional-writer receive loop: write each request/response to
/// `$writer` (logging any error), emit a `\r\n` separator between messages, and
/// flush when the channel closes. Shared by the unbounded and bounded
/// constructors, which differ only in receiver type and tracing span — both
/// satisfied by passing `$rx` (`recv()` is common to both receivers).
macro_rules! drive_bidirectional_writer {
    ($writer:ident, $rx:ident, $req_headers:ident, $req_body:ident, $res_headers:ident, $res_body:ident) => {{
        while let Some(msg) = $rx.recv().await {
            match msg {
                BidirectionalMessage::Request(req) => {
                    if let Err(err) =
                        write_http_request_streaming(&mut $writer, req, $req_headers, $req_body)
                            .await
                    {
                        tracing::error!("failed to write http request to writer: {err:?}")
                    }
                }
                BidirectionalMessage::Response(res) => {
                    if let Err(err) =
                        write_http_response_streaming(&mut $writer, res, $res_headers, $res_body)
                            .await
                    {
                        tracing::error!("failed to write http response to writer: {err:?}")
                    }
                }
            }
            if let Err(err) = $writer.write_all(b"\r\n").await {
                tracing::error!("failed to write separator to writer: {err:?}")
            }
        }

        if let Err(err) = $writer.flush().await {
            tracing::error!("failed to flush writer: {err:?}")
        }
    }};
}

/// A writer that can write both requests and responses.
#[derive(Clone)]
pub struct BidirectionalWriter<S> {
    sender: S,
}

impl<S> std::fmt::Debug for BidirectionalWriter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BidirectionalWriter")
            .field("sender", &format_args!("{}", std::any::type_name::<S>()))
            .finish()
    }
}

impl BidirectionalWriter<UnboundedSender<BidirectionalMessage>> {
    /// Create a new [`BidirectionalWriter`] with a custom writer gated behind an unbounded sender.
    pub fn unbounded<W>(
        executor: &Executor,
        mut writer: W,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = unbounded_channel();
        let (write_request_headers, write_request_body) = write_headers_body_flags(request_mode);
        let (write_response_headers, write_response_body) = write_headers_body_flags(response_mode);

        executor.spawn_task(async move {
            drive_bidirectional_writer!(
                writer,
                rx,
                write_request_headers,
                write_request_body,
                write_response_headers,
                write_response_body
            );
        });

        Self { sender: tx }
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stdout
    /// over an unbounded channel.
    #[must_use]
    pub fn stdout_unbounded(
        executor: &Executor,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::unbounded(executor, tokio::io::stdout(), request_mode, response_mode)
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stderr
    /// over an unbounded channel.
    #[must_use]
    pub fn stderr_unbounded(
        executor: &Executor,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::unbounded(executor, tokio::io::stderr(), request_mode, response_mode)
    }
}

impl BidirectionalWriter<Sender<BidirectionalMessage>> {
    /// Create a new [`BidirectionalWriter`] with a custom writer gated behind a custom bounded channel.
    pub fn new<W>(
        executor: &Executor,
        mut writer: W,
        buffer: usize,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = channel(buffer);
        let (write_request_headers, write_request_body) = write_headers_body_flags(request_mode);
        let (write_response_headers, write_response_body) = write_headers_body_flags(response_mode);

        let span = tracing::trace_root_span!(
            "TrafficWriter::bidirectional::bounded",
            otel.kind = "consumer",
        );

        executor.spawn_task(
            async move {
                drive_bidirectional_writer!(
                    writer,
                    rx,
                    write_request_headers,
                    write_request_body,
                    write_response_headers,
                    write_response_body
                );
            }
            .instrument(span),
        );

        Self { sender: tx }
    }

    /// Create a new [`BidirectionalWriter`] with a custom writer that only
    /// writes the last request and response received.
    ///
    /// Selected bodies are intentionally buffered in full because output is
    /// deferred until the channel closes. Do not use body-writing modes here
    /// for unbounded or attacker-controlled bodies.
    pub fn last<W>(
        executor: &Executor,
        mut writer: W,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = channel(2);
        let (write_request_headers, write_request_body) = write_headers_body_flags(request_mode);
        let (write_response_headers, write_response_body) = write_headers_body_flags(response_mode);

        let span = tracing::trace_root_span!(
            "TrafficWriter::bidirectional::last",
            otel.kind = "consumer",
        );

        executor.spawn_task(
            async move {
                let mut last_request = None;
                let mut last_response = None;

                while let Some(msg) = rx.recv().await {
                    match msg {
                        BidirectionalMessage::Request(req) => {
                            let (parts, body) = req.into_parts();
                            let body = if write_request_body {
                                match body.collect().await {
                                    Ok(body) => Body::from(body.to_bytes()),
                                    Err(error) => {
                                        tracing::error!(%error, "failed to buffer last request body");
                                        Body::empty()
                                    }
                                }
                            } else {
                                Body::empty()
                            };
                            last_request = Some(Request::from_parts(parts, body));
                        }
                        BidirectionalMessage::Response(res) => {
                            let (parts, body) = res.into_parts();
                            let body = if write_response_body {
                                match body.collect().await {
                                    Ok(body) => Body::from(body.to_bytes()),
                                    Err(error) => {
                                        tracing::error!(%error, "failed to buffer last response body");
                                        Body::empty()
                                    }
                                }
                            } else {
                                Body::empty()
                            };
                            last_response = Some(Response::from_parts(parts, body));
                        }
                    }
                }

                if let Some(req) = last_request {
                    if let Err(err) = write_http_request_streaming(
                        &mut writer,
                        req,
                        write_request_headers,
                        write_request_body,
                    )
                    .await
                    {
                        tracing::error!("failed to write last http request to writer: {err:?}")
                    }
                    if let Err(err) = writer.write_all(b"\r\n").await {
                        tracing::error!("failed to write separator to writer: {err:?}")
                    }
                }

                if let Some(res) = last_response {
                    if let Err(err) = write_http_response_streaming(
                        &mut writer,
                        res,
                        write_response_headers,
                        write_response_body,
                    )
                    .await
                    {
                        tracing::error!("failed to write last http response to writer: {err:?}")
                    }
                    if let Err(err) = writer.write_all(b"\r\n").await {
                        tracing::error!("failed to write separator to writer: {err:?}")
                    }
                }

                if let Err(err) = writer.flush().await {
                    tracing::error!("failed to flush writer: {err:?}")
                }
            }
            .instrument(span),
        );

        Self { sender: tx }
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stdout
    /// over a bounded channel.
    #[must_use]
    pub fn stdout(
        executor: &Executor,
        buffer: usize,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::new(
            executor,
            tokio::io::stdout(),
            buffer,
            request_mode,
            response_mode,
        )
    }

    /// Create a new [`BidirectionalWriter`] that prints the last request and
    /// response to stdout.
    ///
    /// See [`Self::last`] for its intentional full-body buffering semantics.
    #[must_use]
    pub fn stdout_last(
        executor: &Executor,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::last(executor, tokio::io::stdout(), request_mode, response_mode)
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stderr
    /// over a bounded channel.
    #[must_use]
    pub fn stderr(
        executor: &Executor,
        buffer: usize,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::new(
            executor,
            tokio::io::stderr(),
            buffer,
            request_mode,
            response_mode,
        )
    }

    /// Create a new [`BidirectionalWriter`] that prints the last request and
    /// response to stderr.
    ///
    /// See [`Self::last`] for its intentional full-body buffering semantics.
    #[must_use]
    pub fn stderr_last(
        executor: &Executor,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::last(executor, tokio::io::stderr(), request_mode, response_mode)
    }
}

impl RequestWriter for BidirectionalWriter<UnboundedSender<BidirectionalMessage>> {
    async fn write_request(&self, req: Request) {
        if let Err(err) = self.sender.send(BidirectionalMessage::Request(req)) {
            tracing::error!("failed to send request to writer over unbounded channel: {err:?}")
        }
    }
}

impl ResponseWriter for BidirectionalWriter<UnboundedSender<BidirectionalMessage>> {
    async fn write_response(&self, res: Response) {
        if let Err(err) = self.sender.send(BidirectionalMessage::Response(res)) {
            tracing::error!("failed to send response to writer over unbounded channel: {err:?}")
        }
    }
}

impl RequestWriter for BidirectionalWriter<Sender<BidirectionalMessage>> {
    async fn write_request(&self, req: Request) {
        if let Err(err) = self.sender.send(BidirectionalMessage::Request(req)).await {
            tracing::error!("failed to send request to writer over bounded channel: {err:?}")
        }
    }
}

impl ResponseWriter for BidirectionalWriter<Sender<BidirectionalMessage>> {
    async fn write_response(&self, res: Response) {
        if let Err(err) = self.sender.send(BidirectionalMessage::Response(res)).await {
            tracing::error!("failed to send response to writer over bounded channel: {err:?}")
        }
    }
}

/// The internal message type for the [`BidirectionalWriter`].
#[derive(Debug)]
pub enum BidirectionalMessage {
    /// A request to be written.
    Request(Request),
    /// A response to be written.
    Response(Response),
}

#[cfg(test)]
mod capture_tests {
    use rama_http_types::CaptureOutcome;

    use super::*;

    #[tokio::test]
    async fn capture_channel_tracks_stream_completion() {
        let (sender, mut body) = capture_body_channel();
        assert!(!body.is_end_stream());

        sender
            .send(BodyCaptureEvent::Frame(Frame::data(
                rama_core::bytes::Bytes::from_static(b"frame"),
            )))
            .await
            .unwrap();
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "frame"
        );
        assert!(!body.is_end_stream());

        sender
            .send(BodyCaptureEvent::End(CaptureOutcome::Complete))
            .await
            .unwrap();
        assert!(body.frame().await.is_none());
        assert!(body.is_end_stream());
    }

    #[tokio::test]
    async fn capture_channel_retains_at_most_one_event() {
        let (sender, mut body) = capture_body_channel();
        sender
            .send(BodyCaptureEvent::Frame(Frame::data(
                rama_core::bytes::Bytes::from_static(b"frame"),
            )))
            .await
            .unwrap();
        let mut end = Box::pin(sender.send(BodyCaptureEvent::End(CaptureOutcome::Complete)));

        tokio::time::timeout(std::time::Duration::from_millis(50), &mut end)
            .await
            .expect_err("a second event must wait for the body to drain the first");
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "frame"
        );
        end.await.unwrap();
        assert!(body.frame().await.is_none());
    }
}
