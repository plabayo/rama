//! Middleware to write Http traffic in std format.
//!
//! Can be useful for cli / debug purposes.
//!
//! Built-in shared writers keep complete messages ordered through one output
//! task. Each message has capacity for one captured frame; a slow or long-lived
//! message therefore applies asynchronous backpressure to later body streams
//! instead of buffering their complete contents in memory. Use a per-message
//! writer when messages must be captured concurrently without sharing that
//! backpressure. In particular, a shared bidirectional body writer can stall a
//! full-duplex exchange when either peer waits for the other direction to make
//! progress; use [`PerMessageFileWriter`] or another independent writer for
//! such traffic.
//!
//! That output task holds the scope it was built with until it ends. Each
//! capture is admitted when its message is served and is then written: it
//! holds the writer's admission until its message is handed over. A cancel
//! starts the drain: the task keeps taking what pending captures send, and while
//! any is pending a newly served one is admitted too. Once the scope is
//! cancelled and no capture is pending, admission closes for good: the task
//! flushes what is queued and ends, and later captures are refused. A writer
//! kept around therefore never holds up a shutdown. At the hard phase the task
//! and its pending captures are dropped. Layers made with the writer's constructors, or
//! with [`BidirectionalWriter::request_layer`] and
//! [`BidirectionalWriter::response_layer`], admit captures this way; a layer
//! made with `new` around a built-in writer has no admission, so a capture
//! racing the cancel may be dropped.

use crate::body::Frame;
use crate::{
    Body, BodyCaptureEvent, Request, Response, StreamingBody,
    body::util::BodyExt as _,
    io::{write_http_request_streaming, write_http_response_streaming},
};
use rama_core::{
    extensions::{Extension, Extensions},
    graceful::{Scope, WeakScope},
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
use uuid::Uuid;

/// The next message for a writer task: any message until it is closed, then only those
/// already queued, so the task flushes and ends instead of waiting for its senders.
macro_rules! next_message {
    ($rx:ident, $closed:ident, $open:ident) => {
        if $open {
            tokio::select! {
                biased;
                () = &mut $closed => {
                    $open = false;
                    $rx.close();
                    $rx.recv().await
                }
                message = $rx.recv() => message,
            }
        } else {
            $rx.recv().await
        }
    };
}

/// Admission of the captures an output task writes: each holds a child of the task's scope
/// from its spawn until it handed over its message.
struct Admission {
    captures: WeakScope,
}

impl Admission {
    fn new(scope: &Scope) -> Self {
        Self {
            captures: scope.child().into_weak_scope(),
        }
    }

    /// The executor captures are spawned on; it refuses them once cancelled and drained.
    fn executor(&self) -> Executor {
        Executor::from(self.captures.clone())
    }

    /// Completes once the scope is cancelled and every capture admitted until then is in.
    fn closed(&self) -> impl Future<Output = ()> + Send + 'static {
        let captures = self.captures.clone();
        async move {
            captures.cancelled().await;
            captures.drained().await;
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
struct TrafficWriterId(Uuid);

fn ensure_traffic_writer_id(extensions: &Extensions) -> TrafficWriterId {
    *extensions.get_ref_or_insert(|| TrafficWriterId(Uuid::new_v4()))
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
                    crate::CaptureOutcome::Error => {
                        tracing::warn!(
                            ?outcome,
                            "captured HTTP body ended before normal completion"
                        );
                    }
                    crate::CaptureOutcome::Aborted => {
                        tracing::debug!(
                            ?outcome,
                            "HTTP body capture stopped before observing end-of-stream"
                        );
                    }
                }
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Ready(None) => {
                tracing::debug!("HTTP body capture channel closed without a terminal event");
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
    ($writer:ident, $rx:ident, $closed:ident, $req_headers:ident, $req_body:ident, $res_headers:ident, $res_body:ident) => {{
        let mut $closed = std::pin::pin!($closed);
        let mut open = true;
        while let Some(msg) = next_message!($rx, $closed, open) {
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
///
/// Make its layers with [`Self::request_layer`] and [`Self::response_layer`], so their
/// captures are admitted by its output task, see the [module docs](self).
#[derive(Clone)]
pub struct BidirectionalWriter<S> {
    sender: S,
    executor: Executor,
}

impl<S: Clone> BidirectionalWriter<S> {
    /// A [`RequestWriterLayer`] writing requests to this writer.
    #[must_use]
    pub fn request_layer(&self) -> RequestWriterLayer<Self> {
        RequestWriterLayer::new_with_executor(self.clone(), self.executor.clone())
    }

    /// A [`ResponseWriterLayer`] writing responses to this writer.
    #[must_use]
    pub fn response_layer(&self) -> ResponseWriterLayer<Self> {
        ResponseWriterLayer::new_with_executor(self.clone(), self.executor.clone())
    }
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
        scope: &Scope,
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

        let admission = Admission::new(scope);
        let closed = admission.closed();

        scope.spawn_abortable_task(async move {
            drive_bidirectional_writer!(
                writer,
                rx,
                closed,
                write_request_headers,
                write_request_body,
                write_response_headers,
                write_response_body
            );
        });

        Self {
            sender: tx,
            executor: admission.executor(),
        }
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stdout
    /// over an unbounded channel.
    #[must_use]
    pub fn stdout_unbounded(
        scope: &Scope,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::unbounded(scope, tokio::io::stdout(), request_mode, response_mode)
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stderr
    /// over an unbounded channel.
    #[must_use]
    pub fn stderr_unbounded(
        scope: &Scope,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::unbounded(scope, tokio::io::stderr(), request_mode, response_mode)
    }
}

impl BidirectionalWriter<Sender<BidirectionalMessage>> {
    /// Create a new [`BidirectionalWriter`] with a custom writer gated behind a custom bounded channel.
    pub fn new<W>(
        scope: &Scope,
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

        let admission = Admission::new(scope);
        let closed = admission.closed();

        scope.spawn_abortable_task(
            async move {
                drive_bidirectional_writer!(
                    writer,
                    rx,
                    closed,
                    write_request_headers,
                    write_request_body,
                    write_response_headers,
                    write_response_body
                );
            }
            .instrument(span),
        );

        Self {
            sender: tx,
            executor: admission.executor(),
        }
    }

    /// Create a new [`BidirectionalWriter`] with a custom writer that only
    /// writes the last request and response received.
    ///
    /// Selected bodies are intentionally buffered in full because output is
    /// deferred until the channel closes. Do not use body-writing modes here
    /// for unbounded or attacker-controlled bodies.
    pub fn last<W>(
        scope: &Scope,
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

        let admission = Admission::new(scope);
        let closed = admission.closed();

        scope.spawn_abortable_task(
            async move {
                let mut last_request = None;
                let mut last_response = None;

                let mut closed = std::pin::pin!(closed);
                let mut open = true;
                while let Some(msg) = next_message!(rx, closed, open) {
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

        Self {
            sender: tx,
            executor: admission.executor(),
        }
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stdout
    /// over a bounded channel.
    #[must_use]
    pub fn stdout(
        scope: &Scope,
        buffer: usize,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::new(
            scope,
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
        scope: &Scope,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::last(scope, tokio::io::stdout(), request_mode, response_mode)
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stderr
    /// over a bounded channel.
    #[must_use]
    pub fn stderr(
        scope: &Scope,
        buffer: usize,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::new(
            scope,
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
        scope: &Scope,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::last(scope, tokio::io::stderr(), request_mode, response_mode)
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
    use rama_core::{
        Layer as _, Service as _, extensions::ExtensionsRef as _, service::service_fn,
    };
    use rama_http_types::CaptureOutcome;
    use std::{io, time::Duration};
    use tokio::io::AsyncReadExt as _;
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

    use super::*;

    #[derive(Clone)]
    struct IdObserver(UnboundedSender<TrafficWriterId>);

    impl RequestWriter for IdObserver {
        async fn write_request(&self, request: Request) {
            self.0
                .send(*request.extensions().get_ref::<TrafficWriterId>().unwrap())
                .unwrap();
        }
    }

    impl ResponseWriter for IdObserver {
        async fn write_response(&self, response: Response) {
            self.0
                .send(*response.extensions().get_ref::<TrafficWriterId>().unwrap())
                .unwrap();
        }
    }

    async fn assert_matching_ids(mut ids: UnboundedReceiver<TrafficWriterId>) {
        let first = tokio::time::timeout(std::time::Duration::from_secs(1), ids.recv())
            .await
            .unwrap()
            .unwrap();
        let second = tokio::time::timeout(std::time::Duration::from_secs(1), ids.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn request_and_response_writers_share_id_with_request_layer_outermost() {
        let (sender, ids) = tokio::sync::mpsc::unbounded_channel();
        let observer = IdObserver(sender);
        let inner = service_fn(|_request: Request| async {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        });
        let service = RequestWriterLayer::new(observer.clone())
            .into_layer(ResponseWriterLayer::new(observer).into_layer(inner));

        service.serve(Request::new(Body::empty())).await.unwrap();
        assert_matching_ids(ids).await;
    }

    #[tokio::test]
    async fn request_and_response_writers_share_id_with_response_layer_outermost() {
        let (sender, ids) = tokio::sync::mpsc::unbounded_channel();
        let observer = IdObserver(sender);
        let inner = service_fn(|_request: Request| async {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        });
        let service = ResponseWriterLayer::new(observer.clone())
            .into_layer(RequestWriterLayer::new(observer).into_layer(inner));

        service.serve(Request::new(Body::empty())).await.unwrap();
        assert_matching_ids(ids).await;
    }

    #[tokio::test]
    async fn last_writer_drains_messages_and_writes_only_the_final_exchange() {
        let scope = Scope::new();
        let (output, mut captured) = tokio::io::duplex(512);
        let writer =
            BidirectionalWriter::last(&scope, output, Some(WriterMode::All), Some(WriterMode::All));

        writer
            .write_request(
                Request::builder()
                    .uri("/first")
                    .body(Body::from("request-one"))
                    .unwrap(),
            )
            .await;
        writer
            .write_response(
                Response::builder()
                    .status(201)
                    .body(Body::from("response-one"))
                    .unwrap(),
            )
            .await;
        writer
            .write_request(
                Request::builder()
                    .uri("/second")
                    .body(Body::from("request-two"))
                    .unwrap(),
            )
            .await;
        writer
            .write_response(
                Response::builder()
                    .status(202)
                    .body(Body::from("response-two"))
                    .unwrap(),
            )
            .await;
        drop(writer);

        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), captured.read_to_end(&mut bytes))
            .await
            .expect("last writer should flush when its channel closes")
            .unwrap();
        assert_eq!(
            bytes,
            b"GET /second HTTP/1.1\r\n\r\nrequest-two\r\nHTTP/1.1 202 Accepted\r\n\r\nresponse-two\r\n"
        );
    }

    #[tokio::test]
    async fn last_writer_replaces_a_failed_body_with_an_empty_body() {
        let scope = Scope::new();
        let (output, mut captured) = tokio::io::duplex(128);
        let writer = BidirectionalWriter::last(&scope, output, Some(WriterMode::All), None);
        let body = Body::from_stream(rama_core::futures::stream::once(async {
            Err::<rama_core::bytes::Bytes, _>(io::Error::other("body failed"))
        }));

        writer
            .write_request(
                Request::builder()
                    .method("POST")
                    .uri("/broken")
                    .body(body)
                    .unwrap(),
            )
            .await;
        drop(writer);

        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), captured.read_to_end(&mut bytes))
            .await
            .expect("last writer should recover from a body error")
            .unwrap();
        assert_eq!(bytes, b"POST /broken HTTP/1.1\r\n\r\n\r\n");
    }

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
    #[tracing_test::traced_test]
    async fn capture_channel_logs_only_errors_as_warnings() {
        let (sender, mut body) = capture_body_channel();
        sender
            .send(BodyCaptureEvent::End(CaptureOutcome::Aborted))
            .await
            .unwrap();
        assert!(body.frame().await.is_none());

        let (sender, mut body) = capture_body_channel();
        drop(sender);
        assert!(body.frame().await.is_none());

        let (sender, mut body) = capture_body_channel();
        sender
            .send(BodyCaptureEvent::End(CaptureOutcome::Error))
            .await
            .unwrap();
        assert!(body.frame().await.is_none());

        logs_assert(|lines| {
            for message in [
                "HTTP body capture stopped before observing end-of-stream",
                "HTTP body capture channel closed without a terminal event",
            ] {
                let line = lines
                    .iter()
                    .find(|line| line.contains(message))
                    .ok_or_else(|| format!("missing log line containing {message:?}"))?;
                if !line.contains("DEBUG") {
                    return Err(format!("expected DEBUG log, got {line:?}"));
                }
            }

            let message = "captured HTTP body ended before normal completion";
            let line = lines
                .iter()
                .find(|line| line.contains(message))
                .ok_or_else(|| format!("missing log line containing {message:?}"))?;
            if !line.contains("WARN") {
                return Err(format!("expected WARN log, got {line:?}"));
            }
            Ok(())
        });
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
