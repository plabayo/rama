//! Streaming HAR recorder contracts and the built-in file recorder.
//!
//! A custom backend implements both [`Recorder`] and [`StreamingRecorder`], with a
//! per-exchange type implementing [`RecorderSession`].
//! [`StreamingRecorder::start_http_recording`] receives the request metadata and a
//! bounded [`BodyCaptureStream`]. The implementation should transfer that stream to
//! a worker that drains it while the request continues, then return a session that
//! correlates the request with its eventual response. Likewise,
//! [`RecorderSession::record_response`] transfers response metadata and its live
//! body stream to the backend. It must return once the backend has accepted the
//! stream, rather than waiting for the body to finish. This lets a backend stream
//! captures to a file, remote collector, or other storage without materializing
//! complete HTTP bodies in memory.
//!
//! For a WebSocket upgrade, the session can return a [`WebSocketCapture`] backed by
//! its own [`WebSocketCaptureSink`]. Rama then reports Chromium-shaped messages
//! until the upgraded connection ends or recording stops. Returning `None` records
//! only the HTTP exchange. WebSocket capture readiness participates in the socket's
//! normal polling, allowing a sink to hand messages to a bounded asynchronous worker
//! without blocking an executor thread or retaining an unbounded queue.

use super::spec;
use crate::BodyCaptureEvent;
use jiff::Timestamp;
use rama_core::error::BoxError;
use rama_core::extensions::Extension;
use rama_http_types::mime::Mime;
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::sync::mpsc;
use tokio::time::Instant;

mod fs;
pub use fs::{FileRecorder, HarFilePath};
use rama_core::extensions::Extensions;
use rama_utils::str::arcstr::ArcStr;

#[derive(Debug, Clone)]
/// This object represents the root of exported data.
pub struct LogMetaInfo {
    /// Version number of the format. If empty, string "1.1" is assumed by default.
    pub version: ArcStr,
    /// Name and version info of the log creator application.
    pub creator: spec::Creator,
    /// Name and version info of used browser.
    pub browser: Option<spec::Browser>,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
}

/// Bounded stream of body events observed while an HTTP body is forwarded.
///
/// A recorder consumes this stream according to its storage policy. The built-in
/// file recorder writes each data frame to a temporary file before accepting the
/// next one, so retained memory is independent of the body's total length.
#[derive(Debug)]
pub struct BodyCaptureStream {
    receiver: mpsc::Receiver<BodyCaptureEvent>,
}

impl BodyCaptureStream {
    /// Receive the next captured body event.
    pub async fn next_event(&mut self) -> Option<BodyCaptureEvent> {
        self.receiver.recv().await
    }

    pub(crate) fn try_next_event(&mut self) -> Option<BodyCaptureEvent> {
        self.receiver.try_recv().ok()
    }
}

pub(crate) fn body_capture_channel() -> (mpsc::Sender<BodyCaptureEvent>, BodyCaptureStream) {
    // Retain at most one frame while the recorder is busy. CaptureBody awaits
    // the send before forwarding that frame, providing bounded backpressure.
    let (sender, receiver) = mpsc::channel(1);
    (sender, BodyCaptureStream { receiver })
}

/// Request metadata and its live body capture stream.
#[derive(Debug)]
pub struct HttpRequestCapture {
    started_date_time: Timestamp,
    begin: Instant,
    request: spec::Request,
    body_mime_type: Option<Mime>,
    body: BodyCaptureStream,
    web_socket: bool,
}

impl HttpRequestCapture {
    pub(crate) fn new(
        started_date_time: Timestamp,
        begin: Instant,
        request: spec::Request,
        body_mime_type: Option<Mime>,
        body: BodyCaptureStream,
        web_socket: bool,
    ) -> Self {
        Self {
            started_date_time,
            begin,
            request,
            body_mime_type,
            body,
            web_socket,
        }
    }

    /// Whether this request starts a WebSocket upgrade.
    #[must_use]
    pub const fn is_web_socket(&self) -> bool {
        self.web_socket
    }

    /// Consume the capture into its constituent parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Timestamp,
        Instant,
        spec::Request,
        Option<Mime>,
        BodyCaptureStream,
        bool,
    ) {
        (
            self.started_date_time,
            self.begin,
            self.request,
            self.body_mime_type,
            self.body,
            self.web_socket,
        )
    }
}

/// Storage callback for an opaque WebSocket capture contract.
///
/// Implementations must write or otherwise accept each message before
/// returning. This makes capture memory independent of the connection's
/// lifetime without coupling `rama-ws` to a concrete recorder.
pub trait WebSocketCaptureSink: Send + Sync + 'static {
    /// Poll until this sink can accept one message without blocking.
    ///
    /// The default is suitable for sinks that always accept synchronously.
    /// A sink returning [`Poll::Pending`] must arrange for the supplied task to
    /// be woken when capacity may be available.
    fn poll_ready(&self, _ctx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    /// Accept one Chromium-shaped WebSocket message after [`poll_ready`](Self::poll_ready).
    ///
    /// This method is invoked from the WebSocket's polling path and must not
    /// perform blocking I/O. A sink that needs asynchronous I/O should enqueue
    /// into capacity reserved by `poll_ready` and let a worker persist it.
    fn start_record(&self, message: spec::WebSocketMessage) -> Result<(), BoxError>;

    /// Finish this message stream. Calls must be idempotent.
    fn close(&self);
}

/// Opaque WebSocket capture handle propagated through HTTP upgrade extensions.
#[derive(Clone, Extension)]
#[extension(tags(http))]
pub struct WebSocketCapture {
    sink: Arc<dyn WebSocketCaptureSink>,
    claimed: Arc<AtomicBool>,
}

impl fmt::Debug for WebSocketCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketCapture")
            .finish_non_exhaustive()
    }
}

impl WebSocketCapture {
    /// Create an opaque capture handle.
    #[must_use]
    pub fn new(sink: Arc<dyn WebSocketCaptureSink>) -> Self {
        Self {
            sink,
            claimed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Claim this capture and bind completion to one WebSocket's lifetime.
    ///
    /// Only the first caller receives a lease. This prevents both sides of a
    /// proxy relay from recording the same logical messages twice when upgrade
    /// extensions are propagated across both sockets.
    #[must_use]
    pub fn lease(&self) -> Option<WebSocketCaptureLease> {
        self.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| WebSocketCaptureLease {
                capture: self.clone(),
            })
    }

    /// Finish capture explicitly, for example after a rejected upgrade.
    pub fn close(&self) {
        self.sink.close();
    }
}

/// WebSocket-lifetime view of a [`WebSocketCapture`].
pub struct WebSocketCaptureLease {
    capture: WebSocketCapture,
}

impl fmt::Debug for WebSocketCaptureLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketCaptureLease")
            .finish_non_exhaustive()
    }
}

impl WebSocketCaptureLease {
    /// Poll until the recorder-defined sink can accept one message.
    pub fn poll_ready(&mut self, ctx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.capture.sink.poll_ready(ctx)
    }

    /// Accept a message after [`poll_ready`](Self::poll_ready) returned ready.
    pub fn start_record(&mut self, message: spec::WebSocketMessage) -> Result<(), BoxError> {
        self.capture.sink.start_record(message)
    }

    /// Wait for capacity and then persist one message.
    pub async fn record(&mut self, message: spec::WebSocketMessage) -> Result<(), BoxError> {
        std::future::poll_fn(|ctx| self.poll_ready(ctx)).await?;
        self.start_record(message)
    }
}

impl Drop for WebSocketCaptureLease {
    fn drop(&mut self) {
        self.capture.close();
    }
}

/// Response metadata and its live body capture stream.
#[derive(Debug)]
pub struct HttpResponseCapture {
    response: spec::Response,
    body: BodyCaptureStream,
}

impl HttpResponseCapture {
    pub(crate) fn new(response: spec::Response, body: BodyCaptureStream) -> Self {
        Self { response, body }
    }

    /// Consume the capture into its constituent parts.
    #[must_use]
    pub fn into_parts(self) -> (spec::Response, BodyCaptureStream) {
        (self.response, self.body)
    }
}

/// One in-progress HTTP exchange owned by a [`Recorder`].
pub trait RecorderSession: Send + 'static {
    /// Return the capture handle for a WebSocket upgrade, when supported.
    fn web_socket_capture(&self) -> Option<WebSocketCapture> {
        None
    }

    /// Attach a response and its streaming body to this exchange.
    ///
    /// This future must resolve after the recorder has accepted the stream, not
    /// after the response body ends. Otherwise returning a streaming response
    /// would deadlock on its own consumer.
    fn record_response(
        self,
        response: HttpResponseCapture,
    ) -> impl Future<Output = Option<Extensions>> + Send;

    /// Finish an exchange which has no recordable response.
    fn record_request_only(self) -> impl Future<Output = Option<Extensions>> + Send;
}

pub trait Recorder: Send + Sync + 'static {
    /// Record an already materialized HAR log.
    ///
    /// Prefer [`StreamingRecorder::start_http_recording`] for live HTTP traffic
    /// so body data can remain streaming.
    fn record(&self, entry: spec::Log) -> impl Future<Output = Option<Extensions>> + Send + '_;

    /// Finish the active recording before this future resolves.
    ///
    /// This function can be called when no session is active, which a recorder
    /// must handle as a no-op.
    fn stop_record(&self) -> impl Future<Output = ()> + Send;
}

impl<R: Recorder> Recorder for Arc<R> {
    fn record(&self, log: spec::Log) -> impl Future<Output = Option<Extensions>> + Send + '_ {
        (**self).record(log)
    }

    fn stop_record(&self) -> impl Future<Output = ()> + Send {
        (**self).stop_record()
    }
}

/// Recorder capable of consuming live HTTP bodies without materializing them.
pub trait StreamingRecorder: Recorder {
    /// Per-exchange recording handle.
    type Session: RecorderSession;

    /// Start capturing an HTTP exchange.
    ///
    /// This future must resolve after the recorder has accepted ownership of
    /// the request stream. Body data continues to flow after it returns.
    fn start_http_recording(
        &self,
        request: HttpRequestCapture,
    ) -> impl Future<Output = Option<Self::Session>> + Send + '_;
}

impl<R: StreamingRecorder> StreamingRecorder for Arc<R> {
    type Session = R::Session;

    fn start_http_recording(
        &self,
        request: HttpRequestCapture,
    ) -> impl Future<Output = Option<Self::Session>> + Send + '_ {
        (**self).start_http_recording(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct TestWebSocketSink {
        messages: Mutex<Vec<spec::WebSocketMessage>>,
        closes: AtomicUsize,
    }

    impl WebSocketCaptureSink for TestWebSocketSink {
        fn start_record(&self, message: spec::WebSocketMessage) -> Result<(), BoxError> {
            self.messages.lock().push(message);
            Ok(())
        }

        fn close(&self) {
            self.closes.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[tokio::test]
    async fn web_socket_capture_has_one_lifetime_owner() {
        let sink = Arc::new(TestWebSocketSink::default());
        let capture = WebSocketCapture::new(sink.clone());
        let mut lease = capture.lease().expect("first claimant");
        assert!(
            capture.lease().is_none(),
            "second claimant must be rejected"
        );

        lease
            .record(spec::WebSocketMessage::text(
                spec::WebSocketMessageType::Send,
                1.0,
                "hello",
            ))
            .await
            .unwrap();
        assert_eq!(sink.messages.lock().len(), 1);
        assert_eq!(sink.closes.load(Ordering::Acquire), 0);

        drop(lease);
        assert_eq!(sink.closes.load(Ordering::Acquire), 1);
    }
}
