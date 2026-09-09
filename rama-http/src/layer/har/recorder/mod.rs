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
//! a [`WebSocketCaptureRecorder`]. [`HARExportLayer`](super::layer::HARExportLayer)
//! stores this opaque handle in the successful HTTP handshake metadata. An
//! explicitly installed Rama WebSocket HAR layer claims it, observes complete
//! application messages, and releases it when the connection ends or recording
//! stops. The handshake and WebSocket protocol engine remain independent of HAR
//! serialization and storage.
//!
//! A custom WebSocket backend implements [`WebSocketCaptureRecorder::record`] as an
//! asynchronous `&self` operation. The future provides natural backpressure: it
//! completes only after the backend has written the message or handed it to bounded
//! storage. That future can be dropped before completion when its socket task is
//! cancelled, so implementations must keep cancellation from corrupting their
//! backend state. The backend decides whether it needs internal synchronization;
//! the capture contract itself neither requires exclusive mutable access nor
//! retains an in-memory message history. Returning `None` from
//! [`RecorderSession::web_socket_capture`] records only the HTTP exchange.

use super::spec;
use crate::BodyCaptureEvent;
use jiff::Timestamp;
use rama_core::error::BoxError;
use rama_core::extensions::Extension;
use rama_http_types::mime::Mime;
use std::{
    fmt,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::mpsc;
use tokio::time::Instant;

mod fs;
pub use fs::{FileRecorder, FileRecorderSession, HarFilePath};
use rama_core::extensions::Extensions;
use rama_utils::str::NonEmptyStr;
use rama_utils::str::arcstr::ArcStr;

#[derive(Debug, Clone)]
/// This object represents the root of exported data.
pub struct LogMetaInfo {
    /// Non-empty HAR format version.
    pub version: NonEmptyStr,
    /// Name and version info of the log creator application.
    pub creator: spec::Creator,
    /// Name and version info of used browser.
    pub browser: Option<spec::Browser>,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
}

impl Default for LogMetaInfo {
    fn default() -> Self {
        let log = spec::Log::default();
        Self {
            version: log.version,
            creator: log.creator,
            browser: log.browser,
            comment: log.comment,
        }
    }
}

impl From<LogMetaInfo> for spec::Log {
    fn from(meta: LogMetaInfo) -> Self {
        Self {
            version: meta.version,
            creator: meta.creator,
            browser: meta.browser,
            pages: None,
            entries: Vec::new(),
            comment: meta.comment,
        }
    }
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
    /// Wall-clock time at which the HTTP exchange started.
    pub started_date_time: Timestamp,
    /// Monotonic time at which the HTTP exchange started.
    pub begin: Instant,
    /// HAR request metadata available before its streaming body is consumed.
    pub request: spec::Request,
    /// Request body media type, when known.
    pub body_mime_type: Option<Mime>,
    /// Live request body capture stream.
    pub body: BodyCaptureStream,
    /// Whether this request initiated a WebSocket handshake.
    pub web_socket: bool,
}

/// Asynchronous recorder for complete Chromium-shaped WebSocket messages.
///
/// Each returned future must resolve only after the message has been persisted
/// or accepted by bounded storage. This lets socket traffic apply backpressure
/// without prescribing how implementations serialize concurrent calls.
///
/// The future may be dropped before it resolves when the WebSocket or its
/// polling task is dropped. Implementations must therefore be cancellation-safe:
/// a partially polled call must not corrupt recorder state or permanently retain
/// capacity reserved for that message. A backend with cancellation-sensitive I/O
/// can hand the message to an owned worker and await that worker's acknowledgement.
pub trait WebSocketCaptureRecorder: Send + Sync + 'static {
    /// Record one WebSocket message.
    fn record(
        &self,
        message: spec::WebSocketMessage,
    ) -> impl Future<Output = Result<(), BoxError>> + Send + '_;
}

trait DynWebSocketCaptureRecorder: Send + Sync + 'static {
    fn record_box(
        self: Arc<Self>,
        message: spec::WebSocketMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send + 'static>>;
}

impl<R> DynWebSocketCaptureRecorder for R
where
    R: WebSocketCaptureRecorder,
{
    fn record_box(
        self: Arc<Self>,
        message: spec::WebSocketMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send + 'static>> {
        Box::pin(async move { self.record(message).await })
    }
}

struct WebSocketCaptureShared {
    closed: AtomicBool,
    close: Box<dyn Fn() + Send + Sync>,
}

impl WebSocketCaptureShared {
    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            (self.close)();
        }
    }
}

struct WebSocketCaptureSlot {
    shared: Arc<WebSocketCaptureShared>,
    recorder: Arc<dyn DynWebSocketCaptureRecorder>,
    claimed: AtomicBool,
}

impl Drop for WebSocketCaptureSlot {
    fn drop(&mut self) {
        self.shared.close();
    }
}

/// Opaque WebSocket capture handle propagated through HTTP upgrade extensions.
#[derive(Clone, Extension)]
#[extension(tags(http))]
pub struct WebSocketCapture {
    slot: Arc<WebSocketCaptureSlot>,
}

impl fmt::Debug for WebSocketCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketCapture")
            .finish_non_exhaustive()
    }
}

impl WebSocketCapture {
    /// Create an opaque capture handle with an asynchronous recorder and close callback.
    ///
    /// `close` must promptly signal any asynchronous worker associated with the
    /// recorder. It can race with `record` and must therefore be thread-safe.
    #[must_use]
    pub fn new<R, C>(recorder: R, close: C) -> Self
    where
        R: WebSocketCaptureRecorder,
        C: Fn() + Send + Sync + 'static,
    {
        let shared = Arc::new(WebSocketCaptureShared {
            closed: AtomicBool::new(false),
            close: Box::new(close),
        });
        Self {
            slot: Arc::new(WebSocketCaptureSlot {
                shared,
                recorder: Arc::new(recorder),
                claimed: AtomicBool::new(false),
            }),
        }
    }

    /// Claim this capture and bind completion to one WebSocket's lifetime.
    ///
    /// Only the first caller receives a lease. This prevents both sides of a
    /// proxy relay from recording the same logical messages twice when upgrade
    /// extensions are propagated across both sockets.
    #[must_use]
    pub fn lease(&self) -> Option<WebSocketCaptureLease> {
        if self.slot.shared.closed.load(Ordering::Acquire)
            || self
                .slot
                .claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            None
        } else {
            Some(WebSocketCaptureLease {
                slot: self.slot.clone(),
            })
        }
    }

    /// Finish capture explicitly, for example after a rejected upgrade.
    pub fn close(&self) {
        self.slot.shared.close();
    }

    pub(crate) fn close_handle(&self) -> WebSocketCaptureCloseHandle {
        WebSocketCaptureCloseHandle(self.slot.shared.clone())
    }
}

pub(crate) struct WebSocketCaptureCloseHandle(Arc<WebSocketCaptureShared>);

impl WebSocketCaptureCloseHandle {
    pub(crate) fn close(&self) {
        self.0.close();
    }
}

impl Drop for WebSocketCaptureCloseHandle {
    fn drop(&mut self) {
        self.close();
    }
}

/// WebSocket-lifetime view of a [`WebSocketCapture`].
pub struct WebSocketCaptureLease {
    slot: Arc<WebSocketCaptureSlot>,
}

/// One in-flight asynchronous WebSocket capture operation.
///
/// This named future hides the recorder's internal type erasure from WebSocket
/// middleware. Custom recorders still implement [`WebSocketCaptureRecorder`]
/// with an ordinary `impl Future` return.
pub struct WebSocketCaptureFuture {
    inner: WebSocketCaptureFutureInner,
}

enum WebSocketCaptureFutureInner {
    Closed,
    Recording(Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send + 'static>>),
}

impl Future for WebSocketCaptureFuture {
    type Output = Result<(), BoxError>;

    fn poll(
        self: Pin<&mut Self>,
        ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match &mut self.get_mut().inner {
            WebSocketCaptureFutureInner::Closed => std::task::Poll::Ready(Ok(())),
            WebSocketCaptureFutureInner::Recording(future) => future.as_mut().poll(ctx),
        }
    }
}

impl fmt::Debug for WebSocketCaptureLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketCaptureLease")
            .finish_non_exhaustive()
    }
}

impl WebSocketCaptureLease {
    /// Return whether this capture has stopped accepting observations.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.slot.shared.closed.load(Ordering::Acquire)
    }

    /// Persist one message, applying recorder-defined backpressure.
    pub fn record(&self, message: spec::WebSocketMessage) -> WebSocketCaptureFuture {
        let inner = if self.is_closed() {
            WebSocketCaptureFutureInner::Closed
        } else {
            WebSocketCaptureFutureInner::Recording(self.slot.recorder.clone().record_box(message))
        };
        WebSocketCaptureFuture { inner }
    }

    /// Stop accepting messages and finish this capture.
    ///
    /// Calling this more than once is harmless. Cloneable owners may use it to
    /// coordinate one logical capture across multiple directional adapters.
    pub fn close(&self) {
        self.slot.shared.close();
    }
}

impl Drop for WebSocketCaptureLease {
    fn drop(&mut self) {
        self.slot.shared.close();
    }
}

/// Response metadata and its live body capture stream.
#[derive(Debug)]
pub struct HttpResponseCapture {
    /// HAR response metadata available before its streaming body is consumed.
    pub response: spec::Response,
    /// Live response body capture stream.
    pub body: BodyCaptureStream,
}

/// One in-progress HTTP exchange owned by a [`Recorder`].
pub trait RecorderSession: Send + 'static {
    /// Return the capture handle for a WebSocket upgrade, when supported.
    ///
    /// [`HARExportLayer`](super::layer::HARExportLayer) calls this at most once
    /// per session, and only when it classified the request as a WebSocket
    /// handshake.
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
    struct TestWebSocketState {
        messages: Mutex<Vec<spec::WebSocketMessage>>,
        closes: AtomicUsize,
    }

    struct TestWebSocketRecorder(Arc<TestWebSocketState>);

    impl WebSocketCaptureRecorder for TestWebSocketRecorder {
        async fn record(&self, message: spec::WebSocketMessage) -> Result<(), BoxError> {
            self.0.messages.lock().push(message);
            Ok(())
        }
    }

    #[tokio::test]
    async fn web_socket_capture_has_one_lifetime_owner() {
        let state = Arc::new(TestWebSocketState::default());
        let capture = WebSocketCapture::new(TestWebSocketRecorder(state.clone()), {
            let state = state.clone();
            move || {
                state.closes.fetch_add(1, Ordering::AcqRel);
            }
        });
        let lease = capture.lease().expect("first claimant");
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
        assert_eq!(state.messages.lock().len(), 1);
        assert_eq!(state.closes.load(Ordering::Acquire), 0);

        drop(lease);
        assert_eq!(state.closes.load(Ordering::Acquire), 1);
        drop(capture);
        assert_eq!(state.closes.load(Ordering::Acquire), 1);
    }

    #[test]
    fn dropping_close_handle_stops_web_socket_capture() {
        let state = Arc::new(TestWebSocketState::default());
        let capture = WebSocketCapture::new(TestWebSocketRecorder(state.clone()), {
            let state = state.clone();
            move || {
                state.closes.fetch_add(1, Ordering::AcqRel);
            }
        });

        drop(capture.close_handle());

        assert_eq!(state.closes.load(Ordering::Acquire), 1);
        assert!(capture.lease().is_none(), "closed capture rejects leases");
    }

    #[test]
    fn explicitly_closed_web_socket_capture_rejects_claims() {
        let state = Arc::new(TestWebSocketState::default());
        let capture = WebSocketCapture::new(TestWebSocketRecorder(state.clone()), {
            let state = state.clone();
            move || {
                state.closes.fetch_add(1, Ordering::AcqRel);
            }
        });

        capture.close();
        capture.close();
        assert_eq!(state.closes.load(Ordering::Acquire), 1);
        assert!(
            capture.lease().is_none(),
            "closed capture cannot be claimed"
        );
    }

    #[tokio::test]
    async fn explicitly_closed_web_socket_lease_stops_recording() {
        let state = Arc::new(TestWebSocketState::default());
        let capture = WebSocketCapture::new(TestWebSocketRecorder(state.clone()), {
            let state = state.clone();
            move || {
                state.closes.fetch_add(1, Ordering::AcqRel);
            }
        });
        let lease = capture.lease().expect("capture lease");

        lease.close();
        lease
            .record(spec::WebSocketMessage::text(
                spec::WebSocketMessageType::Send,
                1.0,
                "ignored",
            ))
            .await
            .unwrap();

        assert_eq!(state.closes.load(Ordering::Acquire), 1);
        assert!(state.messages.lock().is_empty());
    }

    #[test]
    fn unclaimed_web_socket_capture_closes_on_drop() {
        let state = Arc::new(TestWebSocketState::default());
        let capture = WebSocketCapture::new(TestWebSocketRecorder(state.clone()), {
            let state = state.clone();
            move || {
                state.closes.fetch_add(1, Ordering::AcqRel);
            }
        });

        drop(capture);
        assert_eq!(state.closes.load(Ordering::Acquire), 1);
    }
}
