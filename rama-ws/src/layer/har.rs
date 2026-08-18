//! HAR capture middleware for WebSocket message streams.
//!
//! This module deliberately decorates an already constructed WebSocket. The
//! core WebSocket runtime and protocol implementation do not know about HAR,
//! recorders, or HTTP middleware extensions.
//!
//! [`HARWebSocketLayer`] is explicitly installed around a service that accepts
//! a client endpoint, server endpoint, or established relay bridge. Manual
//! handshake users can instead apply [`ClientWebSocket::map_socket`] or
//! [`ServerWebSocket::map_socket`] and construct [`HARWebSocket`] directly.
//! Code that does not apply either form keeps using the ordinary WebSocket
//! types and pays no capture-wrapper cost.
//!
//! A relay capture records the messages finally accepted by its destination
//! legs: writes to the upstream-facing egress socket are HAR `send` messages,
//! while writes to the downstream-facing ingress socket are HAR `receive`
//! messages. Messages dropped by relay middleware are therefore absent, and
//! transformed or expanded outputs are represented as actually forwarded.
//! The opaque capture handle is carried by the egress transport because it
//! continues the HAR session created around the upstream HTTP handshake. Once
//! claimed, that one session is shared by the wrappers on both bridge legs;
//! its egress location does not limit observation to egress traffic.
//!
//! In an endpoint stack, apply this layer to the service that consumes a
//! [`ClientWebSocket`] or [`ServerWebSocket`]. The layer reads the opaque
//! capture handle from that wrapper's preserved HTTP handshake metadata,
//! replaces only its generic socket parameter, and calls the inner endpoint.
//! For a relay, place the same layer between
//! [`WebSocketRelayIoService`](crate::handshake::mitm::WebSocketRelayIoService)
//! and a message-level relay service:
//!
//! ```text
//! BridgeIo<raw ingress, raw egress>
//!     -> WebSocketRelayIoService
//!     -> HARWebSocketLayer
//!     -> WebSocketRelayService
//! ```
//!
//! A manual client can clone [`WebSocketCapture`] from
//! `websocket.response().extensions` and pass it to [`HARWebSocket::new`]
//! through [`ClientWebSocket::map_socket`]. The equivalent server metadata is
//! available through `websocket.request().extensions`. No HAR-specific
//! extension trait or handshake variant is required.
//!
//! [`ClientWebSocket::map_socket`]: crate::handshake::client::ClientWebSocket::map_socket
//! [`ServerWebSocket::map_socket`]: crate::handshake::server::ServerWebSocket::map_socket

use crate::{
    Message, ProtocolError, WebSocketIo,
    handshake::{client::ClientWebSocket, mitm::WebSocketBridge, server::ServerWebSocket},
    protocol::Role,
};
use rama_core::{
    Layer, Service,
    extensions::{Extensions, ExtensionsRef},
    futures::{Sink, SinkExt as _, Stream, StreamExt as _, task::AtomicWaker},
    telemetry::tracing::debug,
};
use rama_http::layer::har::{
    recorder::{WebSocketCapture, WebSocketCaptureFuture, WebSocketCaptureLease},
    spec::{WebSocketMessage, WebSocketMessageType},
};
use rama_utils::time::unix_timestamp_millis;
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker, ready},
};

struct PendingObservation {
    future: WebSocketCaptureFuture,
    close_after: bool,
}

#[derive(Clone, Copy)]
enum ObservationSide {
    Read,
    Write,
}

// `StreamExt::split` can poll one observation from two different tasks. Poll
// the recorder with this fan-out waker so its latest registration always wakes
// both halves, even if the half that polled last is subsequently cancelled.
struct ObservationWakers {
    read: AtomicWaker,
    write: AtomicWaker,
}

impl ObservationWakers {
    fn new() -> Self {
        Self {
            read: AtomicWaker::new(),
            write: AtomicWaker::new(),
        }
    }

    fn register(&self, side: ObservationSide, waker: &Waker) {
        match side {
            ObservationSide::Read => self.read.register(waker),
            ObservationSide::Write => self.write.register(waker),
        }
    }

    fn wake_waiters(&self) {
        self.read.wake();
        self.write.wake();
    }
}

impl Wake for ObservationWakers {
    fn wake(self: Arc<Self>) {
        self.wake_waiters();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_waiters();
    }
}

/// Rama layer that installs HAR capture around WebSocket endpoint services or
/// an established relay bridge.
#[derive(Debug, Clone, Copy, Default)]
pub struct HARWebSocketLayer;

impl HARWebSocketLayer {
    /// Create a WebSocket HAR service layer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for HARWebSocketLayer {
    type Service = HARWebSocketService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HARWebSocketService { inner }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HARWebSocketService { inner }
    }
}

/// Service produced by [`HARWebSocketLayer`].
#[derive(Debug, Clone)]
pub struct HARWebSocketService<S> {
    inner: S,
}

impl<Inner, Socket> Service<ClientWebSocket<Socket>> for HARWebSocketService<Inner>
where
    Inner: Service<ClientWebSocket<HARWebSocket<Socket>>>,
    Socket: WebSocketIo,
{
    type Output = Inner::Output;
    type Error = Inner::Error;

    async fn serve(&self, websocket: ClientWebSocket<Socket>) -> Result<Self::Output, Self::Error> {
        let capture = websocket
            .response()
            .extensions
            .get_ref::<WebSocketCapture>()
            .cloned();
        self.inner
            .serve(
                websocket
                    .map_socket(move |socket| HARWebSocket::new(socket, Role::Client, capture)),
            )
            .await
    }
}

impl<Inner, Socket> Service<ServerWebSocket<Socket>> for HARWebSocketService<Inner>
where
    Inner: Service<ServerWebSocket<HARWebSocket<Socket>>>,
    Socket: WebSocketIo,
{
    type Output = Inner::Output;
    type Error = Inner::Error;

    async fn serve(&self, websocket: ServerWebSocket<Socket>) -> Result<Self::Output, Self::Error> {
        let capture = websocket
            .request()
            .extensions
            .get_ref::<WebSocketCapture>()
            .cloned();
        self.inner
            .serve(
                websocket
                    .map_socket(move |socket| HARWebSocket::new(socket, Role::Server, capture)),
            )
            .await
    }
}

impl<Inner, Ingress, Egress> Service<WebSocketBridge<Ingress, Egress>>
    for HARWebSocketService<Inner>
where
    Inner: Service<WebSocketBridge<HARWebSocket<Ingress>, HARWebSocket<Egress>>>,
    Ingress: WebSocketIo,
    Egress: WebSocketIo,
{
    type Output = Inner::Output;
    type Error = Inner::Error;

    async fn serve(
        &self,
        WebSocketBridge { ingress, egress }: WebSocketBridge<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        // HARExportLayer creates this session around the upstream HTTP
        // handshake. A successful response carries its continuation into the
        // upgraded egress transport; the lease itself then observes writes on
        // both legs of the message bridge.
        let capture_lease = egress
            .extensions()
            .get_ref::<WebSocketCapture>()
            .and_then(WebSocketCapture::lease)
            .map(Arc::new);

        let ingress = HARWebSocket::relay_leg(
            ingress,
            WebSocketMessageType::Receive,
            capture_lease.clone(),
        );
        let egress =
            HARWebSocket::relay_leg(egress, WebSocketMessageType::Send, capture_lease.clone());

        let result = self
            .inner
            .serve(WebSocketBridge::new(ingress, egress))
            .await;
        if let Some(capture_lease) = capture_lease {
            capture_lease.close();
        }
        result
    }
}

#[derive(Debug, Clone, Copy)]
enum CaptureMode {
    Endpoint(Role),
    Writes(WebSocketMessageType),
}

impl CaptureMode {
    fn message_type(self, outgoing: bool) -> Option<WebSocketMessageType> {
        match (self, outgoing) {
            (Self::Endpoint(Role::Client), true) | (Self::Endpoint(Role::Server), false) => {
                Some(WebSocketMessageType::Send)
            }
            (Self::Endpoint(Role::Client), false) | (Self::Endpoint(Role::Server), true) => {
                Some(WebSocketMessageType::Receive)
            }
            (Self::Writes(message_type), true) => Some(message_type),
            (Self::Writes(_), false) => None,
        }
    }
}

impl fmt::Debug for PendingObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingObservation")
            .field("close_after", &self.close_after)
            .finish_non_exhaustive()
    }
}

/// HAR-capturing middleware around a WebSocket message stream.
///
/// The wrapper observes complete text and binary messages after the underlying
/// WebSocket protocol accepts or produces them. It awaits the configured
/// recorder before accepting the next socket operation, which applies bounded
/// backpressure without adding capture concerns to the underlying WebSocket.
///
/// This type intentionally does not dereference to `S`, because directly
/// polling the inner transport would bypass capture. Use [`Self::get_ref`] or
/// [`Self::get_mut`] only when that bypass is explicitly intended, and call
/// [`Self::into_inner`] to remove the middleware.
pub struct HARWebSocket<S> {
    inner: S,
    mode: CaptureMode,
    capture_lease: Option<Arc<WebSocketCaptureLease>>,
    close_on_terminal: bool,
    pending_observation: Option<PendingObservation>,
    observation_wakers: Arc<ObservationWakers>,
    pending_read: Option<Result<Message, ProtocolError>>,
    pending_write_error: Option<ProtocolError>,
}

impl<S: fmt::Debug> fmt::Debug for HARWebSocket<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HARWebSocket")
            .field("inner", &self.inner)
            .field("mode", &self.mode)
            .field("capture_lease", &self.capture_lease)
            .field("pending_observation", &self.pending_observation)
            .field("pending_read", &self.pending_read)
            .field("pending_write_error", &self.pending_write_error)
            .finish()
    }
}

impl<S> HARWebSocket<S> {
    /// Wrap a WebSocket with an optional opaque capture handle.
    #[must_use]
    pub fn new(inner: S, role: Role, capture: Option<WebSocketCapture>) -> Self {
        Self::from_parts(
            inner,
            CaptureMode::Endpoint(role),
            capture.and_then(|capture| capture.lease()).map(Arc::new),
            true,
        )
    }

    fn relay_leg(
        inner: S,
        message_type: WebSocketMessageType,
        capture_lease: Option<Arc<WebSocketCaptureLease>>,
    ) -> Self {
        Self::from_parts(
            inner,
            CaptureMode::Writes(message_type),
            capture_lease,
            false,
        )
    }

    fn from_parts(
        inner: S,
        mode: CaptureMode,
        capture_lease: Option<Arc<WebSocketCaptureLease>>,
        close_on_terminal: bool,
    ) -> Self {
        Self {
            inner,
            mode,
            capture_lease,
            close_on_terminal,
            pending_observation: None,
            observation_wakers: Arc::new(ObservationWakers::new()),
            pending_read: None,
            pending_write_error: None,
        }
    }

    /// Wrap a WebSocket using the capture handle reachable from its extensions.
    #[must_use]
    pub fn from_extensions(inner: S, role: Role) -> Self
    where
        S: ExtensionsRef,
    {
        let capture = inner.extensions().get_ref::<WebSocketCapture>().cloned();
        Self::new(inner, role, capture)
    }

    /// Remove this middleware and return the underlying WebSocket.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Return a shared reference to the underlying WebSocket.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Return a mutable reference to the underlying WebSocket.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    fn poll_observation(&mut self, ctx: &Context<'_>, side: ObservationSide) -> Poll<()> {
        let Some(observation) = &mut self.pending_observation else {
            return Poll::Ready(());
        };
        self.observation_wakers.register(side, ctx.waker());
        let observation_waker = Waker::from(self.observation_wakers.clone());
        let mut observation_ctx = Context::from_waker(&observation_waker);
        match Pin::new(&mut observation.future).poll(&mut observation_ctx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.observation_wakers.wake_waiters();
                let close_after = self
                    .pending_observation
                    .take()
                    .is_some_and(|observation| observation.close_after);
                let failed = result.is_err();
                if let Err(err) = result {
                    debug!("failed to record WebSocket HAR observation: {err}");
                }
                if failed || close_after {
                    if let Some(capture) = &self.capture_lease {
                        capture.close();
                    }
                    self.capture_lease.take();
                }
                Poll::Ready(())
            }
        }
    }

    fn message_observation(
        &self,
        outgoing: bool,
        message: &Message,
    ) -> Option<WebSocketCaptureFuture> {
        let capture = self.capture_lease.as_ref()?;
        let message_type = self.mode.message_type(outgoing)?;
        into_har_message(message_type, message).map(|message| capture.record(message))
    }

    fn begin_message_observation(
        &mut self,
        outgoing: bool,
        message: &Message,
        close_after: bool,
    ) -> bool {
        if let Some(future) = self.message_observation(outgoing, message) {
            debug_assert!(self.pending_observation.is_none());
            self.pending_observation = Some(PendingObservation {
                future,
                close_after,
            });
            true
        } else {
            if close_after && self.close_on_terminal {
                if let Some(capture) = &self.capture_lease {
                    capture.close();
                }
                self.capture_lease.take();
            }
            false
        }
    }

    fn begin_error_observation(&mut self, error: &ProtocolError) -> bool {
        let Some(capture) = &self.capture_lease else {
            return false;
        };
        debug_assert!(self.pending_observation.is_none());
        self.pending_observation = Some(PendingObservation {
            future: capture.record(WebSocketMessage::error(
                epoch_seconds_from_millis(unix_timestamp_millis()),
                error.to_string(),
            )),
            close_after: self.close_on_terminal,
        });
        true
    }

    fn set_pending_observation(&mut self, future: WebSocketCaptureFuture) {
        debug_assert!(self.pending_observation.is_none());
        self.pending_observation = Some(PendingObservation {
            future,
            close_after: false,
        });
    }
}

impl<S: ExtensionsRef> ExtensionsRef for HARWebSocket<S> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

impl<S> Stream for HARWebSocket<S>
where
    S: Stream<Item = Result<Message, ProtocolError>> + Unpin,
{
    type Item = Result<Message, ProtocolError>;

    fn poll_next(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        ready!(this.poll_observation(ctx, ObservationSide::Read));
        if let Some(message) = this.pending_read.take() {
            return Poll::Ready(Some(message));
        }

        match ready!(Pin::new(&mut this.inner).poll_next(ctx)) {
            Some(Ok(message)) => {
                let close_after = matches!(&message, Message::Close(_));
                if this.begin_message_observation(false, &message, close_after) {
                    this.pending_read = Some(Ok(message));
                    ready!(this.poll_observation(ctx, ObservationSide::Read));
                    Poll::Ready(this.pending_read.take())
                } else {
                    Poll::Ready(Some(Ok(message)))
                }
            }
            Some(Err(error)) => {
                this.begin_error_observation(&error);
                if this.pending_observation.is_some() {
                    this.pending_read = Some(Err(error));
                    ready!(this.poll_observation(ctx, ObservationSide::Read));
                    Poll::Ready(this.pending_read.take())
                } else {
                    Poll::Ready(Some(Err(error)))
                }
            }
            None => {
                if this.close_on_terminal {
                    if let Some(capture) = &this.capture_lease {
                        capture.close();
                    }
                    this.capture_lease.take();
                }
                Poll::Ready(None)
            }
        }
    }
}

impl<S> Sink<Message> for HARWebSocket<S>
where
    S: Sink<Message, Error = ProtocolError> + Unpin,
{
    type Error = ProtocolError;

    fn poll_ready(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        ready!(this.poll_observation(ctx, ObservationSide::Write));
        if let Some(error) = this.pending_write_error.take() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_ready(ctx)
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        let this = self.get_mut();
        debug_assert!(this.pending_observation.is_none());
        let observation = this.message_observation(true, &item);
        match Pin::new(&mut this.inner).start_send(item) {
            Ok(()) => {
                if let Some(observation) = observation {
                    this.set_pending_observation(observation);
                }
                Ok(())
            }
            Err(error) => {
                drop(observation);
                if this.begin_error_observation(&error) {
                    this.pending_write_error = Some(error);
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        ready!(this.poll_observation(ctx, ObservationSide::Write));
        if let Some(error) = this.pending_write_error.take() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(ctx)
    }

    fn poll_close(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        ready!(this.poll_observation(ctx, ObservationSide::Write));
        if let Some(error) = this.pending_write_error.take() {
            return Poll::Ready(Err(error));
        }
        let result = ready!(Pin::new(&mut this.inner).poll_close(ctx));
        if this.close_on_terminal {
            if let Some(capture) = &this.capture_lease {
                capture.close();
            }
            this.capture_lease.take();
        }
        Poll::Ready(result)
    }
}

impl<S> HARWebSocket<S>
where
    S: Stream<Item = Result<Message, ProtocolError>> + Sink<Message, Error = ProtocolError> + Unpin,
{
    /// Write and flush one message.
    pub async fn send_message(&mut self, message: Message) -> Result<(), ProtocolError> {
        self.send(message).await
    }

    /// Receive one complete message.
    pub async fn recv_message(&mut self) -> Result<Message, ProtocolError> {
        self.next().await.ok_or_else(|| {
            ProtocolError::Io(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Connection closed: no messages to receive",
            ))
        })?
    }

    /// Close the WebSocket.
    pub async fn close(
        &mut self,
        message: Option<crate::protocol::CloseFrame>,
    ) -> Result<(), ProtocolError> {
        self.send(Message::Close(message)).await
    }
}

fn into_har_message(
    message_type: WebSocketMessageType,
    message: &Message,
) -> Option<WebSocketMessage> {
    let time = epoch_seconds_from_millis(unix_timestamp_millis());
    match message {
        Message::Text(data) => Some(WebSocketMessage::text(message_type, time, data.as_str())),
        Message::Binary(data) => Some(WebSocketMessage::binary(message_type, time, data)),
        Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => None,
    }
}

fn epoch_seconds_from_millis(timestamp: i64) -> f64 {
    timestamp as f64 / 1_000.0
}

#[cfg(test)]
mod tests {
    use super::{
        HARWebSocket, HARWebSocketLayer, ObservationSide, epoch_seconds_from_millis,
        into_har_message,
    };
    use crate::{
        AsyncWebSocket, Message,
        handshake::mitm::WebSocketBridge,
        protocol::{Role, WebSocketConfig, frame::Frame},
    };
    use parking_lot::Mutex;
    use rama_core::{
        Layer, Service, ServiceInput,
        error::BoxError,
        extensions::{Extensions, ExtensionsRef},
        futures::{Sink, SinkExt as _, Stream, StreamExt as _},
        service::service_fn,
    };
    use rama_http::layer::har::{
        recorder::{WebSocketCapture, WebSocketCaptureRecorder},
        spec::{WebSocketMessage, WebSocketMessageOpcode, WebSocketMessageType},
    };
    use std::{
        future::Future,
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::sync::Notify;

    #[derive(Default)]
    struct TestState {
        messages: Mutex<Vec<WebSocketMessage>>,
        closes: AtomicUsize,
    }

    struct TestRecorder(Arc<TestState>);

    impl WebSocketCaptureRecorder for TestRecorder {
        async fn record(&self, message: WebSocketMessage) -> Result<(), BoxError> {
            self.0.messages.lock().push(message);
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, rama_core::extensions::Extension)]
    struct TestExtension(u8);

    #[derive(Debug, Default)]
    struct DelegatingSocketState {
        ready: AtomicUsize,
        closes: AtomicUsize,
        messages: Mutex<Vec<Message>>,
    }

    #[derive(Debug)]
    struct DelegatingSocket {
        extensions: Extensions,
        state: Arc<DelegatingSocketState>,
    }

    impl ExtensionsRef for DelegatingSocket {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl Stream for DelegatingSocket {
        type Item = Result<Message, crate::ProtocolError>;

        fn poll_next(self: Pin<&mut Self>, _ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Sink<Message> for DelegatingSocket {
        type Error = crate::ProtocolError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _ctx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.state.ready.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.state.messages.lock().push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _ctx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _ctx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.state.closes.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct ReadinessState {
        ready: AtomicBool,
        polls: AtomicUsize,
        notify: Notify,
        messages: Mutex<Vec<WebSocketMessage>>,
    }

    struct StallingRecorder(Arc<ReadinessState>);

    impl WebSocketCaptureRecorder for StallingRecorder {
        async fn record(&self, message: WebSocketMessage) -> Result<(), BoxError> {
            loop {
                let notified = self.0.notify.notified();
                if self.0.ready.swap(false, Ordering::AcqRel) {
                    break;
                }
                tokio::pin!(notified);
                std::future::poll_fn(|ctx| {
                    self.0.polls.fetch_add(1, Ordering::AcqRel);
                    notified.as_mut().poll(ctx)
                })
                .await;
            }
            self.0.messages.lock().push(message);
            Ok(())
        }
    }

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn observation_waker_wakes_both_sides_by_ref() {
        let observation_wakers = Arc::new(super::ObservationWakers::new());
        let read = Arc::new(WakeCounter::default());
        let write = Arc::new(WakeCounter::default());
        observation_wakers.register(ObservationSide::Read, &Waker::from(read.clone()));
        observation_wakers.register(ObservationSide::Write, &Waker::from(write.clone()));

        Waker::from(observation_wakers).wake_by_ref();

        assert_eq!(read.0.load(Ordering::Acquire), 1);
        assert_eq!(write.0.load(Ordering::Acquire), 1);
    }

    #[derive(Clone, Copy)]
    enum WriteBehavior {
        Pending,
        BrokenPipe,
    }

    struct TestIo(WriteBehavior);

    impl AsyncRead for TestIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _ctx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _ctx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.0 {
                WriteBehavior::Pending => Poll::Pending,
                WriteBehavior::BrokenPipe => {
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn socket_with_write_behavior(
        behavior: WriteBehavior,
        state: Arc<TestState>,
    ) -> HARWebSocket<AsyncWebSocket<ServiceInput<TestIo>>> {
        let socket = AsyncWebSocket::from_raw_socket(
            ServiceInput::new(TestIo(behavior)),
            Role::Client,
            Some(WebSocketConfig::default().with_write_buffer_size(0)),
        )
        .await;
        HARWebSocket::new(
            socket,
            Role::Client,
            Some(WebSocketCapture::new(
                TestRecorder(state.clone()),
                move || {
                    state.closes.fetch_add(1, Ordering::AcqRel);
                },
            )),
        )
    }

    #[tokio::test]
    async fn start_send_distinguishes_backpressure_from_fatal_io() {
        let pending_sink = Arc::new(TestState::default());
        let mut pending =
            socket_with_write_behavior(WriteBehavior::Pending, pending_sink.clone()).await;
        std::future::poll_fn(|ctx| Sink::poll_ready(Pin::new(&mut pending), ctx))
            .await
            .expect("pending socket ready");
        Sink::start_send(Pin::new(&mut pending), Message::text("queued"))
            .expect("WouldBlock means the frame was accepted into the write buffer");
        std::future::poll_fn(|ctx| pending.poll_observation(ctx, ObservationSide::Write)).await;
        {
            let pending_messages = pending_sink.messages.lock();
            assert_eq!(pending_messages.len(), 1);
            assert_eq!(pending_messages[0].r#type, WebSocketMessageType::Send);
            assert_eq!(pending_messages[0].data.as_str(), "queued");
        }

        let broken_sink = Arc::new(TestState::default());
        let mut broken =
            socket_with_write_behavior(WriteBehavior::BrokenPipe, broken_sink.clone()).await;
        broken
            .send_message(Message::text("rejected"))
            .await
            .expect_err("normal send flow returns the transport error after recording it");
        let broken_messages = broken_sink.messages.lock();
        assert_eq!(broken_messages.len(), 1);
        assert_eq!(broken_messages[0].r#type, WebSocketMessageType::Error);
        assert_eq!(broken_messages[0].opcode, WebSocketMessageOpcode::ERROR);
        drop(broken_messages);
        assert_eq!(broken_sink.closes.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn async_recorder_backpressures_web_socket_sends() {
        let sink = Arc::new(ReadinessState::default());
        let socket = AsyncWebSocket::from_raw_socket(
            ServiceInput::new(TestIo(WriteBehavior::Pending)),
            Role::Client,
            None,
        )
        .await;
        let mut socket = HARWebSocket::new(
            socket,
            Role::Client,
            Some(WebSocketCapture::new(StallingRecorder(sink.clone()), || {})),
        );
        std::future::poll_fn(|ctx| Sink::poll_ready(Pin::new(&mut socket), ctx))
            .await
            .expect("socket initially ready");
        Sink::start_send(Pin::new(&mut socket), Message::text("bounded"))
            .expect("socket accepts message before recording it");

        let mut observation = Box::pin(std::future::poll_fn(|ctx| {
            socket.poll_observation(ctx, ObservationSide::Write)
        }));
        assert!(rama_core::futures::poll!(&mut observation).is_pending());
        sink.ready.store(true, Ordering::Release);
        sink.notify.notify_one();
        observation.await;

        let messages = sink.messages.lock();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data.as_str(), "bounded");
    }

    #[tokio::test]
    async fn async_recorder_backpressures_incoming_web_socket_messages() {
        let sink = Arc::new(ReadinessState::default());
        let (server_io, client_io) = tokio::io::duplex(1024);
        let server =
            AsyncWebSocket::from_raw_socket(ServiceInput::new(server_io), Role::Server, None).await;
        let mut server = HARWebSocket::new(
            server,
            Role::Server,
            Some(WebSocketCapture::new(StallingRecorder(sink.clone()), || {})),
        );
        let mut client =
            AsyncWebSocket::from_raw_socket(ServiceInput::new(client_io), Role::Client, None).await;

        client
            .send_message(Message::text("incoming"))
            .await
            .expect("send test message");
        let mut receive = Box::pin(server.recv_message());
        assert!(rama_core::futures::poll!(&mut receive).is_pending());
        sink.ready.store(true, Ordering::Release);
        sink.notify.notify_one();

        assert_eq!(receive.await.unwrap(), Message::text("incoming"));
        let messages = sink.messages.lock();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data.as_str(), "incoming");
    }

    #[tokio::test]
    async fn split_socket_keeps_independent_recorder_wakers() {
        let recorder_state = Arc::new(ReadinessState::default());
        let socket_state = Arc::new(DelegatingSocketState::default());
        let socket = HARWebSocket::new(
            DelegatingSocket {
                extensions: Extensions::new(),
                state: socket_state.clone(),
            },
            Role::Client,
            Some(WebSocketCapture::new(
                StallingRecorder(recorder_state.clone()),
                || {},
            )),
        );
        let (mut writer, mut reader) = socket.split();

        let writer_task = tokio::spawn(async move { writer.send(Message::text("split")).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while recorder_state.polls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer polls the recorder");

        let reader_task = tokio::spawn(async move { reader.next().await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while recorder_state.polls.load(Ordering::Acquire) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reader repolls the pending recorder future");

        // The reader was the last task to poll the recorder future. Cancelling
        // it must not strand the writer's earlier waiter.
        reader_task.abort();
        _ = reader_task.await;

        recorder_state.ready.store(true, Ordering::Release);
        recorder_state.notify.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), writer_task)
            .await
            .expect("split writer is woken after recorder completion")
            .expect("writer task succeeds")
            .expect("split send succeeds");
    }

    #[tokio::test]
    async fn relay_layer_claims_only_egress_capture() {
        let ingress_capture =
            WebSocketCapture::new(TestRecorder(Arc::new(TestState::default())), || {});
        let egress_capture =
            WebSocketCapture::new(TestRecorder(Arc::new(TestState::default())), || {});

        let ingress_extensions = Extensions::new();
        ingress_extensions.insert(ingress_capture.clone());
        let egress_extensions = Extensions::new();
        egress_extensions.insert(egress_capture.clone());

        let inner = service_fn(
            |bridge: WebSocketBridge<
                HARWebSocket<DelegatingSocket>,
                HARWebSocket<DelegatingSocket>,
            >| async move {
                assert!(bridge.ingress.capture_lease.is_some());
                assert!(bridge.egress.capture_lease.is_some());
                Ok::<_, std::convert::Infallible>(())
            },
        );
        HARWebSocketLayer::new()
            .into_layer(inner)
            .serve(WebSocketBridge::new(
                DelegatingSocket {
                    extensions: ingress_extensions,
                    state: Arc::new(DelegatingSocketState::default()),
                },
                DelegatingSocket {
                    extensions: egress_extensions,
                    state: Arc::new(DelegatingSocketState::default()),
                },
            ))
            .await
            .expect("HAR relay layer is infallible");

        let ingress_lease = ingress_capture
            .lease()
            .expect("ingress capture remains unclaimed");
        assert!(
            egress_capture.lease().is_none(),
            "egress capture was claimed for the relay"
        );
        drop(ingress_lease);
    }

    #[tokio::test]
    async fn server_role_uses_client_perspective() {
        let sink = Arc::new(TestState::default());
        let socket = AsyncWebSocket::from_raw_socket(
            ServiceInput::new(tokio::io::duplex(1024).0),
            Role::Server,
            None,
        )
        .await;
        let mut socket = HARWebSocket::new(
            socket,
            Role::Server,
            Some(WebSocketCapture::new(TestRecorder(sink.clone()), || {})),
        );

        assert!(socket.begin_message_observation(false, &Message::text("from-client"), false));
        std::future::poll_fn(|ctx| socket.poll_observation(ctx, ObservationSide::Read)).await;
        assert!(socket.begin_message_observation(true, &Message::binary(vec![1, 2]), false));
        std::future::poll_fn(|ctx| socket.poll_observation(ctx, ObservationSide::Write)).await;

        let messages = sink.messages.lock();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].r#type, WebSocketMessageType::Send);
        assert_eq!(messages[0].opcode, WebSocketMessageOpcode::TEXT);
        assert_eq!(messages[1].r#type, WebSocketMessageType::Receive);
        assert_eq!(messages[1].opcode, WebSocketMessageOpcode::BINARY);
    }

    #[tokio::test]
    async fn wrapper_delegates_socket_contract_and_convenience_methods() {
        let extensions = Extensions::new();
        extensions.insert(TestExtension(42));
        let state = Arc::new(DelegatingSocketState::default());
        let mut socket = HARWebSocket::new(
            DelegatingSocket {
                extensions,
                state: state.clone(),
            },
            Role::Client,
            None,
        );

        assert_eq!(
            socket.extensions().get_ref::<TestExtension>(),
            Some(&TestExtension(42))
        );
        std::future::poll_fn(|ctx| Sink::poll_ready(Pin::new(&mut socket), ctx))
            .await
            .expect("inner sink ready");
        socket
            .send_message(Message::text("message"))
            .await
            .expect("send convenience method delegates");
        socket
            .close(None)
            .await
            .expect("close convenience method delegates");
        std::future::poll_fn(|ctx| Sink::poll_close(Pin::new(&mut socket), ctx))
            .await
            .expect("inner sink closes");

        assert_eq!(state.ready.load(Ordering::Acquire), 3);
        assert_eq!(state.closes.load(Ordering::Acquire), 1);
        assert_eq!(
            *state.messages.lock(),
            vec![Message::text("message"), Message::Close(None)]
        );
        assert!(format!("{socket:?}").contains("HARWebSocket"));
    }

    #[test]
    fn pending_observation_debug_exposes_capture_state() {
        let capture = WebSocketCapture::new(TestRecorder(Arc::new(TestState::default())), || {});
        let lease = capture.lease().expect("capture lease");
        let observation = super::PendingObservation {
            future: lease.record(WebSocketMessage::text(
                WebSocketMessageType::Send,
                1.0,
                "message",
            )),
            close_after: true,
        };

        let debug = format!("{observation:?}");
        assert!(debug.contains("PendingObservation"));
        assert!(debug.contains("close_after: true"));
    }

    #[test]
    fn har_messages_encode_complete_data_messages() {
        let cases = [
            (
                Message::text("hello"),
                WebSocketMessageOpcode::TEXT,
                "hello",
            ),
            (
                Message::binary(vec![0_u8, 1, 0xff]),
                WebSocketMessageOpcode::BINARY,
                "AAH/",
            ),
        ];

        for (message, opcode, data) in cases {
            let message = into_har_message(WebSocketMessageType::Send, &message)
                .expect("complete data message");
            assert_eq!(message.r#type, WebSocketMessageType::Send);
            assert_eq!(message.opcode, opcode);
            assert_eq!(message.data.as_str(), data);
            assert!(message.time > 1_700_000_000.0);
        }
    }

    #[test]
    fn har_messages_skip_control_and_raw_frames() {
        for message in [
            Message::Ping(vec![2, 3].into()),
            Message::Pong(vec![4, 5].into()),
            Message::Close(None),
            Message::Frame(Frame::ping(rama_core::bytes::Bytes::from_static(&[6]))),
        ] {
            assert!(into_har_message(WebSocketMessageType::Send, &message).is_none());
        }
    }

    #[test]
    fn har_timestamp_conversion_preserves_milliseconds() {
        assert_eq!(
            epoch_seconds_from_millis(1_558_730_482_507),
            1_558_730_482.507
        );
    }
}
