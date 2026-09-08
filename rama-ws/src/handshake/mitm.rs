use std::{collections::VecDeque, convert::Infallible, num::NonZeroUsize, time::Duration};

use rama_core::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, ErrorExt},
    extensions::{self, Extensions, ExtensionsRef},
    futures::{
        Sink, SinkExt as _, Stream, StreamExt as _,
        channel::{mpsc, oneshot},
    },
    io::{BridgeIo, Io},
    service::MirrorService,
    telemetry::tracing,
};
use tokio::sync::{mpsc as tokio_mpsc, watch};

use crate::{
    AsyncWebSocket, ProtocolError, Utf8Bytes, WebSocketIo,
    handshake::matcher::RelayWebSocketConfig,
    protocol::{CloseFrame, Role, frame::coding::CloseCode},
};

const DEFAULT_CLOSE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_WRITER_QUEUE_CAPACITY: usize = 8;
const DEFAULT_MESSAGE_INJECTION_QUEUE_CAPACITY: NonZeroUsize = NonZeroUsize::new(16).unwrap();
const DEFAULT_MAX_INJECTED_MESSAGE_SIZE: usize = 16 << 20;

/// Opt in to bounded reading while relay middleware awaits an external decision.
///
/// Insert this extension on each transport that should keep reading. Application
/// data stays ordered and control events are observed after earlier middleware
/// completes, but ping replies and peer-initiated close are handled immediately.
/// Exceeding either bound closes both legs with code 1009. Without this extension,
/// the relay applies ordinary backpressure without reading ahead.
#[derive(Debug, Clone, Copy)]
pub struct WebSocketRelayReadAhead {
    /// Maximum number of messages retained per direction.
    pub max_messages: NonZeroUsize,
    /// Maximum combined payload bytes retained per direction.
    pub max_bytes: NonZeroUsize,
}

impl extensions::Extension for WebSocketRelayReadAhead {}

/// A pair of established WebSocket message transports joined by a relay.
///
/// The ingress side faces the downstream client and uses the server protocol
/// role. The egress side faces the upstream server and uses the client role.
/// Keeping this boundary distinct from [`BridgeIo`] lets ordinary Rama layers
/// decorate complete WebSocket messages without entering the protocol runtime
/// or decoding raw bytes themselves. The bridge deliberately does not select
/// one side as its extension source; use [`Self::ingress`] or [`Self::egress`]
/// to access the intended transport explicitly.
#[derive(Debug)]
pub struct WebSocketBridge<Ingress, Egress> {
    /// Message transport facing the downstream client.
    pub ingress: Ingress,
    /// Message transport facing the upstream server.
    pub egress: Egress,
}

/// Adapt a raw byte-level [`BridgeIo`] into a [`WebSocketBridge`] before
/// invoking an inner service.
///
/// This adapter is useful when message-level layers must sit between protocol
/// construction and a relay. Existing [`WebSocketRelayService`] and
/// [`WebSocketRelayEventService`] values continue to accept raw [`BridgeIo`]
/// directly for backwards compatibility.
#[derive(Debug, Clone)]
pub struct WebSocketRelayIoService<S> {
    inner: S,
}

/// Layer that adapts a raw byte-level [`BridgeIo`] into a message-level
/// [`WebSocketBridge`].
#[derive(Debug, Clone, Copy, Default)]
pub struct WebSocketRelayIoLayer;

impl WebSocketRelayIoLayer {
    /// Create a WebSocket relay I/O adapter layer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for WebSocketRelayIoLayer {
    type Service = WebSocketRelayIoService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WebSocketRelayIoService::new(inner)
    }
}

impl<S> WebSocketRelayIoService<S> {
    /// Create a raw-I/O adapter for a message-level WebSocket service.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    /// Return a reference to the inner message-level service.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Consume this adapter and return its inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S, Ingress, Egress> Service<BridgeIo<Ingress, Egress>> for WebSocketRelayIoService<S>
where
    S: Service<WebSocketBridge<AsyncWebSocket<Ingress>, AsyncWebSocket<Egress>>>,
    Ingress: Io + Unpin + ExtensionsRef,
    Egress: Io + Unpin + ExtensionsRef,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, bridge: BridgeIo<Ingress, Egress>) -> Result<Self::Output, Self::Error> {
        self.inner
            .serve(upgrade_websocket_bridge(bridge).await)
            .await
    }
}

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay WebSocket messages.
///
/// By default they get mirrored but the logic is fully up to you.
///
/// This service accepts both a raw [`BridgeIo`] and an established
/// [`WebSocketBridge`]. Direct raw-I/O use remains convenient and backwards
/// compatible. To install message-level layers, wrap this service in those
/// layers and then place [`WebSocketRelayIoService`] around the result.
///
/// ## KISS
///
/// This service is for simple DPI purposes.
///
/// Ping and pong are handled locally on each of the two independent WebSocket
/// connections and are not exposed to middleware. A ping is acknowledged on
/// its source connection and also produces an unsolicited pong heartbeat on
/// the opposite connection, so activity on one leg keeps both legs alive
/// without coupling their ping round trips. Other pongs are not forwarded. An
/// incoming close starts coordinated shutdown; data received while closing is
/// discarded rather than passed to middleware.
///
/// Middleware is processed independently per direction. Its future can be
/// cancelled when either peer starts closing, so it must be cancel-safe. A
/// failure to send middleware-produced data terminates the relay.
///
/// Use [`WebSocketRelayEventService`] when middleware also needs to observe
/// control messages. Fork or create your own relay service for lower-level
/// purposes such as preserving raw frame boundaries.
pub struct WebSocketRelayService<S = MirrorService> {
    middleware: S,
    close_handshake_timeout: Duration,
    message_injection: bool,
    message_injection_queue_capacity: NonZeroUsize,
    max_injected_message_size: Option<usize>,
}

impl<S> WebSocketRelayService<S> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`WebSocketRelayService`]
    pub fn new(middleware: S) -> Self {
        Self {
            middleware,
            close_handshake_timeout: DEFAULT_CLOSE_HANDSHAKE_TIMEOUT,
            message_injection: false,
            message_injection_queue_capacity: DEFAULT_MESSAGE_INJECTION_QUEUE_CAPACITY,
            max_injected_message_size: Some(DEFAULT_MAX_INJECTED_MESSAGE_SIZE),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set how long the relay waits for both peers to finish a coordinated
        /// close handshake before dropping the connections.
        ///
        /// The default is five seconds. Both connections and their relay state
        /// remain alive until the handshake finishes or this timeout expires.
        pub fn close_handshake_timeout(mut self, timeout: Duration) -> Self {
            self.close_handshake_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable external application-data injection through a
        /// [`WebSocketRelayInjector`] exposed to middleware extensions.
        ///
        /// Disabled by default, avoiding the liveness channel and extension
        /// storage for relays that do not need external message injection.
        pub fn message_injection(mut self, enabled: bool) -> Self {
            self.message_injection = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum number of injected messages waiting per relay side.
        ///
        /// The default is 16. Once full,
        /// [`WebSocketRelayInjector::send`] returns
        /// [`ProtocolError::WriteBufferFull`] without disturbing relay traffic.
        pub fn message_injection_queue_capacity(mut self, capacity: NonZeroUsize) -> Self {
            self.message_injection_queue_capacity = capacity;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum payload size accepted from a relay injector.
        ///
        /// The default is 16 MiB. Use
        /// [`Self::without_max_injected_message_size`] to disable this
        /// injector-side limit; the destination WebSocket's own write limits
        /// still apply.
        pub fn max_injected_message_size(mut self, max_size: Option<usize>) -> Self {
            self.max_injected_message_size = max_size;
            self
        }
    }
}

#[derive(Debug, Clone)]
/// A WebSocket MITM relay that exposes every message observable through the
/// high-level WebSocket protocol API to its middleware.
///
/// Like [`WebSocketRelayService`], this accepts either raw [`BridgeIo`] or an
/// established [`WebSocketBridge`]. Use [`WebSocketRelayIoService`] when
/// message-level layers must run between protocol construction and this relay.
///
/// Unlike [`WebSocketRelayService`], this service exposes ping, pong and close
/// events. Control messages remain owned by the relay: a ping is acknowledged
/// locally and produces an unsolicited pong heartbeat on the opposite
/// connection, while other pongs are not forwarded. An incoming close always
/// starts coordinated shutdown.
///
/// Middleware is processed independently per direction. Its future can be
/// cancelled when either peer starts closing, so it must be cancel-safe. Data
/// received after shutdown starts is discarded rather than exposed, and a
/// failure to send middleware-produced data terminates the relay.
pub struct WebSocketRelayEventService<S = MirrorService> {
    middleware: S,
    close_handshake_timeout: Duration,
    message_injection: bool,
    message_injection_queue_capacity: NonZeroUsize,
    max_injected_message_size: Option<usize>,
}

impl<S> WebSocketRelayEventService<S> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`WebSocketRelayEventService`].
    pub fn new(middleware: S) -> Self {
        Self {
            middleware,
            close_handshake_timeout: DEFAULT_CLOSE_HANDSHAKE_TIMEOUT,
            message_injection: false,
            message_injection_queue_capacity: DEFAULT_MESSAGE_INJECTION_QUEUE_CAPACITY,
            max_injected_message_size: Some(DEFAULT_MAX_INJECTED_MESSAGE_SIZE),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set how long the relay waits for both peers to finish a coordinated
        /// close handshake before dropping the connections.
        ///
        /// The default is five seconds. Both connections and their relay state
        /// remain alive until the handshake finishes or this timeout expires.
        pub fn close_handshake_timeout(mut self, timeout: Duration) -> Self {
            self.close_handshake_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable external application-data injection through a
        /// [`WebSocketRelayInjector`] exposed to middleware extensions.
        ///
        /// Disabled by default, avoiding the liveness channel and extension
        /// storage for relays that do not need external message injection.
        pub fn message_injection(mut self, enabled: bool) -> Self {
            self.message_injection = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum number of injected messages waiting per relay side.
        ///
        /// The default is 16. Once full,
        /// [`WebSocketRelayInjector::send`] returns
        /// [`ProtocolError::WriteBufferFull`] without disturbing relay traffic.
        pub fn message_injection_queue_capacity(mut self, capacity: NonZeroUsize) -> Self {
            self.message_injection_queue_capacity = capacity;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum payload size accepted from a relay injector.
        ///
        /// The default is 16 MiB. Use
        /// [`Self::without_max_injected_message_size`] to disable this
        /// injector-side limit; the destination WebSocket's own write limits
        /// still apply.
        pub fn max_injected_message_size(mut self, max_size: Option<usize>) -> Self {
            self.max_injected_message_size = max_size;
            self
        }
    }
}

#[derive(Debug, Clone)]
/// Most typically used as Input
/// for users of [`WebSocketRelayService`].
pub struct WebSocketRelayInput {
    pub direction: WebSocketRelayDirection,
    pub message: WebSocketRelayMessage,
    pub extensions: Extensions,
}

impl ExtensionsRef for WebSocketRelayInput {
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

#[derive(Debug, Clone)]
/// Most typically used as Output
/// for users of [`WebSocketRelayService`].
pub struct WebSocketRelayOutput {
    /// 0 or more messages, providing the ability
    /// to drop messages first and return buffered messages later.
    /// Messages are sent to the opposite WebSocket connection.
    pub messages: Vec<WebSocketRelayMessage>,
    /// Per-direction relay state. Middleware should normally return the input
    /// store (or a derivative of it); replacing it with a fresh store also
    /// replaces its connection-extension parent link.
    pub extensions: Extensions,
}

impl From<WebSocketRelayInput> for WebSocketRelayOutput {
    fn from(value: WebSocketRelayInput) -> Self {
        let WebSocketRelayInput {
            direction: _,
            message,
            extensions,
        } = value;

        Self {
            messages: vec![message],
            extensions,
        }
    }
}

impl ExtensionsRef for WebSocketRelayOutput {
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

#[derive(Debug, Clone)]
/// Input for middleware used by [`WebSocketRelayEventService`].
pub struct WebSocketRelayEventInput {
    pub direction: WebSocketRelayDirection,
    pub event: WebSocketRelayEvent,
    pub extensions: Extensions,
}

impl ExtensionsRef for WebSocketRelayEventInput {
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

#[derive(Debug, Clone)]
/// Output for middleware used by [`WebSocketRelayEventService`].
pub struct WebSocketRelayEventOutput {
    /// Zero or more data messages to send to the opposite WebSocket connection.
    ///
    /// Ping, pong and raw frames cannot be produced through this API.
    pub messages: Vec<WebSocketRelayMessage>,
    /// Optionally request coordinated shutdown of both WebSocket connections.
    /// Messages are sent before a valid requested shutdown starts.
    ///
    /// When serving [`WebSocketRelayEvent::Close`], shutdown has already been
    /// initiated by the relay and both `messages` and `close` are ignored.
    pub close: Option<WebSocketRelayClose>,
    /// Per-direction relay state. Middleware should normally return the input
    /// store (or a derivative of it); replacing it with a fresh store also
    /// replaces its connection-extension parent link.
    pub extensions: Extensions,
}

impl From<WebSocketRelayEventInput> for WebSocketRelayEventOutput {
    fn from(value: WebSocketRelayEventInput) -> Self {
        let WebSocketRelayEventInput {
            direction: _,
            event,
            extensions,
        } = value;

        let messages = match event {
            WebSocketRelayEvent::Data(message) => vec![message],
            WebSocketRelayEvent::Open
            | WebSocketRelayEvent::Ping(_)
            | WebSocketRelayEvent::Pong(_)
            | WebSocketRelayEvent::Close(_) => Vec::new(),
        };

        Self {
            messages,
            close: None,
            extensions,
        }
    }
}

impl ExtensionsRef for WebSocketRelayEventOutput {
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
/// A message observed by [`WebSocketRelayEventService`] middleware.
///
/// Raw [`crate::protocol::frame::Frame`] values are intentionally absent:
/// [`crate::Message::Frame`] is send-only and is never returned while reading.
pub enum WebSocketRelayEvent {
    /// The relay direction is ready. When message injection is enabled, its
    /// [`WebSocketRelayInjector`] is already available in the event
    /// extensions. Output messages and close requests are ignored for this
    /// observation-only lifecycle event.
    Open,
    /// An application data message.
    Data(WebSocketRelayMessage),
    /// A ping received from one WebSocket peer.
    Ping(Bytes),
    /// A pong received from one WebSocket peer.
    Pong(Bytes),
    /// A close received from one WebSocket peer.
    Close(Option<CloseFrame>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
/// A coordinated close requested by [`WebSocketRelayEventOutput`].
///
/// This enum distinguishes no close request (`None`) from a close message that
/// intentionally carries no status code or reason ([`Self::WithoutFrame`]).
pub enum WebSocketRelayClose {
    /// Close without a status code or reason.
    WithoutFrame,
    /// Close with a status code and optional reason.
    ///
    /// The relay rejects codes that cannot appear on the wire and reasons
    /// longer than 123 bytes. The entire middleware output is then rejected:
    /// its messages are discarded and both connections close with status 1011.
    WithFrame(CloseFrame),
}

impl From<Option<CloseFrame>> for WebSocketRelayClose {
    fn from(value: Option<CloseFrame>) -> Self {
        match value {
            Some(frame) => Self::WithFrame(frame),
            None => Self::WithoutFrame,
        }
    }
}

impl WebSocketRelayClose {
    fn into_frame(self) -> Option<CloseFrame> {
        match self {
            Self::WithoutFrame => None,
            Self::WithFrame(frame) => Some(frame),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
/// Non-meta WebSocket messages, used as part of [`WebSocketRelayInput`]
/// and [`WebSocketRelayOutput`], most typically for users of [`WebSocketRelayService`].
pub enum WebSocketRelayMessage {
    /// A text WebSocket message
    Text(Utf8Bytes),
    /// A binary WebSocket message
    Binary(Bytes),
}

impl From<WebSocketRelayMessage> for crate::protocol::Message {
    fn from(value: WebSocketRelayMessage) -> Self {
        match value {
            WebSocketRelayMessage::Text(utf8_bytes) => Self::Text(utf8_bytes),
            WebSocketRelayMessage::Binary(bytes) => Self::Binary(bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
/// Direction data used as part of [`WebSocketRelayInput`],
/// most typically for users of [`WebSocketRelayService`].
pub enum WebSocketRelayDirection {
    Ingress,
    Egress,
}

/// A handle for injecting application data into a live WebSocket MITM relay.
///
/// Relay middleware can retrieve this handle from its extensions after
/// message injection is enabled on the relay service.
///
/// The supplied [`WebSocketRelayDirection`] describes the direction the
/// message travels: ingress messages are sent to the upstream peer, while
/// egress messages are sent to the downstream peer. Injected messages bypass
/// relay middleware because they did not originate from either peer.
#[derive(Clone)]
pub struct WebSocketRelayInjector {
    ingress: tokio_mpsc::Sender<WriterCommand>,
    egress: tokio_mpsc::Sender<WriterCommand>,
    liveness: watch::Receiver<bool>,
    max_message_size: Option<usize>,
}

impl std::fmt::Debug for WebSocketRelayInjector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketRelayInjector")
            .field("ingress_open", &!self.ingress.is_closed())
            .field("egress_open", &!self.egress.is_closed())
            .finish()
    }
}

impl extensions::Extension for WebSocketRelayInjector {}

impl WebSocketRelayInjector {
    /// Returns whether both sides of the relay can still accept injected data.
    #[must_use]
    pub fn is_open(&self) -> bool {
        *self.liveness.borrow() && !self.ingress.is_closed() && !self.egress.is_closed()
    }

    /// Maximum accepted payload size, or `None` if the relay has no size limit.
    /// Inspectors can check recorded lengths before loading message bytes.
    #[must_use]
    pub fn max_message_size(&self) -> Option<usize> {
        self.max_message_size
    }

    /// Wait until the relay has stopped accepting injected messages.
    pub async fn closed(&self) {
        let mut liveness = self.liveness.clone();
        loop {
            if !*liveness.borrow() {
                return;
            }
            if liveness.changed().await.is_err() {
                return;
            }
        }
    }

    /// Send an application data message through the live relay.
    ///
    /// This resolves only after the destination WebSocket sink accepted and
    /// flushed the message. A full injection queue returns
    /// [`ProtocolError::WriteBufferFull`] with the original message, an
    /// oversized payload returns [`ProtocolError::MessageTooLong`], and a
    /// closed relay is reported as an I/O-flavoured [`ProtocolError`].
    pub async fn send(
        &self,
        direction: WebSocketRelayDirection,
        message: WebSocketRelayMessage,
    ) -> Result<(), ProtocolError> {
        if !self.is_open() {
            return Err(relay_injector_closed());
        }
        let message_size = match &message {
            WebSocketRelayMessage::Text(text) => text.len(),
            WebSocketRelayMessage::Binary(bytes) => bytes.len(),
        };
        if let Some(max_size) = self.max_message_size
            && message_size > max_size
        {
            return Err(ProtocolError::MessageTooLong {
                size: message_size,
                max_size,
            });
        }
        let writer = match direction {
            WebSocketRelayDirection::Ingress => &self.ingress,
            WebSocketRelayDirection::Egress => &self.egress,
        };
        let (response, receiver) = oneshot::channel();
        match writer.try_send(WriterCommand::Send {
            message: message.into(),
            response,
        }) {
            Ok(()) => {}
            Err(tokio_mpsc::error::TrySendError::Full(WriterCommand::Send { message, .. })) => {
                return Err(ProtocolError::WriteBufferFull(message));
            }
            Err(tokio_mpsc::error::TrySendError::Closed(_)) => {
                return Err(relay_injector_closed());
            }
            Err(tokio_mpsc::error::TrySendError::Full(WriterCommand::Flush { .. })) => {
                return Err(ProtocolError::Io(std::io::Error::other(
                    "WebSocket injector queued an invalid flush command",
                )));
            }
        };
        match receiver.await {
            Ok(result) => result,
            Err(_) => Err(relay_injector_closed()),
        }
    }
}

fn relay_injector_closed() -> ProtocolError {
    ProtocolError::Io(std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "WebSocket MITM relay is closed",
    ))
}

impl<S, Ingress, Egress> Service<BridgeIo<Ingress, Egress>> for WebSocketRelayService<S>
where
    S: Service<WebSocketRelayInput, Output: Into<WebSocketRelayOutput>, Error: Into<BoxError>>,
    Ingress: Io + Unpin + extensions::ExtensionsRef,
    Egress: Io + Unpin + extensions::ExtensionsRef,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, bridge: BridgeIo<Ingress, Egress>) -> Result<Self::Output, Self::Error> {
        let WebSocketBridge {
            ingress: ingress_socket,
            egress: egress_socket,
        } = upgrade_websocket_bridge(bridge).await;
        relay_websocket_bridge(
            MessageRelayHandler {
                middleware: &self.middleware,
            },
            ingress_socket,
            egress_socket,
            self.close_handshake_timeout,
            self.message_injection,
            self.message_injection_queue_capacity,
            self.max_injected_message_size,
        )
        .await;
        Ok(())
    }
}

impl<S, Ingress, Egress> Service<WebSocketBridge<Ingress, Egress>> for WebSocketRelayService<S>
where
    S: Service<WebSocketRelayInput, Output: Into<WebSocketRelayOutput>, Error: Into<BoxError>>,
    Ingress: WebSocketIo,
    Egress: WebSocketIo,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(
        &self,
        WebSocketBridge {
            ingress: ingress_socket,
            egress: egress_socket,
        }: WebSocketBridge<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        relay_websocket_bridge(
            MessageRelayHandler {
                middleware: &self.middleware,
            },
            ingress_socket,
            egress_socket,
            self.close_handshake_timeout,
            self.message_injection,
            self.message_injection_queue_capacity,
            self.max_injected_message_size,
        )
        .await;
        Ok(())
    }
}

impl<S, Ingress, Egress> Service<BridgeIo<Ingress, Egress>> for WebSocketRelayEventService<S>
where
    S: Service<
            WebSocketRelayEventInput,
            Output: Into<WebSocketRelayEventOutput>,
            Error: Into<BoxError>,
        >,
    Ingress: Io + Unpin + extensions::ExtensionsRef,
    Egress: Io + Unpin + extensions::ExtensionsRef,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, bridge: BridgeIo<Ingress, Egress>) -> Result<Self::Output, Self::Error> {
        let WebSocketBridge {
            ingress: ingress_socket,
            egress: egress_socket,
        } = upgrade_websocket_bridge(bridge).await;
        relay_websocket_bridge(
            EventRelayHandler {
                middleware: &self.middleware,
            },
            ingress_socket,
            egress_socket,
            self.close_handshake_timeout,
            self.message_injection,
            self.message_injection_queue_capacity,
            self.max_injected_message_size,
        )
        .await;
        Ok(())
    }
}

impl<S, Ingress, Egress> Service<WebSocketBridge<Ingress, Egress>> for WebSocketRelayEventService<S>
where
    S: Service<
            WebSocketRelayEventInput,
            Output: Into<WebSocketRelayEventOutput>,
            Error: Into<BoxError>,
        >,
    Ingress: WebSocketIo,
    Egress: WebSocketIo,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(
        &self,
        WebSocketBridge {
            ingress: ingress_socket,
            egress: egress_socket,
        }: WebSocketBridge<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        relay_websocket_bridge(
            EventRelayHandler {
                middleware: &self.middleware,
            },
            ingress_socket,
            egress_socket,
            self.close_handshake_timeout,
            self.message_injection,
            self.message_injection_queue_capacity,
            self.max_injected_message_size,
        )
        .await;
        Ok(())
    }
}

struct RelayHandlerOutput {
    messages: Vec<WebSocketRelayMessage>,
    close: Option<WebSocketRelayClose>,
    extensions: Extensions,
}

trait RelayHandler {
    fn serve(
        &self,
        direction: WebSocketRelayDirection,
        event: WebSocketRelayEvent,
        extensions: Extensions,
    ) -> impl Future<Output = Result<RelayHandlerOutput, BoxError>> + Send + '_;
}

struct MessageRelayHandler<'a, S> {
    middleware: &'a S,
}

impl<S> RelayHandler for MessageRelayHandler<'_, S>
where
    S: Service<WebSocketRelayInput, Output: Into<WebSocketRelayOutput>, Error: Into<BoxError>>,
{
    async fn serve(
        &self,
        direction: WebSocketRelayDirection,
        event: WebSocketRelayEvent,
        extensions: Extensions,
    ) -> Result<RelayHandlerOutput, BoxError> {
        let WebSocketRelayEvent::Data(message) = event else {
            return Ok(RelayHandlerOutput {
                messages: Vec::new(),
                close: None,
                extensions,
            });
        };

        let WebSocketRelayOutput {
            messages,
            extensions,
        } = self
            .middleware
            .serve(WebSocketRelayInput {
                direction,
                message,
                extensions,
            })
            .await
            .map(Into::into)
            .map_err(Into::into)?;

        Ok(RelayHandlerOutput {
            messages,
            close: None,
            extensions,
        })
    }
}

struct EventRelayHandler<'a, S> {
    middleware: &'a S,
}

impl<S> RelayHandler for EventRelayHandler<'_, S>
where
    S: Service<
            WebSocketRelayEventInput,
            Output: Into<WebSocketRelayEventOutput>,
            Error: Into<BoxError>,
        >,
{
    async fn serve(
        &self,
        direction: WebSocketRelayDirection,
        event: WebSocketRelayEvent,
        extensions: Extensions,
    ) -> Result<RelayHandlerOutput, BoxError> {
        let WebSocketRelayEventOutput {
            messages,
            close,
            extensions,
        } = self
            .middleware
            .serve(WebSocketRelayEventInput {
                direction,
                event,
                extensions,
            })
            .await
            .map(Into::into)
            .map_err(Into::into)?;

        Ok(RelayHandlerOutput {
            messages,
            close,
            extensions,
        })
    }
}

async fn upgrade_websocket_bridge<Ingress, Egress>(
    BridgeIo(ingress_stream, egress_stream): BridgeIo<Ingress, Egress>,
) -> WebSocketBridge<AsyncWebSocket<Ingress>, AsyncWebSocket<Egress>>
where
    Ingress: Io + Unpin + ExtensionsRef,
    Egress: Io + Unpin + ExtensionsRef,
{
    let maybe_ws_config = egress_stream
        .extensions()
        .get_ref()
        .map(|RelayWebSocketConfig(cfg)| *cfg);

    let ingress_socket =
        AsyncWebSocket::from_raw_socket(ingress_stream, Role::Server, maybe_ws_config).await;
    let egress_socket =
        AsyncWebSocket::from_raw_socket(egress_stream, Role::Client, maybe_ws_config).await;
    WebSocketBridge {
        ingress: ingress_socket,
        egress: egress_socket,
    }
}

async fn relay_websocket_bridge<H, Ingress, Egress>(
    handler: H,
    ingress_socket: Ingress,
    egress_socket: Egress,
    close_handshake_timeout: Duration,
    message_injection: bool,
    message_injection_queue_capacity: NonZeroUsize,
    max_injected_message_size: Option<usize>,
) where
    H: RelayHandler,
    Ingress: WebSocketIo,
    Egress: WebSocketIo,
{
    // Each direction gets a child store of the socket the event arrived on.
    // Middleware can see the live socket's extensions without mutating it or
    // leaking inserts into the other relay direction.
    let mut ingress_relay_extensions = ingress_socket.extensions().fork();
    let mut egress_relay_extensions = egress_socket.extensions().fork();

    let (ingress_writer, ingress_reader) = ingress_socket.split();
    let (egress_writer, egress_reader) = egress_socket.split();

    let (ingress_writer_tx, ingress_writer_rx) = tokio_mpsc::channel(RELAY_WRITER_QUEUE_CAPACITY);
    let (egress_writer_tx, egress_writer_rx) = tokio_mpsc::channel(RELAY_WRITER_QUEUE_CAPACITY);
    // External injection is isolated from relay/control commands. A saturated
    // injector can therefore be rejected without preventing peer data or close
    // frames from reaching the writer.
    let (ingress_injection_tx, ingress_injection_rx) =
        tokio_mpsc::channel(message_injection_queue_capacity.get());
    let (egress_injection_tx, egress_injection_rx) =
        tokio_mpsc::channel(message_injection_queue_capacity.get());
    let liveness = if message_injection {
        let (liveness_tx, liveness_rx) = watch::channel(true);
        let injector = WebSocketRelayInjector {
            // An ingress-direction message travels to the egress/upstream peer.
            ingress: egress_injection_tx,
            // An egress-direction message travels to the ingress/downstream peer.
            egress: ingress_injection_tx,
            liveness: liveness_rx,
            max_message_size: max_injected_message_size,
        };
        ingress_relay_extensions.insert(injector.clone());
        egress_relay_extensions.insert(injector);
        Some(liveness_tx)
    } else {
        drop(ingress_injection_tx);
        drop(egress_injection_tx);
        None
    };
    let (ingress_close_tx, ingress_close_rx) = mpsc::unbounded();
    let (egress_close_tx, egress_close_rx) = mpsc::unbounded();
    let close_controls = CloseControls {
        ingress: ingress_close_tx,
        egress: egress_close_tx,
        liveness,
    };
    let (signal_tx, signal_rx) = mpsc::unbounded();

    let ingress_direction = relay_direction(
        &handler,
        WebSocketRelayDirection::Ingress,
        ingress_reader,
        DirectionChannels {
            source_writer: ingress_writer_tx.clone(),
            destination_writer: egress_writer_tx.clone(),
            close_control: ingress_close_rx,
            close_controls: close_controls.clone(),
            signals: signal_tx.clone(),
        },
        &mut ingress_relay_extensions,
    );
    let egress_direction = relay_direction(
        &handler,
        WebSocketRelayDirection::Egress,
        egress_reader,
        DirectionChannels {
            source_writer: egress_writer_tx,
            destination_writer: ingress_writer_tx,
            close_control: egress_close_rx,
            close_controls,
            signals: signal_tx,
        },
        &mut egress_relay_extensions,
    );
    let drivers = async {
        tokio::join!(
            writer_loop(
                "ingress",
                ingress_writer,
                ingress_writer_rx,
                ingress_injection_rx,
            ),
            writer_loop(
                "egress",
                egress_writer,
                egress_writer_rx,
                egress_injection_rx,
            ),
            ingress_direction,
            egress_direction,
        );
    };

    tokio::select! {
        () = supervise_relay(signal_rx, close_handshake_timeout) => {}
        () = drivers => {}
    }
}

#[derive(Debug)]
enum WriterCommand {
    Send {
        message: crate::Message,
        response: oneshot::Sender<Result<(), ProtocolError>>,
    },
    Flush {
        response: oneshot::Sender<Result<(), ProtocolError>>,
    },
}

async fn writer_loop<Socket>(
    socket_name: &'static str,
    mut socket: Socket,
    mut commands: tokio_mpsc::Receiver<WriterCommand>,
    mut injections: tokio_mpsc::Receiver<WriterCommand>,
) where
    Socket: Sink<crate::Message, Error = ProtocolError> + Unpin,
{
    let mut commands_open = true;
    let mut injections_open = true;
    while commands_open || injections_open {
        let command = tokio::select! {
            biased;
            command = commands.recv(), if commands_open => {
                commands_open = command.is_some();
                command
            }
            command = injections.recv(), if injections_open => {
                injections_open = command.is_some();
                command
            }
        };
        let Some(command) = command else { continue };
        let (result, response) = match command {
            WriterCommand::Send { message, response } => (socket.send(message).await, response),
            WriterCommand::Flush { response } => (socket.flush().await, response),
        };
        if response.send(result).is_err() {
            tracing::trace!("{socket_name} WS writer response receiver was dropped");
        }
    }
}

fn queue_message(
    writer: &tokio_mpsc::Sender<WriterCommand>,
    message: crate::Message,
) -> Option<oneshot::Receiver<Result<(), ProtocolError>>> {
    let (response, receiver) = oneshot::channel();
    writer
        .try_send(WriterCommand::Send { message, response })
        .ok()
        .map(|()| receiver)
}

fn queue_flush(
    writer: &tokio_mpsc::Sender<WriterCommand>,
) -> Option<oneshot::Receiver<Result<(), ProtocolError>>> {
    let (response, receiver) = oneshot::channel();
    writer
        .try_send(WriterCommand::Flush { response })
        .ok()
        .map(|()| receiver)
}

#[derive(Clone)]
struct CloseControls {
    ingress: mpsc::UnboundedSender<()>,
    egress: mpsc::UnboundedSender<()>,
    liveness: Option<watch::Sender<bool>>,
}

impl CloseControls {
    fn start_closing(&self) {
        if let Some(liveness) = &self.liveness {
            _ = liveness.send(false);
        }
        _ = self.ingress.unbounded_send(());
        _ = self.egress.unbounded_send(());
    }
}

#[derive(Debug, Clone, Copy)]
enum RelaySignal {
    ClosingStarted,
    SideFinished(WebSocketRelayDirection),
    Terminate,
}

fn signal(signals: &mpsc::UnboundedSender<RelaySignal>, signal: RelaySignal) {
    _ = signals.unbounded_send(signal);
}

async fn supervise_relay(
    mut signals: mpsc::UnboundedReceiver<RelaySignal>,
    close_handshake_timeout: Duration,
) {
    let mut ingress_finished = false;
    let mut egress_finished = false;

    loop {
        match signals.next().await {
            Some(RelaySignal::ClosingStarted) => break,
            Some(RelaySignal::SideFinished(WebSocketRelayDirection::Ingress)) => {
                ingress_finished = true;
            }
            Some(RelaySignal::SideFinished(WebSocketRelayDirection::Egress)) => {
                egress_finished = true;
            }
            Some(RelaySignal::Terminate) | None => return,
        }
    }

    let finish_close = async {
        while !ingress_finished || !egress_finished {
            match signals.next().await {
                Some(RelaySignal::SideFinished(WebSocketRelayDirection::Ingress)) => {
                    ingress_finished = true;
                }
                Some(RelaySignal::SideFinished(WebSocketRelayDirection::Egress)) => {
                    egress_finished = true;
                }
                Some(RelaySignal::ClosingStarted) => {}
                Some(RelaySignal::Terminate) | None => return,
            }
        }
    };

    if tokio::time::timeout(close_handshake_timeout, finish_close)
        .await
        .is_err()
    {
        tracing::debug!(
            ?close_handshake_timeout,
            "WS close handshake timed out; drop MITM relay"
        );
    }
}

enum WriterWait {
    Complete(Result<(), ProtocolError>),
    StartClosing,
}

struct DirectionChannels {
    source_writer: tokio_mpsc::Sender<WriterCommand>,
    destination_writer: tokio_mpsc::Sender<WriterCommand>,
    close_control: mpsc::UnboundedReceiver<()>,
    close_controls: CloseControls,
    signals: mpsc::UnboundedSender<RelaySignal>,
}

async fn await_writer_or_close(
    response: oneshot::Receiver<Result<(), ProtocolError>>,
    close_control: &mut mpsc::UnboundedReceiver<()>,
) -> WriterWait {
    tokio::select! {
        biased;
        _ = close_control.next() => WriterWait::StartClosing,
        result = response => match result {
            Ok(result) => WriterWait::Complete(result),
            Err(_) => WriterWait::Complete(Err(ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "WS writer task ended",
            )))),
        }
    }
}

async fn relay_direction<H, Source>(
    handler: &H,
    direction: WebSocketRelayDirection,
    mut source: Source,
    channels: DirectionChannels,
    relay_extensions: &mut Extensions,
) where
    H: RelayHandler,
    Source: Stream<Item = Result<crate::Message, ProtocolError>> + Unpin,
{
    let DirectionChannels {
        source_writer,
        destination_writer,
        mut close_control,
        close_controls,
        signals,
    } = channels;
    let (source_name, destination_name) = match direction {
        WebSocketRelayDirection::Ingress => ("ingress", "egress"),
        WebSocketRelayDirection::Egress => ("egress", "ingress"),
    };

    let read_ahead = relay_extensions
        .get_ref::<WebSocketRelayReadAhead>()
        .copied();
    let mut buffered: VecDeque<(crate::Message, bool)> = VecDeque::new();
    let mut buffered_bytes = 0usize;
    let open_extensions = std::mem::take(relay_extensions);
    let open_result = tokio::select! {
        biased;
        _ = close_control.next() => {
            return drain_close(
                direction,
                source_name,
                &mut source,
                &source_writer,
                &signals,
            ).await;
        }
        result = handler.serve(direction, WebSocketRelayEvent::Open, open_extensions) => result,
    };
    match open_result {
        Ok(output) => {
            if !output.messages.is_empty() || output.close.is_some() {
                tracing::trace!(
                    discarded_message_count = output.messages.len(),
                    discarded_close_request = output.close.is_some(),
                    "ignore WS relay middleware output returned while observing {source_name} open"
                );
            }
            *relay_extensions = output.extensions;
        }
        Err(error) => {
            tracing::debug!(
                "WS relay middleware failed while observing {source_name} open: ({})... drop MITM relay",
                error.into_box_error()
            );
            signal(&signals, RelaySignal::Terminate);
            return;
        }
    }

    'relay: loop {
        let (source_result, control_handled) =
            if let Some((message, handled)) = buffered.pop_front() {
                buffered_bytes -= message.len();
                (Some(Ok(message)), handled)
            } else {
                (
                    tokio::select! {
                        biased;
                        _ = close_control.next() => {
                            return drain_close(
                                direction,
                                source_name,
                                &mut source,
                                &source_writer,
                                &signals,
                            ).await;
                        }
                        result = source.next() => result,
                    },
                    false,
                )
            };

        let message = match source_result {
            Some(Ok(message)) => message,
            Some(Err(error)) => {
                tracing::debug!(
                    "{source_name} WS socket ended with protocol error ({error})... drop MITM relay"
                );
                signal(&signals, RelaySignal::Terminate);
                return;
            }
            None => {
                tracing::debug!("{source_name} WS socket disconnected... drop MITM relay");
                signal(&signals, RelaySignal::Terminate);
                return;
            }
        };

        let (event, flush_automatic_response, opposite_heartbeat) = match message {
            crate::Message::Text(text) => (
                WebSocketRelayEvent::Data(WebSocketRelayMessage::Text(text)),
                false,
                None,
            ),
            crate::Message::Binary(bytes) => (
                WebSocketRelayEvent::Data(WebSocketRelayMessage::Binary(bytes)),
                false,
                None,
            ),
            crate::Message::Ping(bytes) => (
                WebSocketRelayEvent::Ping(bytes.clone()),
                !control_handled,
                (!control_handled).then_some(bytes),
            ),
            crate::Message::Pong(bytes) => (WebSocketRelayEvent::Pong(bytes), false, None),
            crate::Message::Close(frame) => {
                let event = WebSocketRelayEvent::Close(frame.clone());
                close_controls.start_closing();
                let flush = queue_flush(&source_writer);
                if queue_message(&destination_writer, crate::Message::Close(frame)).is_none() {
                    tracing::debug!("failed to queue close for {destination_name} WS socket");
                }
                signal(&signals, RelaySignal::ClosingStarted);

                let observe = async {
                    match handler
                        .serve(direction, event, std::mem::take(relay_extensions))
                        .await
                    {
                        Ok(output) => {
                            tracing::trace!(
                                discarded_message_count = output.messages.len(),
                                discarded_close_request = output.close.is_some(),
                                "ignore WS relay middleware output returned while observing {source_name} close"
                            );
                        }
                        Err(error) => {
                            tracing::debug!(
                                "WS relay middleware failed while observing {source_name} close: ({})...",
                                error.into_box_error()
                            );
                        }
                    }
                };
                let complete = finish_close_side(direction, source_name, flush, &signals);
                tokio::join!(observe, complete);
                return;
            }
            crate::Message::Frame(_) => {
                tracing::debug!(
                    "unexpected raw frame returned while reading {source_name} WS socket; drop it"
                );
                continue;
            }
        };

        if flush_automatic_response {
            let Some(response) = queue_flush(&source_writer) else {
                tracing::debug!(
                    "failed to queue automatic WS control response for {source_name} socket"
                );
                signal(&signals, RelaySignal::Terminate);
                return;
            };
            match await_writer_or_close(response, &mut close_control).await {
                WriterWait::Complete(Ok(())) => {}
                WriterWait::Complete(Err(error)) => {
                    tracing::debug!(
                        "failed to flush automatic WS control response to {source_name} socket: {error}; drop MITM relay"
                    );
                    signal(&signals, RelaySignal::Terminate);
                    return;
                }
                WriterWait::StartClosing => {
                    return drain_close(
                        direction,
                        source_name,
                        &mut source,
                        &source_writer,
                        &signals,
                    )
                    .await;
                }
            }
        }

        if let Some(payload) = opposite_heartbeat {
            // RFC 6455 permits unsolicited Pong frames as a unidirectional
            // heartbeat. This keeps the other independent relay leg active
            // without making the source peer wait on its round trip.
            let Some(response) = queue_message(&destination_writer, crate::Message::Pong(payload))
            else {
                tracing::debug!("failed to queue WS heartbeat for {destination_name} socket");
                signal(&signals, RelaySignal::Terminate);
                return;
            };
            match await_writer_or_close(response, &mut close_control).await {
                WriterWait::Complete(Ok(())) => {}
                WriterWait::Complete(Err(error)) => {
                    tracing::debug!(
                        "failed to send WS heartbeat to {destination_name}: {error}; drop MITM relay"
                    );
                    signal(&signals, RelaySignal::Terminate);
                    return;
                }
                WriterWait::StartClosing => {
                    return drain_close(
                        direction,
                        source_name,
                        &mut source,
                        &source_writer,
                        &signals,
                    )
                    .await;
                }
            }
        }

        // Keep extensions available to a close observer if the in-flight
        // middleware is cancelled by a close read on this same leg.
        let extensions = if read_ahead.is_some() {
            relay_extensions.clone()
        } else {
            std::mem::take(relay_extensions)
        };
        let handling = handler.serve(direction, event, extensions);
        tokio::pin!(handling);
        let handler_result = loop {
            tokio::select! {
                biased;
                _ = close_control.next() => {
                    return drain_close(direction, source_name, &mut source, &source_writer, &signals).await;
                }
                result = &mut handling => break result,
                next = source.next(), if read_ahead.is_some() => {
                    let Some(Ok(message)) = next else {
                        signal(&signals, RelaySignal::Terminate);
                        return;
                    };
                    if matches!(message, crate::Message::Close(_)) {
                        buffered.clear();
                        buffered_bytes = message.len();
                        buffered.push_front((message, false));
                        continue 'relay;
                    }
                    let Some(limits) = read_ahead else { signal(&signals, RelaySignal::Terminate); return; };
                    if buffered.len() >= limits.max_messages.get()
                        || message.len() > limits.max_bytes.get().saturating_sub(buffered_bytes)
                    {
                        start_coordinated_close(&source_writer, &destination_writer, &close_controls, &signals,
                            Some(CloseFrame { code: CloseCode::Size, reason: "relay read-ahead limit exceeded".into() }));
                        return drain_close(direction, source_name, &mut source, &source_writer, &signals).await;
                    }
                    if let crate::Message::Ping(payload) = &message {
                        for response in [queue_flush(&source_writer), queue_message(&destination_writer, crate::Message::Pong(payload.clone()))] {
                            let Some(response) = response else { signal(&signals, RelaySignal::Terminate); return; };
                            match await_writer_or_close(response, &mut close_control).await {
                                WriterWait::Complete(Ok(())) => (),
                                WriterWait::Complete(Err(_)) => { signal(&signals, RelaySignal::Terminate); return; }
                                WriterWait::StartClosing => return drain_close(direction, source_name, &mut source, &source_writer, &signals).await,
                            }
                        }
                    }
                    buffered_bytes += message.len();
                    buffered.push_back((message, true));
                }
            }
        };

        let RelayHandlerOutput {
            messages,
            close,
            extensions,
        } = match handler_result {
            Ok(output) => output,
            Err(error) => {
                tracing::debug!(
                    "WS relay middleware failed on {source_name} event: ({})... close both connections",
                    error.into_box_error()
                );
                start_coordinated_close(
                    &source_writer,
                    &destination_writer,
                    &close_controls,
                    &signals,
                    Some(internal_error_close("relay middleware error")),
                );
                return drain_close(
                    direction,
                    source_name,
                    &mut source,
                    &source_writer,
                    &signals,
                )
                .await;
            }
        };
        *relay_extensions = extensions;

        let requested_close = close.map(WebSocketRelayClose::into_frame);
        if requested_close
            .as_ref()
            .is_some_and(|frame| !valid_close_frame(frame.as_ref()))
        {
            tracing::debug!(
                "WS relay middleware returned an invalid close frame on {source_name} event; close both connections with 1011"
            );
            start_coordinated_close(
                &source_writer,
                &destination_writer,
                &close_controls,
                &signals,
                Some(internal_error_close("invalid relay close frame")),
            );
            return drain_close(
                direction,
                source_name,
                &mut source,
                &source_writer,
                &signals,
            )
            .await;
        }

        for (message_index, message) in messages.into_iter().enumerate() {
            tracing::trace!(
                "relay {source_name} WS data message #{message_index} to {destination_name}"
            );
            let Some(response) = queue_message(&destination_writer, message.into()) else {
                tracing::debug!(
                    "{destination_name} WS writer ended @ message#{message_index}; drop MITM relay"
                );
                signal(&signals, RelaySignal::Terminate);
                return;
            };
            match await_writer_or_close(response, &mut close_control).await {
                WriterWait::Complete(Ok(())) => {}
                WriterWait::Complete(Err(error)) => {
                    tracing::debug!(
                        "failed to relay {source_name} message to {destination_name}: {error} @ message#{message_index}; drop MITM relay"
                    );
                    signal(&signals, RelaySignal::Terminate);
                    return;
                }
                WriterWait::StartClosing => {
                    return drain_close(
                        direction,
                        source_name,
                        &mut source,
                        &source_writer,
                        &signals,
                    )
                    .await;
                }
            }
        }

        if let Some(frame) = requested_close {
            start_coordinated_close(
                &source_writer,
                &destination_writer,
                &close_controls,
                &signals,
                frame,
            );
            return drain_close(
                direction,
                source_name,
                &mut source,
                &source_writer,
                &signals,
            )
            .await;
        }
    }
}

fn start_coordinated_close(
    source_writer: &tokio_mpsc::Sender<WriterCommand>,
    destination_writer: &tokio_mpsc::Sender<WriterCommand>,
    close_controls: &CloseControls,
    signals: &mpsc::UnboundedSender<RelaySignal>,
    frame: Option<CloseFrame>,
) {
    close_controls.start_closing();
    _ = queue_message(source_writer, crate::Message::Close(frame.clone()));
    _ = queue_message(destination_writer, crate::Message::Close(frame));
    signal(signals, RelaySignal::ClosingStarted);
}

async fn drain_close<Source>(
    direction: WebSocketRelayDirection,
    source_name: &'static str,
    source: &mut Source,
    source_writer: &tokio_mpsc::Sender<WriterCommand>,
    signals: &mpsc::UnboundedSender<RelaySignal>,
) where
    Source: Stream<Item = Result<crate::Message, ProtocolError>> + Unpin,
{
    loop {
        match source.next().await {
            Some(Ok(crate::Message::Close(_))) => {
                finish_close_side(direction, source_name, queue_flush(source_writer), signals)
                    .await;
                return;
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => {
                tracing::debug!(
                    "{source_name} WS socket ended while closing with protocol error: {error}"
                );
                signal(signals, RelaySignal::SideFinished(direction));
                return;
            }
            None => {
                tracing::debug!("{source_name} WS socket disconnected while closing");
                signal(signals, RelaySignal::SideFinished(direction));
                return;
            }
        }
    }
}

async fn finish_close_side(
    direction: WebSocketRelayDirection,
    source_name: &'static str,
    response: Option<oneshot::Receiver<Result<(), ProtocolError>>>,
    signals: &mpsc::UnboundedSender<RelaySignal>,
) {
    match response {
        Some(response) => match response.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(
                    "failed to flush automatic close response to {source_name} WS socket: {error}"
                );
            }
            Err(_) => {
                tracing::debug!("{source_name} WS writer ended while flushing close response");
            }
        },
        None => {
            tracing::debug!("failed to queue close response flush for {source_name} WS socket");
        }
    }
    signal(signals, RelaySignal::SideFinished(direction));
}

fn valid_close_frame(frame: Option<&CloseFrame>) -> bool {
    frame.is_none_or(|frame| frame.code.is_allowed() && frame.reason.len() <= 123)
}

fn internal_error_close(reason: &'static str) -> CloseFrame {
    CloseFrame {
        code: CloseCode::Error,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end regression coverage for data/control routing, coordinated
    //! close behavior and per-direction middleware-extension isolation.
    //! The isolation test distinguishes a shared `clone()` (cross-direction
    //! marker leak) from per-direction `clone()` (live-socket pollution).

    use std::{
        future::pending,
        num::NonZeroUsize,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };

    use parking_lot::Mutex;
    use rama_core::{
        Layer, Service,
        bytes::Bytes,
        error::{BoxError, BoxErrorExt as _},
        extensions::{Extension, Extensions, ExtensionsRef},
        futures::{SinkExt as _, channel::oneshot},
        io::{BridgeIo, Io},
        service::MirrorService,
    };
    use rama_net::test_utils::client::MockSocket;
    use rama_utils::octets::kib;
    use tokio::{
        io::duplex,
        sync::{Notify, mpsc as tokio_mpsc},
        time::timeout,
    };

    use crate::{
        AsyncWebSocket, Message, ProtocolError,
        handshake::mitm::{
            DEFAULT_MAX_INJECTED_MESSAGE_SIZE, DEFAULT_MESSAGE_INJECTION_QUEUE_CAPACITY,
            WebSocketBridge, WebSocketRelayClose, WebSocketRelayDirection, WebSocketRelayEvent,
            WebSocketRelayEventInput, WebSocketRelayEventOutput, WebSocketRelayEventService,
            WebSocketRelayInjector, WebSocketRelayInput, WebSocketRelayIoLayer,
            WebSocketRelayIoService, WebSocketRelayMessage, WebSocketRelayOutput,
            WebSocketRelayReadAhead, WebSocketRelayService, WriterCommand, valid_close_frame,
            writer_loop,
        },
        protocol::{CloseFrame, Role, frame::coding::CloseCode},
    };

    #[derive(Debug, Clone, Extension)]
    struct IngressMarker;

    #[derive(Debug, Clone, Extension)]
    struct EgressMarker;

    #[derive(Debug, Clone, Extension)]
    struct LeakProbeIngress;

    #[derive(Debug, Clone, Extension)]
    struct LeakProbeEgress;

    #[test]
    fn message_bridge_and_raw_adapter_preserve_their_inputs() {
        let ingress = Extensions::new();
        ingress.insert(IngressMarker);
        let bridge = WebSocketBridge {
            ingress,
            egress: Extensions::new(),
        };
        assert!(
            bridge
                .ingress
                .extensions()
                .get_ref::<IngressMarker>()
                .is_some()
        );
        assert!(
            bridge
                .egress
                .extensions()
                .get_ref::<IngressMarker>()
                .is_none()
        );

        let adapter = WebSocketRelayIoService::new(42_u8);
        assert_eq!(adapter.inner(), &42);
        assert_eq!(adapter.into_inner(), 42);

        let adapter = WebSocketRelayIoLayer::new().into_layer(42_u8);
        assert_eq!(adapter.into_inner(), 42);
    }

    #[derive(Debug, Clone)]
    struct Observation {
        direction: WebSocketRelayDirection,
        saw_ingress_marker: bool,
        saw_egress_marker: bool,
        saw_leak_ingress: bool,
        saw_leak_egress: bool,
    }

    #[derive(Clone)]
    struct RecordingMiddleware {
        log: Arc<Mutex<Vec<Observation>>>,
    }

    impl Service<WebSocketRelayInput> for RecordingMiddleware {
        type Output = WebSocketRelayOutput;
        type Error = BoxError;

        async fn serve(&self, input: WebSocketRelayInput) -> Result<Self::Output, Self::Error> {
            let WebSocketRelayInput {
                direction,
                message,
                extensions,
            } = input;
            let obs = Observation {
                direction,
                // Parent visibility: a fork() walks into the parent on lookup,
                // so the side's pre-inserted marker MUST be reachable.
                saw_ingress_marker: extensions.get_ref::<IngressMarker>().is_some(),
                saw_egress_marker: extensions.get_ref::<EgressMarker>().is_some(),
                // Cross-direction visibility: forks are independent, so neither
                // direction's middleware insert should be visible in the other.
                saw_leak_ingress: extensions.get_ref::<LeakProbeIngress>().is_some(),
                saw_leak_egress: extensions.get_ref::<LeakProbeEgress>().is_some(),
            };
            self.log.lock().push(obs);
            match direction {
                WebSocketRelayDirection::Ingress => {
                    extensions.insert(LeakProbeIngress);
                }
                WebSocketRelayDirection::Egress => {
                    extensions.insert(LeakProbeEgress);
                }
            }
            Ok(WebSocketRelayOutput {
                messages: vec![message],
                extensions,
            })
        }
    }

    #[tokio::test]
    async fn relay_per_direction_fork_isolation() {
        // Two duplex pairs: one for the ingress side of the relay, one for
        // the egress side. `MockSocket` wraps each end in an `ExtensionsRef`
        // shell so the relay's `from_raw_socket` is happy.
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let relay_ingress = MockSocket::new(relay_ingress_dup);
        let relay_egress = MockSocket::new(relay_egress_dup);
        relay_ingress.extensions().insert(IngressMarker);
        relay_egress.extensions().insert(EgressMarker);

        // Capture handles to the live socket extension stores BEFORE
        // moving the sockets into the relay. `Extensions::clone()` shares
        // the top-level `Arc`, so any insert that ends up on the live
        // store would be observable through these handles after the
        // relay finishes. `fork()` does NOT share that `Arc`, so
        // correctly-forked inserts won't be observable here.
        let ingress_live_ext = relay_ingress.extensions().clone();
        let egress_live_ext = relay_egress.extensions().clone();

        let log = Arc::new(Mutex::new(Vec::<Observation>::new()));
        let middleware = RecordingMiddleware { log: log.clone() };
        let svc = WebSocketRelayService::new(middleware);

        let relay =
            tokio::spawn(async move { svc.serve(BridgeIo(relay_ingress, relay_egress)).await });

        // Relay's ingress is `Role::Server`, so the peer plays `Role::Client`
        // (masked frames). Egress is the mirror.
        let peer_ingress = MockSocket::new(peer_ingress_dup);
        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(peer_ingress, Role::Client, None).await;
        let peer_egress = MockSocket::new(peer_egress_dup);
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(peer_egress, Role::Server, None).await;

        // ingress -> egress
        peer_ingress_ws
            .send_message(Message::text("ping"))
            .await
            .expect("peer ingress send");
        match expect_message(&mut peer_egress_ws, "peer egress recv").await {
            Message::Text(t) => assert_eq!(t.as_str(), "ping"),
            other => panic!("unexpected message on egress peer: {other:?}"),
        }

        // egress -> ingress
        peer_egress_ws
            .send_message(Message::text("pong"))
            .await
            .expect("peer egress send");
        match expect_message(&mut peer_ingress_ws, "peer ingress recv").await {
            Message::Text(t) => assert_eq!(t.as_str(), "pong"),
            other => panic!("unexpected message on ingress peer: {other:?}"),
        }

        // Dropping a peer closes its duplex end; the relay sees a connection
        // error and returns.
        drop(peer_ingress_ws);
        drop(peer_egress_ws);
        _ = relay.await.expect("relay task join");

        let log = log.lock();
        assert_eq!(log.len(), 2, "exactly one middleware call per direction");

        let ingress = log
            .iter()
            .find(|o| o.direction == WebSocketRelayDirection::Ingress)
            .expect("ingress observation");
        let egress = log
            .iter()
            .find(|o| o.direction == WebSocketRelayDirection::Egress)
            .expect("egress observation");

        // Per-direction parent visibility: fork() preserves walk-into-parent.
        assert!(
            ingress.saw_ingress_marker,
            "ingress fork sees IngressMarker"
        );
        assert!(egress.saw_egress_marker, "egress fork sees EgressMarker");
        assert!(
            !ingress.saw_egress_marker,
            "ingress fork must NOT see EgressMarker (forks are independent)"
        );
        assert!(
            !egress.saw_ingress_marker,
            "egress fork must NOT see IngressMarker (forks are independent)"
        );

        // Cross-direction probe isolation. If the wiring regresses to a
        // single shared `egress_socket.extensions().clone()` threaded to
        // BOTH directions, the egress middleware call would see
        // `LeakProbeIngress` (and/or vice versa).
        assert!(
            !ingress.saw_leak_egress,
            "ingress fork must NOT see LeakProbeEgress (cross-direction leak)"
        );
        assert!(
            !egress.saw_leak_ingress,
            "egress fork must NOT see LeakProbeIngress (cross-direction leak)"
        );

        // Live-socket isolation. If the wiring regresses to per-direction
        // `clone()`, the top-level `Arc` would be shared with the live
        // socket store, so the middleware insert would surface here.
        assert!(
            !ingress_live_ext.self_contains::<LeakProbeIngress>(),
            "LeakProbeIngress must NOT leak onto the live ingress socket"
        );
        assert!(
            !egress_live_ext.self_contains::<LeakProbeEgress>(),
            "LeakProbeEgress must NOT leak onto the live egress socket"
        );
    }

    #[derive(Clone)]
    struct CaptureInjector {
        injector: Arc<Mutex<Option<WebSocketRelayInjector>>>,
    }

    impl Service<WebSocketRelayInput> for CaptureInjector {
        type Output = WebSocketRelayOutput;
        type Error = BoxError;

        async fn serve(&self, input: WebSocketRelayInput) -> Result<Self::Output, Self::Error> {
            if let Some(injector) = input.extensions.get_ref::<WebSocketRelayInjector>() {
                *self.injector.lock() = Some(injector.clone());
            }
            Ok(input.into())
        }
    }

    #[derive(Clone)]
    struct CaptureEventInjector {
        sender: Arc<Mutex<Option<oneshot::Sender<WebSocketRelayInjector>>>>,
    }

    impl Service<WebSocketRelayEventInput> for CaptureEventInjector {
        type Output = WebSocketRelayEventOutput;
        type Error = BoxError;

        async fn serve(
            &self,
            input: WebSocketRelayEventInput,
        ) -> Result<Self::Output, Self::Error> {
            if matches!(&input.event, WebSocketRelayEvent::Open)
                && let Some(injector) = input.extensions.get_ref::<WebSocketRelayInjector>()
                && let Some(sender) = self.sender.lock().take()
            {
                _ = sender.send(injector.clone());
            }
            Ok(input.into())
        }
    }

    #[test]
    fn injector_is_open_requires_both_destination_writers() {
        let injector = |drop_ingress: bool| {
            let (ingress, ingress_rx) = tokio_mpsc::channel(1);
            let (egress, egress_rx) = tokio_mpsc::channel(1);
            let (_liveness_tx, liveness) = tokio::sync::watch::channel(true);
            let injector = WebSocketRelayInjector {
                ingress,
                egress,
                liveness,
                max_message_size: None,
            };
            assert!(injector.is_open());
            if drop_ingress {
                drop(ingress_rx);
            } else {
                drop(egress_rx);
            }
            assert!(!injector.is_open());
        };
        injector(true);
        injector(false);
    }

    struct StalledSink {
        ready_polled: Arc<Notify>,
    }

    impl rama_core::futures::Sink<Message> for StalledSink {
        type Error = ProtocolError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.ready_polled.notify_one();
            Poll::Pending
        }

        fn start_send(self: Pin<&mut Self>, _message: Message) -> Result<(), Self::Error> {
            Err(ProtocolError::SendAfterClosing)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn stalled_sink_bounds_injection_queue_and_reports_busy() {
        const QUEUE_CAPACITY: usize = 2;

        let (_commands, command_rx) = tokio_mpsc::channel::<WriterCommand>(1);
        let (ingress, injection_rx) = tokio_mpsc::channel(QUEUE_CAPACITY);
        let (egress, _egress_rx) = tokio_mpsc::channel(1);
        let (_liveness_tx, liveness) = tokio::sync::watch::channel(true);
        let ready_polled = Arc::new(Notify::new());
        let writer = tokio::spawn(writer_loop(
            "stalled",
            StalledSink {
                ready_polled: ready_polled.clone(),
            },
            command_rx,
            injection_rx,
        ));
        let injector = WebSocketRelayInjector {
            ingress,
            egress,
            liveness,
            max_message_size: None,
        };

        let first = tokio::spawn({
            let injector = injector.clone();
            async move {
                injector
                    .send(
                        WebSocketRelayDirection::Ingress,
                        WebSocketRelayMessage::Text("in flight".into()),
                    )
                    .await
            }
        });
        timeout(Duration::from_secs(1), ready_polled.notified())
            .await
            .expect("writer never attempted the first injected message");

        let queued: Vec<_> = (0..QUEUE_CAPACITY)
            .map(|index| {
                let injector = injector.clone();
                tokio::spawn(async move {
                    injector
                        .send(
                            WebSocketRelayDirection::Ingress,
                            WebSocketRelayMessage::Text(format!("queued {index}").into()),
                        )
                        .await
                })
            })
            .collect();
        timeout(Duration::from_secs(1), async {
            while injector.ingress.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("injection queue did not reach its configured capacity");

        let result = timeout(
            Duration::from_secs(1),
            injector.send(
                WebSocketRelayDirection::Ingress,
                WebSocketRelayMessage::Text("busy".into()),
            ),
        )
        .await
        .expect("a full injection queue must fail without waiting");
        match result {
            Err(ProtocolError::WriteBufferFull(message)) => {
                assert_eq!(message, Message::text("busy"));
            }
            other => panic!("expected a write-buffer-full error, got {other:?}"),
        }
        assert_eq!(injector.ingress.capacity(), 0);

        writer.abort();
        first.abort();
        for task in queued {
            task.abort();
        }
    }

    #[tokio::test]
    async fn injector_rejects_oversized_payload_before_queueing() {
        let (ingress, ingress_rx) = tokio_mpsc::channel(1);
        let (egress, _egress_rx) = tokio_mpsc::channel(1);
        let (_liveness_tx, liveness) = tokio::sync::watch::channel(true);
        let injector = WebSocketRelayInjector {
            ingress,
            egress,
            liveness,
            max_message_size: Some(3),
        };

        assert!(matches!(
            injector
                .send(
                    WebSocketRelayDirection::Ingress,
                    WebSocketRelayMessage::Binary(Bytes::from_static(b"four")),
                )
                .await,
            Err(ProtocolError::MessageTooLong {
                size: 4,
                max_size: 3
            })
        ));
        assert!(ingress_rx.is_empty());
    }

    #[tokio::test]
    async fn event_relay_exposes_injector_before_peer_traffic() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));
        let (sender, receiver) = oneshot::channel();
        let service = WebSocketRelayEventService::new(CaptureEventInjector {
            sender: Arc::new(Mutex::new(Some(sender))),
        })
        .with_message_injection(true);
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;
        let injector = timeout(Duration::from_secs(1), receiver)
            .await
            .expect("relay open event timed out")
            .expect("relay open observer dropped");

        injector
            .send(
                WebSocketRelayDirection::Ingress,
                WebSocketRelayMessage::Text("sent before peer traffic".into()),
            )
            .await
            .expect("inject on freshly opened relay");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive opening injection").await,
            Message::text("sent before peer traffic")
        );

        drop(peer_ingress_ws);
        drop(peer_egress_ws);
        _ = relay.await.expect("relay task join");
    }

    #[tokio::test]
    async fn live_relay_injector_sends_data_in_both_directions_and_closes_with_relay() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));
        let captured = Arc::new(Mutex::new(None));
        let service = WebSocketRelayService::new(CaptureInjector {
            injector: captured.clone(),
        })
        .with_message_injection(true);
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        peer_ingress_ws
            .send_message(Message::text("register injector"))
            .await
            .expect("send registration message");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive registration message").await,
            Message::text("register injector")
        );
        let injector = captured
            .lock()
            .clone()
            .expect("middleware received live relay injector");
        assert!(injector.is_open());
        let mut closed = tokio::spawn({
            let injector = injector.clone();
            async move { injector.closed().await }
        });
        assert!(
            timeout(Duration::from_millis(50), &mut closed)
                .await
                .is_err(),
            "closed notification resolved while the relay was live"
        );

        injector
            .send(
                WebSocketRelayDirection::Ingress,
                WebSocketRelayMessage::Text("replayed text".into()),
            )
            .await
            .expect("inject ingress text");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive injected ingress text").await,
            Message::text("replayed text")
        );

        injector
            .send(
                WebSocketRelayDirection::Egress,
                WebSocketRelayMessage::Binary(Bytes::from_static(b"replayed binary")),
            )
            .await
            .expect("inject egress binary");
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive injected egress binary").await,
            Message::Binary(Bytes::from_static(b"replayed binary"))
        );

        drop(peer_ingress_ws);
        drop(peer_egress_ws);
        _ = relay.await.expect("relay task join");
        timeout(Duration::from_secs(1), closed)
            .await
            .expect("live close waiter timed out")
            .expect("live close waiter task failed");
        assert!(!injector.is_open());
        timeout(Duration::from_secs(1), injector.closed())
            .await
            .expect("injector close notification");
        assert!(
            injector
                .send(
                    WebSocketRelayDirection::Ingress,
                    WebSocketRelayMessage::Text("too late".into()),
                )
                .await
                .is_err()
        );
    }

    async fn expect_message<Stream>(
        socket: &mut AsyncWebSocket<Stream>,
        description: &str,
    ) -> Message
    where
        Stream: Io + Unpin,
    {
        timeout(Duration::from_secs(1), socket.recv_message())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting to {description}"))
            .unwrap_or_else(|error| panic!("failed to {description}: {error}"))
    }

    async fn assert_no_message<Stream>(socket: &mut AsyncWebSocket<Stream>, peer_name: &str)
    where
        Stream: Io + Unpin,
    {
        assert!(
            timeout(Duration::from_millis(50), socket.recv_message())
                .await
                .is_err(),
            "{peer_name} unexpectedly received a message"
        );
    }

    fn test_close_frame(reason: &'static str) -> CloseFrame {
        CloseFrame {
            code: CloseCode::Away,
            reason: reason.into(),
        }
    }

    #[tokio::test]
    async fn regular_relay_keeps_both_legs_active_when_either_peer_pings() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let log = Arc::new(Mutex::new(Vec::<Observation>::new()));
        let service = WebSocketRelayService::new(RecordingMiddleware { log: log.clone() });
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        let ingress_ping = Bytes::from_static(b"ingress-ping");
        peer_ingress_ws
            .send_message(Message::Ping(ingress_ping.clone()))
            .await
            .expect("send ingress ping");
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive automatic ingress pong").await,
            Message::Pong(ingress_ping)
        );
        assert_no_message(
            &mut peer_ingress_ws,
            "ingress peer after its automatic pong",
        )
        .await;
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive egress heartbeat").await,
            Message::Pong(Bytes::from_static(b"ingress-ping"))
        );

        let unsolicited_pong = Bytes::from_static(b"unsolicited-pong");
        peer_ingress_ws
            .send_message(Message::Pong(unsolicited_pong))
            .await
            .expect("send unsolicited ingress pong");
        assert_no_message(&mut peer_egress_ws, "egress peer after ingress pong").await;

        let egress_ping = Bytes::from_static(b"egress-ping");
        peer_egress_ws
            .send_message(Message::Ping(egress_ping.clone()))
            .await
            .expect("send egress ping");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive automatic egress pong").await,
            Message::Pong(egress_ping)
        );
        assert_no_message(&mut peer_egress_ws, "egress peer after its automatic pong").await;
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive ingress heartbeat").await,
            Message::Pong(Bytes::from_static(b"egress-ping"))
        );

        drop(peer_ingress_ws);
        drop(peer_egress_ws);
        _ = relay.await.expect("relay task join");
        assert!(
            log.lock().is_empty(),
            "regular middleware must not observe ping or pong"
        );
    }

    #[tokio::test]
    async fn regular_relay_coordinates_both_close_handshakes() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let service = WebSocketRelayService::new(MirrorService::new());
        let mut relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        let close_frame = test_close_frame("regular shutdown");
        peer_ingress_ws
            .send_message(Message::Close(Some(close_frame.clone())))
            .await
            .expect("send ingress close");

        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive ingress close reply").await,
            Message::Close(Some(close_frame.clone()))
        );
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive propagated egress close").await,
            Message::Close(Some(close_frame))
        );

        assert!(
            timeout(Duration::from_millis(50), &mut relay)
                .await
                .is_err(),
            "relay must await the egress peer's close reply"
        );
        peer_egress_ws
            .flush()
            .await
            .expect("flush egress close reply");
        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay close timeout")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[tokio::test]
    async fn regular_relay_bounds_close_reply_wait() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let service = WebSocketRelayService::new(MirrorService::new())
            .with_close_handshake_timeout(Duration::from_millis(20));
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        let close_frame = test_close_frame("bounded shutdown");
        peer_ingress_ws
            .send_message(Message::Close(Some(close_frame.clone())))
            .await
            .expect("send ingress close");
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive ingress close reply").await,
            Message::Close(Some(close_frame.clone()))
        );
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive propagated egress close").await,
            Message::Close(Some(close_frame))
        );

        // Intentionally do not flush the egress peer's automatically queued
        // reply. The relay must still terminate at its configured bound.
        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay did not enforce its close handshake timeout")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[derive(Clone)]
    struct RecordingEventMiddleware {
        events: Arc<Mutex<Vec<(WebSocketRelayDirection, WebSocketRelayEvent)>>>,
    }

    impl Service<WebSocketRelayEventInput> for RecordingEventMiddleware {
        type Output = WebSocketRelayEventOutput;
        type Error = BoxError;

        async fn serve(
            &self,
            input: WebSocketRelayEventInput,
        ) -> Result<Self::Output, Self::Error> {
            self.events
                .lock()
                .push((input.direction, input.event.clone()));
            Ok(input.into())
        }
    }

    #[derive(Clone)]
    struct FailingCloseObserver;

    impl Service<WebSocketRelayEventInput> for FailingCloseObserver {
        type Output = WebSocketRelayEventOutput;
        type Error = BoxError;

        async fn serve(
            &self,
            input: WebSocketRelayEventInput,
        ) -> Result<Self::Output, Self::Error> {
            if matches!(&input.event, WebSocketRelayEvent::Close(_)) {
                Err(BoxError::from_static_str("close observation failed"))
            } else {
                Ok(input.into())
            }
        }
    }

    #[derive(Clone)]
    struct FailingDataObserver;

    impl Service<WebSocketRelayEventInput> for FailingDataObserver {
        type Output = WebSocketRelayEventOutput;
        type Error = BoxError;

        async fn serve(
            &self,
            input: WebSocketRelayEventInput,
        ) -> Result<Self::Output, Self::Error> {
            if matches!(&input.event, WebSocketRelayEvent::Data(_)) {
                Err(BoxError::from_static_str("data observation failed"))
            } else {
                Ok(input.into())
            }
        }
    }

    #[derive(Clone)]
    struct StallingCloseObserver;

    impl Service<WebSocketRelayEventInput> for StallingCloseObserver {
        type Output = WebSocketRelayEventOutput;
        type Error = BoxError;

        async fn serve(
            &self,
            input: WebSocketRelayEventInput,
        ) -> Result<Self::Output, Self::Error> {
            if matches!(&input.event, WebSocketRelayEvent::Close(_)) {
                return pending().await;
            }
            Ok(input.into())
        }
    }

    #[tokio::test]
    async fn incoming_close_is_propagated_even_when_event_middleware_fails() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let service = WebSocketRelayEventService::new(FailingCloseObserver);
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        let close_frame = test_close_frame("observer failure");
        peer_ingress_ws
            .send_message(Message::Close(Some(close_frame.clone())))
            .await
            .expect("send ingress close");
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive ingress close reply").await,
            Message::Close(Some(close_frame.clone()))
        );
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive propagated egress close").await,
            Message::Close(Some(close_frame))
        );
        peer_egress_ws
            .flush()
            .await
            .expect("flush egress close reply");
        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay close timeout")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[tokio::test]
    async fn incoming_close_completion_is_not_delayed_by_stalled_observer() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let service = WebSocketRelayEventService::new(StallingCloseObserver);
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        let close_frame = test_close_frame("observer stalls");
        peer_ingress_ws
            .send_message(Message::Close(Some(close_frame.clone())))
            .await
            .expect("send ingress close");
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive ingress close reply").await,
            Message::Close(Some(close_frame.clone()))
        );
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive propagated egress close").await,
            Message::Close(Some(close_frame))
        );
        peer_egress_ws
            .flush()
            .await
            .expect("flush egress close reply");

        timeout(Duration::from_secs(1), relay)
            .await
            .expect("stalled close observer delayed relay completion")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[tokio::test]
    async fn event_middleware_error_closes_both_connections_with_1011() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let service = WebSocketRelayEventService::new(FailingDataObserver);
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        peer_ingress_ws
            .send_message(Message::text("middleware fails"))
            .await
            .expect("send ingress text");

        for (peer, description) in [
            (&mut peer_ingress_ws, "receive ingress error close"),
            (&mut peer_egress_ws, "receive egress error close"),
        ] {
            match expect_message(peer, description).await {
                Message::Close(Some(frame)) => assert_eq!(frame.code, CloseCode::Error),
                other => panic!("unexpected message while {description}: {other:?}"),
            }
        }

        peer_ingress_ws
            .flush()
            .await
            .expect("flush ingress close reply");
        peer_egress_ws
            .flush()
            .await
            .expect("flush egress close reply");
        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay close timeout")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[tokio::test]
    async fn event_relay_observes_controls_without_forwarding_them() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let events = Arc::new(Mutex::new(Vec::new()));
        let service = WebSocketRelayIoService::new(WebSocketRelayEventService::new(
            RecordingEventMiddleware {
                events: events.clone(),
            },
        ));
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        peer_ingress_ws
            .send_message(Message::text("hello"))
            .await
            .expect("send ingress text");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive mirrored text").await,
            Message::text("hello")
        );

        let ping = Bytes::from_static(b"observed-ping");
        peer_ingress_ws
            .send_message(Message::Ping(ping.clone()))
            .await
            .expect("send observed ping");
        assert_eq!(
            expect_message(
                &mut peer_ingress_ws,
                "receive observed ping's automatic pong",
            )
            .await,
            Message::Pong(ping.clone())
        );
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive observed ping heartbeat").await,
            Message::Pong(ping.clone())
        );

        let pong = Bytes::from_static(b"observed-pong");
        peer_egress_ws
            .send_message(Message::Pong(pong.clone()))
            .await
            .expect("send observed pong");
        assert_no_message(&mut peer_ingress_ws, "ingress peer after observed pong").await;

        let close_frame = test_close_frame("observed shutdown");
        peer_egress_ws
            .send_message(Message::Close(Some(close_frame.clone())))
            .await
            .expect("send observed close");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive egress close reply").await,
            Message::Close(Some(close_frame.clone()))
        );
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive propagated ingress close").await,
            Message::Close(Some(close_frame.clone()))
        );
        peer_ingress_ws
            .flush()
            .await
            .expect("flush ingress close reply");
        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay close timeout")
            .expect("relay task join")
            .expect("relay service result");

        let events = events.lock().clone();
        for direction in [
            WebSocketRelayDirection::Ingress,
            WebSocketRelayDirection::Egress,
        ] {
            let first = events
                .iter()
                .find(|(observed, _)| *observed == direction)
                .expect("both relay directions are observed");
            assert_eq!(first.1, WebSocketRelayEvent::Open);
        }
        assert_eq!(
            events
                .into_iter()
                .filter(|(_, event)| !matches!(event, WebSocketRelayEvent::Open))
                .collect::<Vec<_>>(),
            vec![
                (
                    WebSocketRelayDirection::Ingress,
                    WebSocketRelayEvent::Data(WebSocketRelayMessage::Text("hello".into())),
                ),
                (
                    WebSocketRelayDirection::Ingress,
                    WebSocketRelayEvent::Ping(ping),
                ),
                (
                    WebSocketRelayDirection::Egress,
                    WebSocketRelayEvent::Pong(pong),
                ),
                (
                    WebSocketRelayDirection::Egress,
                    WebSocketRelayEvent::Close(Some(close_frame)),
                ),
            ]
        );
    }

    #[derive(Clone)]
    struct StallingIngressPingMiddleware {
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    }

    #[derive(Clone)]
    struct StallingIngressOpenMiddleware {
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    }

    impl Service<WebSocketRelayEventInput> for StallingIngressOpenMiddleware {
        type Output = WebSocketRelayEventOutput;
        type Error = BoxError;

        async fn serve(
            &self,
            input: WebSocketRelayEventInput,
        ) -> Result<Self::Output, Self::Error> {
            if input.direction == WebSocketRelayDirection::Ingress
                && matches!(&input.event, WebSocketRelayEvent::Open)
            {
                if let Some(started) = self.started.lock().take() {
                    _ = started.send(());
                }
                return pending().await;
            }
            Ok(input.into())
        }
    }

    impl Service<WebSocketRelayEventInput> for StallingIngressPingMiddleware {
        type Output = WebSocketRelayEventOutput;
        type Error = BoxError;

        async fn serve(
            &self,
            input: WebSocketRelayEventInput,
        ) -> Result<Self::Output, Self::Error> {
            if input.direction == WebSocketRelayDirection::Ingress
                && matches!(&input.event, WebSocketRelayEvent::Ping(_))
            {
                if let Some(started) = self.started.lock().take() {
                    _ = started.send(());
                }
                return pending().await;
            }
            Ok(input.into())
        }
    }

    #[tokio::test]
    async fn stalled_middleware_does_not_block_the_opposite_direction_or_close() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));
        let (started_tx, started_rx) = oneshot::channel();

        let service = WebSocketRelayEventService::new(StallingIngressPingMiddleware {
            started: Arc::new(Mutex::new(Some(started_tx))),
        });
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        let ping = Bytes::from_static(b"stalling ping");
        peer_ingress_ws
            .send_message(Message::Ping(ping.clone()))
            .await
            .expect("send ingress ping");
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive automatic ingress pong").await,
            Message::Pong(ping.clone())
        );
        timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("middleware was not called")
            .expect("middleware start sender dropped");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive egress heartbeat").await,
            Message::Pong(ping)
        );

        peer_egress_ws
            .send_message(Message::text("opposite direction stays live"))
            .await
            .expect("send egress text");
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive egress text").await,
            Message::text("opposite direction stays live")
        );

        let close_frame = test_close_frame("opposite close");
        peer_egress_ws
            .send_message(Message::Close(Some(close_frame.clone())))
            .await
            .expect("send egress close");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive egress close reply").await,
            Message::Close(Some(close_frame.clone()))
        );
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive propagated ingress close").await,
            Message::Close(Some(close_frame))
        );
        peer_ingress_ws
            .flush()
            .await
            .expect("flush ingress close reply");

        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay close timeout")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[tokio::test]
    async fn stalled_open_is_cancelled_by_an_opposite_close() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));
        let (started_tx, started_rx) = oneshot::channel();

        let service = WebSocketRelayEventService::new(StallingIngressOpenMiddleware {
            started: Arc::new(Mutex::new(Some(started_tx))),
        });
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;
        timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("open middleware was not called")
            .expect("open middleware start sender dropped");

        let close_frame = test_close_frame("opposite close during open");
        peer_egress_ws
            .send_message(Message::Close(Some(close_frame.clone())))
            .await
            .expect("send egress close");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive egress close reply").await,
            Message::Close(Some(close_frame.clone()))
        );
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive propagated ingress close").await,
            Message::Close(Some(close_frame))
        );
        peer_ingress_ws.flush().await.expect("flush ingress close");

        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay close timeout")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[derive(Clone)]
    struct CloseAfterDataMiddleware {
        close: WebSocketRelayClose,
    }

    impl Service<WebSocketRelayEventInput> for CloseAfterDataMiddleware {
        type Output = WebSocketRelayEventOutput;
        type Error = BoxError;

        async fn serve(
            &self,
            input: WebSocketRelayEventInput,
        ) -> Result<Self::Output, Self::Error> {
            let WebSocketRelayEventInput {
                direction: _,
                event,
                extensions,
            } = input;
            let messages = match event {
                WebSocketRelayEvent::Data(message) => vec![message],
                WebSocketRelayEvent::Open
                | WebSocketRelayEvent::Ping(_)
                | WebSocketRelayEvent::Pong(_)
                | WebSocketRelayEvent::Close(_) => Vec::new(),
            };
            Ok(WebSocketRelayEventOutput {
                messages,
                close: Some(self.close.clone()),
                extensions,
            })
        }
    }

    #[tokio::test]
    async fn event_relay_sends_messages_before_requested_coordinated_close() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let close_frame = test_close_frame("middleware shutdown");
        let service = WebSocketRelayEventService::new(CloseAfterDataMiddleware {
            close: WebSocketRelayClose::WithFrame(close_frame.clone()),
        });
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        peer_egress_ws
            .send_message(Message::text("last message"))
            .await
            .expect("send final egress text");
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive final ingress text").await,
            Message::text("last message")
        );
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive requested egress close").await,
            Message::Close(Some(close_frame.clone()))
        );
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive requested ingress close").await,
            Message::Close(Some(close_frame))
        );

        peer_ingress_ws
            .flush()
            .await
            .expect("flush ingress close reply");
        peer_egress_ws
            .flush()
            .await
            .expect("flush egress close reply");
        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay close timeout")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[tokio::test]
    async fn event_relay_can_request_frameless_close() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let service = WebSocketRelayEventService::new(CloseAfterDataMiddleware {
            close: WebSocketRelayClose::WithoutFrame,
        });
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        peer_ingress_ws
            .send_message(Message::text("last frameless message"))
            .await
            .expect("send final ingress text");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive final egress text").await,
            Message::text("last frameless message")
        );
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive frameless ingress close").await,
            Message::Close(None)
        );
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive frameless egress close").await,
            Message::Close(None)
        );

        peer_ingress_ws
            .flush()
            .await
            .expect("flush ingress close reply");
        peer_egress_ws
            .flush()
            .await
            .expect("flush egress close reply");
        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay close timeout")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[tokio::test]
    async fn event_relay_can_request_close_from_ping() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let close_frame = test_close_frame("close on ping");
        let service = WebSocketRelayEventService::new(CloseAfterDataMiddleware {
            close: WebSocketRelayClose::WithFrame(close_frame.clone()),
        });
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        let ping = Bytes::from_static(b"close trigger");
        peer_ingress_ws
            .send_message(Message::Ping(ping.clone()))
            .await
            .expect("send ingress ping");
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive automatic ingress pong").await,
            Message::Pong(ping.clone())
        );
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive egress heartbeat").await,
            Message::Pong(ping)
        );
        assert_eq!(
            expect_message(&mut peer_ingress_ws, "receive requested ingress close").await,
            Message::Close(Some(close_frame.clone()))
        );
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive requested egress close").await,
            Message::Close(Some(close_frame))
        );

        peer_ingress_ws
            .flush()
            .await
            .expect("flush ingress close reply");
        peer_egress_ws
            .flush()
            .await
            .expect("flush egress close reply");
        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay close timeout")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[tokio::test]
    async fn event_relay_rejects_invalid_requested_close_frame() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let invalid_close = CloseFrame {
            code: CloseCode::Normal,
            reason: "x".repeat(124).into(),
        };
        let service = WebSocketRelayEventService::new(CloseAfterDataMiddleware {
            close: WebSocketRelayClose::WithFrame(invalid_close),
        });
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(
                    MockSocket::new(relay_ingress_dup),
                    MockSocket::new(relay_egress_dup),
                ))
                .await
        });

        let mut peer_ingress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_dup), Role::Client, None)
                .await;
        let mut peer_egress_ws =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_dup), Role::Server, None)
                .await;

        peer_ingress_ws
            .send_message(Message::text("must not be relayed"))
            .await
            .expect("send ingress text");
        for (peer, description) in [
            (&mut peer_ingress_ws, "receive ingress invalid-output close"),
            (&mut peer_egress_ws, "receive egress invalid-output close"),
        ] {
            match expect_message(peer, description).await {
                Message::Close(Some(frame)) => assert_eq!(frame.code, CloseCode::Error),
                other => panic!("unexpected message while {description}: {other:?}"),
            }
        }

        peer_ingress_ws
            .flush()
            .await
            .expect("flush ingress close reply");
        peer_egress_ws
            .flush()
            .await
            .expect("flush egress close reply");
        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay close timeout")
            .expect("relay task join")
            .expect("relay service result");
    }

    #[test]
    fn event_output_mirrors_only_data_and_distinguishes_empty_close() {
        let extensions = Extensions::new();
        extensions.insert(IngressMarker);
        let input = WebSocketRelayInput {
            direction: WebSocketRelayDirection::Ingress,
            message: WebSocketRelayMessage::Text("input".into()),
            extensions,
        };
        assert!(input.extensions().contains::<IngressMarker>());

        let extensions = Extensions::new();
        extensions.insert(IngressMarker);
        let output = WebSocketRelayOutput {
            messages: Vec::new(),
            extensions,
        };
        assert!(output.extensions().contains::<IngressMarker>());

        let extensions = Extensions::new();
        extensions.insert(IngressMarker);
        let event_input = WebSocketRelayEventInput {
            direction: WebSocketRelayDirection::Ingress,
            event: WebSocketRelayEvent::Ping(Bytes::new()),
            extensions,
        };
        assert!(event_input.extensions().contains::<IngressMarker>());

        let extensions = Extensions::new();
        extensions.insert(IngressMarker);
        let event_output = WebSocketRelayEventOutput {
            messages: Vec::new(),
            close: None,
            extensions,
        };
        assert!(event_output.extensions().contains::<IngressMarker>());

        let data_output: WebSocketRelayEventOutput = WebSocketRelayEventInput {
            direction: WebSocketRelayDirection::Ingress,
            event: WebSocketRelayEvent::Data(WebSocketRelayMessage::Binary(Bytes::from_static(
                b"data",
            ))),
            extensions: Extensions::new(),
        }
        .into();
        assert_eq!(
            data_output.messages,
            vec![WebSocketRelayMessage::Binary(Bytes::from_static(b"data"))]
        );
        assert_eq!(data_output.close, None);

        for event in [
            WebSocketRelayEvent::Ping(Bytes::from_static(b"ping")),
            WebSocketRelayEvent::Pong(Bytes::from_static(b"pong")),
            WebSocketRelayEvent::Close(None),
        ] {
            let output: WebSocketRelayEventOutput = WebSocketRelayEventInput {
                direction: WebSocketRelayDirection::Egress,
                event,
                extensions: Extensions::new(),
            }
            .into();
            assert!(output.messages.is_empty());
            assert_eq!(output.close, None);
        }

        assert_eq!(WebSocketRelayClose::WithoutFrame.into_frame(), None);
        let close_frame = test_close_frame("with frame");
        assert_eq!(
            WebSocketRelayClose::WithFrame(close_frame.clone()).into_frame(),
            Some(close_frame.clone())
        );
        assert_eq!(
            WebSocketRelayClose::from(Some(close_frame.clone())),
            WebSocketRelayClose::WithFrame(close_frame)
        );
        assert_eq!(
            WebSocketRelayClose::from(None),
            WebSocketRelayClose::WithoutFrame
        );

        assert!(valid_close_frame(None));
        assert!(valid_close_frame(Some(&CloseFrame {
            code: CloseCode::Normal,
            reason: "x".repeat(123).into(),
        })));
        assert!(!valid_close_frame(Some(&CloseFrame {
            code: CloseCode::Normal,
            reason: "x".repeat(124).into(),
        })));
        assert!(!valid_close_frame(Some(&CloseFrame {
            code: CloseCode::Abnormal,
            reason: "forbidden code".into(),
        })));
    }

    #[test]
    fn relay_services_expose_timeout_and_message_injection_setters() {
        let timeout = Duration::from_secs(7);

        let mut service = WebSocketRelayService::new(MirrorService::new());
        assert!(!service.message_injection);
        assert_eq!(
            service.message_injection_queue_capacity,
            DEFAULT_MESSAGE_INJECTION_QUEUE_CAPACITY
        );
        assert_eq!(
            service.max_injected_message_size,
            Some(DEFAULT_MAX_INJECTED_MESSAGE_SIZE)
        );
        service.set_close_handshake_timeout(timeout);
        service.set_message_injection(true);
        service.set_message_injection_queue_capacity(NonZeroUsize::new(3).unwrap());
        service.set_max_injected_message_size(1_024);
        assert_eq!(service.close_handshake_timeout, timeout);
        assert!(service.message_injection);
        assert_eq!(service.message_injection_queue_capacity.get(), 3);
        assert_eq!(service.max_injected_message_size, Some(1_024));

        let service = WebSocketRelayEventService::new(MirrorService::new())
            .with_close_handshake_timeout(timeout)
            .with_message_injection(true)
            .with_message_injection_queue_capacity(NonZeroUsize::new(5).unwrap())
            .without_max_injected_message_size();
        assert_eq!(service.close_handshake_timeout, timeout);
        assert!(service.message_injection);
        assert_eq!(service.message_injection_queue_capacity.get(), 5);
        assert_eq!(service.max_injected_message_size, None);
    }

    #[tokio::test]
    async fn read_ahead_keeps_ping_and_same_side_close_live_during_a_hold() {
        let (relay_in, peer_in) = duplex(kib(16));
        let (relay_out, peer_out) = duplex(kib(16));
        let (started_tx, started_rx) = oneshot::channel();
        let service = WebSocketRelayEventService::new(StallingIngressPingMiddleware {
            started: Arc::new(Mutex::new(Some(started_tx))),
        });
        let ingress = MockSocket::new(relay_in);
        ingress.extensions().insert(WebSocketRelayReadAhead {
            max_messages: NonZeroUsize::new(8).unwrap(),
            max_bytes: NonZeroUsize::new(1024).unwrap(),
        });
        let relay = tokio::spawn(async move {
            service
                .serve(BridgeIo(ingress, MockSocket::new(relay_out)))
                .await
        });
        let mut client =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_in), Role::Client, None).await;
        let mut server =
            AsyncWebSocket::from_raw_socket(MockSocket::new(peer_out), Role::Server, None).await;
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            client
                .send_message(Message::Ping(Bytes::copy_from_slice(payload)))
                .await
                .unwrap();
            assert_eq!(
                expect_message(&mut client, "pong while middleware is held").await,
                Message::Pong(Bytes::copy_from_slice(payload))
            );
            assert_eq!(
                expect_message(&mut server, "opposite heartbeat while middleware is held").await,
                Message::Pong(Bytes::copy_from_slice(payload))
            );
        }
        timeout(Duration::from_secs(1), started_rx)
            .await
            .unwrap()
            .unwrap();
        client
            .send_message(Message::text("data must not escape the hold"))
            .await
            .unwrap();
        let frame = test_close_frame("same-side close");
        client
            .send_message(Message::Close(Some(frame.clone())))
            .await
            .unwrap();
        assert_eq!(
            expect_message(&mut client, "same-side close reply").await,
            Message::Close(Some(frame.clone()))
        );
        assert_eq!(
            expect_message(&mut server, "close skips held data").await,
            Message::Close(Some(frame))
        );
        server.flush().await.unwrap();
        timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn read_ahead_bounds_message_count_and_payload_bytes() {
        for (count, bytes, payloads) in [(1, 1024, vec!["a", "b"]), (8, 4, vec!["oversized"])] {
            let (relay_in, peer_in) = duplex(kib(16));
            let (relay_out, peer_out) = duplex(kib(16));
            let (started_tx, started_rx) = oneshot::channel();
            let service = WebSocketRelayEventService::new(StallingIngressPingMiddleware {
                started: Arc::new(Mutex::new(Some(started_tx))),
            })
            .with_close_handshake_timeout(Duration::from_millis(50));
            let ingress = MockSocket::new(relay_in);
            ingress.extensions().insert(WebSocketRelayReadAhead {
                max_messages: NonZeroUsize::new(count).unwrap(),
                max_bytes: NonZeroUsize::new(bytes).unwrap(),
            });
            let relay = tokio::spawn(async move {
                service
                    .serve(BridgeIo(ingress, MockSocket::new(relay_out)))
                    .await
            });
            let mut client =
                AsyncWebSocket::from_raw_socket(MockSocket::new(peer_in), Role::Client, None).await;
            let mut server =
                AsyncWebSocket::from_raw_socket(MockSocket::new(peer_out), Role::Server, None)
                    .await;
            client
                .send_message(Message::Ping(Bytes::new()))
                .await
                .unwrap();
            assert!(matches!(
                expect_message(&mut client, "initial pong").await,
                Message::Pong(_)
            ));
            assert!(matches!(
                expect_message(&mut server, "initial heartbeat").await,
                Message::Pong(_)
            ));
            timeout(Duration::from_secs(1), started_rx)
                .await
                .unwrap()
                .unwrap();
            for payload in payloads {
                client.send_message(Message::text(payload)).await.unwrap();
            }
            assert!(matches!(
                expect_message(&mut client, "bounded read-ahead closes client").await,
                Message::Close(Some(CloseFrame {
                    code: CloseCode::Size,
                    ..
                }))
            ));
            assert!(matches!(
                expect_message(&mut server, "bounded read-ahead closes server").await,
                Message::Close(Some(CloseFrame {
                    code: CloseCode::Size,
                    ..
                }))
            ));
            _ = client.flush().await;
            _ = server.flush().await;
            timeout(Duration::from_secs(1), relay)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
}
