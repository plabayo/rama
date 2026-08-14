use std::convert::Infallible;

use rama_core::{
    Service,
    bytes::Bytes,
    error::{BoxError, ErrorExt},
    extensions::{self, Extensions, ExtensionsRef},
    futures::SinkExt as _,
    io::{BridgeIo, Io},
    service::MirrorService,
    telemetry::tracing,
};

use crate::{
    AsyncWebSocket, Utf8Bytes,
    handshake::matcher::RelayWebSocketConfig,
    protocol::{CloseFrame, Role},
};

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay WebSocket messages.
///
/// By default they get mirrored but the logic is fully up to you.
///
/// ## KISS
///
/// This service is for simple DPI purposes.
///
/// Use [`WebSocketRelayEventService`] when middleware also needs to observe
/// control messages. Fork or create your own relay service for lower-level
/// purposes such as preserving raw frame boundaries.
pub struct WebSocketRelayService<S = MirrorService> {
    middleware: S,
}

impl<S> WebSocketRelayService<S> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`WebSocketRelayService`]
    pub fn new(middleware: S) -> Self {
        Self { middleware }
    }
}

#[derive(Debug, Clone)]
/// A WebSocket MITM relay that exposes every message observable through the
/// high-level WebSocket protocol API to its middleware.
///
/// Unlike [`WebSocketRelayService`], this service exposes ping, pong and close
/// events. Control messages remain owned by the relay: ping and pong are never
/// forwarded across the two independent WebSocket connections, and an incoming
/// close always starts coordinated shutdown.
pub struct WebSocketRelayEventService<S = MirrorService> {
    middleware: S,
}

impl<S> WebSocketRelayEventService<S> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`WebSocketRelayEventService`].
    pub fn new(middleware: S) -> Self {
        Self { middleware }
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
    /// to drop messages first and return buffered messages later
    pub messages: Vec<WebSocketRelayMessage>,
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
    /// Messages are sent before shutdown starts.
    ///
    /// When serving [`WebSocketRelayEvent::Close`], shutdown has already been
    /// initiated by the relay and both `messages` and `close` are ignored.
    pub close: Option<WebSocketRelayClose>,
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
            WebSocketRelayEvent::Ping(_)
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
    WithFrame(CloseFrame),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Direction data used as part of [`WebSocketRelayInput`],
/// most typically for users of [`WebSocketRelayService`].
pub enum WebSocketRelayDirection {
    Ingress,
    Egress,
}

impl<S, Ingress, Egress> Service<BridgeIo<Ingress, Egress>> for WebSocketRelayService<S>
where
    S: Service<WebSocketRelayInput, Output: Into<WebSocketRelayOutput>, Error: Into<BoxError>>,
    Ingress: Io + Unpin + extensions::ExtensionsRef,
    Egress: Io + Unpin + extensions::ExtensionsRef,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(
        &self,
        BridgeIo(ingress_stream, egress_stream): BridgeIo<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        relay_websockets(
            MessageRelayHandler {
                middleware: &self.middleware,
            },
            ingress_stream,
            egress_stream,
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

    async fn serve(
        &self,
        BridgeIo(ingress_stream, egress_stream): BridgeIo<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        relay_websockets(
            EventRelayHandler {
                middleware: &self.middleware,
            },
            ingress_stream,
            egress_stream,
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

enum RelayState {
    Continue,
    Finished,
}

async fn relay_websockets<H, Ingress, Egress>(
    handler: H,
    ingress_stream: Ingress,
    egress_stream: Egress,
) where
    H: RelayHandler,
    Ingress: Io + Unpin + extensions::ExtensionsRef,
    Egress: Io + Unpin + extensions::ExtensionsRef,
{
    let maybe_ws_config = egress_stream
        .extensions()
        .get_ref()
        .map(|RelayWebSocketConfig(cfg)| *cfg);

    let mut ingress_socket =
        AsyncWebSocket::from_raw_socket(ingress_stream, Role::Server, maybe_ws_config).await;
    let mut egress_socket =
        AsyncWebSocket::from_raw_socket(egress_stream, Role::Client, maybe_ws_config).await;

    // Each direction gets a child store of the socket the event arrived on.
    // Middleware can see the live socket's extensions without mutating it or
    // leaking inserts into the other relay direction.
    let mut ingress_relay_extensions = ingress_socket.extensions().fork();
    let mut egress_relay_extensions = egress_socket.extensions().fork();

    loop {
        let state = tokio::select! {
            ingress_result = ingress_socket.recv_message() => {
                match ingress_result {
                    Ok(message) => relay_message(
                        &handler,
                        WebSocketRelayDirection::Ingress,
                        message,
                        &mut ingress_socket,
                        &mut egress_socket,
                        &mut ingress_relay_extensions,
                    ).await,
                    Err(error) => {
                        tracing::debug!(
                            "ingress WS socket ended with error ({error})... drop MITM relay"
                        );
                        RelayState::Finished
                    }
                }
            }
            egress_result = egress_socket.recv_message() => {
                match egress_result {
                    Ok(message) => relay_message(
                        &handler,
                        WebSocketRelayDirection::Egress,
                        message,
                        &mut egress_socket,
                        &mut ingress_socket,
                        &mut egress_relay_extensions,
                    ).await,
                    Err(error) => {
                        tracing::debug!(
                            "egress WS socket ended with error ({error})... drop MITM relay"
                        );
                        RelayState::Finished
                    }
                }
            }
        };

        if matches!(state, RelayState::Finished) {
            return;
        }
    }
}

async fn relay_message<H, Source, Destination>(
    handler: &H,
    direction: WebSocketRelayDirection,
    message: crate::Message,
    source: &mut AsyncWebSocket<Source>,
    destination: &mut AsyncWebSocket<Destination>,
    relay_extensions: &mut Extensions,
) -> RelayState
where
    H: RelayHandler,
    Source: Io + Unpin,
    Destination: Io + Unpin,
{
    let (source_name, destination_name) = match direction {
        WebSocketRelayDirection::Ingress => ("ingress", "egress"),
        WebSocketRelayDirection::Egress => ("egress", "ingress"),
    };

    let (event, received_close, flush_automatic_response) = match message {
        crate::Message::Text(text) => (
            WebSocketRelayEvent::Data(WebSocketRelayMessage::Text(text)),
            None,
            false,
        ),
        crate::Message::Binary(bytes) => (
            WebSocketRelayEvent::Data(WebSocketRelayMessage::Binary(bytes)),
            None,
            false,
        ),
        crate::Message::Ping(bytes) => (WebSocketRelayEvent::Ping(bytes), None, true),
        crate::Message::Pong(bytes) => (WebSocketRelayEvent::Pong(bytes), None, false),
        crate::Message::Close(frame) => {
            (WebSocketRelayEvent::Close(frame.clone()), Some(frame), true)
        }
        crate::Message::Frame(_) => {
            tracing::debug!(
                "unexpected raw frame returned while reading {source_name} WS socket; drop it"
            );
            return RelayState::Continue;
        }
    };

    if flush_automatic_response && !flush_automatic_response_for(source, source_name).await {
        return RelayState::Finished;
    }

    if let Some(close_frame) = received_close {
        // Close is protocol-owned and cannot be delayed, dropped or rewritten
        // by middleware. Start the other connection's handshake before
        // notifying the handler; the advanced service observes the event, but
        // its output has no effect once shutdown has started.
        let wait_for_close = send_close(destination, destination_name, close_frame).await;
        let extensions = std::mem::take(relay_extensions);
        match handler.serve(direction, event, extensions).await {
            Ok(output) => *relay_extensions = output.extensions,
            Err(error) => {
                tracing::debug!(
                    "WS relay middleware failed while observing {source_name} close: ({})...",
                    error.into_box_error()
                );
            }
        }
        if wait_for_close {
            await_close_reply(destination, destination_name).await;
        }
        return RelayState::Finished;
    }

    let extensions = std::mem::take(relay_extensions);
    let RelayHandlerOutput {
        messages,
        close,
        extensions,
    } = match handler.serve(direction, event, extensions).await {
        Ok(output) => output,
        Err(error) => {
            tracing::debug!(
                "dropping WS relay due to middleware error on {source_name} event: ({})...",
                error.into_box_error()
            );
            return RelayState::Finished;
        }
    };
    *relay_extensions = extensions;

    for (message_index, message) in messages.into_iter().enumerate() {
        tracing::trace!(
            "relay {source_name} WS data message #{message_index} to {destination_name}"
        );
        if let Err(error) = destination.send(message.into()).await {
            if error.is_connection_error() {
                tracing::debug!(
                    "{destination_name} socket disconnected ({error}) @ message#{message_index}; drop MITM relay"
                );
                return RelayState::Finished;
            }
            tracing::debug!(
                "failed to relay {source_name} message to {destination_name}: {error} @ message#{message_index}; continue anyway.."
            );
        }
    }

    if let Some(close) = close {
        close_both(
            source,
            source_name,
            destination,
            destination_name,
            close.into_frame(),
        )
        .await;
        RelayState::Finished
    } else {
        RelayState::Continue
    }
}

async fn flush_automatic_response_for<Stream>(
    socket: &mut AsyncWebSocket<Stream>,
    socket_name: &str,
) -> bool
where
    Stream: Io + Unpin,
{
    match socket.flush().await {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(
                "failed to flush automatic WS control response to {socket_name} socket: {error}; drop MITM relay"
            );
            false
        }
    }
}

async fn close_both<Left, Right>(
    left: &mut AsyncWebSocket<Left>,
    left_name: &str,
    right: &mut AsyncWebSocket<Right>,
    right_name: &str,
    frame: Option<CloseFrame>,
) where
    Left: Io + Unpin,
    Right: Io + Unpin,
{
    let wait_for_left = send_close(left, left_name, frame.clone()).await;
    let wait_for_right = send_close(right, right_name, frame).await;

    tokio::join!(
        async {
            if wait_for_left {
                await_close_reply(left, left_name).await;
            }
        },
        async {
            if wait_for_right {
                await_close_reply(right, right_name).await;
            }
        },
    );
}

async fn send_close<Stream>(
    socket: &mut AsyncWebSocket<Stream>,
    socket_name: &str,
    frame: Option<CloseFrame>,
) -> bool
where
    Stream: Io + Unpin,
{
    match socket.send(crate::Message::Close(frame)).await {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!("failed to send close to {socket_name} socket: {error}");
            false
        }
    }
}

async fn await_close_reply<Stream>(socket: &mut AsyncWebSocket<Stream>, socket_name: &str)
where
    Stream: Io + Unpin,
{
    loop {
        match socket.recv_message().await {
            Ok(crate::Message::Close(_)) => {
                _ = socket.flush().await;
                return;
            }
            Ok(crate::Message::Ping(_)) => {
                _ = socket.flush().await;
            }
            Ok(_) => {}
            Err(error) => {
                tracing::debug!("{socket_name} socket ended while awaiting close: {error}");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Regression coverage for the per-direction `fork()` wiring of the
    //! relay's middleware extensions (see the `ingress_relay_extensions` /
    //! `egress_relay_extensions` `fork()` calls above). Two invariants are
    //! pinned end-to-end by driving `serve` over in-memory duplex streams:
    //!
    //! 1. **Live-socket isolation.** Middleware inserts must NOT leak onto
    //!    the underlying ingress/egress socket's extension store. `fork()`
    //!    lands inserts on a child blob whose parent is the live store;
    //!    `clone()` shares the top-level `Arc`, so inserts WOULD leak
    //!    back. The live store is reachable from the surrounding stack
    //!    (e.g. the proxy inspects the egress upgraded io's extensions),
    //!    so pollution is observable beyond this loop.
    //!
    //! 2. **Per-direction isolation.** Inserts from one direction must
    //!    NOT appear in the other direction's relay extensions. The
    //!    earlier shape used a single shared
    //!    `egress_socket.extensions().clone()` for BOTH directions,
    //!    conflating their relay state.
    //!
    //! The test exchanges one message per direction; the middleware
    //! records what it saw on each call and inserts a direction-specific
    //! marker. Post-conditions on the recorded log + the captured live
    //! socket stores cover both invariants.
    //!
    //! If the wiring ever regresses to `clone()` (per-direction or
    //! shared), the matching assertion below fails:
    //!   * shared `clone()` of one side  → cross-direction probe assertion
    //!   * per-direction `clone()`       → live-socket containment assertion

    use parking_lot::Mutex;
    use std::{sync::Arc, time::Duration};

    use rama_core::{
        Service,
        bytes::Bytes,
        error::{BoxError, BoxErrorExt as _},
        extensions::{Extension, Extensions, ExtensionsRef},
        futures::SinkExt as _,
        io::{BridgeIo, Io},
        service::MirrorService,
    };
    use rama_net::test_utils::client::MockSocket;
    use rama_utils::octets::kib;
    use tokio::{io::duplex, time::timeout};

    use crate::{
        AsyncWebSocket, Message,
        handshake::mitm::{
            WebSocketRelayClose, WebSocketRelayDirection, WebSocketRelayEvent,
            WebSocketRelayEventInput, WebSocketRelayEventOutput, WebSocketRelayEventService,
            WebSocketRelayInput, WebSocketRelayMessage, WebSocketRelayOutput,
            WebSocketRelayService,
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
    async fn regular_relay_keeps_ping_and_pong_on_their_connection() {
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
        assert_no_message(&mut peer_egress_ws, "egress peer after ingress ping").await;

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
        assert_no_message(&mut peer_ingress_ws, "ingress peer after egress ping").await;

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
            _input: WebSocketRelayEventInput,
        ) -> Result<Self::Output, Self::Error> {
            Err(BoxError::from_static_str("close observation failed"))
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
    async fn event_relay_observes_controls_without_forwarding_them() {
        let (relay_ingress_dup, peer_ingress_dup) = duplex(kib(16));
        let (relay_egress_dup, peer_egress_dup) = duplex(kib(16));

        let events = Arc::new(Mutex::new(Vec::new()));
        let service = WebSocketRelayEventService::new(RecordingEventMiddleware {
            events: events.clone(),
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
        assert_no_message(&mut peer_egress_ws, "egress peer after observed ping").await;

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

        assert_eq!(
            *events.lock(),
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
    struct CloseAfterDataMiddleware {
        frame: CloseFrame,
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
                WebSocketRelayEvent::Ping(_)
                | WebSocketRelayEvent::Pong(_)
                | WebSocketRelayEvent::Close(_) => Vec::new(),
            };
            Ok(WebSocketRelayEventOutput {
                messages,
                close: Some(WebSocketRelayClose::WithFrame(self.frame.clone())),
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
            frame: close_frame.clone(),
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
            .send_message(Message::text("last message"))
            .await
            .expect("send final ingress text");
        assert_eq!(
            expect_message(&mut peer_egress_ws, "receive final egress text").await,
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
            Some(close_frame)
        );
    }
}
