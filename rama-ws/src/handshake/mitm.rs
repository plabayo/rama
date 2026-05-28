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
    AsyncWebSocket, ProtocolError, Utf8Bytes, handshake::matcher::RelayWebSocketConfig,
    protocol::Role,
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
/// Fork or create your own relay service for more advanced purposes,
/// such as the possibility to side-channel messages,
/// or even route messages via external services.
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
        let Self { middleware } = self;

        let maybe_ws_config = egress_stream
            .extensions()
            .get_ref()
            .map(|RelayWebSocketConfig(cfg)| *cfg);

        let mut ingress_socket =
            AsyncWebSocket::from_raw_socket(ingress_stream, Role::Server, maybe_ws_config).await;
        let mut egress_socket =
            AsyncWebSocket::from_raw_socket(egress_stream, Role::Client, maybe_ws_config).await;

        // Per-direction relay state, each `fork`ed from its own socket so the
        // middleware sees the extensions of the side a message arrived on, and
        // its inserts stay isolated (a child store) instead of leaking back
        // onto the live ingress/egress WS sockets (which a shared `clone` of
        // the egress store would have done for both directions).
        let mut ingress_relay_extensions = ingress_socket.extensions().fork();
        let mut egress_relay_extensions = egress_socket.extensions().fork();

        loop {
            tokio::select! {
                ingress_result = ingress_socket.recv_message() => {
                    match ingress_result {
                        Ok(msg) => {
                            let msg = match msg {
                                crate::Message::Text(utf8_bytes) => {
                                    WebSocketRelayMessage::Text(utf8_bytes)
                                },
                                crate::Message::Binary(bytes) => {
                                    WebSocketRelayMessage::Binary(bytes)
                                }
                                crate::Message::Ping(_) | crate::Message::Pong(_) | crate::Message::Close(_) | crate::Message::Frame(_) => {
                                    tracing::trace!("relay ingress WS meta message as-is, without passing through middleware");
                                    if let Err(err) = egress_socket.send(msg).await {
                                        if err.is_connection_error() {
                                            tracing::debug!("egress socket disconnected ({err})... drop MITM relay");
                                            return Ok(());
                                        }
                                        tracing::debug!("failed to relay ingress msg: {err}; continue anyway..");
                                    }
                                    continue;
                                },
                            };
                            match middleware.serve(WebSocketRelayInput {
                                direction: WebSocketRelayDirection::Ingress,
                                message: msg,
                                extensions: ingress_relay_extensions,
                            }).await.map(Into::into) {
                                Ok(WebSocketRelayOutput {
                                    messages,
                                    extensions,
                                }) => {
                                    ingress_relay_extensions = extensions;
                                    tracing::trace!("relay text/binary ingress WS message(s)");
                                    for (message_index, message) in messages.into_iter().enumerate() {
                                        tracing::trace!("relay text/binary ingress WS message #{message_index}");
                                        if let Err(err) = egress_socket.send(message.into()).await {
                                            if err.is_connection_error() {
                                                tracing::debug!("egress socket disconnected ({err}) @ message#{message_index}... drop MITM relay");
                                                return Ok(());
                                            }
                                            tracing::debug!("failed to relay ingress msg: {err} @ message#{message_index}; continue anyway..");
                                        }
                                    }
                                },
                                Err(err) => {
                                    tracing::debug!("dropping WS Relay msg due to middleware error on ingress msg: ({})...", err.into_box_error());
                                    return Ok(());
                                },
                            }
                        },
                        Err(err) => {
                            if err.is_connection_error() || matches!(err, ProtocolError::ResetWithoutClosingHandshake) {
                                tracing::debug!("ingress WS socket disconnected ({err})... drop MITM relay");
                            } else {
                                tracing::debug!("ingress WS socket failed with error: {err}; drop MITM relay");
                            }
                            return Ok(());
                        }
                    }
                }

                egress_result = egress_socket.recv_message() => {
                    match egress_result {
                        Ok(msg) => {
                            let msg = match msg {
                                crate::Message::Text(utf8_bytes) => {
                                    WebSocketRelayMessage::Text(utf8_bytes)
                                },
                                crate::Message::Binary(bytes) => {
                                    WebSocketRelayMessage::Binary(bytes)
                                }
                                crate::Message::Ping(_) | crate::Message::Pong(_) | crate::Message::Close(_) | crate::Message::Frame(_) => {
                                    tracing::trace!("relay egress WS meta message as-is, without passing through middleware");
                                    if let Err(err) = ingress_socket.send(msg).await {
                                        if err.is_connection_error() {
                                            tracing::debug!("ingress socket disconnected ({err})... drop MITM relay");
                                            return Ok(());
                                        }
                                        tracing::debug!("failed to relay egress msg: {err}; continue anyway..");
                                    }
                                    continue;
                                },
                            };
                            match middleware.serve(WebSocketRelayInput {
                                direction: WebSocketRelayDirection::Egress,
                                message: msg,
                                extensions: egress_relay_extensions,
                            }).await.map(Into::into) {
                                Ok(WebSocketRelayOutput {
                                    messages,
                                    extensions,
                                }) => {
                                    egress_relay_extensions = extensions;
                                    tracing::trace!("relay text/binary egress WS message(s)");
                                    for (message_index, message) in messages.into_iter().enumerate() {
                                        tracing::trace!("relay text/binary egress WS message #{message_index}");
                                        if let Err(err) = ingress_socket.send(message.into()).await {
                                            if err.is_connection_error() {
                                                tracing::debug!("ingress socket disconnected ({err}) @ message#{message_index}... drop MITM relay");
                                                return Ok(());
                                            }
                                            tracing::debug!("failed to relay egress msg: {err} @ message#{message_index}; continue anyway..");
                                        }
                                    }
                                },
                                Err(err) => {
                                    tracing::debug!("dropping WS relay msg due to middleware error on egress msg: ({})...", err.into_box_error());
                                    return Ok(());
                                },
                            }
                        },
                        Err(err) => {
                            if err.is_connection_error() || matches!(err, ProtocolError::ResetWithoutClosingHandshake) {
                                tracing::debug!("egress WS socket disconnected ({err})... drop MITM relay");
                            } else {
                                tracing::debug!("egress WS socket failed with error: {err}; drop MITM relay");
                            }
                            return Ok(());
                        }
                    }
                }
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

    use std::sync::{Arc, Mutex};

    use rama_core::{
        Service,
        error::BoxError,
        extensions::{Extension, ExtensionsRef},
        io::BridgeIo,
    };
    use rama_net::test_utils::client::MockSocket;
    use tokio::io::duplex;

    use crate::{
        AsyncWebSocket, Message,
        handshake::mitm::{
            WebSocketRelayDirection, WebSocketRelayInput, WebSocketRelayOutput,
            WebSocketRelayService,
        },
        protocol::Role,
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

        async fn serve(
            &self,
            input: WebSocketRelayInput,
        ) -> Result<Self::Output, Self::Error> {
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
            self.log.lock().unwrap().push(obs);
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
        let (relay_ingress_dup, peer_ingress_dup) = duplex(16 * 1024);
        let (relay_egress_dup, peer_egress_dup) = duplex(16 * 1024);

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

        let relay = tokio::spawn(async move {
            svc.serve(BridgeIo(relay_ingress, relay_egress)).await
        });

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
        match peer_egress_ws
            .recv_message()
            .await
            .expect("peer egress recv")
        {
            Message::Text(t) => assert_eq!(t.as_str(), "ping"),
            other => panic!("unexpected message on egress peer: {other:?}"),
        }

        // egress -> ingress
        peer_egress_ws
            .send_message(Message::text("pong"))
            .await
            .expect("peer egress send");
        match peer_ingress_ws
            .recv_message()
            .await
            .expect("peer ingress recv")
        {
            Message::Text(t) => assert_eq!(t.as_str(), "pong"),
            other => panic!("unexpected message on ingress peer: {other:?}"),
        }

        // Dropping a peer closes its duplex end; the relay sees a connection
        // error and returns.
        drop(peer_ingress_ws);
        drop(peer_egress_ws);
        let _ = relay.await.expect("relay task join");

        let log = log.lock().unwrap();
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
        assert!(ingress.saw_ingress_marker, "ingress fork sees IngressMarker");
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
}
