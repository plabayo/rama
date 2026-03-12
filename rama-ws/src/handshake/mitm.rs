use std::convert::Infallible;

use rama_core::{
    Service,
    bytes::Bytes,
    error::{BoxError, ErrorExt},
    extensions::{self, Extensions, ExtensionsMut, ExtensionsRef},
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
/// such as the possibility to drop or buffer messages,
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
/// Most typically used as Input+Output
/// for users of [`WebSocketRelayService`].
pub struct WebSocketRelayData {
    pub direction: WebSocketRelayDirection,
    pub message: WebSocketRelayMessage,
    pub extensions: Extensions,
}

impl ExtensionsRef for WebSocketRelayData {
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl ExtensionsMut for WebSocketRelayData {
    #[inline(always)]
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

#[derive(Debug, Clone)]
/// Non-meta WebSocket messages, used as part of [`WebSocketRelayData`],
/// most typically for users of [`WebSocketRelayService`].
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
/// Direction data used as part of [`WebSocketRelayData`],
/// most typically for users of [`WebSocketRelayService`].
pub enum WebSocketRelayDirection {
    Ingress,
    Egress,
}

impl<S, Ingress, Egress> Service<BridgeIo<Ingress, Egress>> for WebSocketRelayService<S>
where
    S: Service<WebSocketRelayData, Output = WebSocketRelayData, Error: Into<BoxError>>,
    Ingress: Io + Unpin + extensions::ExtensionsMut,
    Egress: Io + Unpin + extensions::ExtensionsMut,
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
            .get()
            .map(|RelayWebSocketConfig(cfg)| *cfg);

        let mut ingress_socket =
            AsyncWebSocket::from_raw_socket(ingress_stream, Role::Server, maybe_ws_config).await;
        let mut egress_socket =
            AsyncWebSocket::from_raw_socket(egress_stream, Role::Client, maybe_ws_config).await;

        let mut relay_extensions = egress_socket.extensions().clone();

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
                            match middleware.serve(WebSocketRelayData {
                                direction: WebSocketRelayDirection::Ingress,
                                message: msg,
                                extensions: relay_extensions,
                            }).await {
                                Ok(WebSocketRelayData {
                                    direction: _,
                                    message,
                                    extensions,
                                }) => {
                                    relay_extensions = extensions;
                                    tracing::trace!("relay text/binary ingress WS message");
                                    if let Err(err) = egress_socket.send(message.into()).await {
                                        if err.is_connection_error() {
                                            tracing::debug!("egress socket disconnected ({err})... drop MITM relay");
                                            return Ok(());
                                        }
                                        tracing::debug!("failed to relay ingress msg: {err}; continue anyway..");
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
                            match middleware.serve(WebSocketRelayData {
                                direction: WebSocketRelayDirection::Egress,
                                message: msg,
                                extensions: relay_extensions,
                            }).await {
                                Ok(WebSocketRelayData {
                                    direction: _,
                                    message,
                                    extensions,
                                }) => {
                                    relay_extensions = extensions;
                                    tracing::trace!("relay text/binary egress WS message");
                                    if let Err(err) = ingress_socket.send(message.into()).await {
                                        if err.is_connection_error() {
                                            tracing::debug!("ingress socket disconnected ({err})... drop MITM relay");
                                            return Ok(());
                                        }
                                        tracing::debug!("failed to relay egress msg: {err}; continue anyway..");
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
