use crate::{
    Utf8Bytes,
    handshake::mitm::{WebSocketRelayDirection, WebSocketRelayInjector, WebSocketRelayMessage},
    protocol::frame::coding::CloseCode,
};
use parking_lot::RwLock;
use rama_core::{
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    extensions::Extension,
    futures::{Stream, stream},
};
use rama_http::inspect::capture::{
    CaptureMetadata, CaptureStore, CapturedBody, CapturedRecord, ExchangeCapture,
    HttpCaptureProtocol,
};
use rama_net::Protocol;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketMessageKind {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}
impl fmt::Display for WebSocketMessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Close => "close",
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketMessageOrigin {
    #[default]
    Peer,
    Replay,
    Injected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedWebSocketMessage {
    pub at: jiff::Timestamp,
    pub direction: WebSocketRelayDirection,
    pub kind: WebSocketMessageKind,
    pub data: Bytes,
    pub close_code: Option<CloseCode>,
    pub origin: WebSocketMessageOrigin,
}
impl CapturedWebSocketMessage {
    pub fn new(
        direction: WebSocketRelayDirection,
        kind: WebSocketMessageKind,
        data: Bytes,
    ) -> Self {
        Self {
            at: jiff::Timestamp::now(),
            direction,
            kind,
            data,
            close_code: None,
            origin: WebSocketMessageOrigin::Peer,
        }
    }
}
impl CapturedRecord for CapturedWebSocketMessage {
    fn matches_search(&self, needle: &str) -> bool {
        rama_inspect::search::matches_display(&rama_utils::fmt::utf8_or_hex(&self.data), needle)
    }
}

#[derive(Debug, Clone, Copy, Extension)]
pub struct WebSocketLimits {
    pub messages: usize,
}
impl Default for WebSocketLimits {
    fn default() -> Self {
        Self { messages: 4096 }
    }
}

/// Recognize an HTTP/1 upgrade or HTTP/2 extended CONNECT handshake. The marker
/// and limits are owned here; HTTP capture doesn't import WebSocket definitions.
pub fn observe_handshake(
    parts: &rama_http::request::Parts,
    metadata: &CaptureMetadata,
    limits: WebSocketLimits,
) -> bool {
    let websocket = match parts.version {
        rama_http::Version::HTTP_10 | rama_http::Version::HTTP_11 => parts
            .headers
            .get(rama_http::header::UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket")),
        rama_http::Version::HTTP_2 => {
            parts.method == rama_http::Method::CONNECT
                && parts
                    .extensions
                    .get_ref::<rama_http::proto::h2::ext::Protocol>()
                    .is_some_and(|value| value.as_str().eq_ignore_ascii_case("websocket"))
        }
        _ => false,
    };
    if websocket {
        let secure =
            rama_http::protocol_from_uri_or_extensions(&parts.extensions, &parts.uri).is_secure();
        metadata.exchange.insert(HttpCaptureProtocol(if secure {
            Protocol::WSS
        } else {
            Protocol::WS
        }));
        metadata.exchange.insert(limits);
    }
    websocket
}

#[derive(Debug, Default, Extension)]
struct State {
    injector: RwLock<Option<WebSocketRelayInjector>>,
    messages: AtomicUsize,
    truncated: AtomicBool,
}
struct AppendGuard {
    exchange: ExchangeCapture,
    state: Arc<State>,
    committed: bool,
}
impl Drop for AppendGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.state.truncated.store(true, Ordering::Release);
            self.exchange.mark_truncated();
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WebSocketDetails {
    pub messages: Vec<CapturedWebSocketMessage>,
    pub page: usize,
    pub total: usize,
    pub replay_active: bool,
}

#[derive(Debug)]
pub enum WebSocketReplayError {
    CaptureNotFound,
    MessageNotFound,
    ControlFrame,
    Truncated,
    ConnectionClosed,
    SendFailed(BoxError),
    InvalidCapture(BoxError),
    InvalidMessage(BoxError),
}
impl fmt::Display for WebSocketReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureNotFound => f.write_str("capture not found"),
            Self::MessageNotFound => f.write_str("WebSocket message not found"),
            Self::ControlFrame => f.write_str("WebSocket control frames cannot be replayed"),
            Self::Truncated => f.write_str("truncated WebSocket data cannot be replayed safely"),
            Self::ConnectionClosed => f.write_str("the original WebSocket connection is closed"),
            Self::SendFailed(error) => write!(f, "failed to send WebSocket message: {error}"),
            Self::InvalidCapture(error) => write!(f, "read captured WebSocket message: {error}"),
            Self::InvalidMessage(error) => write!(f, "invalid WebSocket message: {error}"),
        }
    }
}
impl std::error::Error for WebSocketReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SendFailed(error) | Self::InvalidCapture(error) | Self::InvalidMessage(error) => {
                Some(error.as_ref())
            }
            _ => None,
        }
    }
}

pub trait CaptureWebSocketExt {
    fn record_websocket_message(
        &self,
        id: u64,
        message: CapturedWebSocketMessage,
    ) -> impl Future<Output = ()> + Send;
    fn register_websocket_injector(&self, id: u64, injector: WebSocketRelayInjector);
    fn websocket_details(
        &self,
        id: u64,
        page: usize,
        page_size: usize,
    ) -> impl Future<Output = Result<WebSocketDetails, BoxError>> + Send;
    fn replay_websocket_message(
        &self,
        id: u64,
        index: usize,
    ) -> impl Future<Output = Result<(), WebSocketReplayError>> + Send;
    fn send_websocket_message(
        &self,
        id: u64,
        direction: WebSocketRelayDirection,
        message: WebSocketRelayMessage,
    ) -> impl Future<Output = Result<(), WebSocketReplayError>> + Send;
    fn websocket_message_stream(
        &self,
        id: u64,
        index: usize,
    ) -> Result<impl Stream<Item = Result<Bytes, BoxError>> + Send + 'static, BoxError>;
}
impl CaptureWebSocketExt for CaptureStore {
    async fn record_websocket_message(&self, id: u64, message: CapturedWebSocketMessage) {
        let Ok(exchange) = self.exchange_capture(id) else {
            return;
        };
        let state = exchange.state::<State>();
        let Some(_permit) = exchange.inspection_state().try_capture() else {
            exchange.mark_truncated();
            return;
        };
        let direction = body_direction(message.direction);
        let length = message.data.len() as u64;
        exchange.record_bytes(direction, length);
        if state.truncated.load(Ordering::Acquire) {
            exchange.changed();
            return;
        }
        let limit = exchange
            .metadata()
            .exchange
            .get_ref::<WebSocketLimits>()
            .copied()
            .unwrap_or_default()
            .messages;
        if !exchange.reserve_body(direction, length)
            || state
                .messages
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < limit).then(|| count + 1)
                })
                .is_err()
        {
            state.truncated.store(true, Ordering::Release);
            exchange.mark_truncated();
            return;
        }
        let mut guard = AppendGuard {
            exchange: exchange.clone(),
            state,
            committed: false,
        };
        match exchange.append(&message).await {
            Ok(true) => guard.committed = true,
            Ok(false) => {}
            Err(error) => rama_core::telemetry::tracing::debug!(
                "failed to capture WebSocket message: {error}"
            ),
        }
        exchange.changed();
    }
    fn register_websocket_injector(&self, id: u64, injector: WebSocketRelayInjector) {
        if !injector.is_open() {
            return;
        }
        let Ok(exchange) = self.exchange_capture(id) else {
            return;
        };
        let state = exchange.state::<State>();
        let mut current = state.injector.write();
        if current.is_none() {
            *current = Some(injector);
            exchange.set_active();
        }
    }
    async fn websocket_details(
        &self,
        id: u64,
        page: usize,
        page_size: usize,
    ) -> Result<WebSocketDetails, BoxError> {
        let exchange = self.exchange_capture(id)?;
        read_details(&exchange, page, page_size).await
    }

    async fn replay_websocket_message(
        &self,
        id: u64,
        index: usize,
    ) -> Result<(), WebSocketReplayError> {
        let exchange = self
            .exchange_capture(id)
            .map_err(|_missing| WebSocketReplayError::CaptureNotFound)?;
        let mut message = exchange
            .records::<CapturedWebSocketMessage>(index..index.saturating_add(1))
            .await
            .map_err(WebSocketReplayError::InvalidCapture)?
            .pop()
            .ok_or(WebSocketReplayError::MessageNotFound)?;
        let summary = exchange.snapshot();
        let truncated = match message.direction {
            WebSocketRelayDirection::Ingress => summary.request_truncated,
            WebSocketRelayDirection::Egress => summary.response_truncated,
        };
        if truncated {
            return Err(WebSocketReplayError::Truncated);
        }
        let relay = match message.kind {
            WebSocketMessageKind::Text => WebSocketRelayMessage::Text(
                Utf8Bytes::try_from(message.data.clone())
                    .context("decode captured WebSocket UTF-8")
                    .map_err(WebSocketReplayError::InvalidCapture)?,
            ),
            WebSocketMessageKind::Binary => WebSocketRelayMessage::Binary(message.data.clone()),
            _ => return Err(WebSocketReplayError::ControlFrame),
        };
        send(&exchange, message.direction, relay).await?;
        message.at = jiff::Timestamp::now();
        message.origin = WebSocketMessageOrigin::Replay;
        self.record_websocket_message(id, message).await;
        Ok(())
    }
    async fn send_websocket_message(
        &self,
        id: u64,
        direction: WebSocketRelayDirection,
        message: WebSocketRelayMessage,
    ) -> Result<(), WebSocketReplayError> {
        let exchange = self
            .exchange_capture(id)
            .map_err(|_missing| WebSocketReplayError::CaptureNotFound)?;
        let (kind, data) = match &message {
            WebSocketRelayMessage::Text(text) => {
                (WebSocketMessageKind::Text, Bytes::from(text.clone()))
            }
            WebSocketRelayMessage::Binary(data) => (WebSocketMessageKind::Binary, data.clone()),
        };
        send(&exchange, direction, message).await?;
        let mut captured = CapturedWebSocketMessage::new(direction, kind, data);
        captured.origin = WebSocketMessageOrigin::Injected;
        self.record_websocket_message(id, captured).await;
        Ok(())
    }
    fn websocket_message_stream(
        &self,
        id: u64,
        index: usize,
    ) -> Result<impl Stream<Item = Result<Bytes, BoxError>> + Send + 'static, BoxError> {
        let exchange = self.exchange_capture(id)?;
        if index >= exchange.count::<CapturedWebSocketMessage>() {
            return Err("WebSocket message not found".into());
        }
        Ok(stream::once(async move {
            exchange
                .records::<CapturedWebSocketMessage>(index..index.saturating_add(1))
                .await?
                .pop()
                .map(|message| message.data)
                .context("WebSocket message not found")
        }))
    }
}
fn body_direction(direction: WebSocketRelayDirection) -> CapturedBody {
    match direction {
        WebSocketRelayDirection::Ingress => CapturedBody::Request,
        WebSocketRelayDirection::Egress => CapturedBody::Response,
    }
}
async fn send(
    exchange: &ExchangeCapture,
    direction: WebSocketRelayDirection,
    message: WebSocketRelayMessage,
) -> Result<(), WebSocketReplayError> {
    let injector = exchange
        .state::<State>()
        .injector
        .read()
        .clone()
        .filter(WebSocketRelayInjector::is_open)
        .ok_or(WebSocketReplayError::ConnectionClosed)?;
    injector
        .send(direction, message)
        .await
        .map_err(|error| WebSocketReplayError::SendFailed(error.into()))
}

/// Read a page from a retained exchange, including after it leaves the live capture list.
pub async fn read_details(
    exchange: &ExchangeCapture,
    page: usize,
    page_size: usize,
) -> Result<WebSocketDetails, BoxError> {
    let total = exchange.count::<CapturedWebSocketMessage>();
    let page = if total == 0 || page_size == 0 {
        0
    } else {
        page.min((total - 1) / page_size)
    };
    let end = total.saturating_sub(page.saturating_mul(page_size));
    let start = end.saturating_sub(page_size);
    let messages = exchange.records(start..end).await?;
    let replay_active = exchange
        .state::<State>()
        .injector
        .read()
        .as_ref()
        .is_some_and(WebSocketRelayInjector::is_open);
    Ok(WebSocketDetails {
        messages,
        page,
        total,
        replay_active,
    })
}
