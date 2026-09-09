use std::{
    fmt,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use parking_lot::RwLock;
use rama_core::{
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    extensions::Extension,
    futures::{Stream, StreamExt, async_stream::stream_fn},
    stream::io::ReaderStream,
};
use rama_http::{
    inspect::capture::{
        CaptureMetadata, CaptureStore, CapturedBody, CapturedRecord, CapturedRecordStream,
        ExchangeCapture,
    },
    request::Parts,
};
use rama_net::{Protocol, ProtocolInputExt as _};
use rama_utils::octets::mib;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncReadExt as _,
    sync::{OwnedSemaphorePermit, Semaphore},
};

use crate::{
    Utf8Bytes,
    handshake::{
        matcher::is_http_req_websocket_handshake,
        mitm::{WebSocketRelayDirection, WebSocketRelayInjector, WebSocketRelayMessage},
    },
    protocol::frame::coding::CloseCode,
};

// The relay accepts owned messages. Bound their aggregate allocation, including
// concurrent replay operations, until the relay has consumed each message.
const MAX_REPLAY_BYTES: usize = mib(8);
static REPLAY_BYTES: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_REPLAY_BYTES)));

struct ReplayPayload {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for ReplayPayload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

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
    #[serde(with = "rama_utils::bytes::serde_base64")]
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

/// Small serializable message head, independent of its raw payload reader.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WebSocketMessageMetadata {
    /// Logical payload length, available without reading the payload.
    pub payload_length: u64,
    pub at: jiff::Timestamp,
    pub direction: WebSocketRelayDirection,
    pub kind: WebSocketMessageKind,
    pub close_code: Option<CloseCode>,
    pub origin: WebSocketMessageOrigin,
}

impl CapturedRecord for CapturedWebSocketMessage {
    type Metadata = WebSocketMessageMetadata;

    fn metadata(&self) -> Self::Metadata {
        WebSocketMessageMetadata {
            payload_length: self.data.len() as u64,
            at: self.at,
            direction: self.direction,
            kind: self.kind,
            close_code: self.close_code,
            origin: self.origin,
        }
    }

    fn payload(&self) -> Bytes {
        self.data.clone()
    }

    fn from_parts(metadata: Self::Metadata, data: Bytes) -> Self {
        Self {
            at: metadata.at,
            direction: metadata.direction,
            kind: metadata.kind,
            close_code: metadata.close_code,
            origin: metadata.origin,
            data,
        }
    }

    async fn matches_stream(
        record: CapturedRecordStream<Self::Metadata>,
        needle: &str,
    ) -> Result<bool, BoxError> {
        Ok(rama_inspect::search::matches_reader(record.payload, needle).await?)
    }
}

/// Per-exchange limit on retained WebSocket messages.
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
    parts: &Parts,
    metadata: &CaptureMetadata,
    limits: WebSocketLimits,
) -> bool {
    let websocket = is_http_req_websocket_handshake(parts);
    if websocket {
        let secure = parts.protocol().is_some_and(Protocol::is_secure);
        metadata
            .exchange
            .insert(if secure { Protocol::WSS } else { Protocol::WS });
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
pub struct WebSocketDetails<M = CapturedWebSocketMessage> {
    pub messages: Vec<M>,
    pub page: usize,
    pub total: usize,
    pub replay_active: bool,
}

/// Bounded raw payload prefix with the original message metadata and full length.
#[derive(Debug, Clone, Serialize)]
pub struct WebSocketMessagePreview {
    pub metadata: WebSocketMessageMetadata,
    #[serde(with = "rama_utils::bytes::serde_base64")]
    pub data: Bytes,
}

impl From<CapturedWebSocketMessage> for WebSocketMessagePreview {
    fn from(message: CapturedWebSocketMessage) -> Self {
        Self {
            metadata: message.metadata(),
            data: message.data,
        }
    }
}

#[derive(Debug)]
pub enum WebSocketReplayError {
    CaptureNotFound,
    MessageNotFound,
    ControlFrame,
    Truncated,
    ConnectionClosed,
    TooLarge,
    Busy,
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
            Self::TooLarge => {
                f.write_str("WebSocket payload exceeds the replay or relay size limit")
            }
            Self::Busy => f.write_str("WebSocket replay memory budget is in use"),
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
        let record = exchange
            .record_stream::<CapturedWebSocketMessage>(index)
            .await
            .map_err(WebSocketReplayError::InvalidCapture)?
            .ok_or(WebSocketReplayError::MessageNotFound)?;
        let summary = exchange.snapshot();
        let truncated = match record.metadata.direction {
            WebSocketRelayDirection::Ingress => summary.request_truncated,
            WebSocketRelayDirection::Egress => summary.response_truncated,
        };
        if truncated {
            return Err(WebSocketReplayError::Truncated);
        }
        if !matches!(
            record.metadata.kind,
            WebSocketMessageKind::Text | WebSocketMessageKind::Binary
        ) {
            return Err(WebSocketReplayError::ControlFrame);
        }
        let injector = injector(&exchange)?;
        let length = record.metadata.payload_length;
        let limit = injector
            .max_message_size()
            .unwrap_or(MAX_REPLAY_BYTES)
            .min(MAX_REPLAY_BYTES);
        if length > limit as u64 {
            return Err(WebSocketReplayError::TooLarge);
        }
        let budget = REPLAY_BYTES
            .clone()
            .try_acquire_many_owned(length.max(1) as u32)
            .map_err(|_full| WebSocketReplayError::Busy)?;
        // Fixed capacity avoids geometric growth beyond the admitted payload.
        let mut payload = vec![0; length as usize];
        let mut reader = record.payload;
        reader
            .read_exact(&mut payload)
            .await
            .context("read captured WebSocket payload")
            .map_err(WebSocketReplayError::InvalidCapture)?;
        let mut trailing = [0];
        if reader
            .read(&mut trailing)
            .await
            .context("finish captured WebSocket payload")
            .map_err(WebSocketReplayError::InvalidCapture)?
            != 0
        {
            return Err(WebSocketReplayError::InvalidCapture(
                std::io::Error::other("captured WebSocket payload exceeds its recorded length")
                    .into(),
            ));
        }
        // The writer queue may outlive a cancelled replay request. Keeping the
        // permit in the shared bytes prevents cancellation from bypassing admission.
        let payload = Bytes::from_owner(ReplayPayload {
            bytes: payload,
            _permit: budget,
        });
        let mut message = CapturedWebSocketMessage::from_parts(record.metadata, payload);
        let relay = match message.kind {
            WebSocketMessageKind::Text => WebSocketRelayMessage::Text(
                Utf8Bytes::try_from(message.data.clone())
                    .context("decode captured WebSocket UTF-8")
                    .map_err(WebSocketReplayError::InvalidCapture)?,
            ),
            WebSocketMessageKind::Binary => WebSocketRelayMessage::Binary(message.data.clone()),
            _ => return Err(WebSocketReplayError::ControlFrame),
        };
        injector
            .send(message.direction, relay)
            .await
            .map_err(|error| WebSocketReplayError::SendFailed(error.into()))?;
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
        Ok(stream_fn(move |mut output| async move {
            let result = async {
                let record = exchange
                    .record_stream::<CapturedWebSocketMessage>(index)
                    .await?
                    .context("WebSocket message not found")?;
                let mut chunks = ReaderStream::new(record.payload);
                while let Some(chunk) = chunks.next().await {
                    output.yield_item(Ok(chunk?)).await;
                }
                Ok::<(), BoxError>(())
            }
            .await;
            if let Err(error) = result {
                output.yield_item(Err(error)).await;
            }
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
    let injector = injector(exchange)?;
    injector
        .send(direction, message)
        .await
        .map_err(|error| WebSocketReplayError::SendFailed(error.into()))
}

fn injector(exchange: &ExchangeCapture) -> Result<WebSocketRelayInjector, WebSocketReplayError> {
    exchange
        .state::<State>()
        .injector
        .read()
        .clone()
        .filter(WebSocketRelayInjector::is_open)
        .ok_or(WebSocketReplayError::ConnectionClosed)
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

/// Read a page of bounded prefixes for a GUI or TUI without materializing messages.
/// The interface chooses its per-message limit from the metadata. Full payloads
/// remain available through record streams and the explicit owned details API.
pub async fn read_preview_details(
    exchange: &ExchangeCapture,
    page: usize,
    page_size: usize,
    payload_limit: impl Fn(&WebSocketMessageMetadata) -> usize + Send + Sync,
) -> Result<WebSocketDetails<WebSocketMessagePreview>, BoxError> {
    let total = exchange.count::<CapturedWebSocketMessage>();
    let page = if total == 0 || page_size == 0 {
        0
    } else {
        page.min((total - 1) / page_size)
    };
    let end = total.saturating_sub(page.saturating_mul(page_size));
    let start = end.saturating_sub(page_size);
    let mut messages = Vec::with_capacity(end - start);
    for index in start..end {
        let record = exchange
            .record_stream::<CapturedWebSocketMessage>(index)
            .await?
            .context("WebSocket message not found")?;
        let mut data = Vec::new();
        record
            .payload
            .take(payload_limit(&record.metadata) as u64)
            .read_to_end(&mut data)
            .await?;
        messages.push(WebSocketMessagePreview {
            metadata: record.metadata,
            data: data.into(),
        });
    }
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

#[cfg(test)]
mod replay_tests;
