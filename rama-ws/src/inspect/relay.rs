//! WebSocket capture and interception adapters, enabled independently of storage.

use std::convert::Infallible;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rama_core::{bytes::Bytes, extensions::Extensions};
use rama_http::inspect::{
    capture::{CaptureStore, HttpExchangeId},
    control::{Decision, Direction, HttpUpgradeContext, Payload},
};
use rama_net::Protocol;
use rama_utils::str::non_empty_str;

use crate::{
    handshake::mitm::{
        WebSocketRelayClose, WebSocketRelayDirection, WebSocketRelayEvent,
        WebSocketRelayEventInput, WebSocketRelayEventOutput, WebSocketRelayInjector,
        WebSocketRelayMessage,
    },
    inspect::{
        CaptureWebSocketExt, CapturedWebSocketMessage, WebSocketMessageKind, WebSocketMessageOrigin,
    },
    protocol::{CloseFrame, frame::coding::CloseCode},
};

fn close_intercepted_websocket(
    extensions: Extensions,
    code: u16,
    reason: String,
) -> WebSocketRelayEventOutput {
    WebSocketRelayEventOutput {
        messages: vec![],
        close: Some(WebSocketRelayClose::WithFrame(CloseFrame {
            code: CloseCode::from(code),
            reason: reason.into(),
        })),
        extensions,
    }
}

pub async fn inspect_websocket_event(
    capture: Option<CaptureStore>,
    input: WebSocketRelayEventInput,
) -> Result<WebSocketRelayEventOutput, Infallible> {
    let WebSocketRelayEventInput {
        direction,
        mut event,
        extensions,
    } = input;
    if let (Some(store), Some(context), WebSocketRelayEvent::Data(data)) = (
        capture.as_ref().filter(|s| s.control().is_active()),
        extensions.get_ref::<HttpUpgradeContext>(),
        &event,
    ) {
        let mut message = context.request.clone();
        message.protocol = if message.protocol.is_secure() {
            Protocol::WSS
        } else {
            Protocol::WS
        };
        message.direction = match direction {
            WebSocketRelayDirection::Ingress => Direction::Ingress,
            WebSocketRelayDirection::Egress => Direction::Egress,
        };
        message.exchange = extensions.get_ref::<HttpExchangeId>().map(|id| id.0);
        message.binary = matches!(data, WebSocketRelayMessage::Binary(_));
        message.kind = Some(if message.binary {
            non_empty_str!("binary")
        } else {
            non_empty_str!("text")
        });
        let size = match data {
            WebSocketRelayMessage::Text(t) => t.len(),
            WebSocketRelayMessage::Binary(b) => b.len().saturating_mul(4).div_ceil(3),
        };
        message.oversized = size > rama_utils::octets::kib(256);
        message.payload = (!message.oversized).then(|| match data {
            WebSocketRelayMessage::Text(t) => Payload::text(t.clone()),
            WebSocketRelayMessage::Binary(b) => Payload::binary(b.clone()),
        });
        let (decision, reason) = store
            .control()
            .decide(&context.connection, message.clone())
            .await;
        if let (Some(id), Some(reason)) = (message.exchange, reason) {
            let outcome = match &decision {
                Decision::Forward { .. } => "Forwarded",
                Decision::Close { .. } => "Closed",
                _ => "Dropped",
            };
            store
                .record_decision(id, &message, &format!("{outcome} · {reason}"), None)
                .await;
        }
        match decision {
            Decision::Forward {
                payload: Some(payload),
                ..
            } => {
                event = WebSocketRelayEvent::Data(if message.binary {
                    let Ok(bytes) = BASE64.decode(payload) else {
                        return Ok(close_intercepted_websocket(
                            extensions,
                            1011,
                            "Invalid approved payload".into(),
                        ));
                    };
                    WebSocketRelayMessage::Binary(bytes.into())
                } else {
                    WebSocketRelayMessage::Text(payload.into())
                });
            }
            Decision::Drop | Decision::Block => {
                return Ok(WebSocketRelayEventOutput {
                    messages: vec![],
                    close: None,
                    extensions,
                });
            }
            Decision::Close { code, reason } => {
                return Ok(close_intercepted_websocket(extensions, code, reason));
            }
            _ => (),
        }
    }
    if let (Some(capture), Some(exchange_id)) =
        (capture, extensions.get_ref::<HttpExchangeId>().copied())
    {
        if let Some(injector) = extensions.get_ref::<WebSocketRelayInjector>() {
            capture.register_websocket_injector(exchange_id.0, injector.clone());
        }
        let (kind, data, close_code) = match &event {
            WebSocketRelayEvent::Open => {
                return Ok(WebSocketRelayEventInput {
                    direction,
                    event,
                    extensions,
                }
                .into());
            }
            WebSocketRelayEvent::Data(WebSocketRelayMessage::Text(text)) => {
                (WebSocketMessageKind::Text, Bytes::from(text.clone()), None)
            }
            WebSocketRelayEvent::Data(WebSocketRelayMessage::Binary(data)) => {
                (WebSocketMessageKind::Binary, data.clone(), None)
            }
            WebSocketRelayEvent::Ping(data) => (WebSocketMessageKind::Ping, data.clone(), None),
            WebSocketRelayEvent::Pong(data) => (WebSocketMessageKind::Pong, data.clone(), None),
            WebSocketRelayEvent::Close(frame) => (
                WebSocketMessageKind::Close,
                frame
                    .as_ref()
                    .map(|frame| Bytes::from(frame.reason.clone()))
                    .unwrap_or_default(),
                frame.as_ref().map(|frame| frame.code),
            ),
        };
        capture
            .record_websocket_message(
                exchange_id.0,
                CapturedWebSocketMessage {
                    at: jiff::Timestamp::now(),
                    direction,
                    kind,
                    data,
                    close_code,
                    origin: WebSocketMessageOrigin::Peer,
                },
            )
            .await;
    }
    Ok(WebSocketRelayEventOutput::from(WebSocketRelayEventInput {
        direction,
        event,
        extensions,
    }))
}
