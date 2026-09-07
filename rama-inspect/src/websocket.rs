//! WebSocket capture and interception adapters, enabled independently of storage.
pub use crate::http::capture::CaptureWebSocketLayer;
use crate::http::capture::{CaptureStore, ExchangeId};
use rama_ws::handshake::mitm::{
    WebSocketRelayEvent, WebSocketRelayEventInput, WebSocketRelayEventOutput,
    WebSocketRelayInjector, WebSocketRelayMessage,
};
use std::convert::Infallible;

fn close_intercepted_websocket(
    extensions: rama_core::extensions::Extensions,
    code: u16,
    reason: String,
) -> WebSocketRelayEventOutput {
    use rama_ws::{
        handshake::mitm::WebSocketRelayClose,
        protocol::{CloseFrame, frame::coding::CloseCode},
    };
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
    use crate::http::control::{Decision, WebSocketContext};
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    let WebSocketRelayEventInput {
        direction,
        mut event,
        extensions,
    } = input;
    if let (Some(store), Some(context), WebSocketRelayEvent::Data(data)) = (
        capture.as_ref().filter(|s| s.control().is_active()),
        extensions.get_ref::<WebSocketContext>(),
        &event,
    ) {
        let mut message = context.request.clone();
        message.protocol = if message.protocol == "https" {
            "wss"
        } else {
            "ws"
        }
        .into();
        message.direction = format!("{direction:?}").to_ascii_lowercase();
        message.exchange = extensions.get_ref::<ExchangeId>().map(|id| id.0);
        message.binary = matches!(data, WebSocketRelayMessage::Binary(_));
        message.kind = if message.binary { "binary" } else { "text" }.into();
        let size = match data {
            WebSocketRelayMessage::Text(t) => t.len(),
            WebSocketRelayMessage::Binary(b) => b.len().saturating_mul(4).div_ceil(3),
        };
        message.oversized = size > 256 * 1024;
        message.payload = (!message.oversized).then(|| match data {
            WebSocketRelayMessage::Text(t) => t.to_string(),
            WebSocketRelayMessage::Binary(b) => BASE64.encode(b),
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
        (capture, extensions.get_ref::<ExchangeId>().copied())
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
                ("text", text.as_bytes().to_vec(), None)
            }
            WebSocketRelayEvent::Data(WebSocketRelayMessage::Binary(data)) => {
                ("binary", data.to_vec(), None)
            }
            WebSocketRelayEvent::Ping(data) => ("ping", data.to_vec(), None),
            WebSocketRelayEvent::Pong(data) => ("pong", data.to_vec(), None),
            WebSocketRelayEvent::Close(frame) => (
                "close",
                frame
                    .as_ref()
                    .map(|frame| frame.reason.as_bytes().to_vec())
                    .unwrap_or_default(),
                frame.as_ref().map(|frame| u16::from(&frame.code)),
            ),
        };
        capture
            .record_websocket_message(
                exchange_id.0,
                format!("{direction:?}"),
                kind.to_owned(),
                data,
                close_code,
            )
            .await;
    }
    Ok(WebSocketRelayEventOutput::from(WebSocketRelayEventInput {
        direction,
        event,
        extensions,
    }))
}
