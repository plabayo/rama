//! WebSocket's HAR extension, separate from HTTP entry conversion.
use crate::{
    Utf8Bytes,
    handshake::mitm::WebSocketRelayDirection,
    inspect::{CapturedMessage, MessageKind},
};
use rama_core::error::BoxError;
use rama_http::layer::har::spec;

pub fn append_messages(
    entry: &mut spec::Entry,
    messages: impl IntoIterator<Item = CapturedMessage>,
) -> Result<(), BoxError> {
    entry.resource_type = Some("websocket".into());
    let records = entry.web_socket_messages.get_or_insert_default();
    for message in messages {
        let direction = match message.direction {
            WebSocketRelayDirection::Ingress => spec::WebSocketMessageType::Send,
            WebSocketRelayDirection::Egress => spec::WebSocketMessageType::Receive,
        };
        let time = message.at.as_millisecond() as f64 / 1_000.0;
        match message.kind {
            MessageKind::Text => records.push(spec::WebSocketMessage::text(
                direction,
                time,
                Utf8Bytes::try_from(message.data)?.as_str(),
            )),
            MessageKind::Binary => records.push(spec::WebSocketMessage::binary(
                direction,
                time,
                message.data,
            )),
            _ => {}
        }
    }
    Ok(())
}
