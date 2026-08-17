//! Adapter between the HTTP HAR layer's opaque capture extension and the
//! protocol-agnostic WebSocket observer hook.

use crate::{
    Message, ProtocolError,
    protocol::Role,
    runtime::observer::{BoxWebSocketObserver, WebSocketObserver},
};
use rama_core::{error::BoxError, extensions::ExtensionsRef};
use rama_http::layer::har::{
    recorder::{WebSocketCapture, WebSocketCaptureLease},
    spec::{WebSocketMessage, WebSocketMessageType},
};
use rama_utils::time::unix_timestamp_millis;
use std::task::{Context, Poll};

pub(crate) fn observer_from_extensions<S>(stream: &S, role: Role) -> Option<BoxWebSocketObserver>
where
    S: ExtensionsRef,
{
    stream
        .extensions()
        .get_ref::<WebSocketCapture>()
        .and_then(WebSocketCapture::lease)
        .map(|capture| Box::new(HarWebSocketObserver { capture, role }) as BoxWebSocketObserver)
}

#[derive(Debug)]
struct HarWebSocketObserver {
    capture: WebSocketCaptureLease,
    role: Role,
}

impl WebSocketObserver for HarWebSocketObserver {
    fn poll_ready(&mut self, ctx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.capture.poll_ready(ctx)
    }

    fn record_message(&mut self, outgoing: bool, message: &Message) -> Result<(), BoxError> {
        let message_type = match (self.role, outgoing) {
            (Role::Client, true) | (Role::Server, false) => WebSocketMessageType::Send,
            (Role::Client, false) | (Role::Server, true) => WebSocketMessageType::Receive,
        };
        if let Some(message) = into_har_message(message_type, message) {
            self.capture.start_record(message)?;
        }
        Ok(())
    }

    fn record_error(&mut self, error: &ProtocolError) -> Result<(), BoxError> {
        self.capture.start_record(WebSocketMessage::error(
            epoch_seconds_from_millis(unix_timestamp_millis()),
            error.to_string(),
        ))
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
    use super::{epoch_seconds_from_millis, into_har_message};
    use crate::{Message, protocol::frame::Frame};
    use rama_http::layer::har::spec::{WebSocketMessageOpcode, WebSocketMessageType};

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
