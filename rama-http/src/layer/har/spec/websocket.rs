use base64::{Engine as _, engine::general_purpose::STANDARD};
use rama_utils::str::arcstr::ArcStr;
use serde::{Deserialize, Serialize};

/// A Chrome DevTools WebSocket message stored in an HAR entry's
/// `_webSocketMessages` extension.
///
/// Chrome exports complete WebSocket messages rather than fragmented wire frames.
/// The shape is unchanged from the [Chrome 76 announcement] and the current
/// Chromium DevTools HAR exporter.
///
/// [Chrome 76 announcement]: https://developer.chrome.com/blog/new-in-devtools-76#websocket
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebSocketMessage {
    /// Whether the message was sent, received, or reports a protocol error.
    pub r#type: WebSocketMessageType,
    /// Unix timestamp in seconds, including any fractional part.
    ///
    /// Unlike HAR's `startedDateTime`, Chromium emits this as a JSON number.
    pub time: f64,
    /// WebSocket opcode, or [`WebSocketMessageOpcode::ERROR`] for an error record.
    pub opcode: WebSocketMessageOpcode,
    /// Message payload.
    ///
    /// Text messages and error records contain their original text. Chromium's
    /// DevTools Protocol supplies non-text message data as base64, so binary
    /// messages use a base64 string here.
    pub data: ArcStr,
}

impl WebSocketMessage {
    /// Create a message with an explicitly supplied opcode and already encoded data.
    #[must_use]
    pub fn new(
        r#type: WebSocketMessageType,
        time: f64,
        opcode: WebSocketMessageOpcode,
        data: impl Into<ArcStr>,
    ) -> Self {
        Self {
            r#type,
            time,
            opcode,
            data: data.into(),
        }
    }

    /// Create a text message (`opcode: 1`).
    #[must_use]
    pub fn text(r#type: WebSocketMessageType, time: f64, data: impl Into<ArcStr>) -> Self {
        Self::new(r#type, time, WebSocketMessageOpcode::TEXT, data)
    }

    /// Create a binary message (`opcode: 2`), base64-encoding the supplied bytes.
    #[must_use]
    pub fn binary(r#type: WebSocketMessageType, time: f64, data: impl AsRef<[u8]>) -> Self {
        Self::binary_with_opcode(r#type, time, WebSocketMessageOpcode::BINARY, data)
    }

    /// Create a non-text message and base64-encode its payload.
    #[must_use]
    pub fn binary_with_opcode(
        r#type: WebSocketMessageType,
        time: f64,
        opcode: WebSocketMessageOpcode,
        data: impl AsRef<[u8]>,
    ) -> Self {
        Self::new(r#type, time, opcode, STANDARD.encode(data))
    }

    /// Create the error record shape used by Chromium (`type: "error"`, `opcode: -1`).
    #[must_use]
    pub fn error(time: f64, message: impl Into<ArcStr>) -> Self {
        Self::new(
            WebSocketMessageType::Error,
            time,
            WebSocketMessageOpcode::ERROR,
            message,
        )
    }

    /// Decode a binary message's base64 payload.
    ///
    /// Returns `None` for other opcodes. A malformed base64 payload remains visible
    /// as a decode error instead of being silently discarded.
    pub fn binary_data(&self) -> Option<Result<Vec<u8>, base64::DecodeError>> {
        (self.opcode == WebSocketMessageOpcode::BINARY)
            .then(|| STANDARD.decode(self.data.as_bytes()))
    }
}

/// The `type` values accepted and emitted by current Chromium DevTools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebSocketMessageType {
    /// A message sent by the inspected client.
    Send,
    /// A message received by the inspected client.
    Receive,
    /// A WebSocket protocol error recorded by DevTools.
    Error,
}

/// Numeric opcode used by Chromium's `_webSocketMessages` records.
///
/// This is intentionally an open newtype rather than a closed enum: Chromium's HAR
/// importer accepts any numeric opcode, and retaining unknown values makes imports
/// forward compatible. The constants cover RFC 6455 opcodes plus Chromium's `-1`
/// error sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WebSocketMessageOpcode(i32);

impl WebSocketMessageOpcode {
    pub const ERROR: Self = Self(-1);
    pub const CONTINUATION: Self = Self(0);
    pub const TEXT: Self = Self(1);
    pub const BINARY: Self = Self(2);
    pub const CLOSE: Self = Self(8);
    pub const PING: Self = Self(9);
    pub const PONG: Self = Self(10);

    #[must_use]
    pub const fn new(value: i32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self.0
    }
}

impl From<i32> for WebSocketMessageOpcode {
    fn from(value: i32) -> Self {
        Self::new(value)
    }
}

impl From<WebSocketMessageOpcode> for i32 {
    fn from(value: WebSocketMessageOpcode) -> Self {
        value.as_i32()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TIME: f64 = 1_558_730_482.507_147_3;

    #[test]
    fn serializes_in_chromium_shape() {
        let message =
            WebSocketMessage::text(WebSocketMessageType::Send, TIME, "Hello, WebSockets!");

        assert_eq!(
            serde_json::to_value(message).expect("serialize text message"),
            json!({
                "type": "send",
                "time": TIME,
                "opcode": 1,
                "data": "Hello, WebSockets!",
            })
        );
    }

    #[test]
    fn binary_constructor_base64_encodes_and_decodes_payload() {
        let bytes = [0x00, 0x01, 0x02, 0xaa];
        let message = WebSocketMessage::binary(WebSocketMessageType::Receive, TIME, bytes);

        assert_eq!(message.opcode, WebSocketMessageOpcode::BINARY);
        assert_eq!(message.data.as_str(), "AAECqg==");
        assert_eq!(
            message
                .binary_data()
                .expect("binary opcode")
                .expect("valid base64"),
            bytes
        );
    }

    #[test]
    fn binary_data_rejects_non_binary_messages_and_invalid_base64() {
        let text = WebSocketMessage::text(WebSocketMessageType::Send, TIME, "hello");
        assert!(text.binary_data().is_none());

        let malformed = WebSocketMessage::new(
            WebSocketMessageType::Receive,
            TIME,
            WebSocketMessageOpcode::BINARY,
            "not base64!",
        );
        malformed
            .binary_data()
            .expect("binary opcode")
            .expect_err("malformed base64 must fail");
    }

    #[test]
    fn error_shape_uses_signed_opcode_sentinel() {
        let message = WebSocketMessage::error(TIME, "Invalid frame header");

        assert_eq!(
            serde_json::to_value(&message).expect("serialize error message"),
            json!({
                "type": "error",
                "time": TIME,
                "opcode": -1,
                "data": "Invalid frame header",
            })
        );
        assert_eq!(message.opcode.as_i32(), -1);
    }

    #[test]
    fn message_round_trip_preserves_all_types_and_unknown_opcodes() {
        let messages = vec![
            WebSocketMessage::text(WebSocketMessageType::Send, TIME, "sent"),
            WebSocketMessage::binary(WebSocketMessageType::Receive, TIME + 1.0, [1, 2, 3]),
            WebSocketMessage::error(TIME + 2.0, "failed"),
            WebSocketMessage::new(
                WebSocketMessageType::Receive,
                TIME + 3.0,
                WebSocketMessageOpcode::new(42),
                "future opcode",
            ),
        ];

        let encoded = serde_json::to_vec(&messages).expect("serialize messages");
        let decoded: Vec<WebSocketMessage> =
            serde_json::from_slice(&encoded).expect("deserialize messages");
        assert_eq!(decoded, messages);
        assert_eq!(decoded[3].opcode.as_i32(), 42);
    }

    #[test]
    fn rfc_opcode_constants_have_expected_wire_values() {
        assert_eq!(WebSocketMessageOpcode::CONTINUATION.as_i32(), 0);
        assert_eq!(WebSocketMessageOpcode::TEXT.as_i32(), 1);
        assert_eq!(WebSocketMessageOpcode::BINARY.as_i32(), 2);
        assert_eq!(WebSocketMessageOpcode::CLOSE.as_i32(), 8);
        assert_eq!(WebSocketMessageOpcode::PING.as_i32(), 9);
        assert_eq!(WebSocketMessageOpcode::PONG.as_i32(), 10);
    }

    #[test]
    fn opcode_integer_conversions_preserve_value() {
        let opcode = WebSocketMessageOpcode::from(42);
        assert_eq!(opcode, WebSocketMessageOpcode::new(42));
        assert_eq!(i32::from(opcode), 42);
    }
}
