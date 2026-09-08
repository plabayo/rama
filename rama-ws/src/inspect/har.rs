//! Streaming WebSocket HAR fields, owned by the WebSocket adapter.
use crate::{
    handshake::mitm::WebSocketRelayDirection,
    inspect::{CapturedWebSocketMessage, WebSocketMessageKind},
};
use rama_core::error::BoxError;
use rama_http::{
    inspect::capture::ExchangeCapture,
    layer::har::{
        inspect::{HarEntryExtension, HarObjectWriter, write_json_string},
        spec,
    },
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Adds captured WebSocket messages to an HTTP handshake's HAR entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct WebSocketHarExtension;
impl HarEntryExtension for WebSocketHarExtension {
    async fn write_fields<W: AsyncWrite + Unpin + Send>(
        &self,
        fields: &mut HarObjectWriter<'_, W>,
        capture: &ExchangeCapture,
    ) -> Result<(), BoxError> {
        if !matches!(capture.snapshot().protocol.as_str(), "ws" | "wss") {
            return Ok(());
        }
        fields.field("_resourceType", "websocket").await?;
        let writer = fields.streamed_field("_webSocketMessages").await?;
        writer.write_all(b"[").await?;
        let count = capture.count::<CapturedWebSocketMessage>();
        let mut first = true;
        for index in 0..count {
            let Some(message) = capture.record::<CapturedWebSocketMessage>(index).await? else {
                break;
            };
            let opcode = match message.kind {
                WebSocketMessageKind::Text => spec::WebSocketMessageOpcode::TEXT,
                WebSocketMessageKind::Binary => spec::WebSocketMessageOpcode::BINARY,
                _ => continue,
            };
            let direction = match message.direction {
                WebSocketRelayDirection::Ingress => spec::WebSocketMessageType::Send,
                WebSocketRelayDirection::Egress => spec::WebSocketMessageType::Receive,
            };
            if !first {
                writer.write_all(b",").await?;
            }
            first = false;
            writer.write_all(b"{\"type\":").await?;
            writer.write_all(&serde_json::to_vec(&direction)?).await?;
            writer.write_all(b",\"time\":").await?;
            writer
                .write_all(&serde_json::to_vec(
                    &(message.at.as_millisecond() as f64 / 1_000.0),
                )?)
                .await?;
            writer.write_all(b",\"opcode\":").await?;
            writer.write_all(&serde_json::to_vec(&opcode)?).await?;
            writer.write_all(b",\"data\":").await?;
            write_json_string(
                writer,
                message.data.as_ref(),
                message.kind == WebSocketMessageKind::Text,
            )
            .await?;
            writer.write_all(b"}").await?;
        }
        writer.write_all(b"]").await?;
        Ok(())
    }
}
