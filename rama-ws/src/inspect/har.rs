//! Streaming WebSocket HAR fields, owned by the WebSocket adapter.
use crate::{
    handshake::mitm::WebSocketRelayDirection,
    inspect::{CapturedWebSocketMessage, WebSocketMessageKind, WebSocketMessageMetadata},
};
use rama_core::error::BoxError;
use rama_http::{
    inspect::capture::{CapturedRecordStream, ExchangeCapture},
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
        if !matches!(
            capture.snapshot().protocol,
            rama_net::Protocol::WS | rama_net::Protocol::WSS
        ) {
            return Ok(());
        }
        fields.field("_resourceType", "websocket").await?;
        let writer = fields.streamed_field("_webSocketMessages").await?;
        writer.write_all(b"[").await?;
        let count = capture.count::<CapturedWebSocketMessage>();
        let mut first = true;
        for index in 0..count {
            let Some(message) = capture
                .record_stream::<CapturedWebSocketMessage>(index)
                .await?
            else {
                break;
            };
            let metadata = message.metadata;
            let opcode = match metadata.kind {
                WebSocketMessageKind::Text => spec::WebSocketMessageOpcode::TEXT,
                WebSocketMessageKind::Binary => spec::WebSocketMessageOpcode::BINARY,
                _ => continue,
            };
            let direction = match metadata.direction {
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
                    &(metadata.at.as_millisecond() as f64 / 1_000.0),
                )?)
                .await?;
            writer.write_all(b",\"opcode\":").await?;
            writer.write_all(&serde_json::to_vec(&opcode)?).await?;
            writer.write_all(b",\"data\":").await?;
            write_json_string(
                writer,
                message.payload,
                metadata.kind == WebSocketMessageKind::Text,
            )
            .await?;
            writer.write_all(b"}").await?;
        }
        writer.write_all(b"]").await?;
        Ok(())
    }
}

/// Stream a captured WebSocket message as JSON without materializing its payload
/// or an encoded string. The JSON shape matches `CapturedWebSocketMessage`.
pub async fn write_captured_websocket_json<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: CapturedRecordStream<WebSocketMessageMetadata>,
) -> Result<(), BoxError> {
    let metadata = message.metadata;
    let mut object = HarObjectWriter::begin(writer).await?;
    object.field("at", &metadata.at).await?;
    object.field("direction", &metadata.direction).await?;
    object.field("kind", &metadata.kind).await?;
    write_json_string(object.streamed_field("data").await?, message.payload, false).await?;
    object.field("close_code", &metadata.close_code).await?;
    object.field("origin", &metadata.origin).await?;
    object.finish().await
}
