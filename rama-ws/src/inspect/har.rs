//! Streaming WebSocket HAR fields, owned by the WebSocket adapter.

use rama_core::error::BoxError;
use rama_http::{
    inspect::capture::ExchangeCapture,
    layer::har::{
        inspect::{HarEntryExtension, HarObjectWriter, write_json_string},
        spec,
    },
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{
    handshake::mitm::WebSocketRelayDirection,
    inspect::{CapturedWebSocketMessage, WebSocketMessageKind},
};

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
        // Fixed-shape scalar metadata only; reuse this small buffer across messages.
        let mut header = Vec::with_capacity(128);
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
            header.clear();
            header.extend_from_slice(b"{\"type\":");
            serde_json::to_writer(&mut header, &direction)?;
            header.extend_from_slice(b",\"time\":");
            serde_json::to_writer(
                &mut header,
                &(metadata.at.as_millisecond() as f64 / 1_000.0),
            )?;
            header.extend_from_slice(b",\"opcode\":");
            serde_json::to_writer(&mut header, &opcode)?;
            header.extend_from_slice(b",\"data\":");
            writer.write_all(&header).await?;
            // HAR's WebSocket extension has no encoding field: the opcode
            // distinguishes UTF-8 text from base64-encoded binary payloads.
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
