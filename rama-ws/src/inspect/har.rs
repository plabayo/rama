//! Streaming WebSocket HAR fields, owned by the WebSocket adapter.

use rama_core::error::BoxError;
use rama_http::{
    inspect::capture::ExchangeCapture,
    layer::har::{
        spec,
        stream::{HarEntryExtension, HarObjectWriter, write_web_socket_message},
    },
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{
    handshake::mitm::WebSocketRelayDirection,
    inspect::{CapturedWebSocketMessage, WebSocketMessageKind},
};

/// Adds captured WebSocket messages to an HTTP handshake's HAR entry.
#[derive(Debug, Clone, Copy)]
pub struct WebSocketHarExtension<'a>(pub &'a ExchangeCapture);

impl HarEntryExtension for WebSocketHarExtension<'_> {
    async fn write_fields<W: AsyncWrite + Unpin + Send>(
        &self,
        fields: &mut HarObjectWriter<'_, W>,
    ) -> Result<(), BoxError> {
        let capture = self.0;
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
            write_web_socket_message(
                writer,
                direction,
                metadata.at.as_millisecond() as f64 / 1_000.0,
                opcode,
                message.payload,
                metadata.kind == WebSocketMessageKind::Text,
            )
            .await?;
        }
        writer.write_all(b"]").await?;
        Ok(())
    }
}
