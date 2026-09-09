use rama_core::error::BoxError;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{HarObjectWriter, spec, write_json_string};

/// Write a Chromium HAR WebSocket message with a streamed payload.
/// Set `utf8` for text or already base64-encoded HAR data; raw binary payloads
/// are base64-encoded incrementally. The opcode determines how HAR readers
/// interpret the data: this extension has no separate encoding field.
pub async fn write_web_socket_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    direction: spec::WebSocketMessageType,
    time: f64,
    opcode: spec::WebSocketMessageOpcode,
    payload: impl AsyncRead + Unpin,
    utf8: bool,
) -> Result<(), BoxError> {
    let mut object = HarObjectWriter::begin(writer).await?;
    object.field("type", &direction).await?;
    object.field("time", &time).await?;
    object.field("opcode", &opcode).await?;
    write_json_string(object.streamed_field("data").await?, payload, utf8).await?;
    object.finish().await
}
