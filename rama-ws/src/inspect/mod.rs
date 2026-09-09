//! WebSocket inspection layered onto an HTTP handshake capture.
//! HTTP owns the handshake and generic upgrade lifetime; this module owns message
//! records, replay, injection and relay decisions.

mod capture;
pub mod har;
mod layer;
mod relay;
pub use capture::{
    CaptureWebSocketExt, CapturedWebSocketMessage, WebSocketDetails, WebSocketLimits,
    WebSocketMessageKind, WebSocketMessageMetadata, WebSocketMessageOrigin,
    WebSocketMessagePreview, WebSocketReplayError, observe_handshake, read_details,
    read_preview_details,
};
pub use layer::{CaptureWebSocketLayer, CaptureWebSocketService};
pub use relay::inspect_websocket_event;

#[cfg(test)]
mod tests;
