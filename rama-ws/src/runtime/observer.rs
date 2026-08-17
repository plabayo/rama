use crate::{Message, ProtocolError};
use rama_core::error::BoxError;
use std::{
    fmt,
    task::{Context, Poll},
};

/// Optional message observer installed around the regular WebSocket runtime.
///
/// The protocol implementation is unaware of concrete observers. Integrations
/// such as HAR capture translate their own extension into this adapter.
pub(crate) trait WebSocketObserver: Send + fmt::Debug + 'static {
    fn poll_ready(&mut self, ctx: &mut Context<'_>) -> Poll<Result<(), BoxError>>;

    fn record_message(&mut self, outgoing: bool, message: &Message) -> Result<(), BoxError>;

    fn record_error(&mut self, error: &ProtocolError) -> Result<(), BoxError>;
}

pub(crate) type BoxWebSocketObserver = Box<dyn WebSocketObserver>;
