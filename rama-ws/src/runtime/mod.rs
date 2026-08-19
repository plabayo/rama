//! Async runtime for Rama WebSockets
//!
//! Forked from tokio-tungstenite.

use rama_core::{
    extensions::ExtensionsRef,
    futures::{Sink, Stream},
};

use crate::{Message, ProtocolError};

mod compat;
mod handshake;
mod stream;

pub use stream::AsyncWebSocket;

/// A complete asynchronous WebSocket message transport.
///
/// This trait gives middleware a protocol-level boundary without coupling it
/// to [`AsyncWebSocket`] or to the raw byte transport below it. Implementations
/// can decorate reads and writes while retaining access to connection
/// extensions.
pub trait WebSocketIo:
    Stream<Item = Result<Message, ProtocolError>>
    + Sink<Message, Error = ProtocolError>
    + ExtensionsRef
    + Send
    + Unpin
    + 'static
{
}

impl<T> WebSocketIo for T where
    T: Stream<Item = Result<Message, ProtocolError>>
        + Sink<Message, Error = ProtocolError>
        + ExtensionsRef
        + Send
        + Unpin
        + 'static
{
}
