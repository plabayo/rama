//! Utilities to aid in the handshake phase of establishing a WebSocket connection.

pub mod client;

mod subprotocol;
#[doc(inline)]
pub use subprotocol::{AcceptedSubProtocol, SubProtocols};
