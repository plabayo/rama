//! Rama services that operate directly on [`crate::net::stream::Stream`] types.
//!
//! Examples are services that can operate directly on a `TCP`, `TLS` or `UDP` stream.

mod echo;
#[doc(inline)]
pub use echo::EchoService;
