//! TLS implementation agnostic client types
//!
//! [`ClientHello`] is used in Rama as the implementation agnostic type
//! to convey what client hello was set by the incoming TLS Connection,
//! if the server middleware is configured to store it.
//!
//! By being implementation agnostic we have the advantage to be able to bridge
//! easily between different implementations. Making it possible to run for example
//! a Rustls proxy service but establish connections using BoringSSL.

mod hello;
#[doc(inline)]
pub use hello::{ClientHello, ClientHelloExtension};

#[cfg(feature = "boring")]
mod parser;
