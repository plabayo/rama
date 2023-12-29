//! TLS server support for Rama.

mod layer;
pub use layer::{TlsAcceptorLayer, TlsAcceptorService, TtlsAcceptorError};
