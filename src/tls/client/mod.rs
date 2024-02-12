//! TLS client support for Rama.

mod service;
pub use service::{TlsConnectError, TlsConnectService};

mod layer;
pub use layer::TlsConnectLayer;
