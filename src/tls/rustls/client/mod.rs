//! TLS client support for Rama.

mod service;
#[doc(inline)]
pub use service::{TlsConnectError, TlsConnectService};

mod layer;
#[doc(inline)]
pub use layer::TlsConnectLayer;
