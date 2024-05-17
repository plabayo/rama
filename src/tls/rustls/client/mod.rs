//! TLS client support for Rama.

mod service;
#[doc(inline)]
pub use service::{TlsConnectError, TlsConnectService};

mod http;
#[doc(inline)]
pub use http::{AutoTlsStream, HttpsConnector, HttpsConnectorLayer};
